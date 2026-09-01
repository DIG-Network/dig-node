//! Rendering attacker-supplied text into an operator-facing sentence (dig-node#346).
//!
//! # The problem this exists to solve
//!
//! `pairing.request` is an OPEN, unauthenticated method, and the `client_name` it carries is
//! composed into the sentence an operator reads before granting a control token. The operator's
//! only evidence about who is asking is that string, so it is the input to a privileged decision.
//!
//! Three attacks follow from composing it verbatim, all of them demonstrated on the dig-app
//! equivalent (dig-app PR #265):
//!
//! 1. **An UNMARKED truncation is a forgery the app performs.** Pad a hostile name with
//!    characters that consume the length budget while rendering as nothing, and the software's own
//!    clip produces a short, trusted-looking name. Nobody typed the lie; the renderer wrote it.
//! 2. **Zero-width and format characters survive `trim`.** U+200B-200F, U+061C, U+2060 and U+FEFF
//!    are neither `char::is_control` nor whitespace, so they pass every obvious filter while
//!    spending budget.
//! 3. **Composition.** The prompt is line-oriented and the value is quoted rather than escaped, so
//!    a newline or a bidi override lets the value forge additional lines in the node's own voice.
//!
//! # The three rules, and why each is structural rather than advisory
//!
//! - **The clip mark is IN-BAND.** [`render_untrusted`] returns ONE `String` that already contains
//!   its marker. There is no companion `bool` a caller can forget to read - the dropped `bool`
//!   *was* the dig-app CRITICAL.
//! - **The budget is charged on RENDERED WIDTH**, after the invisible characters are made visible,
//!   so a name cannot buy silence with characters that occupy no columns.
//! - **Only the RENDERING is neutralised.** The stored `client_name` stays byte-verbatim, because
//!   anything that is ever compared or used as an identity must not be quietly rewritten.

use unicode_width::UnicodeWidthChar;

/// The in-band marker appended when a value was clipped.
///
/// It names the actor: the operator must be able to tell "this name is short" from "we made this
/// name short".
pub const CLIP_MARK: &str = "[clipped by dig-node]";

/// The replacement for a character that must not reach the terminal.
///
/// A visible placeholder rather than a deletion: silently dropping a character lets an attacker
/// choose what the operator sees just as effectively as inserting one, and leaves no trace that
/// anything was removed.
pub const REPLACEMENT: char = '\u{fffd}';

/// Whether `c` may never be rendered into an operator-facing sentence.
///
/// Covers three families, all of which the naive `char::is_control` check misses at least part of:
///
/// - **Control characters**, including the newline and carriage return that let a value forge its
///   own line, and the tab that lets it forge a column.
/// - **Unicode `Cf` FORMAT characters** - the zero-width space/joiner family, the word joiner and
///   the byte-order mark. Enumerated by range rather than by an `is_*` predicate the standard
///   library does not offer.
/// - **Bidirectional overrides and isolates**, which reorder the text AROUND them and so can
///   rewrite the quoting the prompt relies on.
fn is_forbidden(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    matches!(c as u32,
        0x00AD                    // SOFT HYPHEN
        | 0x061C                  // ARABIC LETTER MARK
        | 0x180E                  // MONGOLIAN VOWEL SEPARATOR
        | 0x200B..=0x200F         // zero-width space/joiner/non-joiner, LRM, RLM
        | 0x202A..=0x202E         // bidi embeddings + overrides
        | 0x2060..=0x2064         // word joiner + invisible operators
        | 0x2066..=0x206F         // bidi isolates + deprecated format chars
        | 0xFEFF                  // zero-width no-break space / BOM
        | 0xFFF9..=0xFFFB         // interlinear annotation
        | 0x1D173..=0x1D17A       // musical format controls
        | 0xE0000..=0xE007F       // tag characters
    )
}

/// Render attacker-supplied `raw` for an operator, within `width_budget` display columns.
///
/// Forbidden characters ([`is_forbidden`]) become [`REPLACEMENT`]; the remainder is charged
/// against the budget by its **display width**, and a value that does not fit is clipped with
/// [`CLIP_MARK`] appended IN-BAND. A value that fits is returned unmarked, so the marker's
/// presence is itself evidence.
///
/// The budget is the width of the VALUE; the marker is additional, because a marker that had to
/// fit inside the budget could be clipped away by a long enough name - which is the failure it
/// exists to prevent.
pub fn render_untrusted(raw: &str, width_budget: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    let mut clipped = false;

    for c in raw.chars() {
        let rendered = if is_forbidden(c) { REPLACEMENT } else { c };
        // A width of `None` means a non-printable the width tables cannot place; charge it as one
        // column so it can never be free.
        let w = rendered.width().unwrap_or(1).max(1);
        if used + w > width_budget {
            clipped = true;
            break;
        }
        out.push(rendered);
        used += w;
    }

    if clipped {
        out.push_str(CLIP_MARK);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** a clip is ALWAYS marked, and the mark is part of the returned string.
    ///
    /// This is the dig-app CRITICAL restated as a type fact: there is no second return value to
    /// drop, so a caller cannot render a clipped value as if it were whole.
    #[test]
    fn a_clipped_value_carries_its_mark_in_band() {
        let long = "a".repeat(200);
        let out = render_untrusted(&long, 16);
        assert!(out.ends_with(CLIP_MARK), "the clip must be marked: {out}");
        assert_eq!(
            out.chars().filter(|c| *c == 'a').count(),
            16,
            "the budget is charged on the value, not on the marker"
        );
    }

    /// **Proves:** a value that FITS is returned unmarked - so the marker means something.
    ///
    /// Without this control, an implementation that appended the mark unconditionally would pass
    /// the test above while telling the operator every name had been tampered with.
    #[test]
    fn a_value_that_fits_is_not_marked() {
        let out = render_untrusted("DIG Chrome Extension", 64);
        assert_eq!(out, "DIG Chrome Extension");
        assert!(!out.contains(CLIP_MARK));
    }

    /// **Proves attack 1:** invisible padding cannot buy a short, trusted-looking render.
    ///
    /// The attack is to spend the budget on characters that occupy zero columns so the honest
    /// suffix is clipped away and the app itself prints a clean name. Every padding character
    /// here becomes a visible replacement and is charged a column, so the result is BOTH visibly
    /// mangled and marked as clipped.
    #[test]
    fn zero_width_padding_cannot_hide_a_clip() {
        let mut hostile = String::new();
        for _ in 0..60 {
            hostile.push('\u{200b}'); // zero-width space: not control, not whitespace
        }
        hostile.push_str("Sage Wallet");

        let out = render_untrusted(&hostile, 64);

        assert!(
            !out.contains('\u{200b}'),
            "a zero-width character must never reach the terminal: {out:?}"
        );
        assert_eq!(
            out.chars().filter(|c| *c == REPLACEMENT).count(),
            60,
            "each invisible character must render visibly and cost a column"
        );
        assert!(
            !out.starts_with("Sage Wallet"),
            "the hostile prefix must remain visible rather than being padded out of view"
        );
    }

    /// **Proves attack 2/3:** a newline cannot forge a second line, and a bidi override cannot
    /// reorder the sentence around the value.
    ///
    /// The forged line is the whole attack - the prompt's own format is
    /// `- <id>  code <code>  "<name>"`, so a value containing a newline plus that shape prints a
    /// second, entirely attacker-written pending request in the node's voice.
    #[test]
    fn newlines_and_bidi_overrides_cannot_forge_a_line() {
        let forged = "ok\n  code 000000  \"Trusted App\"";
        let out = render_untrusted(forged, 200);
        assert!(!out.contains('\n'), "no newline may survive: {out:?}");
        assert!(
            out.starts_with(&format!("ok{REPLACEMENT}")),
            "the newline must render as a visible replacement: {out:?}"
        );

        for override_char in ['\u{202e}', '\u{2066}', '\u{202d}'] {
            let out = render_untrusted(&format!("a{override_char}b"), 64);
            assert!(
                !out.contains(override_char),
                "bidi control {override_char:?} must not survive: {out:?}"
            );
        }
    }

    /// **Proves:** a wide (double-column) character is charged two columns, so a CJK name cannot
    /// overflow the operator's line by rendering at twice its code-point count.
    #[test]
    fn wide_characters_are_charged_their_rendered_width() {
        // Each of these occupies two terminal columns.
        let wide = "\u{4f60}\u{597d}\u{4e16}\u{754c}"; // 4 chars, 8 columns
        assert_eq!(
            render_untrusted(wide, 8),
            wide,
            "8 columns fits a budget of 8"
        );

        let out = render_untrusted(wide, 7);
        assert!(out.ends_with(CLIP_MARK), "7 columns cannot hold 8: {out}");
        assert_eq!(
            out.chars().filter(|c| !CLIP_MARK.contains(*c)).count(),
            3,
            "only three wide characters fit in seven columns"
        );
    }

    /// **Proves:** an empty value renders empty and unmarked - the renderer invents nothing.
    #[test]
    fn an_empty_value_renders_empty() {
        assert_eq!(render_untrusted("", 64), "");
    }
}
