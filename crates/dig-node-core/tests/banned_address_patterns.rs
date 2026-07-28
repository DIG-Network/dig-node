//! A source-level ban on building a socket address out of concatenated text (#1593).
//!
//! `format!("{host}:{port}")` followed by a `SocketAddr` parse is invalid for EVERY IPv6 literal — the
//! grammar requires brackets — and §5.2 makes this ecosystem IPv6-FIRST, so the pattern is a latent v6
//! outage wherever it survives. It has already cost real time: in dig-download it made the fetchRange
//! metadata probe fail *before a socket was opened*, which presented as a 404 with no holder inbound and
//! blocked the entire #836 read leg.
//!
//! A unit test cannot catch a pattern that has not been written yet, so the guard is a scan of the
//! source itself. It fails on the CONSTRUCT — a parsed `{…}:{…}` shape in a `format!` call that names
//! address vocabulary, in ANY interpolation spelling and across rustfmt's line wrapping — rather than on
//! a list of known-bad spellings, which is what makes it hold against code nobody has written yet.
//!
//! What it does NOT cover, stated so the boundary is not mistaken for the whole: an address assembled by
//! `push_str`/`+`/`write!` rather than `format!`, or one assembled across statements. The ban targets the
//! idiom that has actually caused outages here; it is not a proof of absence.
//!
//! The right constructions, for reference: `SocketAddr::new(ip, port)` from a parsed
//! [`IpAddr`](std::net::IpAddr), or `(host, port).to_socket_addrs()` when the host may be a DNS name.

use std::path::{Path, PathBuf};

/// Violations that already existed when this guard was strengthened — TRACKED, not waived.
///
/// **Currently EMPTY**, and that is the intended steady state: both original entries were the
/// #1682 defects and both are now fixed at the source. It is kept rather than deleted because the
/// mechanism — an exception matched on its distinguishing SNIPPET and its FILE, never on a line
/// number or a filename alone — is what makes a future tracked violation recordable without going
/// blind, and [`a_tracked_violation_excuses_only_its_own_call_not_its_whole_file`] keeps that
/// property honest against an empty list too.
///
/// Adding an entry is a debt, not a waiver: it needs a ticket, and the reason fixing it does not
/// belong in the same change. Weakening the matcher instead is never the answer — that trades a
/// real defect for a comfortable test, which is precisely how these two defects stayed invisible.
const KNOWN_VIOLATIONS: &[(&str, &str)] = &[];

/// A relative path with platform separators normalized to `/`, so every path comparison in this
/// scanner reads the same on Windows and Unix.
fn normalize(relative_path: &str) -> String {
    relative_path.replace('\\', "/")
}

/// Is this call excused by `tracked`, in the file that entry names?
///
/// Takes the list as a PARAMETER rather than reading [`KNOWN_VIOLATIONS`] directly so the matching
/// rule stays provable while the real list is empty. A self-test that could only feed it real
/// entries would go vacuous the moment the debt was paid — and the rule it proves (an entry excuses
/// its own call, never its whole file) is exactly what must not rot before the NEXT entry is added.
fn is_known_violation(tracked: &[(&str, &str)], relative_path: &str, call: &str) -> bool {
    let normalized = normalize(relative_path);
    tracked
        .iter()
        .any(|(file, snippet)| normalized.ends_with(file) && call.contains(snippet))
}

/// The crates directory this test scans — the whole workspace, not just this crate, so a sibling crate
/// cannot reintroduce the pattern unnoticed.
fn crates_root() -> PathBuf {
    // <workspace>/crates/dig-node-core/ → <workspace>/crates
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dig-node-core sits under crates/")
        .to_path_buf()
}

/// Every `.rs` file under `dir`, recursively, skipping build output.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// Does this `format!` call build an ADDRESS by interpolating a port onto a host?
///
/// Two conditions, both required, and both evaluated over the WHOLE `format!` call rather than over one
/// source line. The call's format string must render an interpolation, a colon, and another
/// interpolation adjacently — AND the values FEEDING that pair must be address-like.
///
/// The shape is PARSED, not spelled (see [`interpolated_colon_pair`]), because a spelling list only ever
/// bans the spellings someone thought to list. An earlier version of this guard matched exactly
/// `{}:{}`, `{host}:{port}` and `{}:{port}`, which let `format!("{ip}:{port}")` — the most natural
/// spelling for the very `IpAddr` this ban exists to protect — through untouched.
///
/// The second condition is an ALLOWLIST of address vocabulary rather than a denylist of everything else,
/// because the same `a:b` rendering is how a CAPSULE (`store_id:root`) is written throughout this
/// ecosystem. A denylist would have to keep pace with every non-address use of a colon; requiring the
/// pair to actually be fed by a host or a port cannot drift that way.
fn builds_an_address_from_text(call: &str) -> bool {
    let Some(format_string) = first_string_literal(call) else {
        return false;
    };
    let Some((left, right)) = interpolated_colon_pair(&format_string) else {
        return false;
    };
    // Vocabulary is drawn from the pair's own two group names plus the argument list — NOT from the rest
    // of the format string. That is what stops a URL built around a capsule
    // (`format!("http://{addr}/s/{}:{}/x", store, root)`) from being flagged: the colon belongs to the
    // CAPSULE, `addr` is a separate and already-correct interpolation, and judging vocabulary over the
    // whole call flagged ten such lines.
    //
    // It is an APPROXIMATION, deliberately erring toward flagging. Positional groups are not mapped to
    // the arguments that fill them, so any address-like argument anywhere in the call still counts:
    // measured, `format!("{}/s/{}:{}/x", addr, store, root)` IS flagged while the equivalent
    // `format!("http://{addr}/s/{}:{}/x", store, root)` is not — the same code, decided by an unrelated
    // choice of inline-vs-positional. Being exact would require mapping each positional group to its
    // argument. A false positive here costs one `SocketAddr::new` rewrite; a false negative costs an IPv6
    // outage, so the approximation leans the safe way on purpose.
    let feeds_the_pair = format!("{left} {right} {}", argument_list(call));
    names_an_address(&feeds_the_pair)
}

/// The argument list of a `format!` call — everything after its format string literal.
fn argument_list(call: &str) -> &str {
    let Some(open) = call.find('"') else {
        return "";
    };
    let bytes = call.as_bytes();
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return &call[i + 1..],
            _ => i += 1,
        }
    }
    ""
}

/// The contents of the two groups in the first `{…}:{…}` that `fmt` renders — an interpolation, a
/// literal colon, then another interpolation.
///
/// Parsing rather than string-matching is what makes the ban cover the CLASS. Every interpolation form
/// satisfies it identically: positional (`{}`), named (`{host}`, `{ip}`), indexed (`{0}`), and one
/// carrying its own format spec (`{host:?}`) — the colon INSIDE a brace group is consumed as part of
/// that group, so only a colon BETWEEN two groups counts as the separator.
fn interpolated_colon_pair(fmt: &str) -> Option<(String, String)> {
    let bytes = fmt.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        // `{{` is an escaped brace, not an interpolation.
        if bytes.get(i + 1) == Some(&b'{') {
            i += 2;
            continue;
        }
        let first_close = close_brace(bytes, i)?;
        let separator_is_colon = bytes.get(first_close + 1) == Some(&b':');
        let second_group_opens = bytes.get(first_close + 2) == Some(&b'{');
        if separator_is_colon && second_group_opens {
            if let Some(second_close) = close_brace(bytes, first_close + 2) {
                return Some((
                    fmt[i + 1..first_close].to_string(),
                    fmt[first_close + 3..second_close].to_string(),
                ));
            }
        }
        i = first_close + 1;
    }
    None
}

/// The index of the `}` closing the brace group that opens at `open`.
fn close_brace(bytes: &[u8], open: usize) -> Option<usize> {
    (open + 1..bytes.len()).find(|&i| bytes[i] == b'}')
}

/// Does this text mention address vocabulary as a WHOLE word?
///
/// Whole words genuinely matter, and an earlier version of this guard only claimed to check them: a
/// substring test for `ip` also fires on `tip.to_hex()`, which renders a CAPSULE and is not an address
/// at all.
fn names_an_address(text: &str) -> bool {
    ["host", "port", "addr", "socket", "ip", "IpAddr"]
        .iter()
        .any(|term| contains_term(text, term))
}

/// Does `text` contain `term` as a whole snake_case COMPONENT?
///
/// The boundary is "not alphanumeric", which deliberately treats `_` as a boundary rather than as part
/// of the word: `candidate_host` and `peer_port` must both count, since that is how Rust names these
/// variables, while `tip` must not count as `ip` and `transport` must not count as `port`. An earlier
/// draft of this helper required a non-IDENTIFIER boundary and therefore missed `candidate_host` — its
/// own self-test caught that.
fn contains_term(text: &str, term: &str) -> bool {
    let is_word_char = |c: char| c.is_alphanumeric();
    text.match_indices(term).any(|(at, _)| {
        let before_ok = text[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        let after_ok = text[at + term.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_word_char(c));
        before_ok && after_ok
    })
}

/// The contents of the first double-quoted string literal in `text`, honouring `\"` escapes.
fn first_string_literal(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let open = bytes.iter().position(|&b| b == b'"')?;
    let mut literal = String::new();
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Keep the escaped character verbatim; only its quote-ness is being neutralized.
                if let Some(&escaped) = bytes.get(i + 1) {
                    literal.push(escaped as char);
                }
                i += 2;
            }
            b'"' => return Some(literal),
            byte => {
                literal.push(byte as char);
                i += 1;
            }
        }
    }
    None
}

/// Every `format!` call in `source`, as (line number, call text).
///
/// The unit of analysis is the CALL, not the line, because rustfmt wraps a long call across lines — and
/// it wraps at exactly the point that separates the format string from its arguments, so a per-line
/// scan sees a line holding `"{}:{}"` with no address vocabulary on it and a line holding `host, port`
/// with no format shape on it. Neither line trips a per-line guard; the call trips this one.
///
/// The paren matching is NOT string-aware, so a `)` inside a string argument truncates the call early.
/// Unlike this scanner's other approximations that direction is a false NEGATIVE — the truncated text can
/// lose the vocabulary that would have flagged it — so it is the first thing to fix if the ban is ever
/// extended. It affects neither tracked site nor any construction currently in the workspace.
fn format_calls(source: &str) -> Vec<(usize, String)> {
    const MARKER: &str = "format!(";
    let mut calls = Vec::new();
    for (start, _) in source.match_indices(MARKER) {
        let body_start = start + MARKER.len();
        let mut depth = 1usize;
        let mut end = body_start;
        for (offset, byte) in source.as_bytes()[body_start..].iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = body_start + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        let line = source[..start].matches('\n').count() + 1;
        calls.push((line, source[body_start..end.max(body_start)].to_string()));
    }
    calls
}

/// `source` with every comment-only line blanked, preserving line count so numbers stay accurate.
///
/// A line that merely DOCUMENTS the ban is not an offender, and this ban is discussed in prose in
/// several modules.
///
/// Stripping is WHOLE-LINE only: a trailing `// format!("{host}:{port}")` after real code still counts,
/// and so does a one-line `/* … */`. Both err toward flagging — the failure is a spurious offender that a
/// human dismisses, not a missed one — so the simpler rule is kept deliberately.
fn without_comment_lines(source: &str) -> String {
    source
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The scan's own reach, asserted so an empty scan cannot masquerade as a clean one.
///
/// Measured at introduction by the scan itself: **112 files, 766 `format!` calls, 2 waived**. The floors
/// sit below those with room for ordinary churn — they exist to catch the reach COLLAPSING, not to pin a
/// count, so a floor is lowered only after re-measuring against a real, intended shrink.
///
/// The file floor is chosen to survive churn but NOT to survive a level-directory move: this crate alone
/// holds 47 `.rs` files, so a [`crates_root`] that resolved to a single crate's level would fall well
/// under 100. That gives two independent detectors for the same accident — this floor and the waived
/// count — which matters because the waived count would go to zero for the same reason.
const MINIMUM_FILES_SCANNED: usize = 100;
const MINIMUM_FORMAT_CALLS_SEEN: usize = 600;

/// How many `dig-node-service` files the scan must read — the SIBLING-crate reach detector.
///
/// One would prove the point; the floor sits higher so a partial read is caught too, and well under
/// the real count (measured 20 at introduction) to survive ordinary churn. Any value above zero
/// gives the property the waived count used to give and no longer can: proof that the scan looked
/// OUTSIDE the crate it lives in.
const MINIMUM_SIBLING_CRATE_FILES: usize = 5;

/// **Proves:** no source file in the workspace builds a socket address by string concatenation (#1593) —
/// AND that the scan actually reached the workspace to find that out.
///
/// **Catches:** a NEW `format!("{host}:{port}")` + `parse::<SocketAddr>()` anywhere in the workspace —
/// including in a crate this test does not otherwise touch, and including in test code, since a fixture
/// that builds addresses the wrong way teaches the wrong idiom and hides the v6 case.
///
/// **Also catches the VACUOUS PASS**, which is the failure this guard is most exposed to: `rust_sources`
/// yields nothing if `read_dir` fails, unreadable files are skipped, and "scanned nothing" and "found
/// nothing" otherwise share one success signature. The strengthened matcher makes that worse rather than
/// better, because its self-test proves the MATCHER works and that reads as proof the BAN works.
///
/// The realistic trigger is not I/O failure but scope narrowing, and it is already scheduled: Appendix B
/// mandates moving crates into level directories, and the moment this crate becomes
/// `crates/00-foundation/dig-node-core`, [`crates_root`] resolves to `crates/00-foundation` — `read_dir`
/// SUCCEEDS, the self-test stays green, and every sibling level goes silently unscanned.
///
/// The SIBLING-CRATE assertion is what makes that detectable rather than merely unlikely: the scan
/// must have read files from `dig-node-service`, which lives beside this crate and not under it, so a
/// [`crates_root`] that collapsed to one crate's directory fails LOUDLY instead of passing clean.
///
/// That detector replaced the waived-count one (#1682). The original relied on both tracked
/// violations living in `dig-node-service`: reaching them proved the scan escaped its own crate. But
/// that check was only ever as strong as the debt was long — fixing both defects took the waived
/// count to `0 == 0`, which is exactly the vacuous shape the file floor alone already was. Pinning
/// the sibling crate directly says the same thing and keeps saying it with an empty allowlist.
#[test]
fn no_source_file_builds_a_socket_address_from_concatenated_text() {
    let root = crates_root();
    let mut offenders = Vec::new();
    let mut files_scanned = 0usize;
    let mut format_calls_seen = 0usize;
    let mut waived = 0usize;
    let mut sibling_crate_files = 0usize;
    for file in rust_sources(&root) {
        // This file necessarily CONTAINS the banned pattern — as the strings it matches on, and as the
        // fixtures that prove the matcher works. Scanning itself would make the ban permanently red.
        if file
            .file_name()
            .is_some_and(|n| n == "banned_address_patterns.rs")
        {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&file) else {
            continue;
        };
        files_scanned += 1;
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .display()
            .to_string();
        if normalize(&relative).starts_with("dig-node-service/") {
            sibling_crate_files += 1;
        }
        for (line, call) in format_calls(&without_comment_lines(&contents)) {
            format_calls_seen += 1;
            let collapsed = call.split_whitespace().collect::<Vec<_>>().join(" ");
            if !builds_an_address_from_text(&call) {
                continue;
            }
            if is_known_violation(KNOWN_VIOLATIONS, &relative, &collapsed) {
                waived += 1;
            } else {
                offenders.push(format!("{relative} line {line}: format!({collapsed})"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these lines build an address from text, which is invalid for every IPv6 literal (#1593).\n\
         Use `SocketAddr::new(ip, port)` from a parsed `IpAddr`, or `(host, port).to_socket_addrs()`:\n\
         {}",
        offenders.join("\n")
    );
    // An empty result is only meaningful if the scan actually looked. Both floors and the waived count
    // must hold for `offenders.is_empty()` above to mean anything at all.
    assert!(
        files_scanned >= MINIMUM_FILES_SCANNED,
        "the scan reached only {files_scanned} files (expected at least {MINIMUM_FILES_SCANNED}), so a \
         clean result proves nothing. Did the crates directory move — see `crates_root` — or did the \
         workspace shrink? Re-measure and lower the floor deliberately if the shrink is real."
    );
    assert!(
        format_calls_seen >= MINIMUM_FORMAT_CALLS_SEEN,
        "the scan parsed only {format_calls_seen} `format!` calls (expected at least \
         {MINIMUM_FORMAT_CALLS_SEEN}), so it listed files without reading their contents meaningfully."
    );
    assert_eq!(
        waived,
        KNOWN_VIOLATIONS.len(),
        "expected to reach all {} tracked violations and reached {waived}. A stale entry — one whose          site was fixed — turns this RED rather than green: delete it (#1682).",
        KNOWN_VIOLATIONS.len()
    );
    assert!(
        sibling_crate_files >= MINIMUM_SIBLING_CRATE_FILES,
        "the scan read only {sibling_crate_files} files from the SIBLING crate `dig-node-service`          (expected at least {MINIMUM_SIBLING_CRATE_FILES}), so it never escaped its own crate and a          clean result proves nothing about the workspace. Check `crates_root` — a move into an          Appendix-B level directory does exactly this while leaving every other assertion green."
    );
}

/// **Proves:** the tracked-violation list excuses ONLY the exact sites it names — a different offending
/// call in the very same file is still an offender.
///
/// **Catches:** the exception list widening into a per-file waiver, which would let the two known
/// defects shelter any future violation that happened to land beside them. An allowlist that matched by
/// filename alone would pass this file and fail this test.
#[test]
fn a_tracked_violation_excuses_only_its_own_call_not_its_whole_file() {
    // A SYNTHETIC list, so this holds while `KNOWN_VIOLATIONS` is empty. The snippet and file are
    // shaped like a real entry; nothing here depends on the real one existing.
    const TRACKED: &[(&str, &str)] = &[("dig-node-service/src/config.rs", "the_tracked_call()")];
    let (tracked_file, tracked_snippet) = TRACKED[0];
    assert!(
        is_known_violation(TRACKED, tracked_file, tracked_snippet),
        "the tracked site must be recognised in its own file"
    );
    assert!(
        !is_known_violation(TRACKED, tracked_file, r#""{ip}:{port}""#),
        "a DIFFERENT offending call in a tracked file must still be an offender"
    );
    assert!(
        !is_known_violation(
            TRACKED,
            "dig-node-core/src/seams/dig_peer/union_locator.rs",
            tracked_snippet
        ),
        "a tracked snippet must not be excused in a file the entry does not name"
    );
    // An EMPTY list excuses nothing — the state the list is actually in, asserted rather than
    // assumed, so a bug that made an empty list match everything could not pass unnoticed.
    assert!(
        !is_known_violation(&[], tracked_file, tracked_snippet),
        "an empty tracked list must excuse nothing"
    );
}

/// Runs a source snippet through the SAME pipeline the real scan uses, so the self-test exercises the
/// comment-stripping, call-extraction and shape-parsing together rather than one predicate in isolation.
fn scanner_flags(source: &str) -> bool {
    format_calls(&without_comment_lines(source))
        .iter()
        .any(|(_, call)| builds_an_address_from_text(call))
}

/// **Proves:** the scanner flags the banned construct in EVERY interpolation spelling and across
/// rustfmt's line wrapping, and does not flag the correct construction or a capsule rendering.
///
/// **Catches:** the ban rotting into a rubber stamp — specifically, the way it rotted once already. The
/// first version of this guard matched three literal spellings while its doc-comment claimed it matched
/// the construct, so `format!("{ip}:{port}")` walked straight through it. Every case below marked
/// `WAS MISSED` fails against that implementation and passes against this one, which is what makes this
/// test discriminate between the two rather than confirm the spellings already handled.
#[test]
fn the_scanner_flags_the_banned_construct_in_every_spelling() {
    for banned in [
        r#"let addr = format!("{}:{}", host, port).parse::<SocketAddr>()?;"#,
        r#"let addr = format!("{host}:{port}");"#,
        r#"let addr = format!("{}:{port}", host);"#,
        // WAS MISSED — the most natural spelling for an `IpAddr`, and the exact bypass proven live.
        r#"fn probe(ip: &str, port: u16) -> String { format!("{ip}:{port}") }"#,
        // WAS MISSED — named host, positional port.
        r#"let addr = format!("{host}:{}", port);"#,
        // WAS MISSED — indexed interpolation.
        r#"let addr = format!("{0}:{1}", host, port);"#,
        // WAS MISSED — a format spec inside the first group. The colon that matters is the one BETWEEN
        // the groups, not the one inside `{host:?}`.
        r#"let addr = format!("{host:?}:{port}");"#,
        // WAS MISSED — rustfmt's natural wrap. The line holding the format string carries no address
        // vocabulary and the line holding the vocabulary carries no format string, so a per-line scan
        // sees nothing. Snake_case names too, which is how these variables are really spelled.
        "let bound = format!(\n    \"{}:{}\",\n    candidate_host, candidate_port\n);",
        // Snake_case components count on a single line as well.
        r#"let bound = format!("{}:{}", peer_host, peer_port);"#,
    ] {
        assert!(
            scanner_flags(banned),
            "the scanner must flag this construct:\n{banned}"
        );
    }
    for allowed in [
        r#"let addr = SocketAddr::new(ip, port);"#,
        r#"let addrs = (host, port).to_socket_addrs()?;"#,
        // The capsule rendering shares the shape but names no address.
        r#"let key = format!("{}:{}", store_hex, root_hex);"#,
        r#"let key = format!("{}:{}", "aa".repeat(32), "bb".repeat(32));"#,
        // `tip` is not `ip` — the whole-component requirement, which the previous version only claimed.
        r#"let key = format!("{}:{}", tip.to_hex(), root.to_hex());"#,
        // `transport` is not `port`, and `description` is not `ip`. The boundary must reject a term
        // buried inside a longer word while still accepting one that is a snake_case component.
        r#"let line = format!("{}:{}", transport.name(), description);"#,
        // A colon inside ONE group is a format spec, not a host/port separator.
        r#"let shown = format!("{port:?}");"#,
        // A commented-out line is documentation, not code.
        r#"// let addr = format!("{host}:{port}");"#,
    ] {
        assert!(
            !scanner_flags(allowed),
            "the scanner must NOT flag this:\n{allowed}"
        );
    }
}
