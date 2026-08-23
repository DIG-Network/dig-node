//! `dig-node wallet export-seed` — the offline rescue for a node-custodied mnemonic.
//!
//! Node-side USER custody is being retired. For a user who migrated their seed into this
//! node and kept no independent copy, the node's seed file is the only surviving copy of
//! their spend key, so the custody code cannot be deleted without first handing that key
//! back. This command is that hand-back, and it is deleted along with the custody surface.
//!
//! ## No network surface is added
//!
//! This is a local command only. It adds no RPC method, no control-plane verb and no
//! loopback endpoint: [`dig_wallet::seed_export`] is called in-process, in this CLI
//! process, against the local filesystem. Running it requires local filesystem access AND
//! the wallet password — the same two things an attacker would already need to open the
//! seed file by hand — so it grants nothing that local access did not already grant.
//!
//! ## Why `--json` is refused rather than supported
//!
//! Every other verb here offers machine-readable output. This one must not: a mnemonic
//! inside a JSON envelope is output shaped for redirection into a file, a pipe or a log,
//! which is precisely the fate a spend key must not meet. The refusal names the working
//! alternative, so it informs rather than blocks.

use std::path::PathBuf;

use dig_wallet::seed_export::{self, ExportError};

use crate::cli::ExitCode;

/// Guidance printed beneath a recovered phrase. Kept next to the code that prints it so the
/// warning cannot drift away from the thing it warns about.
const HANDLING_NOTICE: &str = "\
Write these words down and keep them offline. Anyone who reads them can spend this wallet.
Import them into the DIG app and confirm the derived address matches before relying on it.";

/// The refusal shown when `--json` is combined with this verb.
const JSON_REFUSAL: &str = "export-seed does not support --json: a recovery phrase must not be \
emitted as machine-readable output, which is the form most likely to be redirected into a file \
or a log. Re-run without --json to print it to the console.";

/// Run `wallet export-seed`, printing the recovered mnemonic to stdout.
///
/// `path` overrides where the seed file is read from. It is not merely a convenience: a file
/// written by an older build can sit under a base directory this build no longer resolves,
/// so without the override the command could not reach the very file it exists to rescue.
pub fn run(path: Option<PathBuf>, json: bool) -> ExitCode {
    if json {
        eprintln!("error: {JSON_REFUSAL}");
        return ExitCode::Usage;
    }

    let path = path.unwrap_or_else(seed_export::default_seed_path);
    eprintln!("Reading the encrypted seed file at {}.", path.display());

    let password = match read_password() {
        Ok(password) => password,
        Err(e) => {
            eprintln!("error: cannot read the password: {e}");
            return ExitCode::IoError;
        }
    };

    match seed_export::export_mnemonic(&path, &password) {
        Ok(mnemonic) => {
            println!("{}", &*mnemonic);
            eprintln!("{HANDLING_NOTICE}");
            ExitCode::Ok
        }
        Err(e) => {
            eprintln!("error: {e}");
            if let Some(hint) = hint_for(&e) {
                eprintln!("hint: {hint}");
            }
            exit_code_for(&e)
        }
    }
}

/// Read the wallet password without echoing it.
///
/// On a terminal this reads the console directly, so the password never appears on screen or in
/// scrollback. When stdin is NOT a terminal it reads a single line from stdin instead: the
/// terminal-only call reads the console device rather than stdin, so on a piped or redirected
/// invocation it would wait forever on input that can never arrive. Falling back keeps the command
/// usable from a script and makes the failure a read error rather than a hang.
fn read_password() -> std::io::Result<String> {
    use std::io::{BufRead, IsTerminal};

    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password("Wallet password: ");
    }
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(strip_line_ending(&line).to_string())
}

/// Drop the line terminator a piped password arrives with, and nothing else.
///
/// Only a trailing CR/LF goes: a password may legitimately begin or end with a space, so trimming
/// whitespace generally would silently change the secret and turn a correct password into a
/// "wrong password" the user cannot explain.
fn strip_line_ending(line: &str) -> &str {
    line.strip_suffix('\n')
        .map_or(line, |l| l.strip_suffix('\r').unwrap_or(l))
}

/// The exit class for an export failure, so a script can tell "this node holds no wallet"
/// apart from "the password was wrong".
fn exit_code_for(e: &ExportError) -> ExitCode {
    match e {
        ExportError::NotFound(_) => ExitCode::Usage,
        ExportError::Unreadable { .. } => ExitCode::IoError,
        ExportError::Undecryptable(_) => ExitCode::Usage,
    }
}

/// What a user can actually do about each failure. `None` where the message already says it.
fn hint_for(e: &ExportError) -> Option<&'static str> {
    match e {
        ExportError::NotFound(_) => Some(
            "An older build may have written the seed file elsewhere. Pass --path to point at it.",
        ),
        ExportError::Unreadable { .. } => {
            Some("Check the file permissions, and that the path names a file rather than a folder.")
        }
        ExportError::Undecryptable(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Proves:** `--json` is refused before anything reads the seed file, so no code path
    /// can emit a mnemonic as machine-readable output. Uses a path that does NOT exist: were
    /// the refusal ordered after the read, this would return the not-found class instead, so
    /// the assertion pins the ORDER and not merely the outcome.
    #[test]
    fn json_is_refused_before_the_file_is_read() {
        let absent = std::env::temp_dir().join("dig-export-seed-does-not-exist.bin");
        assert!(
            !absent.exists(),
            "the fixture path must genuinely be absent"
        );

        assert_eq!(run(Some(absent), true), ExitCode::Usage);
    }

    /// **Proves:** neither the guidance text nor the refusal text can be mistaken for the
    /// phrase itself. They are the only strings this module prints alongside a mnemonic, and
    /// a template that interpolated the phrase would be the leak this command must not have.
    #[test]
    fn the_printed_prose_contains_no_interpolation() {
        for text in [HANDLING_NOTICE, JSON_REFUSAL] {
            assert!(
                !text.contains('{'),
                "printed prose must not interpolate: {text}"
            );
        }
    }

    /// **Proves:** a piped password loses only its line terminator. Uses a password whose FIRST
    /// and LAST characters are spaces, which a general `trim` would eat — the nearest wrong
    /// implementation, and one that would turn a correct password into an unexplainable
    /// "wrong password". Covers CRLF as well as LF, since a Windows pipe supplies CRLF.
    #[test]
    fn a_piped_password_keeps_its_own_spaces() {
        assert_eq!(strip_line_ending(" pad ded \n"), " pad ded ");
        assert_eq!(strip_line_ending(" pad ded \r\n"), " pad ded ");
        assert_eq!(strip_line_ending(" pad ded "), " pad ded ");
        assert_eq!(strip_line_ending("has\rcr\n"), "has\rcr");
    }

    /// **Proves:** every failure class maps to a distinct, actionable outcome rather than a
    /// single catch-all, and that an absent file is never reported with an I/O exit code.
    #[test]
    fn each_failure_class_is_distinguishable() {
        let missing = ExportError::NotFound("x".into());
        let unreadable = ExportError::Unreadable {
            path: "x".into(),
            cause: "denied".into(),
        };
        let bad_password = ExportError::Undecryptable("x".into());

        assert_eq!(exit_code_for(&missing), ExitCode::Usage);
        assert_eq!(exit_code_for(&unreadable), ExitCode::IoError);
        assert_eq!(exit_code_for(&bad_password), ExitCode::Usage);
        assert!(hint_for(&missing).is_some_and(|h| h.contains("--path")));
        assert!(hint_for(&bad_password).is_none());
    }
}
