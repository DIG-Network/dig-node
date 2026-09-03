//! Test-only guard against the "lost string continuation" defect class (dig-node#526).
//!
//! A Rust string literal continued with a trailing `\` renders correctly. When that
//! backslash is lost -- `cargo fmt` rejoining a wrapped literal, or a mechanical regex
//! repair -- the literal keeps the SOURCE's leading indentation, so the emitted text
//! carries a 14-22 space run in the middle of a sentence. It compiles, every other test
//! stays green, and the mangled and correct forms are indistinguishable in a normal
//! diff. The only witness is a person reading the emitted text -- so this scanner reads
//! it instead, on every build.
#![cfg(test)]

use std::path::Path;

/// No directory under `src` is exempt from the crate-wide scan (dig-node#501 closed
/// the exclusion this list used to carry for `mirror/`, once that directory's own
/// six lost-continuation sites were fixed).
const EXCLUDED_DIRS: &[&str] = &[];

/// `service.rs`'s `sc qc` parser test pins a byte-identical copy of real `sc.exe`
/// output; its fixed-width `LABEL   : value` columns are deliberate alignment the
/// parser depends on, not a lost continuation.
const EXCLUDED_LINE_RANGES: &[(&str, u32, u32)] = &[("service.rs", 2045, 2056)];

/// A handful of CLI summary builders format a banner with `\n` plus hand-aligned
/// label columns (network_info.rs, spend_audit_cli.rs, pair.rs, peer_ping.rs,
/// peers.rs). Once a line has committed to that idiom -- it contains a literal
/// `\n` escape anywhere -- every space run on it is column alignment, not a torn
/// sentence, so the whole line is exempt.
const CLI_COLUMN_FILES: &[&str] = &[
    "network_info.rs",
    "spend_audit_cli.rs",
    "pair.rs",
    "peer_ping.rs",
    "peers.rs",
];

/// A lost continuation always leaves 14-22 spaces (the source's own indentation);
/// ordinary column-alignment padding measured in this crate never exceeds 8. Ten
/// leaves margin on both sides: comfortably above every legitimate pad, comfortably
/// below the smallest real defect.
const MIN_DEFECT_RUN: usize = 10;

/// One offending run found by the scan.
struct Offense {
    file: String,
    line: u32,
    fragment: String,
}

fn is_excluded_line(file_name: &str, line_no: u32) -> bool {
    EXCLUDED_LINE_RANGES
        .iter()
        .any(|(f, start, end)| *f == file_name && line_no >= *start && line_no <= *end)
}

fn is_excluded_dir(rel_path: &Path) -> bool {
    rel_path
        .components()
        .any(|c| EXCLUDED_DIRS.contains(&c.as_os_str().to_string_lossy().as_ref()))
}

/// Walks every `.rs` file under `src`, returning `(files_scanned, offenses)`.
fn scan_source_tree() -> (usize, Vec<Offense>) {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files_scanned = 0usize;
    let mut offenses = Vec::new();

    let mut stack = vec![src_root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(&src_root).unwrap_or(&path);
            if path.is_dir() {
                if is_excluded_dir(rel) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if is_excluded_dir(rel) {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            files_scanned += 1;

            for (idx, raw_line) in contents.lines().enumerate() {
                let line_no = (idx + 1) as u32;
                if is_excluded_line(&file_name, line_no) {
                    continue;
                }

                // Leading indentation is source layout, not literal content -- ignore it.
                let trimmed_start = raw_line.trim_start();
                if trimmed_start.is_empty() {
                    continue;
                }

                // A comment line is never scanned, structurally -- rewording a comment
                // (including this guard's own prose) must never dodge the check by
                // reformatting it as non-comment text; it stays excluded because it
                // starts with `//`, not because of what it says.
                if trimmed_start.starts_with("//") {
                    continue;
                }

                // Control characters (excluding the line's own trailing newline, which
                // `.lines()` already stripped) are always a defect signature.
                if let Some(pos) = trimmed_start.char_indices().find(|(_, c)| c.is_control()) {
                    offenses.push(Offense {
                        file: file_name.clone(),
                        line: line_no,
                        fragment: format!("<control char at byte {}>", pos.0),
                    });
                    continue;
                }

                // A line in one of the CLI banner files that carries a literal `\n`
                // escape anywhere is deliberate column layout end to end -- see
                // CLI_COLUMN_FILES above.
                if CLI_COLUMN_FILES.contains(&file_name.as_str()) && trimmed_start.contains(r"\n") {
                    continue;
                }

                // Find every run of 2+ spaces; only a run at or above MIN_DEFECT_RUN is
                // a candidate, and only once it clears the trailing-comment check below.
                let bytes = trimmed_start.as_bytes();
                let mut i = 0usize;
                while i < bytes.len() {
                    if bytes[i] != b' ' {
                        i += 1;
                        continue;
                    }
                    let run_start = i;
                    while i < bytes.len() && bytes[i] == b' ' {
                        i += 1;
                    }
                    let run_len = i - run_start;
                    if run_len < MIN_DEFECT_RUN {
                        continue;
                    }

                    // A run immediately followed by `//` is aligning a TRAILING
                    // COMMENT to a fixed column (untrusted_text.rs's unicode-range
                    // table, state.rs's fixture annotations, server.rs's origin
                    // list) -- structurally never inside a string literal's body.
                    if trimmed_start[i..].starts_with("//") {
                        continue;
                    }

                    offenses.push(Offense {
                        file: file_name.clone(),
                        line: line_no,
                        fragment: trimmed_start.to_string(),
                    });
                    break;
                }
            }
        }
    }

    (files_scanned, offenses)
}

/// This crate has dozens of source files; a scan that reads zero (a wrong
/// `CARGO_MANIFEST_DIR`, a moved `src/`, a walk that silently matched nothing) is a
/// broken guard, not a passing one, and must FAIL rather than vacuously succeed.
const MIN_FILES_SCANNED: usize = 20;

#[test]
fn no_lost_string_continuation_leaves_a_multi_space_run_mid_sentence() {
    let (files_scanned, offenses) = scan_source_tree();

    assert!(
        files_scanned > MIN_FILES_SCANNED,
        "scanned {files_scanned} files, expected more than {MIN_FILES_SCANNED} -- a guard \
         that reads zero (or too few) files is not scanning the crate, and a scan that \
         reads nothing must fail rather than pass vacuously"
    );

    if !offenses.is_empty() {
        let report: Vec<String> = offenses
            .iter()
            .map(|o| format!("  {}:{} -> {:?}", o.file, o.line, o.fragment))
            .collect();
        panic!(
            "found {} site(s) with a lost string continuation (a run of {}+ spaces mid-line, \
             outside a comment/fixture/CLI-column exemption):\n{}",
            offenses.len(),
            MIN_DEFECT_RUN,
            report.join("\n")
        );
    }
}
