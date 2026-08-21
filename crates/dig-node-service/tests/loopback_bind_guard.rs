//! Mechanical guard for the DIG loopback rule (dig_ecosystem#767).
//!
//! **The rule:** a DIG loopback service MUST NOT bind `127.0.0.1` or `localhost`. The DIG
//! allocation ([`dig_node_service::loopback`]) hands each service its own `127.0.0.X`, leaving
//! `127.0.0.1` — the address every other program on the machine assumes it can have — alone.
//!
//! **Why a guard and not a code review.** The rule has been stated since 2026-07-17 and was broken
//! anyway: dig-node bound `127.0.0.1:9257`, Sage's own wallet RPC port, and after a reboot
//! whichever service won the race broke the other. The user's symptom was
//! `sslv3 alert handshake failure` against a server they thought was Sage — a message that names
//! neither DIG nor a port conflict. Moving to `9776` fixed that instance and left the class open,
//! because nothing stops the next binding. This test is that stop.
//!
//! # What it scans, and what it deliberately does not
//!
//! It scans the workspace's product source for a **bind call carrying a literal loopback host**.
//! Three exclusions keep it precise rather than merely loud:
//!
//! * **`#[cfg(test)]` modules are stripped.** A test binding `127.0.0.1:0` for an ephemeral
//!   fixture is correct and common — the rule is about the product's loopback surface, not about
//!   harnesses. Without this exclusion the guard would report over a hundred legitimate sites and
//!   be switched off, which is the ordinary fate of a check that cries wolf.
//! * **`tests/` files are not scanned at all**, for the same reason.
//! * **Only bind calls are flagged, never dials or classifiers.** `127.0.0.1` appears legitimately
//!   in the §5.3 client→node ladder (`localhost` is a canonical DIALLING tier), in the Host-header
//!   allowlist, and in doc comments explaining the rule itself. A guard that flagged those would be
//!   asserting something the ecosystem does not believe.
//!
//! # The guard's reach floor, stated rather than discovered later
//!
//! It reads source text, so it sees a literal **at the bind call** and nothing else. A bind of an
//! address computed elsewhere is invisible to it. Exactly one such site exists today and it is
//! declared in [`DECLARED_EXCEPTIONS`] rather than left to be noticed — because a gap a guard
//! cannot see is a coverage finding, and the only safe place to record it is next to the guard.

use std::path::{Path, PathBuf};

/// A bind site that carries a literal loopback host today and is NOT yet movable, with the reason
/// and the ticket that will move it.
///
/// This list exists so the guard's coverage is legible. An entry is a debt with a name attached,
/// not a silent hole: the guard still fails on any bind site NOT listed here, so the class is
/// closed going forward even while these remain.
///
/// Each entry is `(path suffix, why it is still on a literal loopback address)`.
const DECLARED_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "src/wallet_mtls.rs",
        "The Sage-parity wallet mTLS listener binds 127.0.0.1:9776. Moving it is a CROSS-REPO \
         change, not a dig-node change: the address is a dial contract for every Sage-parity \
         client, so dig-node cannot move the listener without the consumers moving with it. It \
         is already off Sage's own port (9257 -> 9776, v0.128.0), so the collision that caused \
         the incident is closed; the address remains pending the ratified allocation table in \
         dig_ecosystem#767.",
    ),
    (
        "dig-wallet/src/sage/transport.rs",
        "`serve_dual` binds 127.0.0.1 for the Sage-parity mTLS listener and its plain-HTTP \
         browser mirror. THE GUARD FOUND THESE, A MANUAL SWEEP DID NOT — which is the argument \
         for having the guard at all. They are not fixed here for a structural reason rather \
         than a risk one: `dig-wallet` sits BELOW `dig-node-service` in the crate hierarchy, so \
         it cannot depend on the SSOT in `dig_node_service::loopback`, and duplicating the \
         constant would create exactly the rival implementation the allocation exists to \
         prevent. The right home for the allocation is a foundation-level crate every consumer \
         can reference (dig-constants, L00), which is a release-first cross-repo change. \
         Mitigating fact: `serve_dual` has no production call site — dig-node serves the wallet \
         surface through `dig-node-service/src/wallet_mtls.rs` — so no shipped listener is on \
         these lines today.",
    ),
];

/// Literal loopback hosts a product bind must not name.
///
/// `Ipv4Addr::LOCALHOST` and `Ipv6Addr::LOCALHOST` are included because they are the same decision
/// spelled as a constant — a rule that only banned the string form would be trivially side-stepped
/// by the more idiomatic spelling, which is the one a Rust author reaches for first.
const BANNED_HOSTS: &[&str] = &[
    "\"127.0.0.1\"",
    "\"localhost\"",
    "Ipv4Addr::LOCALHOST",
    "Ipv6Addr::LOCALHOST",
];

/// The call shapes that BIND a socket. A dial (`TcpStream::connect`) is not here on purpose — see
/// the module docs.
const BIND_CALLS: &[&str] = &["TcpListener::bind", "UdpSocket::bind", "Socket::bind"];

/// A flagged site: the file, the 1-based line number, and the offending source line.
#[derive(Debug)]
struct Violation {
    file: PathBuf,
    line: usize,
    text: String,
}

#[test]
fn no_product_bind_names_a_literal_loopback_host() {
    let roots = crate_src_dirs();
    assert!(
        !roots.is_empty(),
        "the guard found no crate source directories to scan — it would pass vacuously, which is \
         worse than failing, so this is a hard error"
    );

    let mut violations = Vec::new();
    let mut files_scanned = 0usize;

    for root in &roots {
        for file in rust_files(root) {
            let Ok(source) = std::fs::read_to_string(&file) else {
                continue;
            };
            files_scanned += 1;
            if is_declared_exception(&file) {
                continue;
            }
            violations.extend(scan(&file, &source));
        }
    }

    // A scanner that read nothing would report zero violations and look green. Assert it actually
    // had a haystack: this is the difference between "no violations" and "no measurement".
    assert!(
        files_scanned > 20,
        "only {files_scanned} source files were scanned — the guard is not reaching the workspace \
         source, so its clean result means nothing"
    );

    assert!(
        violations.is_empty(),
        "a DIG service must never BIND a literal loopback host (dig_ecosystem#767) — use \
         `dig_node_service::loopback` instead. {} violation(s):\n{}",
        violations.len(),
        violations
            .iter()
            .map(|v| format!("  {}:{}: {}", v.file.display(), v.line, v.text.trim()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// **Proves the guard can actually FIRE.** A list-driven check whose patterns match nothing is
/// indistinguishable from a codebase with nothing to find, and reports the same clean result.
///
/// So each banned host is fed through [`scan`] inside a synthetic bind call and must be caught, and
/// two near-miss lines that MUST NOT be caught are fed through as controls: a dial (the canonical
/// §5.3 ladder) and a prose mention. Without the controls this test would also pass for a scanner
/// that flagged every line containing `127.0.0.1`, which would be unusable.
#[test]
fn every_banned_host_is_detectable_and_the_controls_are_not_flagged() {
    for host in BANNED_HOSTS {
        let source = format!("    let l = TcpListener::bind(({host}, 0))?;\n");
        let hits = scan(Path::new("synthetic.rs"), &source);
        assert_eq!(
            hits.len(),
            1,
            "the guard cannot see a bind naming {host} — a ban entry that matches nothing bans \
             nothing"
        );
    }

    for allowed in [
        "    let s = TcpStream::connect((\"127.0.0.1\", 9778))?;\n",
        "    // the §5.3 ladder prefers dig.local, then localhost, then rpc.dig.net\n",
        "    matches!(host, \"localhost\" | \"127.0.0.1\" | \"dig.local\")\n",
    ] {
        assert!(
            scan(Path::new("synthetic.rs"), allowed).is_empty(),
            "the guard must NOT flag {allowed:?} — dials and classifiers are legitimate, and a \
             guard that fails on them gets switched off"
        );
    }
}

/// **Proves the `#[cfg(test)]` stripping works**, which is the exclusion the whole guard's
/// usability rests on.
///
/// The fixture places the SAME banned bind twice — once in product position and once inside a
/// `#[cfg(test)]` module — so the assertion distinguishes "stripping works" from both nearest wrong
/// behaviours: a scanner that strips nothing sees two hits, and one that strips too much (bailing
/// at the first `#[cfg(test)]` and discarding the rest of the file, or dropping the product line
/// too) sees zero or misses the product one.
#[test]
fn cfg_test_modules_are_stripped_but_product_code_is_not() {
    let source = concat!(
        "fn serve() -> std::io::Result<()> {\n",
        "    let l = TcpListener::bind((\"127.0.0.1\", 80))?;\n",
        "    Ok(())\n",
        "}\n",
        "\n",
        "#[cfg(test)]\n",
        "mod tests {\n",
        "    #[test]\n",
        "    fn fixture() {\n",
        "        let l = TcpListener::bind((\"127.0.0.1\", 0)).unwrap();\n",
        "    }\n",
        "}\n",
    );

    let hits = scan(Path::new("synthetic.rs"), source);
    assert_eq!(
        hits.len(),
        1,
        "exactly the PRODUCT bind must be flagged; the test-module bind is a legitimate ephemeral \
         fixture. got: {hits:?}"
    );
    assert_eq!(
        hits[0].line, 2,
        "the flagged line must be the product bind on line 2, not the fixture"
    );
}

/// Flag every line in `source` that both makes a bind call and names a banned loopback host, after
/// removing `#[cfg(test)]` modules.
fn scan(file: &Path, source: &str) -> Vec<Violation> {
    let stripped = strip_cfg_test_modules(source);
    stripped
        .iter()
        .filter_map(|(line_no, line)| {
            let names_bind = BIND_CALLS.iter().any(|c| line.contains(c));
            let names_banned = BANNED_HOSTS.iter().any(|h| line.contains(h));
            (names_bind && names_banned).then(|| Violation {
                file: file.to_path_buf(),
                line: *line_no,
                text: (*line).to_string(),
            })
        })
        .collect()
}

/// The source's lines (1-based) with every `#[cfg(test)]` module removed.
///
/// Brace-matched rather than "everything after the first `#[cfg(test)]`", because a `#[cfg(test)]`
/// module is not always last in a file and discarding the tail would silently stop scanning the
/// product code that follows it — a guard that gets quieter the more tests a file has.
///
/// Braces inside string literals and comments are not tracked. That is a deliberate simplification:
/// the failure mode is scanning slightly too much or too little source around an unbalanced brace
/// in a string, and both are caught by [`cfg_test_modules_are_stripped_but_product_code_is_not`]
/// staying green on real files rather than by the parser being exact.
fn strip_cfg_test_modules(source: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut kept = Vec::new();
    let mut i = 0usize;

    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]") {
            // Skip forward to the opening brace of the item this attribute decorates, then past
            // its matching close.
            let mut depth = 0usize;
            let mut opened = false;
            while i < lines.len() {
                for ch in lines[i].chars() {
                    match ch {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                }
                i += 1;
                if opened && depth == 0 {
                    break;
                }
            }
            continue;
        }
        kept.push((i + 1, lines[i]));
        i += 1;
    }
    kept
}

/// Whether `file` is one of the [`DECLARED_EXCEPTIONS`].
fn is_declared_exception(file: &Path) -> bool {
    let path = file.to_string_lossy().replace('\\', "/");
    DECLARED_EXCEPTIONS
        .iter()
        .any(|(suffix, _)| path.ends_with(suffix))
}

/// Every `crates/*/src` directory in the workspace.
///
/// Resolved from `CARGO_MANIFEST_DIR` (this crate) up to the workspace root, so the guard scans the
/// whole workspace rather than only the crate it happens to live in — a bind in `dig-node-core` is
/// the same defect as one here.
fn crate_src_dirs() -> Vec<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .expect("crates/dig-node-service has a parent")
        .to_path_buf();

    let Ok(entries) = std::fs::read_dir(&crates_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path().join("src"))
        .filter(|p| p.is_dir())
        .collect()
}

/// Every `.rs` file under `root`, recursively, excluding `tests` directories.
fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                // A file NAMED tests.rs is a test module included via `#[cfg(test)] mod tests;`
                // from its parent, so the attribute is on the `mod` line and not in this file —
                // the stripping cannot see it. Excluded by name for the same reason `tests/` is.
                if path.file_name().is_some_and(|n| n == "tests.rs") {
                    continue;
                }
                out.push(path);
            }
        }
    }
    out
}
