//! `dig-node ensure-hosts` (#91/#503) — idempotently register the `dig.local` hosts entry.
//!
//! The bare-`http://dig.local` listener binds `127.0.0.2:80` (§4.1), which only works if the OS
//! resolves `dig.local` → `127.0.0.2`. The native install packages (#503) call this after placing
//! the binary so `dig.local` resolves without a separate installer step. It is the clean,
//! cross-platform, NO-SHELL way to do it (the MSI custom action, the .deb postinst, and the macOS
//! postinstall all converge here rather than hand-editing the hosts file with a shell).
//!
//! Idempotent + additive: an existing `127.0.0.2 dig.local` mapping is left untouched; only a
//! MISSING mapping is appended. Other hosts entries are never modified.

use std::path::PathBuf;

use crate::cli::Outcome;

/// The loopback IP `dig.local` must resolve to (matches [`crate::config::DIG_LOCAL_IP`] / the #91
/// bare-listener bind and the dig-installer's historical hosts entry).
pub const DIG_LOCAL_IP: &str = "127.0.0.2";
/// The canonical hostname the bare-`http://dig.local` listener answers to (§4.1).
pub const DIG_LOCAL_HOST: &str = "dig.local";

/// The OS hosts-file path. Windows honors `%SystemRoot%`; Unix is the FHS `/etc/hosts`.
pub fn hosts_path() -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hosts")
    }
}

/// Whether `content` already maps `host` to `ip` on some non-comment line. PURE. Tolerant of
/// arbitrary leading/inner whitespace and trailing comments/aliases, and case-insensitive on the
/// hostname (DNS names are case-insensitive), so it does not append a duplicate for an existing
/// mapping written in any reasonable form.
pub fn has_entry(content: &str, ip: &str, host: &str) -> bool {
    content.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return false;
        }
        let mut toks = line.split_whitespace();
        let Some(addr) = toks.next() else {
            return false;
        };
        addr == ip && toks.any(|h| h.eq_ignore_ascii_case(host))
    })
}

/// Return `content` with an `ip\thost` mapping appended (only meaningful when [`has_entry`] is
/// false). PURE. Guarantees the appended line starts on its own line (adds a separating newline
/// when `content` does not already end in one) and is itself newline-terminated.
pub fn with_entry(content: &str, ip: &str, host: &str) -> String {
    let mut out = String::with_capacity(content.len() + host.len() + ip.len() + 2);
    out.push_str(content);
    if !content.is_empty() && !content.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(ip);
    out.push('\t');
    out.push_str(host);
    out.push('\n');
    out
}

/// Ensure the OS hosts file maps `dig.local` → `127.0.0.2`, appending the entry only if absent.
/// Requires write access to the hosts file (the installer/service runs elevated), so a permission
/// failure surfaces as an `io::Error`. Reports whether the entry was ADDED or already present.
pub fn run() -> std::io::Result<Outcome> {
    let path = hosts_path();
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    if has_entry(&content, DIG_LOCAL_IP, DIG_LOCAL_HOST) {
        return Ok(Outcome::new(
            format!(
                "dig-node: {DIG_LOCAL_HOST} already maps to {DIG_LOCAL_IP} in {} — nothing to do.",
                path.display()
            ),
            serde_json::json!({ "added": false, "hosts_path": path.display().to_string() }),
        ));
    }
    let updated = with_entry(&content, DIG_LOCAL_IP, DIG_LOCAL_HOST);
    std::fs::write(&path, updated)?;
    Ok(Outcome::new(
        format!(
            "dig-node: added {DIG_LOCAL_IP} {DIG_LOCAL_HOST} to {} so http://{DIG_LOCAL_HOST} resolves.",
            path.display()
        ),
        serde_json::json!({ "added": true, "hosts_path": path.display().to_string() }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_an_existing_mapping_in_various_forms() {
        assert!(has_entry(
            "127.0.0.2\tdig.local\n",
            "127.0.0.2",
            "dig.local"
        ));
        assert!(has_entry("127.0.0.2 dig.local", "127.0.0.2", "dig.local"));
        assert!(has_entry(
            "  127.0.0.2   dig.local  # DIG\n",
            "127.0.0.2",
            "dig.local"
        ));
        // Case-insensitive host, extra aliases on the line.
        assert!(has_entry(
            "127.0.0.2 foo DIG.LOCAL bar\n",
            "127.0.0.2",
            "dig.local"
        ));
    }

    #[test]
    fn does_not_match_a_commented_or_different_mapping() {
        assert!(!has_entry(
            "# 127.0.0.2 dig.local\n",
            "127.0.0.2",
            "dig.local"
        ));
        assert!(!has_entry(
            "127.0.0.1 dig.local\n",
            "127.0.0.2",
            "dig.local"
        ));
        assert!(!has_entry(
            "127.0.0.2 other.host\n",
            "127.0.0.2",
            "dig.local"
        ));
        assert!(!has_entry("", "127.0.0.2", "dig.local"));
    }

    #[test]
    fn appends_on_its_own_newline_terminated_line() {
        // No trailing newline in the source → a separator is inserted so the entry is its own line.
        let out = with_entry("127.0.0.1 localhost", "127.0.0.2", "dig.local");
        assert_eq!(out, "127.0.0.1 localhost\n127.0.0.2\tdig.local\n");
        // Already newline-terminated → no blank line inserted.
        let out2 = with_entry("127.0.0.1 localhost\n", "127.0.0.2", "dig.local");
        assert_eq!(out2, "127.0.0.1 localhost\n127.0.0.2\tdig.local\n");
        // Empty file → just the entry.
        assert_eq!(
            with_entry("", "127.0.0.2", "dig.local"),
            "127.0.0.2\tdig.local\n"
        );
    }

    #[test]
    fn appended_content_is_then_detected_as_present() {
        let out = with_entry("127.0.0.1 localhost\n", DIG_LOCAL_IP, DIG_LOCAL_HOST);
        assert!(has_entry(&out, DIG_LOCAL_IP, DIG_LOCAL_HOST));
    }
}
