//! `dig-node open <chia://… | urn:dig:chia:…>` (#389) — the OS scheme-handler target.
//!
//! The dig-installer registers the OS handlers for `chia://` and `urn:dig:chia:` to invoke
//! `dig-node open "%1"`. This subcommand is therefore the OS-level fallback resolver for a DIG
//! link that no in-browser DIG extension intercepted (a link clicked outside a browser, or in a
//! browser without the extension): it opens the user's DEFAULT browser at the node's LOCAL serve
//! URL (`/s/<storeId>[:<root>]/<path>`, the #289 plaintext content surface), so the node — the
//! resolver of record (#365 thin-client) — serves the decrypted content and any installed DIG
//! extension can still verify it. It NEVER opens dig-node's own GUI (it has none).
//!
//! # Security — the argument is UNTRUSTED
//!
//! `%1` arrives from an OS protocol handler, so a hostile web page can invoke the registered
//! scheme with an attacker-chosen argument. This module therefore:
//!
//! 1. **Validates STRICTLY.** Only `chia://` and `urn:dig:chia:` are accepted (case-insensitive
//!    scheme); every other scheme (`file:`, `javascript:`, `data:`, `http:`, …) is rejected. The
//!    store reference must be canonical 64-hex (`storeId` or `storeId:root`). Shell
//!    metacharacters, control characters, whitespace, and `..` path traversal are rejected
//!    outright — even though the launch path never uses a shell (defense in depth).
//! 2. **Never touches a shell.** The resolved URL is handed to the OS "open a URL" facility as a
//!    SINGLE, non-shell argv entry (`rundll32 url.dll,FileProtocolHandler` on Windows,
//!    `xdg-open` on Linux, `/usr/bin/open` on macOS) — never `cmd /c start` / `sh -c`, so even a
//!    crafted argument cannot inject a command. The launcher is behind [`UrlLauncher`] so tests
//!    assert the exact URL without spawning a real browser.

use serde_json::json;

use crate::cli::Outcome;
use crate::config::Config;

/// Shell metacharacters (and quoting/grouping characters) rejected anywhere in the link. The
/// launch path never uses a shell, so this is defense-in-depth against the untrusted OS argument
/// — it also keeps a well-formed DIG link from ever carrying surprising bytes into the serve URL.
const DISALLOWED: &[char] = &[
    '&', '|', ';', '`', '$', '<', '>', '(', ')', '{', '}', '[', ']', '!', '*', '"', '\'', '\\',
    '^', '\n', '\r', ' ', '\t',
];

/// A validated, normalized DIG link: a 64-hex store id, an optional 64-hex root (a capsule
/// pin), and the (traversal-free) resource path within the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigLink {
    /// The 64-hex store id.
    pub store_id: String,
    /// The optional 64-hex root hash (present for a `storeId:root` capsule reference).
    pub root: Option<String>,
    /// The resource path within the store (may be empty for the store root).
    pub path: String,
}

impl DigLink {
    /// The `storeId` or `storeId:root` reference the `/s/<ref>/…` serve route expects.
    fn store_ref(&self) -> String {
        match &self.root {
            Some(r) => format!("{}:{}", self.store_id, r),
            None => self.store_id.clone(),
        }
    }
}

/// Abstracts the OS "open this URL in the default browser / protocol handler" action so the
/// launch path is unit-testable (a fake asserts the exact URL) and the real implementation never
/// goes through a shell. `url` is ALREADY strictly validated + built by this module.
pub trait UrlLauncher {
    /// Open `url` in the user's default browser. Implementations MUST pass `url` as a single,
    /// non-shell argument.
    fn open_url(&self, url: &str) -> std::io::Result<()>;
}

/// The real OS launcher. Opens `url` via a per-OS facility with the URL as a SINGLE argv entry —
/// never a shell — so a crafted URL cannot inject a command. Fire-and-forget: a failure to SPAWN
/// the launcher (e.g. `xdg-open` not installed) is surfaced; the launcher's own exit code is not
/// awaited (it hands off to the browser and exits).
pub struct OsLauncher;

impl UrlLauncher for OsLauncher {
    fn open_url(&self, url: &str) -> std::io::Result<()> {
        use std::process::{Command, Stdio};
        let mut cmd;
        #[cfg(target_os = "windows")]
        {
            // `rundll32 url.dll,FileProtocolHandler <url>` invokes the registered URL/protocol
            // handler with the URL as one argv entry and NO shell — unlike `cmd /c start`, which
            // would parse `&`/`^`/`|` in the argument.
            cmd = Command::new("rundll32.exe");
            cmd.arg("url.dll,FileProtocolHandler").arg(url);
        }
        #[cfg(target_os = "macos")]
        {
            cmd = Command::new("/usr/bin/open");
            cmd.arg(url);
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            cmd = Command::new("xdg-open");
            cmd.arg(url);
        }
        #[cfg(not(any(windows, unix)))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "dig-node open: no URL launcher for this platform",
            ));
        }
        #[cfg(any(windows, unix))]
        {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            Ok(())
        }
    }
}

/// Run `dig-node open <link>`: validate + normalize the link, build the local serve URL, and open
/// it in the default browser via the real [`OsLauncher`]. See [`run_with`] for the injectable form.
pub fn run(config: &Config, link: &str) -> std::io::Result<Outcome> {
    run_with(config, link, &OsLauncher)
}

/// [`run`] with an injected [`UrlLauncher`] (so tests assert the exact URL without spawning a
/// browser). A rejected link returns an `InvalidInput` error (→ `USAGE` exit) and the launcher is
/// NEVER invoked.
pub fn run_with(
    config: &Config,
    link: &str,
    launcher: &dyn UrlLauncher,
) -> std::io::Result<Outcome> {
    let parsed = normalize(link).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("dig-node open: {e}"),
        )
    })?;
    let url = serve_url(config, &parsed);
    launcher.open_url(&url)?;
    Ok(Outcome::new(
        format!("dig-node: opening {url} in your default browser"),
        json!({
            "opened": true,
            "url": url,
            "store_id": parsed.store_id,
            "root": parsed.root,
            "path": parsed.path,
        }),
    ))
}

/// Strictly validate + normalize a DIG link into a [`DigLink`]. PURE. Accepts ONLY `chia://` and
/// `urn:dig:chia:` (case-insensitive scheme); rejects any other scheme, shell metacharacters,
/// control characters, whitespace, `..` path traversal, and a non-64-hex store reference.
pub fn normalize(input: &str) -> Result<DigLink, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty link".to_string());
    }
    if let Some(bad) = s.chars().find(|c| c.is_control()) {
        return Err(format!("control character not allowed (U+{:04X})", bad as u32));
    }
    if let Some(bad) = s.chars().find(|c| DISALLOWED.contains(c)) {
        return Err(format!("disallowed character in link: {bad:?}"));
    }
    // Scheme gate — ONLY chia:// or urn:dig:chia: (case-insensitive), nothing else.
    let rest = strip_prefix_ci(s, "chia://")
        .or_else(|| strip_prefix_ci(s, "urn:dig:chia:"))
        .ok_or_else(|| {
            "only chia:// and urn:dig:chia: links are allowed (this link's scheme is rejected)"
                .to_string()
        })?;
    // Drop any query/fragment — the serve path is store-ref + resource path only.
    let rest = rest
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_start_matches('/');
    // Split the store reference from the resource path.
    let (store_ref, path) = match rest.split_once('/') {
        Some((r, p)) => (r, p),
        None => (rest, ""),
    };
    if path.split('/').any(|seg| seg == "..") {
        return Err("path traversal (`..`) not allowed".to_string());
    }
    // The store reference MUST be canonical 64-hex (storeId or storeId:root) — this rejects any
    // non-hex authority (a hostname, an IP, an attacker string) outright.
    let (store_id, root) = crate::control::parse_store_ref(store_ref)?;
    Ok(DigLink {
        store_id,
        root,
        path: path.to_string(),
    })
}

/// Build the node's LOCAL serve URL for a validated link: `http://<host>:<port>/s/<ref>/<path>`
/// (the #289 plaintext content route). The host/port come from the node's own config (default
/// `localhost:9778`), so the URL always reaches the running node on this machine.
fn serve_url(config: &Config, link: &DigLink) -> String {
    let host = browser_host(config);
    let port = config.port;
    let store_ref = link.store_ref();
    if link.path.is_empty() {
        format!("http://{host}:{port}/s/{store_ref}/")
    } else {
        format!("http://{host}:{port}/s/{store_ref}/{}", link.path)
    }
}

/// The host to put in the browser URL: the operator's explicit `DIG_NODE_HOST` when set (bracketed
/// for IPv6), else `localhost` — friendlier than `127.0.0.1` and equally reachable (the node binds
/// both loopback families on the port).
fn browser_host(config: &Config) -> String {
    match config.host {
        Some(ip) if ip.is_ipv6() => format!("[{ip}]"),
        Some(ip) => ip.to_string(),
        None => "localhost".to_string(),
    }
}

/// Case-insensitive prefix strip that is safe on non-ASCII input (never panics on a char
/// boundary): returns the remainder after `prefix` when `s` starts with it ignoring ASCII case.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn store() -> String {
        "a".repeat(64)
    }
    fn root() -> String {
        "b".repeat(64)
    }

    /// A test launcher that records the URL it was asked to open (and proves the real launcher was
    /// never reached, so no browser/shell is spawned in CI).
    #[derive(Default)]
    struct FakeLauncher {
        opened: Mutex<Vec<String>>,
    }
    impl UrlLauncher for FakeLauncher {
        fn open_url(&self, url: &str) -> std::io::Result<()> {
            self.opened.lock().unwrap().push(url.to_string());
            Ok(())
        }
    }

    #[test]
    fn accepts_chia_scheme_with_store_only() {
        let n = normalize(&format!("chia://{}", store())).unwrap();
        assert_eq!(n.store_id, store());
        assert_eq!(n.root, None);
        assert_eq!(n.path, "");
    }

    #[test]
    fn accepts_chia_scheme_with_capsule_and_path() {
        let n = normalize(&format!("chia://{}:{}/index.html", store(), root())).unwrap();
        assert_eq!(n.store_id, store());
        assert_eq!(n.root.as_deref(), Some(root().as_str()));
        assert_eq!(n.path, "index.html");
    }

    #[test]
    fn accepts_urn_dig_chia_scheme() {
        let n = normalize(&format!("urn:dig:chia:{}/a/b.css", store())).unwrap();
        assert_eq!(n.store_id, store());
        assert_eq!(n.path, "a/b.css");
    }

    #[test]
    fn scheme_match_is_case_insensitive() {
        assert!(normalize(&format!("CHIA://{}", store())).is_ok());
        assert!(normalize(&format!("Urn:Dig:Chia:{}", store())).is_ok());
    }

    #[test]
    fn strips_query_and_fragment() {
        let n = normalize(&format!("chia://{}/p?x=1#frag", store())).unwrap();
        assert_eq!(n.path, "p");
    }

    #[test]
    fn rejects_dangerous_schemes() {
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>",
            "http://evil.example/",
            "https://evil.example/",
            "chrome://settings",
            "ftp://host/x",
        ] {
            assert!(normalize(bad).is_err(), "must reject {bad}");
        }
    }

    #[test]
    fn rejects_shell_metacharacters_and_traversal() {
        let s = store();
        for bad in [
            format!("chia://{s};rm -rf /"),
            format!("chia://{s}/$(whoami)"),
            format!("chia://{s}/`id`"),
            format!("chia://{s}/a&b"),
            format!("chia://{s}/a|b"),
            format!("chia://{s}/../../secret"),
            format!("chia://{s}/a b"),
            "chia://not-hex-authority/x".to_string(),
            "chia://".to_string(),
            "".to_string(),
        ] {
            assert!(normalize(&bad).is_err(), "must reject {bad}");
        }
    }

    #[test]
    fn rejects_non_64_hex_store_id() {
        assert!(normalize("chia://deadbeef").is_err());
        assert!(normalize(&format!("chia://{}", "g".repeat(64))).is_err());
    }

    #[test]
    fn serve_url_targets_local_node_route() {
        let cfg = Config::default();
        let link = normalize(&format!("chia://{}:{}/index.html", store(), root())).unwrap();
        let url = serve_url(&cfg, &link);
        assert_eq!(
            url,
            format!(
                "http://localhost:9778/s/{}:{}/index.html",
                store(),
                root()
            )
        );
    }

    #[test]
    fn serve_url_store_root_has_trailing_slash() {
        let cfg = Config::default();
        let link = normalize(&format!("chia://{}", store())).unwrap();
        assert_eq!(
            serve_url(&cfg, &link),
            format!("http://localhost:9778/s/{}/", store())
        );
    }

    #[test]
    fn run_with_opens_the_exact_serve_url() {
        let cfg = Config::default();
        let fake = FakeLauncher::default();
        let out = run_with(&cfg, &format!("chia://{}/index.html", store()), &fake).unwrap();
        let opened = fake.opened.lock().unwrap();
        // Exactly one URL, the local serve route — and it is a plain http URL carrying no shell
        // metacharacters (the trait contract passes ONLY a URL string, never a shell command).
        assert_eq!(opened.len(), 1);
        assert_eq!(
            opened[0],
            format!("http://localhost:9778/s/{}/index.html", store())
        );
        assert!(opened[0].starts_with("http://"));
        assert!(!opened[0].chars().any(|c| DISALLOWED.contains(&c)));
        assert_eq!(out.result["opened"], json!(true));
    }

    #[test]
    fn run_with_rejects_bad_link_without_launching() {
        let cfg = Config::default();
        let fake = FakeLauncher::default();
        let err = run_with(&cfg, "javascript:alert(1)", &fake).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        // The launcher was NEVER invoked for a rejected link.
        assert!(fake.opened.lock().unwrap().is_empty());
    }
}
