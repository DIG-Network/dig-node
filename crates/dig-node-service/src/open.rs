//! `dig-node open <chia://… | urn:dig:chia:…>` (#389, #745) — the OS scheme-handler target.
//!
//! The dig-installer registers the OS handlers for `chia://` and `urn:dig:chia:` to invoke
//! `dig-node open "%1"`. This subcommand is therefore the OS-level fallback resolver for a DIG
//! link that no in-browser DIG extension intercepted (a link clicked outside a browser, or in a
//! browser without the extension). It NEVER opens dig-node's own GUI (it has none).
//!
//! # How it resolves + opens (#745, the canonical resolver)
//!
//! `open` is a CLIENT operation — resolve a URN, then show its content — exactly like the
//! extension URN bar (#308) and every other URN-consuming client (#668 convergence). It therefore
//! routes through the shared [`dig_urn_resolver`]: the canonical §5.3 ladder
//! (`dig.local` → `localhost:9778` → `rpc.dig.net`) with FAIL-CLOSED integrity verification. The
//! resolver — not this command — decides whether the content is loadable, and never returns
//! unverified bytes.
//!
//! On a verified [`ResolveOutcome::Success`] the command opens the best BROWSER-NAVIGABLE form so
//! the user gets live, relative-link-resolving navigation, matching the extension URN bar's
//! preference order:
//!
//! 1. **`.dig` form** `http://<storeId>.dig/<path>` — when dig-dns resolves `*.dig` (offered only
//!    for a rootless link, since the host cannot pin a capsule root).
//! 2. **`dig.local`** `http://dig.local/s/<storeId>[:<root>]/<path>`.
//! 3. **`localhost`** `http://localhost:9778/s/<storeId>[:<root>]/<path>`.
//!
//! Each tier is cheaply PROBED (a short-timeout GET); the first that actually serves the content is
//! opened. If NONE of the browser tiers can serve it — e.g. the local node's `/s/` chain-read is
//! currently 502-ing (#747) while the resolver still succeeded via `rpc.dig.net` — the command
//! serves the resolver's already-VERIFIED bytes over an EPHEMERAL LOOPBACK HTTP endpoint
//! (`http://127.0.0.1:<port>/…`) and opens THAT, so the user always sees the exact verified content
//! and NEVER a raw `502 …` string.
//!
//! On a non-success outcome ([`ResolveOutcome::IntegrityFailure`] / [`ResolveOutcome::Unreachable`])
//! or a hard [`ResolveError`] (not-found / rpc error), the command serves a BRANDED DIG error asset
//! from the resolver ([`dig_urn_resolver::images`]) over the same loopback endpoint — never a
//! hand-rolled page and never a raw error string.
//!
//! # Security — the argument AND the resolved bytes are UNTRUSTED
//!
//! `%1` arrives from an OS protocol handler, so a hostile web page can invoke the registered scheme
//! with an attacker-chosen argument. Just as importantly, ANYONE can publish a DIG store, so the
//! resolved bytes + their content type + the resource name are ALL attacker-controlled — a verified
//! [`ResolveOutcome::Success`] proves only that the bytes chain to the store's on-chain root, NOT
//! that they are safe or from a trusted publisher. This module therefore:
//!
//! 1. **Validates STRICTLY before doing anything.** Only `chia://` and `urn:dig:chia:` are accepted
//!    (case-insensitive scheme); every other scheme (`file:`, `javascript:`, `data:`, `http:`, …)
//!    is rejected outright — the resolver and the launcher are NEVER reached for a rejected link.
//!    The store reference must be canonical 64-hex; shell metacharacters, control characters,
//!    whitespace, and `..` path traversal are rejected. A branded error page is shown only for a
//!    link that PARSES as a valid DIG URN but fails to RESOLVE — never for a hostile input.
//! 2. **NEVER writes resolved bytes to disk and NEVER hands the OS a local file to open.** Doing so
//!    would bypass the browser's download protections: an attacker store could publish `evil.hta` /
//!    `evil.js` (content type `application/x-msdownload`, …), which — written to `%TEMP%` with no
//!    Mark-of-the-Web and then handed to `rundll32 …FileProtocolHandler` / `open` / `xdg-open` —
//!    would EXECUTE with full local trust (RCE), and HTML would gain a privileged `file://` origin.
//!    Instead the bytes are served over a loopback `http://127.0.0.1:<ephemeral>` origin, so the
//!    browser applies its NORMAL content-type handling (render-vs-download, Mark-of-the-Web,
//!    SmartScreen, a sandboxed web origin) — exactly the protection the pre-#745 localhost-serve had.
//! 3. **Never touches a shell.** The opened target is always a validated http URL passed to the OS
//!    "open" facility as a SINGLE non-shell argv entry.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use dig_urn_resolver::images::{self, ErrorImage};
use dig_urn_resolver::{ResolveError, ResolveOutcome, ResolvedData};
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

    /// The canonical `urn:dig:chia:<storeId>[:<root>]/<path>` this link resolves as — the exact
    /// input the shared [`dig_urn_resolver`] parses (its ladder + fail-closed verify take over).
    fn to_urn(&self) -> String {
        let store_ref = self.store_ref();
        if self.path.is_empty() {
            format!("urn:dig:chia:{store_ref}")
        } else {
            format!("urn:dig:chia:{store_ref}/{}", self.path)
        }
    }
}

/// Abstracts the OS "open this URL in the default browser / protocol handler" action so the launch
/// path is unit-testable (a fake asserts the exact URL) and the real implementation never goes
/// through a shell. `url` is ALWAYS one this module built (a validated http(s) URL) — never raw
/// untrusted input and never a local file path.
pub trait UrlLauncher {
    /// Open `url` in the user's default browser. Implementations MUST pass `url` as a single,
    /// non-shell argument.
    fn open_url(&self, url: &str) -> std::io::Result<()>;
}

/// Resolves a DIG URN through the canonical [`dig_urn_resolver`] §5.3 ladder + fail-closed verify.
/// Injectable so tests drive the three outcomes without real network I/O.
pub trait UrnResolver {
    /// Resolve `urn` to a typed [`ResolveOutcome`] (or a hard [`ResolveError`]).
    fn resolve(&self, urn: &str) -> Result<ResolveOutcome, ResolveError>;
}

/// Cheaply probes whether a browser-navigable URL actually serves content right now. Injectable so
/// tests pick which tier "serves" without a live node.
pub trait BrowserProbe {
    /// `true` iff a quick request to `url` returns a serveable (2xx) response.
    fn serves(&self, url: &str) -> bool;
}

/// Serves a single blob (verified content or a branded asset) over an EPHEMERAL loopback HTTP
/// endpoint so the browser handles it under its normal, sandboxed protections instead of the
/// process ever writing attacker bytes to disk (see the module security notes). Injectable so tests
/// assert the served bytes + the opened URL without real sockets.
pub trait LocalContentServer {
    /// Bind an ephemeral `127.0.0.1:<port>` endpoint serving `data` (with its content type) at a
    /// URL whose last segment is `filename`, invoke `on_ready(url)` once bound (so the caller opens
    /// the browser), then serve requests until the content has been fetched (plus a short grace) or
    /// a bounded timeout elapses. Returns the served URL.
    fn serve_until_fetched(
        &self,
        data: &ResolvedData,
        filename: &str,
        on_ready: &dyn Fn(&str) -> std::io::Result<()>,
    ) -> std::io::Result<String>;
}

/// The real OS launcher. Opens `url` via a per-OS facility with it as a SINGLE argv entry — never a
/// shell — so a crafted URL cannot inject a command. Fire-and-forget: a failure to SPAWN the
/// launcher (e.g. `xdg-open` not installed) is surfaced; the launcher's own exit code is not
/// awaited (it hands off to the browser and exits).
pub struct OsLauncher;

impl UrlLauncher for OsLauncher {
    fn open_url(&self, url: &str) -> std::io::Result<()> {
        use std::process::{Command, Stdio};
        let mut cmd;
        #[cfg(target_os = "windows")]
        {
            // `rundll32 url.dll,FileProtocolHandler <url>` invokes the registered URL handler with
            // the URL as one argv entry and NO shell — unlike `cmd /c start`, which would parse
            // `&`/`^`/`|`. We only ever pass an `http://` URL here (never a local file path).
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

/// The real resolver: the shared [`dig_urn_resolver`] over its native `reqwest` transport, walking
/// the §5.3 ladder with fail-closed verification. Runs on a private blocking runtime (this CLI path
/// is synchronous).
pub struct NativeResolver;

impl UrnResolver for NativeResolver {
    fn resolve(&self, urn: &str) -> Result<ResolveOutcome, ResolveError> {
        dig_urn_resolver::native::resolve_blocking(urn)
    }
}

/// The real browser-tier probe: a short-timeout blocking GET. A dead tier (no DNS, refused
/// connection, timeout, or a 502 from the local `/s/` chain-read, #747) simply reports "does not
/// serve", so the caller falls through to the next tier / the loopback-serve fallback.
pub struct HttpProbe;

impl BrowserProbe for HttpProbe {
    fn serves(&self, url: &str) -> bool {
        let Ok(client) = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_millis(700))
            .timeout(Duration::from_secs(3))
            .build()
        else {
            return false;
        };
        client
            .get(url)
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

/// How long the loopback content server stays up waiting for the browser to connect, and how long
/// it lingers after the first request is served (for favicon / subresource requests).
const SERVE_MAX_LIFETIME: Duration = Duration::from_secs(12);
const SERVE_LINGER_AFTER_FIRST: Duration = Duration::from_millis(1200);

/// The real loopback content server. Binds `127.0.0.1:0`, serves the blob over plain HTTP under a
/// sandboxed `http://127.0.0.1:<port>` origin (with `X-Content-Type-Options: nosniff` and
/// `Cache-Control: no-store`), and tears down after the content is fetched or the timeout elapses.
/// The bytes NEVER touch disk, so no Mark-of-the-Web-less executable can be OS-opened.
pub struct RealLocalServer;

impl LocalContentServer for RealLocalServer {
    fn serve_until_fetched(
        &self,
        data: &ResolvedData,
        filename: &str,
        on_ready: &dyn Fn(&str) -> std::io::Result<()>,
    ) -> std::io::Result<String> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let url = format!("http://127.0.0.1:{port}/{filename}");
        listener.set_nonblocking(true)?;

        // Announce the URL (open the browser) only once the port is actually bound.
        on_ready(&url)?;

        let hard_deadline = Instant::now() + SERVE_MAX_LIFETIME;
        let mut linger_deadline: Option<Instant> = None;
        loop {
            let now = Instant::now();
            if now >= hard_deadline || linger_deadline.is_some_and(|d| now >= d) {
                break;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = serve_one(stream, data, filename);
                    // Keep serving briefly for any follow-up (favicon/subresource) requests.
                    linger_deadline = Some(Instant::now() + SERVE_LINGER_AFTER_FIRST);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(url)
    }
}

/// Serve one HTTP response carrying `data`. The request is drained (its contents are irrelevant —
/// every path gets the same blob). The content-type and filename are attacker-influenced, so both
/// are sanitized of control characters to prevent HTTP response-header injection.
fn serve_one(mut stream: TcpStream, data: &ResolvedData, filename: &str) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut scratch = [0u8; 2048];
    let _ = stream.read(&mut scratch); // best-effort drain of the request line/headers

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Content-Disposition: inline; filename=\"{filename}\"\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        content_type = sanitize_header_value(&data.content_type),
        len = data.bytes.len(),
        filename = sanitize_header_value(filename),
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&data.bytes)?;
    stream.flush()
}

/// Strip control characters (notably CR/LF) from an attacker-influenced header value to prevent
/// response-header injection / response splitting, and cap its length.
fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect()
}

/// The collaborators `open` needs, grouped so `run`/`run_with` read cleanly and tests inject fakes
/// for all of them at once.
pub struct OpenEnv<'a> {
    /// Resolves the URN via the canonical §5.3 ladder + fail-closed verify.
    pub resolver: &'a dyn UrnResolver,
    /// Probes which browser tier can serve the content right now.
    pub probe: &'a dyn BrowserProbe,
    /// Opens the chosen URL in the default browser.
    pub launcher: &'a dyn UrlLauncher,
    /// Serves verified bytes / a branded asset over a loopback HTTP endpoint.
    pub server: &'a dyn LocalContentServer,
}

impl OpenEnv<'static> {
    /// The production wiring (real resolver + probe + launcher + loopback server).
    fn real() -> Self {
        OpenEnv {
            resolver: &NativeResolver,
            probe: &HttpProbe,
            launcher: &OsLauncher,
            server: &RealLocalServer,
        }
    }
}

/// Run `dig-node open <link>`: validate the link, resolve it through the canonical resolver, and
/// open its verified content (or a branded error asset) in the default browser. See [`run_with`]
/// for the injectable form.
pub fn run(config: &Config, link: &str) -> std::io::Result<Outcome> {
    run_with(config, link, &OpenEnv::real())
}

/// [`run`] with injected collaborators (so tests drive resolve outcomes, tier availability, and
/// assert the exact opened URL without network I/O or a real browser). A rejected link returns an
/// `InvalidInput` error (→ `USAGE` exit) and NOTHING downstream is invoked.
pub fn run_with(config: &Config, link: &str, env: &OpenEnv) -> std::io::Result<Outcome> {
    // Strict security gate FIRST — a hostile input never reaches the resolver or the launcher.
    let parsed = normalize(link).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("dig-node open: {e}"),
        )
    })?;

    match env.resolver.resolve(&parsed.to_urn()) {
        Ok(ResolveOutcome::Success(data)) => open_success(config, &parsed, &data, env),
        // A reached-but-untrusted or unreachable outcome → its branded asset.
        Ok(outcome) => open_branded(&parsed, images::for_outcome(&outcome), outcome.kind(), env),
        // A hard resolve error (bad URN over rpc / not-found / rpc protocol error) → its branded
        // asset too — never a raw error string.
        Err(err) => open_branded(&parsed, images::for_error(&err), error_kind(&err), env),
    }
}

/// Open verified `Success` content. Prefer a live browser tier (`.dig` → `dig.local` → `localhost`,
/// §5.3), opening the first that actually serves; if none can (e.g. the local `/s/` 502s, #747)
/// serve the resolver's already-verified bytes over a loopback HTTP endpoint (NEVER to disk) so the
/// browser handles them under its normal, sandboxed download/render protections.
fn open_success(
    config: &Config,
    link: &DigLink,
    data: &ResolvedData,
    env: &OpenEnv,
) -> std::io::Result<Outcome> {
    if let Some(url) = candidate_urls(config, link)
        .into_iter()
        .find(|u| env.probe.serves(u))
    {
        env.launcher.open_url(&url)?;
        return Ok(open_outcome(link, "browser", "success", &url));
    }
    serve_locally(
        link,
        data,
        &safe_filename(&link.path),
        "content",
        "success",
        env,
    )
}

/// Serve a branded DIG error asset (from [`dig_urn_resolver::images`]) for a non-success outcome /
/// hard error over the loopback endpoint. A static, inert PNG — it never carries resolved bytes.
fn open_branded(
    link: &DigLink,
    image: ErrorImage,
    kind: &str,
    env: &OpenEnv,
) -> std::io::Result<Outcome> {
    let data = ResolvedData::new(images::png(image).to_vec(), "image/png".to_string());
    serve_locally(link, &data, "dig-error.png", "error", kind, env)
}

/// Serve `data` over the loopback content server and open its `http://127.0.0.1:<port>/…` URL.
fn serve_locally(
    link: &DigLink,
    data: &ResolvedData,
    filename: &str,
    mode: &str,
    kind: &str,
    env: &OpenEnv,
) -> std::io::Result<Outcome> {
    let url = env
        .server
        .serve_until_fetched(data, filename, &|u| env.launcher.open_url(u))?;
    Ok(open_outcome(link, mode, kind, &url))
}

/// The browser-navigable candidate URLs for a link, in §5.3 preference order. The `.dig` host form
/// is offered ONLY for a rootless link (the host cannot pin a capsule root); the `dig.local` and
/// `localhost` `/s/<ref>/<path>` forms carry the full `storeId[:root]` reference.
fn candidate_urls(config: &Config, link: &DigLink) -> Vec<String> {
    let store_ref = link.store_ref();
    let path = &link.path;
    let mut urls = Vec::with_capacity(3);
    if link.root.is_none() {
        urls.push(format!("http://{}.dig/{}", link.store_id, path));
    }
    urls.push(serve_url("dig.local", None, &store_ref, path));
    let host = browser_host(config);
    urls.push(serve_url(&host, Some(config.port), &store_ref, path));
    urls
}

/// Build a node `/s/<ref>/<path>` serve URL for `host` (with an optional explicit `port`). A
/// store-root (empty path) keeps a trailing slash (the #289 route contract).
fn serve_url(host: &str, port: Option<u16>, store_ref: &str, path: &str) -> String {
    let authority = match port {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    if path.is_empty() {
        format!("http://{authority}/s/{store_ref}/")
    } else {
        format!("http://{authority}/s/{store_ref}/{path}")
    }
}

/// The host for the `localhost` tier URL: the operator's explicit `DIG_NODE_HOST` when set
/// (bracketed for IPv6), else `localhost` — friendlier than `127.0.0.1` and equally reachable.
fn browser_host(config: &Config) -> String {
    match config.host {
        Some(ip) if ip.is_ipv6() => format!("[{ip}]"),
        Some(ip) => ip.to_string(),
        None => "localhost".to_string(),
    }
}

/// A safe, cosmetic filename for the loopback URL's last segment: the resource's basename reduced to
/// `[A-Za-z0-9._-]`, or `content` when empty/degenerate. Purely for display + the browser's
/// download-name hint — it is NEVER a filesystem path (nothing is written to disk).
fn safe_filename(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "content".to_string()
    } else {
        cleaned
    }
}

/// A stable machine-readable tag for a hard [`ResolveError`] (for the `--json` result).
fn error_kind(err: &ResolveError) -> &'static str {
    match err {
        ResolveError::Parse(_) => "invalid_urn",
        ResolveError::RootRequired => "root_required",
        ResolveError::NotFound => "not_found",
        ResolveError::Transport(_) => "unreachable",
        ResolveError::Rpc(_) => "rpc_error",
        ResolveError::VerifyFailed(_) | ResolveError::DecryptFailed => "integrity_failure",
    }
}

/// Build the [`Outcome`] for an opened target. `mode` is `browser` (a live tier URL), `content`
/// (verified bytes served over loopback), or `error` (a branded asset); `kind` is the resolve
/// outcome. `url` is always an `http(s)` URL — never a local file path.
fn open_outcome(link: &DigLink, mode: &str, kind: &str, url: &str) -> Outcome {
    let summary = match mode {
        "error" => format!("dig-node: could not load content ({kind}); showing a DIG error page"),
        _ => format!("dig-node: opening {url} in your default browser"),
    };
    Outcome::new(
        summary,
        json!({
            "opened": true,
            "mode": mode,
            "outcome": kind,
            "url": url,
            "store_id": link.store_id,
            "root": link.root,
            "path": link.path,
        }),
    )
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
        return Err(format!(
            "control character not allowed (U+{:04X})",
            bad as u32
        ));
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
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    fn store() -> String {
        "a".repeat(64)
    }
    fn root() -> String {
        "b".repeat(64)
    }

    /// A test launcher recording every URL it was asked to open (proving the real launcher — and
    /// thus a browser/shell — is never reached in CI).
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

    /// A resolver that records the URN it received and returns a canned outcome.
    struct FakeResolver {
        outcome: Mutex<Option<Result<ResolveOutcome, ResolveError>>>,
        seen: Mutex<Vec<String>>,
    }
    impl FakeResolver {
        fn new(outcome: Result<ResolveOutcome, ResolveError>) -> Self {
            FakeResolver {
                outcome: Mutex::new(Some(outcome)),
                seen: Mutex::new(Vec::new()),
            }
        }
    }
    impl UrnResolver for FakeResolver {
        fn resolve(&self, urn: &str) -> Result<ResolveOutcome, ResolveError> {
            self.seen.lock().unwrap().push(urn.to_string());
            self.outcome.lock().unwrap().take().expect("resolve once")
        }
    }

    /// A probe that "serves" exactly the URLs it was seeded with (and records what it was asked).
    #[derive(Default)]
    struct FakeProbe {
        serving: HashSet<String>,
        asked: Mutex<Vec<String>>,
    }
    impl FakeProbe {
        fn serving(urls: &[String]) -> Self {
            FakeProbe {
                serving: urls.iter().cloned().collect(),
                asked: Mutex::new(Vec::new()),
            }
        }
    }
    impl BrowserProbe for FakeProbe {
        fn serves(&self, url: &str) -> bool {
            self.asked.lock().unwrap().push(url.to_string());
            self.serving.contains(url)
        }
    }

    /// A content server that records the blob it was asked to serve and returns a deterministic
    /// loopback URL (also invoking `on_ready` so the launcher records that URL). No real socket.
    #[derive(Default)]
    struct FakeServer {
        served: Mutex<Vec<(ResolvedData, String)>>,
    }
    impl LocalContentServer for FakeServer {
        fn serve_until_fetched(
            &self,
            data: &ResolvedData,
            filename: &str,
            on_ready: &dyn Fn(&str) -> std::io::Result<()>,
        ) -> std::io::Result<String> {
            self.served
                .lock()
                .unwrap()
                .push((data.clone(), filename.to_string()));
            let url = format!("http://127.0.0.1:54321/{filename}");
            on_ready(&url)?;
            Ok(url)
        }
    }

    struct Fakes {
        resolver: FakeResolver,
        probe: FakeProbe,
        launcher: FakeLauncher,
        server: FakeServer,
    }
    impl Fakes {
        fn env(&self) -> OpenEnv<'_> {
            OpenEnv {
                resolver: &self.resolver,
                probe: &self.probe,
                launcher: &self.launcher,
                server: &self.server,
            }
        }
        fn opened(&self) -> Vec<String> {
            self.launcher.opened.lock().unwrap().clone()
        }
    }

    fn success(bytes: &[u8], ct: &str) -> ResolveOutcome {
        ResolveOutcome::Success(ResolvedData::new(bytes.to_vec(), ct.to_string()))
    }

    // ---- success: opens the best live browser tier -------------------------------------------

    #[test]
    fn success_opens_localhost_tier_when_only_it_serves() {
        let cfg = Config::default();
        let localhost = format!("http://localhost:9778/s/{}/index.html", store());
        let fakes = Fakes {
            resolver: FakeResolver::new(Ok(success(b"<html>", "text/html"))),
            probe: FakeProbe::serving(std::slice::from_ref(&localhost)),
            launcher: FakeLauncher::default(),
            server: FakeServer::default(),
        };
        let out = run_with(
            &cfg,
            &format!("chia://{}/index.html", store()),
            &fakes.env(),
        )
        .unwrap();
        assert_eq!(fakes.opened(), vec![localhost]);
        assert_eq!(out.result["mode"], json!("browser"));
        assert_eq!(out.result["outcome"], json!("success"));
        // The resolver saw the canonical URN, not a hard-rolled localhost URL. Nothing was served
        // over the loopback endpoint (the live tier handled it).
        assert_eq!(
            fakes.resolver.seen.lock().unwrap()[0],
            format!("urn:dig:chia:{}/index.html", store())
        );
        assert!(fakes.server.served.lock().unwrap().is_empty());
    }

    #[test]
    fn success_prefers_dot_dig_form_for_rootless_link() {
        let cfg = Config::default();
        let dot_dig = format!("http://{}.dig/index.html", store());
        let localhost = format!("http://localhost:9778/s/{}/index.html", store());
        let fakes = Fakes {
            resolver: FakeResolver::new(Ok(success(b"x", "text/html"))),
            // Both the .dig and localhost tiers serve — .dig must win (§5.3 preference).
            probe: FakeProbe::serving(&[dot_dig.clone(), localhost]),
            launcher: FakeLauncher::default(),
            server: FakeServer::default(),
        };
        run_with(
            &cfg,
            &format!("chia://{}/index.html", store()),
            &fakes.env(),
        )
        .unwrap();
        assert_eq!(fakes.opened(), vec![dot_dig]);
    }

    #[test]
    fn success_with_root_pin_never_offers_dot_dig_and_uses_dig_local() {
        let cfg = Config::default();
        let dig_local = format!("http://dig.local/s/{}:{}/", store(), root());
        let fakes = Fakes {
            resolver: FakeResolver::new(Ok(success(b"x", "text/html"))),
            probe: FakeProbe::serving(std::slice::from_ref(&dig_local)),
            launcher: FakeLauncher::default(),
            server: FakeServer::default(),
        };
        run_with(
            &cfg,
            &format!("chia://{}:{}", store(), root()),
            &fakes.env(),
        )
        .unwrap();
        assert_eq!(fakes.opened(), vec![dig_local]);
        // A root-pinned link must NEVER probe a `.dig` host form (it can't carry the root).
        let asked = fakes.probe.asked.lock().unwrap();
        assert!(asked.iter().all(|u| !u.contains(".dig/")));
    }

    // ---- success: loopback-serve fallback when no tier serves (the #747 case) -----------------

    #[test]
    fn success_serves_verified_bytes_over_loopback_when_no_browser_tier_serves() {
        let cfg = Config::default();
        let fakes = Fakes {
            resolver: FakeResolver::new(Ok(success(b"\xff\xd8verified", "image/jpeg"))),
            probe: FakeProbe::default(), // nothing serves (local /s/ 502s, #747)
            launcher: FakeLauncher::default(),
            server: FakeServer::default(),
        };
        let out = run_with(&cfg, &format!("chia://{}/photo.jpg", store()), &fakes.env()).unwrap();
        // The VERIFIED bytes were served over a loopback HTTP endpoint (never written to disk) and
        // that http URL opened — not a file path, and never a 502 string.
        let served = fakes.server.served.lock().unwrap();
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].0.bytes, b"\xff\xd8verified");
        assert_eq!(served[0].0.content_type, "image/jpeg");
        assert_eq!(served[0].1, "photo.jpg");
        assert_eq!(out.result["mode"], json!("content"));
        let opened = fakes.opened();
        assert_eq!(opened.len(), 1);
        assert!(opened[0].starts_with("http://127.0.0.1:"));
    }

    // ---- SECURITY REGRESSION (#745 RCE): attacker executables are served, never OS-opened -----

    #[test]
    fn attacker_executable_is_served_over_http_never_written_or_os_opened() {
        // The routine no-serving-node path. An attacker publishes an executable/script resource
        // with an executable content type; the victim activates chia://<store>/payload.hta.
        for (path, ct) in [
            ("payload.hta", "application/x-msdownload"),
            ("evil.js", "application/javascript"),
            ("run.vbs", "text/vbscript"),
        ] {
            let cfg = Config::default();
            let fakes = Fakes {
                resolver: FakeResolver::new(Ok(success(b"<script>steal()</script>", ct))),
                probe: FakeProbe::default(), // no browser tier serves → the fallback path
                launcher: FakeLauncher::default(),
                server: FakeServer::default(),
            };
            let out = run_with(&cfg, &format!("chia://{}/{path}", store()), &fakes.env()).unwrap();

            // 1) The opened target is a SANDBOXED loopback HTTP URL — never a `file://` URL and
            //    never a local filesystem path handed to the OS "open" facility (which would
            //    execute an .hta/.js with full local trust — the RCE this test guards).
            let opened = fakes.opened();
            assert_eq!(opened.len(), 1, "{path}: exactly one open");
            assert!(
                opened[0].starts_with("http://127.0.0.1:"),
                "{path}: must open a loopback http URL, got {}",
                opened[0]
            );
            assert!(!opened[0].starts_with("file:"), "{path}: never a file URL");
            // 2) The bytes are SERVED (the browser then applies MOTW/download handling), carrying
            //    the attacker content type verbatim — they are never persisted to disk by us.
            let served = fakes.server.served.lock().unwrap();
            assert_eq!(served[0].0.content_type, ct);
            assert_eq!(out.result["mode"], json!("content"));
        }
    }

    // ---- failures: branded assets, never a raw 502 --------------------------------------------

    #[test]
    fn integrity_failure_serves_branded_integrity_asset_never_bytes() {
        let cfg = Config::default();
        let fakes = Fakes {
            resolver: FakeResolver::new(Ok(ResolveOutcome::IntegrityFailure)),
            probe: FakeProbe::default(),
            launcher: FakeLauncher::default(),
            server: FakeServer::default(),
        };
        let out = run_with(
            &cfg,
            &format!("chia://{}:{}/x", store(), root()),
            &fakes.env(),
        )
        .unwrap();
        let served = fakes.server.served.lock().unwrap();
        // Exactly the static branded integrity PNG served as image/png — no browser tier probed.
        assert_eq!(served[0].0.bytes, images::png(ErrorImage::Integrity));
        assert_eq!(served[0].0.content_type, "image/png");
        assert!(fakes.probe.asked.lock().unwrap().is_empty());
        assert_eq!(out.result["mode"], json!("error"));
        assert_eq!(out.result["outcome"], json!("integrity_failure"));
        assert!(!out.summary.contains("502"));
    }

    #[test]
    fn unreachable_serves_branded_unreachable_asset() {
        let cfg = Config::default();
        let fakes = Fakes {
            resolver: FakeResolver::new(Ok(ResolveOutcome::Unreachable)),
            probe: FakeProbe::default(),
            launcher: FakeLauncher::default(),
            server: FakeServer::default(),
        };
        let out = run_with(&cfg, &format!("chia://{}/x", store()), &fakes.env()).unwrap();
        assert_eq!(
            fakes.server.served.lock().unwrap()[0].0.bytes,
            images::png(ErrorImage::Unreachable)
        );
        assert_eq!(out.result["outcome"], json!("unreachable"));
    }

    #[test]
    fn not_found_error_serves_branded_not_found_asset() {
        let cfg = Config::default();
        let fakes = Fakes {
            resolver: FakeResolver::new(Err(ResolveError::NotFound)),
            probe: FakeProbe::default(),
            launcher: FakeLauncher::default(),
            server: FakeServer::default(),
        };
        let out = run_with(&cfg, &format!("chia://{}/missing", store()), &fakes.env()).unwrap();
        assert_eq!(
            fakes.server.served.lock().unwrap()[0].0.bytes,
            images::png(ErrorImage::NotFound)
        );
        assert_eq!(out.result["outcome"], json!("not_found"));
        assert!(!out.summary.contains("502"));
    }

    // ---- security: hostile input never reaches the resolver, launcher, or server --------------

    #[test]
    fn hostile_link_rejected_before_resolve_or_launch() {
        let cfg = Config::default();
        let fakes = Fakes {
            resolver: FakeResolver::new(Ok(success(b"x", "text/html"))),
            probe: FakeProbe::default(),
            launcher: FakeLauncher::default(),
            server: FakeServer::default(),
        };
        let err = run_with(&cfg, "javascript:alert(1)", &fakes.env()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(fakes.resolver.seen.lock().unwrap().is_empty());
        assert!(fakes.opened().is_empty());
        assert!(fakes.server.served.lock().unwrap().is_empty());
    }

    // ---- URN reconstruction + filename sanitization -------------------------------------------

    #[test]
    fn to_urn_reconstructs_canonical_forms() {
        let bare = DigLink {
            store_id: store(),
            root: None,
            path: String::new(),
        };
        assert_eq!(bare.to_urn(), format!("urn:dig:chia:{}", store()));
        let capsule = DigLink {
            store_id: store(),
            root: Some(root()),
            path: "a/b.css".into(),
        };
        assert_eq!(
            capsule.to_urn(),
            format!("urn:dig:chia:{}:{}/a/b.css", store(), root())
        );
    }

    #[test]
    fn safe_filename_reduces_to_basename_or_default() {
        assert_eq!(safe_filename("img/logo.png"), "logo.png");
        assert_eq!(safe_filename(""), "content");
        assert_eq!(safe_filename("a/b/"), "content");
        // Any stray non-token bytes are dropped (defensive; normalize already screened the link).
        assert_eq!(safe_filename("weird name!.txt"), "weirdname.txt");
    }

    #[test]
    fn sanitize_header_value_strips_crlf_injection() {
        let injected = "image/png\r\nSet-Cookie: x=1";
        let clean = sanitize_header_value(injected);
        assert!(!clean.contains('\r') && !clean.contains('\n'));
        assert!(clean.starts_with("image/png"));
    }

    // ---- the REAL loopback server actually serves bytes over http (end-to-end) ----------------

    #[test]
    fn real_local_server_serves_bytes_over_loopback_http() {
        let data = ResolvedData::new(b"\xff\xd8verified-body".to_vec(), "image/jpeg".to_string());
        let response = Arc::new(Mutex::new(Vec::<u8>::new()));
        let response_writer = response.clone();

        let url = RealLocalServer
            .serve_until_fetched(&data, "photo.jpg", &move |u| {
                // Act as the browser: fetch the URL from a background thread so the (blocking)
                // accept loop can serve it.
                let hostport = u
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap()
                    .to_string();
                let sink = response_writer.clone();
                std::thread::spawn(move || {
                    if let Ok(mut stream) = TcpStream::connect(&hostport) {
                        let _ = stream.write_all(b"GET /photo.jpg HTTP/1.1\r\nHost: x\r\n\r\n");
                        let mut buf = Vec::new();
                        let _ = stream.read_to_end(&mut buf);
                        *sink.lock().unwrap() = buf;
                    }
                });
                Ok(())
            })
            .unwrap();

        assert!(url.starts_with("http://127.0.0.1:"));
        let resp = response.lock().unwrap().clone();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("200 OK"), "status line present: {text}");
        assert!(text.contains("Content-Type: image/jpeg"));
        assert!(text.contains("X-Content-Type-Options: nosniff"));
        assert!(text.contains("verified-body"), "body served");
    }

    // ---- preserved normalize validation (security boundary) -----------------------------------

    #[test]
    fn accepts_chia_and_urn_schemes_case_insensitively() {
        assert!(normalize(&format!("CHIA://{}", store())).is_ok());
        assert!(normalize(&format!("Urn:Dig:Chia:{}/a/b.css", store())).is_ok());
        let n = normalize(&format!("chia://{}:{}/index.html", store(), root())).unwrap();
        assert_eq!(n.root.as_deref(), Some(root().as_str()));
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
}
