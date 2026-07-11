//! Pure HTTP helpers for the local plaintext content-serve surface (#289): route parsing, the
//! store-root `<base>`/Referer rerooting, the SPA-vs-asset classifier, the ecosystem content-type
//! map, and the served-store Content-Security-Policy. All PURE + unit-testable; the wiring +
//! `Node::serve_content_plaintext` calls live in [`crate::server`].
//!
//! Store-root scoping is a shared-origin best-effort (the honest web-platform limit of serving many
//! stores off ONE `dig.local` origin): the node injects `<base href="/s/<store>[:<root>]/">` so a
//! store's RELATIVE links resolve within its own path, plus `<meta name="referrer" content="same-origin">`
//! so a ROOT-ABSOLUTE `/foo` request still carries a same-origin `Referer` the node reroots by
//! ([`reroot_via_referer`]). An unattributable root-absolute request degrades to a 404 (asset) or the
//! SPA fallback (route) — see [`crate::server`].

/// Known static-asset file extensions (lowercased, no leading dot) — a request whose FINAL path
/// segment ends in one of these names a concrete static asset, never an application/navigation route.
/// `html`/`htm` are deliberately ABSENT: a document/navigation request is a ROUTE (it gets the SPA
/// fallback, never an honest 404). Ported to match the on.dig.net resolver's classifier
/// (`is_static_asset_path`) + the loader `sw.js` `contentType()` extension set, so a store behaves
/// identically served locally or via `*.on.dig.net`.
const STATIC_ASSET_EXTENSIONS: &[&str] = &[
    "js", "mjs", "css", "json", "wasm", "map", "svg", "png", "jpg", "jpeg", "gif", "webp", "ico",
    "avif", "woff", "woff2", "ttf", "otf", "txt", "pdf", "mp4", "webm", "mp3", "wav", "ogg", "xml",
    "md",
];

/// Whether `path`'s FINAL segment names a concrete STATIC ASSET (a known non-HTML extension) rather
/// than an application/navigation route.
///
/// WHY (#144 MIME rule): the serve path returns the store's `index.html` (`text/html`) for a
/// navigation ROUTE so an SPA client-side deep link boots. But an ASSET path that MISSES (most
/// critically a `service-worker.js`) MUST get an honest `404`, never `text/html` — a browser rejects
/// a `text/html` service-worker registration / ES-module import with a MIME `SecurityError`. Only the
/// final segment's extension decides, and only KNOWN asset extensions match, so a route that merely
/// contains a dot (`/user/john.doe`) stays a route.
pub fn is_static_asset_path(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    match last.rsplit_once('.') {
        Some((name, ext)) if !name.is_empty() => {
            STATIC_ASSET_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
        }
        _ => false,
    }
}

/// The Content-Type for a served resource path, from its final-segment extension. Ported byte-for-byte
/// from the ecosystem's single source of truth — the DIG loader's `contentType()`
/// (`hub.dig.net/apps/web/lib/embed-core.ts`, mirrored in `on.dig.net/assets/sw.js`) — so a resource
/// is labelled identically whether decrypted in the browser SW or here in the node. An unknown /
/// extensionless path is `application/octet-stream` (never guessed). An empty path resolves to the
/// default view `index.html` (⇒ `text/html`).
pub fn content_type_for(path: &str) -> &'static str {
    let effective = if path.is_empty() { "index.html" } else { path };
    let last = effective.rsplit('/').next().unwrap_or("");
    let ext = match last.rsplit_once('.') {
        Some((name, ext)) if !name.is_empty() => ext.to_ascii_lowercase(),
        _ => return "application/octet-stream",
    };
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "avif" => "image/avif",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wasm" => "application/wasm",
        "xml" => "application/xml",
        "md" => "text/markdown",
        _ => "application/octet-stream",
    }
}

/// Whether the Content-Type names an HTML document (so the serve path injects `<base>`/`<meta>` and
/// attaches the store CSP).
pub fn is_html(content_type: &str) -> bool {
    content_type.starts_with("text/html")
}

/// The Content-Security-Policy the node synthesizes on every served store HTML document. Hardened
/// (no plugins, same-origin base, un-framed) while allowing what a self-contained DIG store legitimately
/// needs on the shared `dig.local` origin — inline script/style, `data:`/`blob:`, and the sanctioned
/// content network legs (the public RPC gateway + coinset + the tip-widget origins), mirroring the
/// on.dig.net store-content sandbox. Attached as a response header, never trusted from the store body.
pub const STORE_CSP: &str = "default-src 'self'; \
script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data: blob: https:; \
font-src 'self' data:; \
connect-src 'self' https://rpc.dig.net https://api.coinset.org https://esm.sh https://hub.dig.net; \
worker-src 'self' blob:; \
media-src 'self' data: blob:; \
object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

/// A parsed `/s/<storeId>[:<root>]/<resource>` request. `resource` is the path within the store
/// (empty ⇒ the default view `index.html`); `root` is the optional pinned capsule root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePath {
    pub store_id: String,
    pub root: Option<String>,
    pub resource: String,
}

/// 64 lowercase/uppercase hex characters (a store id or root).
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse a `/s/<storeId>[:<root>]/<resource>` request path into its parts, or `None` when it is not a
/// well-formed store path (missing `/s/` prefix, or a store id / root that is not 64-hex). Accepts the
/// full request path (`/s/...`) OR the bare wildcard tail (`<store>[:<root>]/<resource>`), so it is
/// robust to how the router hands over the captured path.
pub fn parse_store_path(path: &str) -> Option<StorePath> {
    let rest = path.strip_prefix('/').unwrap_or(path);
    // Accept the full "/s/..." form or the bare tail after the router already stripped "/s/".
    let rest = rest.strip_prefix("s/").unwrap_or(rest);
    // head = "<store>[:<root>]", resource = everything after the first '/'.
    let (head, resource) = match rest.split_once('/') {
        Some((h, r)) => (h, r.to_string()),
        None => (rest, String::new()),
    };
    let (store_id, root) = match head.split_once(':') {
        Some((s, r)) => (s, Some(r.to_string())),
        None => (head, None),
    };
    if !is_hex64(store_id) {
        return None;
    }
    if let Some(r) = &root {
        if !is_hex64(r) {
            return None;
        }
    }
    Some(StorePath {
        store_id: store_id.to_ascii_lowercase(),
        root: root.map(|r| r.to_ascii_lowercase()),
        resource,
    })
}

/// The store-root base href for a `<base>` tag: `/s/<store>[:<root>]/`. A store's RELATIVE links
/// resolve within its own path against this.
pub fn store_base_href(sp: &StorePath) -> String {
    match &sp.root {
        Some(root) => format!("/s/{}:{}/", sp.store_id, root),
        None => format!("/s/{}/", sp.store_id),
    }
}

/// Reroot a ROOT-ABSOLUTE subresource request (`GET /foo.js`) back into its store using the same-origin
/// `Referer` a store page carries (`http://dig.local/s/<store>[:<root>]/...`). Returns the store +
/// root from the Referer combined with the requested path as the resource, or `None` when the Referer
/// is absent or does not name a store (the request is then unattributable — the caller 404s an asset
/// / SPA-falls-back a route).
pub fn reroot_via_referer(referer: Option<&str>, req_path: &str) -> Option<StorePath> {
    let referer = referer?;
    // Take the PATH component of the Referer URL (strip scheme + host).
    let after_scheme = referer.split_once("://").map_or(referer, |x| x.1);
    let ref_path = &after_scheme[after_scheme.find('/')?..];
    let base = parse_store_path(ref_path)?;
    Some(StorePath {
        store_id: base.store_id,
        root: base.root,
        resource: req_path.trim_start_matches('/').to_string(),
    })
}

/// Case-insensitive first-index of `needle` within `haystack`.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let hay = haystack.to_ascii_lowercase();
    hay.find(needle)
}

/// Inject `<base href="…">` + `<meta name="referrer" content="same-origin">` into a served store
/// HTML document so RELATIVE links resolve within the store's path AND a root-absolute subresource
/// request carries a same-origin Referer the node can reroot. Inserted right after the opening
/// `<head>` tag (case-insensitive); if the document has no `<head>`, the tags are prepended (a `<base>`
/// before any content still applies).
pub fn inject_html_head(html: &str, base_href: &str) -> String {
    let inject =
        format!("<base href=\"{base_href}\"><meta name=\"referrer\" content=\"same-origin\">");
    if let Some(head_pos) = find_ci(html, "<head") {
        if let Some(gt_rel) = html[head_pos..].find('>') {
            let insert_at = head_pos + gt_rel + 1;
            let mut out = String::with_capacity(html.len() + inject.len());
            out.push_str(&html[..insert_at]);
            out.push_str(&inject);
            out.push_str(&html[insert_at..]);
            return out;
        }
    }
    format!("{inject}{html}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE: &str = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    const ROOT: &str = "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddee";

    #[test]
    fn asset_paths_are_classified_vs_routes() {
        // Routes (navigation): no extension, or an unknown "extension", or html.
        for route in [
            "/",
            "/about",
            "/chat/123",
            "/index.html",
            "/user/john.doe",
            "/v1.2",
        ] {
            assert!(!is_static_asset_path(route), "{route:?} is a route");
        }
        // Assets: a known static extension on the final segment.
        for asset in [
            "/sw.js",
            "/assets/app.min.mjs",
            "/styles/main.css",
            "/data/config.json",
            "/img/logo.png",
            "/x/dotnet.wasm",
        ] {
            assert!(is_static_asset_path(asset), "{asset:?} is an asset");
        }
    }

    #[test]
    fn content_type_maps_known_extensions_and_defaults_octet_stream() {
        assert_eq!(content_type_for("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type_for(""), "text/html; charset=utf-8"); // empty ⇒ index.html
        assert_eq!(content_type_for("app.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type_for("a.mjs"), "text/javascript; charset=utf-8");
        assert_eq!(content_type_for("s.css"), "text/css; charset=utf-8");
        assert_eq!(content_type_for("d.json"), "application/json");
        assert_eq!(content_type_for("m.wasm"), "application/wasm");
        assert_eq!(content_type_for("i.png"), "image/png");
        assert_eq!(content_type_for("f.woff2"), "font/woff2");
        // Unknown / extensionless ⇒ octet-stream (never guessed).
        assert_eq!(content_type_for("data.bin"), "application/octet-stream");
        assert_eq!(content_type_for("noext"), "application/octet-stream");
    }

    #[test]
    fn parse_store_path_extracts_store_root_and_resource() {
        // With root + resource.
        let sp = parse_store_path(&format!("/s/{STORE}:{ROOT}/assets/app.js")).unwrap();
        assert_eq!(sp.store_id, STORE);
        assert_eq!(sp.root.as_deref(), Some(ROOT));
        assert_eq!(sp.resource, "assets/app.js");

        // Store only, bare (no resource) → empty resource (⇒ index.html downstream).
        let sp = parse_store_path(&format!("/s/{STORE}/")).unwrap();
        assert_eq!(sp.store_id, STORE);
        assert_eq!(sp.root, None);
        assert_eq!(sp.resource, "");

        // The bare wildcard tail (router already stripped "/s/").
        let sp = parse_store_path(&format!("{STORE}/index.html")).unwrap();
        assert_eq!(sp.store_id, STORE);
        assert_eq!(sp.resource, "index.html");
    }

    #[test]
    fn parse_store_path_rejects_non_store_paths() {
        assert!(parse_store_path("/health").is_none());
        assert!(parse_store_path("/s/not-hex/index.html").is_none());
        assert!(parse_store_path(&format!("/s/{STORE}:zz/index.html")).is_none());
        // bad root
    }

    #[test]
    fn store_base_href_is_the_store_root_prefix() {
        let with_root = StorePath {
            store_id: STORE.into(),
            root: Some(ROOT.into()),
            resource: "deep/route".into(),
        };
        assert_eq!(store_base_href(&with_root), format!("/s/{STORE}:{ROOT}/"));
        let no_root = StorePath {
            store_id: STORE.into(),
            root: None,
            resource: String::new(),
        };
        assert_eq!(store_base_href(&no_root), format!("/s/{STORE}/"));
    }

    #[test]
    fn reroot_via_referer_maps_a_root_absolute_request_into_its_store() {
        let referer = format!("http://dig.local/s/{STORE}:{ROOT}/some/page");
        let sp = reroot_via_referer(Some(&referer), "/assets/app.js").unwrap();
        assert_eq!(sp.store_id, STORE);
        assert_eq!(sp.root.as_deref(), Some(ROOT));
        assert_eq!(sp.resource, "assets/app.js");
    }

    #[test]
    fn reroot_via_referer_is_none_without_a_store_referer() {
        assert!(reroot_via_referer(None, "/foo.js").is_none());
        assert!(reroot_via_referer(Some("http://dig.local/health"), "/foo.js").is_none());
    }

    #[test]
    fn inject_html_head_inserts_base_and_referrer_after_head() {
        let html = "<html><head><title>x</title></head><body>hi</body></html>";
        let base = format!("/s/{STORE}/");
        let out = inject_html_head(html, &base);
        assert!(out.contains(&format!("<base href=\"/s/{STORE}/\">")));
        assert!(out.contains("<meta name=\"referrer\" content=\"same-origin\">"));
        // Inserted INSIDE head, before the title.
        let head_open = out.find("<head>").unwrap();
        let base_at = out.find("<base").unwrap();
        let title_at = out.find("<title>").unwrap();
        assert!(head_open < base_at && base_at < title_at);
    }

    #[test]
    fn inject_html_head_prepends_when_no_head() {
        let html = "<div>no head here</div>";
        let out = inject_html_head(html, "/s/x/");
        assert!(out.starts_with("<base href=\"/s/x/\">"));
    }
}
