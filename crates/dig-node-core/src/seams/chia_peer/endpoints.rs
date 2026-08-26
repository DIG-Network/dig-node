//! Which chain endpoints the node may ask, and which of them are genuinely DIFFERENT VOICES.
//!
//! # Independence is derived from REACH, never from type or from a name
//!
//! NC-12 asks that a chain fact be agreed by several *independent* sources. The failure this
//! module exists to prevent is a "quorum" that is really one voice wearing two hats — the exact
//! defect found in `dig-wallet` on dig-node PR#354, where a 2-of-2 "independent-group" rule was
//! satisfied by ONE HTTPS endpoint because the second group's peer tier was configured with
//! `max_peers: 0` and could reach nothing at all.
//!
//! So independence here is not a property of a source's TYPE, and not a property of its URL
//! either: two hostnames are one voice whenever they land on the same machine, and a CNAME costs
//! an attacker nothing. It is derived from what each endpoint can actually be REACHED at — its
//! resolved addresses — and two endpoints whose address sets INTERSECT are treated as a single
//! voice, however different they look on paper.
//!
//! Among SEVERAL endpoints, one that cannot be resolved contributes NO voice. That is the
//! fail-closed direction: a source whose independence cannot be measured has not been shown to be
//! a second machine, and counting it would let a typo inflate a quorum. With a SINGLE endpoint
//! there is no independence to measure and the lookup is skipped entirely — see
//! [`super::corroborated_resolver::CorroboratedResolver`], where that carve-out lives, for why a
//! name lookup must not become a gate on reading.

use std::collections::BTreeSet;
use std::net::IpAddr;

/// A chain endpoint's network identity: the host and port a client would connect to.
///
/// Held separately from the URL because the URL is what an operator wrote and the authority is
/// what the network sees — `https://api.example.org/v1/` and `https://API.example.org` are one
/// authority, and the resolved-address comparison below only makes sense per authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Authority {
    /// Lowercased host, with no brackets around an IPv6 literal.
    pub host: String,
    /// The port a client dials — the URL's explicit port, else the scheme's default.
    pub port: u16,
}

/// One configured chain endpoint: the URL to query, and the authority it dials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainEndpoint {
    /// The URL as configured, passed through to the coinset client unchanged.
    pub url: String,
    /// Where that URL lands on the network.
    pub authority: Authority,
}

impl ChainEndpoint {
    /// Parse `url` into an endpoint, or `None` when it names no host this node could dial.
    ///
    /// Deliberately a small hand-rolled parse rather than a URL crate: the only fields that matter
    /// here are the host and the port, and pulling a parser in for two fields would add a
    /// dependency whose own failure modes then need answers of their own.
    pub fn parse(url: &str) -> Option<Self> {
        let url = url.trim();
        let (scheme, rest) = url.split_once("://")?;
        let default_port = match scheme.to_ascii_lowercase().as_str() {
            "http" => 80,
            "https" => 443,
            _ => return None,
        };
        // Keep only what a client would dial: no path, no query, no fragment, no userinfo.
        let hostport = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let hostport = hostport.rsplit_once('@').map_or(hostport, |(_, host)| host);

        let (host, port) = split_host_port(hostport, default_port)?;
        Some(Self {
            url: url.to_string(),
            authority: Authority { host, port },
        })
    }
}

/// Split `hostport` into a lowercased host and a port, honouring the `[::1]:8555` IPv6 form.
///
/// IPv6 literals are bracketed precisely because a bare `::1:8555` is ambiguous, so the bracketed
/// form is handled first and a `:` split is only ever applied to a name or an IPv4 literal.
fn split_host_port(hostport: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(explicit) => explicit.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return non_empty(host.to_ascii_lowercase()).map(|host| (host, port));
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse().ok()?;
            non_empty(host.to_ascii_lowercase()).map(|host| (host, port))
        }
        None => non_empty(hostport.to_ascii_lowercase()).map(|host| (host, default_port)),
    }
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

/// What a chain endpoint can actually be reached at.
///
/// A trait so the independence rule can be pinned against address sets chosen to express the
/// same-machine case, which no live DNS lookup can be relied upon to produce on demand.
#[async_trait::async_trait]
pub(crate) trait EndpointReach: Send + Sync {
    /// The addresses `authority` resolves to, or `Err` when it resolves to nothing.
    async fn addrs(&self, authority: &Authority) -> Result<BTreeSet<IpAddr>, String>;
}

/// How long one endpoint's name resolution may take before it counts as unreachable.
///
/// Chosen to bound the request path rather than to be generous: independence is recomputed per
/// resolution, so this is paid on reads, and an endpoint slower than this is not one the node can
/// usefully corroborate against anyway.
const LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Production reach: ordinary DNS, through the same resolver the HTTP client will use.
pub(crate) struct DnsReach;

#[async_trait::async_trait]
impl EndpointReach for DnsReach {
    /// Resolve `authority` by handing the host and the port to the resolver SEPARATELY.
    ///
    /// The `(host, port)` tuple form is not stylistic. Rendering an address as
    /// `format!("{host}:{port}")` is invalid for every IPv6 literal — the grammar requires brackets
    /// — and this module strips those brackets when it parses, so re-joining the two would produce
    /// `::1:8555` and fail to resolve every v6 endpoint. §5.2 makes IPv6 the first-class case here,
    /// so that would not be an edge; it would be the common path. `crates/dig-node-core/tests/
    /// banned_address_patterns.rs` bans the concatenation at the source for exactly this reason,
    /// and it caught this function.
    async fn addrs(&self, authority: &Authority) -> Result<BTreeSet<IpAddr>, String> {
        let Authority { host, port } = authority;
        // BOUNDED, because this runs on the content-serve request path. A resolver that never
        // answers would otherwise hold a read open indefinitely, and it would do so while the node
        // looks healthy — the endpoint set is consulted per resolution, so one black-holed DNS
        // server would stall every read rather than costing one voice.
        //
        // A timeout is an UNREACHABLE verdict, which is the fail-closed direction: the endpoint
        // contributes no voice, and too few voices refuses.
        let addrs: BTreeSet<IpAddr> = tokio::time::timeout(
            LOOKUP_TIMEOUT,
            tokio::net::lookup_host((host.as_str(), *port)),
        )
        .await
        .map_err(|_| {
            format!(
                "host {host} port {port} did not resolve within {}s",
                LOOKUP_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| format!("host {host} port {port} does not resolve: {e}"))?
        .map(|socket| socket.ip())
        .collect();
        if addrs.is_empty() {
            return Err(format!("host {host} port {port} resolves to no address"));
        }
        Ok(addrs)
    }
}

/// How long a resolved address set is reused before the name is looked up again.
///
/// Independence must not be decided from a verdict fixed at start-up — an endpoint's addresses
/// change, and a permanently-cached grouping would keep claiming corroboration long after two
/// endpoints had converged on one host. A short TTL keeps that from happening while removing the
/// per-READ lookup: the verdict can be at most this stale, which is the same order as the DNS TTLs
/// the resolver is honouring anyway.
const REACH_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a previously-resolved address set is still served AFTER the name stops resolving.
///
/// A resolver blip is not evidence that an endpoint moved, and treating it as one silently changes
/// the VOICE COUNT — the number the refusal rule trusts — on the basis of a failure that has
/// nothing to do with the chain. Serving the last known answer for a bounded window keeps a DNS
/// hiccup from being reported as a corroboration failure. Beyond the window the entry is abandoned:
/// a name that has not resolved for ten minutes has genuinely stopped resolving.
const REACH_STALE_GRACE: std::time::Duration = std::time::Duration::from_secs(600);

/// What one authority last resolved to, and when.
struct CachedAddrs {
    /// The addresses that lookup returned.
    addrs: BTreeSet<IpAddr>,
    /// When they were learned.
    learned: std::time::Instant,
}

/// An [`EndpointReach`] that remembers, so name resolution is not paid on every read.
///
/// Wrapping rather than folding the cache into [`DnsReach`] keeps the lookup and the caching
/// policy separately testable: a cache tested through a live resolver can only be tested against
/// whatever that resolver happens to do.
pub(crate) struct CachedReach<R> {
    /// The reach this one is a cache over.
    inner: R,
    /// One entry per authority. A `std::sync::Mutex` is deliberate — the critical section is a map
    /// lookup with no `await` in it, so an async mutex would buy nothing and cost a task wake.
    entries: std::sync::Mutex<std::collections::HashMap<Authority, CachedAddrs>>,
}

impl<R> CachedReach<R> {
    /// A cache over `inner`.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The cached answer for `authority`, if one is fresh enough to be used under `limit`.
    fn cached(
        &self,
        authority: &Authority,
        limit: std::time::Duration,
    ) -> Option<BTreeSet<IpAddr>> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(authority)?;
        (entry.learned.elapsed() <= limit).then(|| entry.addrs.clone())
    }
}

#[async_trait::async_trait]
impl<R: EndpointReach> EndpointReach for CachedReach<R> {
    async fn addrs(&self, authority: &Authority) -> Result<BTreeSet<IpAddr>, String> {
        if let Some(fresh) = self.cached(authority, REACH_TTL) {
            return Ok(fresh);
        }
        match self.inner.addrs(authority).await {
            Ok(addrs) => {
                if let Ok(mut entries) = self.entries.lock() {
                    entries.insert(
                        authority.clone(),
                        CachedAddrs {
                            addrs: addrs.clone(),
                            learned: std::time::Instant::now(),
                        },
                    );
                }
                Ok(addrs)
            }
            // A failed lookup falls back to the last known answer rather than dropping the voice.
            Err(why) => self.cached(authority, REACH_STALE_GRACE).ok_or(why),
        }
    }
}

/// Partition `endpoints` into groups that are each ONE voice, dropping every endpoint that could
/// not be reached.
///
/// Returned as indices into `endpoints` so a caller can try each member of a group in turn: a
/// group is a voice, and any of its endpoints may speak for it.
///
/// Two endpoints join the same group when their resolved address sets INTERSECT. The relation is
/// made transitive on purpose — if A and B share an address and B and C share another, all three
/// are one machine's worth of evidence, and treating A and C as independent because they happen
/// not to overlap directly is how a three-way "quorum" becomes one host.
pub(crate) async fn independent_voices(
    endpoints: &[ChainEndpoint],
    reach: &dyn EndpointReach,
) -> Vec<Vec<usize>> {
    // CONCURRENTLY, because this is on the content-serve request path and the lookups are
    // independent of one another: resolving N endpoints one after another makes the cost of
    // configuring another source a latency penalty on every read, which is a reason not to
    // configure one. `join_all` keeps the results in endpoint order, so the grouping below stays
    // deterministic — the merge is order-sensitive, and a set of voices that varied run to run
    // would make the refusal rule itself nondeterministic.
    let looked_up = futures::future::join_all(
        endpoints
            .iter()
            .map(|endpoint| reach.addrs(&endpoint.authority)),
    )
    .await;
    let reachable: Vec<(usize, BTreeSet<IpAddr>)> = looked_up
        .into_iter()
        .enumerate()
        .filter_map(|(ix, addrs)| addrs.ok().map(|addrs| (ix, addrs)))
        .collect();

    let mut groups: Vec<(Vec<usize>, BTreeSet<IpAddr>)> = Vec::new();
    for (ix, addrs) in reachable {
        // Merge into EVERY group this endpoint touches, not merely the first — an endpoint that
        // bridges two previously-disjoint groups makes them one voice, and stopping at the first
        // match would leave the other counted as a second.
        let mut members = vec![ix];
        let mut merged = addrs;
        groups.retain(|(existing, existing_addrs)| {
            if existing_addrs.is_disjoint(&merged) {
                return true;
            }
            members.extend(existing.iter().copied());
            merged.extend(existing_addrs.iter().copied());
            false
        });
        members.sort_unstable();
        groups.push((members, merged));
    }

    let mut voices: Vec<Vec<usize>> = groups.into_iter().map(|(members, _)| members).collect();
    voices.sort();
    voices
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// A reach table written by the test: authority -> the addresses it lands on, or absence for
    /// "does not resolve". A map rather than a single-answer double, because every property here
    /// is about how the answers for DIFFERENT authorities relate to each other, and a double that
    /// can only vary one field cannot express a disagreement between two of them.
    struct TableReach(BTreeMap<Authority, Vec<IpAddr>>);

    impl TableReach {
        fn new(rows: &[(&str, &[&str])]) -> Arc<Self> {
            let mut table = BTreeMap::new();
            for (url, addrs) in rows {
                let endpoint = ChainEndpoint::parse(url).expect("a parseable fixture url");
                table.insert(
                    endpoint.authority,
                    addrs.iter().map(|a| a.parse().expect("an ip")).collect(),
                );
            }
            Arc::new(Self(table))
        }
    }

    #[async_trait::async_trait]
    impl EndpointReach for TableReach {
        async fn addrs(&self, authority: &Authority) -> Result<BTreeSet<IpAddr>, String> {
            match self.0.get(authority) {
                Some(addrs) => Ok(addrs.iter().copied().collect()),
                // Rendered with the host and port kept APART, matching the production reach and
                // the source-level ban -- an IPv6 literal has no valid bare  form.
                None => Err(format!(
                    "host {} port {} does not resolve",
                    authority.host, authority.port
                )),
            }
        }
    }

    fn endpoints(urls: &[&str]) -> Vec<ChainEndpoint> {
        urls.iter()
            .map(|u| ChainEndpoint::parse(u).expect("a parseable fixture url"))
            .collect()
    }

    #[test]
    fn an_authority_is_the_host_and_the_port_a_client_would_dial() {
        let parsed = ChainEndpoint::parse("https://API.Coinset.ORG/v1/?x=1").expect("parses");
        assert_eq!(
            parsed.authority,
            Authority {
                host: "api.coinset.org".into(),
                port: 443
            },
            "case, path and query are not part of what the network sees; folding them is what \
             makes two spellings of one host compare equal before any lookup happens"
        );
        assert_eq!(
            parsed.url, "https://API.Coinset.ORG/v1/?x=1",
            "the URL is passed to the client UNCHANGED — an endpoint rewritten to its authority \
             would drop the path an operator deliberately configured"
        );

        assert_eq!(
            ChainEndpoint::parse("http://[::1]:8555")
                .expect("parses")
                .authority,
            Authority {
                host: "::1".into(),
                port: 8555
            },
            "a bracketed IPv6 literal keeps its colons and yields the explicit port (§5.2 makes \
             IPv6 the ordinary case here, not the exotic one)"
        );
        assert_eq!(
            ChainEndpoint::parse("http://example.org")
                .expect("parses")
                .authority
                .port,
            80,
            "an http URL with no port dials 80, so it is NOT the same authority as the https one"
        );

        for rejected in ["", "api.coinset.org", "ftp://api.coinset.org", "https://"] {
            assert!(
                ChainEndpoint::parse(rejected).is_none(),
                "{rejected:?} names no host this node could dial over http(s), and admitting it \
                 would let an unusable entry count toward a quorum"
            );
        }
    }

    /// Two endpoints that land on the same machine are ONE voice, however different they look.
    ///
    /// This is the PR#354 trap in its purest form. The fixture varies exactly one thing — the
    /// second endpoint's address — between the two halves, so a grouping rule that keys off the
    /// URL, the host name, or the source's type reports two voices in BOTH halves and this test
    /// fails on the first. A control that keys off reach reports one and two respectively.
    #[tokio::test]
    async fn two_names_for_one_machine_are_one_voice_and_two_machines_are_two() {
        let endpoints = endpoints(["https://a.example.org", "https://b.example.org"].as_slice());

        let shared = TableReach::new(&[
            ("https://a.example.org", &["203.0.113.7"]),
            ("https://b.example.org", &["203.0.113.7"]),
        ]);
        assert_eq!(
            independent_voices(&endpoints, shared.as_ref()).await,
            vec![vec![0, 1]],
            "two hostnames resolving to ONE address are one voice — a CNAME must not manufacture \
             a second, which is precisely how a 2-of-2 rule was satisfied by one endpoint"
        );

        let distinct = TableReach::new(&[
            ("https://a.example.org", &["203.0.113.7"]),
            ("https://b.example.org", &["198.51.100.9"]),
        ]);
        assert_eq!(
            independent_voices(&endpoints, distinct.as_ref()).await,
            vec![vec![0], vec![1]],
            "the SAME two names on genuinely different machines are two voices — without this \
             control an implementation that always answers one voice passes the assertion above"
        );
    }

    /// A partial overlap is still one voice, and the merge is transitive.
    ///
    /// A dual-stack host answers with several addresses (§5.2 makes IPv6 the ordinary case here),
    /// so requiring set EQUALITY would call one machine two voices whenever a resolver returned
    /// its addresses in different combinations.
    ///
    /// # The bridging endpoint is deliberately LAST, and that ordering is the whole test
    ///
    /// The property is that an endpoint joining two ALREADY-DISJOINT groups merges both. An
    /// earlier version of this fixture listed the bridge in the middle, so at every step there was
    /// only ever ONE existing group to consider and merge-into-all and merge-into-the-first agreed
    /// on every input — measured: reverting the merge to stop at the first match left this test
    /// GREEN. The fixture asserted a property the code has, on an input that could not exhibit it.
    ///
    /// With the bridge last, `a` and `c` are two separate voices by the time it arrives, and only
    /// a rule that keeps merging collapses all three.
    #[tokio::test]
    async fn an_endpoint_bridging_two_disjoint_groups_merges_all_of_them() {
        let endpoints = endpoints(
            [
                "https://a.example.org",
                "https://c.example.org",
                "https://bridge.example.org",
            ]
            .as_slice(),
        );
        let bridged = TableReach::new(&[
            ("https://a.example.org", &["203.0.113.7"]),
            ("https://c.example.org", &["2001:db8::1"]),
            (
                "https://bridge.example.org",
                &["203.0.113.7", "2001:db8::1"],
            ),
        ]);

        assert_eq!(
            independent_voices(&endpoints, bridged.as_ref()).await,
            vec![vec![0, 1, 2]],
            "a and c share no address directly and are two groups when the bridge arrives; a rule \
             that merged only into the FIRST match leaves c standing alone, so ONE machine \
             reachable under three names reports two independent voices and satisfies the quorum"
        );

        // The control: the same three endpoints with the bridge reaching a THIRD machine are
        // three voices. Without it an implementation that collapsed everything into one group
        // would satisfy the assertion above while destroying the property it is named for.
        let unbridged = TableReach::new(&[
            ("https://a.example.org", &["203.0.113.7"]),
            ("https://c.example.org", &["2001:db8::1"]),
            ("https://bridge.example.org", &["192.0.2.5"]),
        ]);
        assert_eq!(
            independent_voices(&endpoints, unbridged.as_ref()).await,
            vec![vec![0], vec![1], vec![2]],
            "three genuinely separate machines must stay three voices"
        );
    }

    /// An endpoint that resolves to nothing is dropped, not counted.
    ///
    /// The control is the point: the same fixture with the second endpoint resolvable yields two
    /// voices, so this cannot pass against an implementation that simply never counts anything.
    #[tokio::test]
    async fn an_unresolvable_endpoint_contributes_no_voice() {
        let endpoints = endpoints(["https://a.example.org", "https://typo.example.org"].as_slice());

        let one_missing = TableReach::new(&[("https://a.example.org", &["203.0.113.7"])]);
        assert_eq!(
            independent_voices(&endpoints, one_missing.as_ref()).await,
            vec![vec![0]],
            "an endpoint nothing can reach has agreed with nothing; counting it would let a typo \
             inflate the quorum to a size the network cannot actually supply"
        );

        let both_present = TableReach::new(&[
            ("https://a.example.org", &["203.0.113.7"]),
            ("https://typo.example.org", &["198.51.100.9"]),
        ]);
        assert_eq!(
            independent_voices(&endpoints, both_present.as_ref()).await,
            vec![vec![0], vec![1]],
            "with the second endpoint reachable the same input yields TWO voices — the control \
             that kills an implementation which drops every endpoint"
        );
    }

    /// A reach that counts its calls and can be switched to failing, so a cache is observable.
    ///
    /// Cloned rather than shared behind a pointer so a test can hold a handle AND hand one to the
    /// cache: the counters live behind their own `Arc`s, so every clone observes the same calls.
    #[derive(Clone)]
    struct CountingReach {
        /// How many lookups actually reached this reach.
        calls: Arc<std::sync::atomic::AtomicUsize>,
        /// Whether lookups currently succeed.
        answering: Arc<std::sync::atomic::AtomicBool>,
    }

    impl CountingReach {
        fn new() -> Self {
            Self {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                answering: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn stop_answering(&self) {
            self.answering
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl EndpointReach for CountingReach {
        async fn addrs(&self, _authority: &Authority) -> Result<BTreeSet<IpAddr>, String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.answering.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(BTreeSet::from(["203.0.113.7".parse().expect("an ip")]))
            } else {
                Err("does not resolve".into())
            }
        }
    }

    /// The lookup is paid once per TTL, not once per read, and a blip does not drop the voice.
    ///
    /// Independence is recomputed on every content read, so an uncached reach makes name
    /// resolution a per-READ `getaddrinfo` on a caller-drivable path — and a resolver failure then
    /// denies a read the HTTP client would have served. The two halves below pin both.
    #[tokio::test]
    async fn a_cached_reach_looks_up_once_per_ttl_and_survives_a_resolver_blip() {
        let inner = CountingReach::new();
        let cached = CachedReach::new(inner.clone());
        let authority = ChainEndpoint::parse("https://a.example.org")
            .expect("parses")
            .authority;

        let first = cached.addrs(&authority).await.expect("resolves");
        let second = cached.addrs(&authority).await.expect("resolves");
        assert_eq!(
            first, second,
            "the cached answer must be the answer that was learned, not an empty stand-in"
        );
        assert_eq!(
            inner.calls(),
            1,
            "the second resolution must be served from the cache. A per-read lookup is a DNS gate \
             on the content-serve path, paid twice on a read that falls back from the tip to the \
             bounded pinned-root check"
        );

        // The resolver now fails. The endpoint has not moved, and the voice count must not change
        // on that evidence.
        inner.stop_answering();
        assert_eq!(
            cached.addrs(&authority).await,
            Ok(first),
            "a lookup failure with a known-good answer in hand must serve that answer: failing \
             closed is right when the CHAIN ANSWER is in doubt, and wrong when only the NAME \
             lookup is"
        );

        // The control, and it is what stops the above passing against a reach that never fails:
        // with nothing ever learned, a failing resolver is still a failure.
        let cold = CachedReach::new(CountingReach::new());
        cold.inner.stop_answering();
        assert!(
            cold.addrs(&authority).await.is_err(),
            "an authority that has NEVER resolved has no last-known answer to fall back on, and \
             inventing one would let a typo contribute a voice"
        );
    }
}
