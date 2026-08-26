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
//! An endpoint that cannot be resolved contributes NO voice. That is the fail-closed direction:
//! an unreachable source has not agreed with anything, and counting it would let a typo inflate a
//! quorum.

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
        let addrs: BTreeSet<IpAddr> = tokio::net::lookup_host((host.as_str(), *port))
            .await
            .map_err(|e| format!("host {host} port {port} does not resolve: {e}"))?
            .map(|socket| socket.ip())
            .collect();
        if addrs.is_empty() {
            return Err(format!("host {host} port {port} resolves to no address"));
        }
        Ok(addrs)
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
    let mut reachable: Vec<(usize, BTreeSet<IpAddr>)> = Vec::new();
    for (ix, endpoint) in endpoints.iter().enumerate() {
        if let Ok(addrs) = reach.addrs(&endpoint.authority).await {
            reachable.push((ix, addrs));
        }
    }

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
}
