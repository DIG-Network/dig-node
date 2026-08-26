//! [`CorroboratedResolver`] — the anchored root, agreed across independent voices or REFUSED.
//!
//! # Why this fact in particular (dig-node#365)
//!
//! The anchored root is the fact that decides WHICH BYTES A USER IS SERVED. Every other chain
//! fact the node holds is a number on a status surface; this one selects content. A source that
//! lies about it redirects a read on every install that trusts it, and the read-path pin then
//! fails closed against the WRONG root rather than the right one — which looks, from the outside,
//! exactly like the store having moved on.
//!
//! NC-12 exists to stop one voice determining a chain fact, so this resolver asks several and
//! serves an answer only when they AGREE.
//!
//! # The rule, stated as the caller sees it
//!
//! * **Two or more independent voices** ([`super::endpoints::independent_voices`]) — every voice
//!   that answered must give the SAME answer, and at least two must have answered. One dissenter
//!   is a REFUSAL, never a repaired value: there is no majority vote and no tie-break here,
//!   because a majority rule hands the answer to whoever can field the most endpoints, and the
//!   caller's failure mode on a refusal (do not serve) is survivable while its failure mode on a
//!   wrong root is not.
//! * **Fewer than two independent voices** — the node has ONE source and says so. The answer is
//!   that source's, exactly as before this resolver existed. This is the DEFAULT INSTALL, and it
//!   is a named limitation rather than a corroboration claim: see `SPEC.md` §"Chain corroboration"
//!   and dig-node#365.
//!
//! Refusing on a default install was considered and rejected: it would stop every unconfigured
//! node serving any content at all, which trades a corroboration gap for a total outage and
//! removes the only surface on which an operator could then configure a second endpoint.

use std::sync::Arc;

use digstore_core::Bytes32;

use super::endpoints::{independent_voices, ChainEndpoint, EndpointReach};
use crate::shared::chain_view::{AnchoredRootResolver, AnchoredStoreState};

/// Builds the resolver that speaks to ONE endpoint.
///
/// Injected rather than hardcoded so the corroboration rule can be exercised against sources that
/// answer from a fixture. Without this seam the only fixture available is a live network, and the
/// dissent case — the entire point of this module — cannot be expressed at all.
pub(crate) type SourceFactory =
    Arc<dyn Fn(&ChainEndpoint) -> Arc<dyn AnchoredRootResolver> + Send + Sync>;

/// An [`AnchoredRootResolver`] that believes a chain fact only when independent voices agree.
pub(crate) struct CorroboratedResolver {
    /// Every endpoint the operator configured, in configuration order.
    endpoints: Vec<ChainEndpoint>,
    /// How an endpoint's independence is measured — its reachable addresses (§5.2 dual-stack;
    /// an IPv6 and an IPv4 address of the SAME host are one voice, which is the reason this
    /// compares address SETS rather than a single address).
    reach: Arc<dyn EndpointReach>,
    /// How a per-endpoint resolver is built.
    source: SourceFactory,
}

impl CorroboratedResolver {
    /// A resolver over `endpoints`, measuring independence with `reach` and building each voice
    /// with `source`.
    pub fn new(
        endpoints: Vec<ChainEndpoint>,
        reach: Arc<dyn EndpointReach>,
        source: SourceFactory,
    ) -> Self {
        Self {
            endpoints,
            reach,
            source,
        }
    }

    /// The independent voices available right now, as resolvers.
    ///
    /// Recomputed per resolution rather than cached: an endpoint's addresses change, and a voice
    /// count fixed at start-up would keep claiming corroboration long after two endpoints had
    /// converged on one host — a stale independence verdict is worse than none, because it is the
    /// verdict the refusal rule trusts.
    async fn voices(&self) -> Vec<Arc<dyn AnchoredRootResolver>> {
        independent_voices(&self.endpoints, self.reach.as_ref())
            .await
            .iter()
            .filter_map(|group| group.first())
            .map(|&ix| (self.source)(&self.endpoints[ix]))
            .collect()
    }

    /// Ask every voice, then apply the agreement rule to whatever came back.
    ///
    /// `ask` returns `Err` for a voice that could not be reached; such a voice is DROPPED rather
    /// than treated as dissent, because "I could not ask" and "I was told something else" demand
    /// opposite remedies and conflating them makes a network blip indistinguishable from an
    /// attack. Dropping is still fail-closed: the agreement rule then has fewer answers, and too
    /// few answers is a refusal.
    async fn agreed<T, F, Fut>(&self, what: &str, ask: F) -> Result<T, String>
    where
        T: PartialEq + Clone,
        F: Fn(Arc<dyn AnchoredRootResolver>) -> Fut,
        Fut: std::future::Future<Output = Result<T, String>>,
    {
        let voices = self.voices().await;
        let Some((first, rest)) = voices.split_first() else {
            return Err(format!(
                "{what}: no configured chain endpoint could be reached (chain is the authority)"
            ));
        };

        // ONE voice is the default install: answer as the single source, and do not dress that up
        // as agreement. `SPEC.md` records the limitation this leaves.
        if rest.is_empty() {
            return ask(first.clone()).await;
        }

        let mut answers: Vec<T> = Vec::new();
        let mut refusals: Vec<String> = Vec::new();
        for voice in &voices {
            match ask(voice.clone()).await {
                Ok(answer) => answers.push(answer),
                Err(e) => refusals.push(e),
            }
        }

        let Some(candidate) = answers.first().cloned() else {
            return Err(format!(
                "{what}: no independent chain source answered ({}) — refusing rather than \
                 guessing (chain is the authority)",
                refusals.join("; ")
            ));
        };
        if answers.len() < 2 {
            return Err(format!(
                "{what}: only ONE independent chain source answered, so nothing corroborates it \
                 ({}) — refusing (chain is the authority)",
                refusals.join("; ")
            ));
        }
        if answers.iter().any(|answer| *answer != candidate) {
            return Err(format!(
                "{what}: independent chain sources DISAGREE — refusing rather than picking one \
                 (chain is the authority)"
            ));
        }
        Ok(candidate)
    }
}

#[async_trait::async_trait]
impl AnchoredRootResolver for CorroboratedResolver {
    async fn anchored_root(&self, store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
        Ok(self.anchored_state(store_id).await?.map(|s| s.root))
    }

    /// The store's tip state, agreed or refused.
    ///
    /// `Option` is part of what must agree: one voice saying "not minted" while another names a
    /// root is a disagreement about whether the store exists, and serving the root would let a
    /// single source conjure a store into being.
    async fn anchored_state(
        &self,
        store_id: &[u8; 32],
    ) -> Result<Option<AnchoredStoreState>, String> {
        let store_id = *store_id;
        self.agreed("anchored state", move |voice| async move {
            voice.anchored_state(&store_id).await
        })
        .await
    }

    /// A pinned root is confirmed only when the voices agree it is current.
    ///
    /// The unit answer carries no value to compare, so agreement here is agreement that the check
    /// PASSED: a voice returning `Err` is a refusal that has already been dropped from the answer
    /// set by [`CorroboratedResolver::agreed`], and fewer than two `Ok`s is too little evidence to
    /// serve on.
    async fn verify_pinned_root(
        &self,
        store_id: &[u8; 32],
        pinned_root: Bytes32,
    ) -> Result<(), String> {
        let store_id = *store_id;
        self.agreed("pinned-root verification", move |voice| async move {
            voice.verify_pinned_root(&store_id, pinned_root).await
        })
        .await
    }

    /// Lineage membership, on the same terms as [`Self::verify_pinned_root`].
    async fn verify_lineage_root(&self, store_id: &[u8; 32], root: Bytes32) -> Result<(), String> {
        let store_id = *store_id;
        self.agreed("lineage-root verification", move |voice| async move {
            voice.verify_lineage_root(&store_id, root).await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::chia_peer::endpoints::Authority;
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::IpAddr;

    const STORE: [u8; 32] = [9u8; 32];

    /// What one endpoint says about the store, keyed by URL.
    #[derive(Clone)]
    enum Voice {
        Root(u8),
        NotMinted,
        Unreachable,
    }

    /// A resolver standing in for ONE endpoint.
    struct Scripted(Voice);

    #[async_trait::async_trait]
    impl AnchoredRootResolver for Scripted {
        async fn anchored_root(&self, _store_id: &[u8; 32]) -> Result<Option<Bytes32>, String> {
            match self.0 {
                Voice::Root(byte) => Ok(Some(Bytes32([byte; 32]))),
                Voice::NotMinted => Ok(None),
                Voice::Unreachable => Err("chain unreachable".into()),
            }
        }
    }

    /// Reach answers built from an explicit address per URL, so a fixture can make two endpoints
    /// one voice or two INDEPENDENTLY of what each of them says about the store. Keeping the two
    /// dimensions separate is what lets the dissent tests hold independence fixed while varying
    /// exactly one voice.
    struct ScriptedReach(BTreeMap<Authority, IpAddr>);

    #[async_trait::async_trait]
    impl EndpointReach for ScriptedReach {
        async fn addrs(&self, authority: &Authority) -> Result<BTreeSet<IpAddr>, String> {
            self.0
                .get(authority)
                .map(|ip| BTreeSet::from([*ip]))
                .ok_or_else(|| "does not resolve".to_string())
        }
    }

    /// Build a resolver from `(url, address, what it says)` rows.
    fn resolver(rows: &[(&str, &str, Voice)]) -> CorroboratedResolver {
        let endpoints: Vec<ChainEndpoint> = rows
            .iter()
            .map(|(url, ..)| ChainEndpoint::parse(url).expect("a parseable fixture url"))
            .collect();
        let reach = ScriptedReach(
            rows.iter()
                .zip(&endpoints)
                .map(|((_, addr, _), endpoint)| {
                    (endpoint.authority.clone(), addr.parse().expect("an ip"))
                })
                .collect(),
        );
        let script: BTreeMap<String, Voice> = rows
            .iter()
            .map(|(url, _, voice)| ((*url).to_string(), voice.clone()))
            .collect();
        CorroboratedResolver::new(
            endpoints,
            Arc::new(reach),
            Arc::new(move |endpoint: &ChainEndpoint| {
                Arc::new(Scripted(
                    script.get(&endpoint.url).cloned().expect("a scripted url"),
                )) as Arc<dyn AnchoredRootResolver>
            }),
        )
    }

    /// Independent voices that agree are believed; ONE dissenter is a refusal, not a repair.
    ///
    /// The fixture varies exactly ONE actor between the two halves and keeps two honest voices in
    /// both, which is what makes each half load-bearing. An all-hostile fixture would be blind
    /// here: with no honest majority left it cannot distinguish "refused because they disagreed"
    /// from "refused because nothing answered", and a majority-vote implementation — the nearest
    /// wrong one — passes it.
    ///
    /// Measured against the compiled resolver: replacing the unanimity check with a MAJORITY vote
    /// (two of three say `0xAA`, so serve `0xAA`) fails this test, and fails
    /// [`one_source_reporting_not_minted_against_a_named_root_is_a_disagreement`] and
    /// [`two_endpoints_on_one_machine_do_not_corroborate_each_other`] with it. That is the revert
    /// this test is named for.
    #[tokio::test]
    async fn a_single_dissenting_source_refuses_rather_than_repairing_the_root() {
        let agreeing = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "198.51.100.2", Voice::Root(0xAA)),
            ("https://c.example.org", "192.0.2.3", Voice::Root(0xAA)),
        ]);
        assert_eq!(
            agreeing.anchored_root(&STORE).await,
            Ok(Some(Bytes32([0xAA; 32]))),
            "three independent voices agreeing must YIELD the root — the control that kills an \
             implementation which refuses unconditionally, which would satisfy every assertion \
             below without corroborating anything"
        );

        let dissenting = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "198.51.100.2", Voice::Root(0xAA)),
            ("https://c.example.org", "192.0.2.3", Voice::Root(0xBB)),
        ]);
        let refusal = dissenting
            .anchored_root(&STORE)
            .await
            .expect_err("one dissenter among three must refuse");
        assert!(
            refusal.contains("DISAGREE"),
            "the refusal must be the AGREEMENT rule. A majority vote — two of three say 0xAA — \
             would serve 0xAA here, which is a repaired value and hands the answer to whoever \
             fields the most endpoints: {refusal}"
        );
    }

    /// Disagreement about whether the store EXISTS is disagreement.
    ///
    /// `Ok(None)` is a legitimate answer, so an implementation comparing only the roots it was
    /// given would drop the `None` and report a unanimous root — letting one source conjure a
    /// store into being for a node whose other sources have never seen it.
    #[tokio::test]
    async fn one_source_reporting_not_minted_against_a_named_root_is_a_disagreement() {
        let split = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "198.51.100.2", Voice::Root(0xAA)),
            ("https://c.example.org", "192.0.2.3", Voice::NotMinted),
        ]);
        let refusal = split
            .anchored_state(&STORE)
            .await
            .expect_err("a not-minted answer beside a named root is dissent");
        assert!(
            refusal.contains("DISAGREE"),
            "absence and presence must compare as different answers: {refusal}"
        );

        let unanimous_absence = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::NotMinted),
            ("https://b.example.org", "198.51.100.2", Voice::NotMinted),
        ]);
        assert_eq!(
            unanimous_absence.anchored_state(&STORE).await,
            Ok(None),
            "unanimous absence is a corroborated answer, not a failure — without this control the \
             assertion above passes against an implementation that refuses on any `None` at all"
        );
    }

    /// Two endpoints on ONE machine are one voice, so their agreement corroborates nothing.
    ///
    /// This is the PR#354 trap at the layer that acts on it: both endpoints say the same thing, so
    /// an implementation counting CONFIGURED sources — or counting sources by type — sees a 2-of-2
    /// agreement and serves the root. The control below moves ONE endpoint to a second machine
    /// and nothing else, so the fixture cannot pass by refusing everything.
    ///
    /// Which revert this catches, measured rather than assumed: it fires on the MAJORITY-vote
    /// revert (a and b are one voice, so the second half is 1-against-1 and a majority rule serves
    /// `0xAA`). It does NOT fire on a name-based independence revert — under that rule a, b and c
    /// are three voices, two agree and one dissents, and unanimity refuses anyway. The name-based
    /// revert is caught in [`super::super::endpoints`] by
    /// `two_names_for_one_machine_are_one_voice_and_two_machines_are_two`, which is where the
    /// grouping rule lives. Recorded because a test whose comment claims a revert it does not
    /// catch is how the revert that IS uncaught goes unnoticed.
    #[tokio::test]
    async fn two_endpoints_on_one_machine_do_not_corroborate_each_other() {
        let one_machine = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "203.0.113.1", Voice::Root(0xAA)),
        ]);
        assert_eq!(
            one_machine.anchored_root(&STORE).await,
            Ok(Some(Bytes32([0xAA; 32]))),
            "one voice answers as a single source — the documented default-install path. What it \
             must NOT do is claim corroboration, which the dissent case below measures"
        );

        // The same two endpoints, still agreeing, but now genuinely two machines — and a third
        // that dissents. Under a rule that counts CONFIGURED endpoints the two-machine and
        // one-machine cases are indistinguishable, so this pair is what separates them.
        let one_machine_plus_dissenter = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://c.example.org", "192.0.2.3", Voice::Root(0xBB)),
        ]);
        let refusal = one_machine_plus_dissenter
            .anchored_root(&STORE)
            .await
            .expect_err("two voices that disagree must refuse");
        assert!(
            refusal.contains("DISAGREE"),
            "a and b are ONE voice, so this is 1-against-1 and not 2-against-1; an implementation \
             counting endpoints sees a majority for 0xAA and serves it: {refusal}"
        );
    }

    /// A source that could not be reached is dropped, and too few answers is a refusal.
    ///
    /// The two halves separate "was not asked" from "was asked and refused": with only one voice
    /// left answering there is nothing to corroborate against, and answering anyway would make an
    /// outage at one endpoint silently restore single-source resolution.
    #[tokio::test]
    async fn an_unreachable_source_leaves_too_little_evidence_to_serve_on() {
        let one_down = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "198.51.100.2", Voice::Unreachable),
        ]);
        let refusal = one_down
            .anchored_root(&STORE)
            .await
            .expect_err("one answer out of two independent voices corroborates nothing");
        assert!(
            refusal.contains("only ONE independent chain source answered"),
            "the refusal must say the evidence was too THIN, not that the sources disagreed — a \
             transient outage and an attack demand opposite remedies: {refusal}"
        );

        let both_up = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "198.51.100.2", Voice::Root(0xAA)),
        ]);
        assert_eq!(
            both_up.anchored_root(&STORE).await,
            Ok(Some(Bytes32([0xAA; 32]))),
            "the same two endpoints both answering DO corroborate — the control proving the \
             refusal above came from the thin-evidence rule and not from a resolver that never \
             answers"
        );
    }

    /// The pinned-root and lineage checks take the same rule, and a lone `Ok` is not enough.
    ///
    /// These two are the calls the read-path pin makes, so a corroboration rule applied to
    /// `anchored_state` alone would leave the actual serve decision single-sourced while the SPEC
    /// claimed otherwise.
    #[tokio::test]
    async fn the_verification_calls_need_two_agreeing_voices_too() {
        let root = Bytes32([0xAA; 32]);
        let one_down = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "198.51.100.2", Voice::Unreachable),
        ]);
        for outcome in [
            one_down.verify_pinned_root(&STORE, root).await,
            one_down.verify_lineage_root(&STORE, root).await,
        ] {
            let refusal = outcome.expect_err("one voice cannot corroborate a serve decision");
            assert!(
                refusal.contains("only ONE independent chain source answered"),
                "both verification calls must refuse on thin evidence, or the read-path pin stays \
                 single-sourced while the resolver reports corroboration: {refusal}"
            );
        }

        let both_up = resolver(&[
            ("https://a.example.org", "203.0.113.1", Voice::Root(0xAA)),
            ("https://b.example.org", "198.51.100.2", Voice::Root(0xAA)),
        ]);
        assert_eq!(
            both_up.verify_pinned_root(&STORE, root).await,
            Ok(()),
            "two agreeing voices confirm the pin — the control that kills an always-refuse \
             implementation of the verification path"
        );
        assert_eq!(
            both_up.verify_lineage_root(&STORE, root).await,
            Ok(()),
            "and the same for lineage membership"
        );
    }
}
