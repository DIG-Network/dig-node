//! The production [`MirrorCoinPointers`] source (dig-node#435, epic #422): what this node CLAIMS
//! bonds each capsule it announces.
//!
//! # The gap this closes
//!
//! `dig-node-core` built the whole pointer mechanism — the trait, the attach on
//! `announce_provider_with_collateral`, the `with_mirror_pointers` constructor, and the epoch
//! rollover re-announce — and the only implementation anywhere was a test double under
//! `#[cfg(test)]`. Production called `DhtHandle::new`, which hard-codes `None`, so **every live
//! announce published `unverified_mirror_coin_id = None`** and the rollover re-announce returned `0`
//! on its first line every tick. The mechanism was complete and fed by nothing.
//!
//! # The claim is UNTRUSTED, and this type cannot make it trusted
//!
//! Publishing a coin id tells a verifier WHERE TO LOOK — one coin to fetch instead of searching
//! for it — and never WHAT THE COIN IS. A verifier
//! accepts a coin on the coin's OWN evidence, and nothing published here enters that judgement
//! (NC-12). So the worst a wrong pointer can do is cost a lookup, and that is the property that
//! makes reading it from a cached observation acceptable at all.
//!
//! # It reads the published observation, not the chain
//!
//! The answer comes from [`BondSnapshot`] — the observation the last mirror pass published, the
//! SAME one `control.mirror.bondStates` serves — rather than from a `dig_mirror_coin::list` of its
//! own. Two reasons, and the second is the load-bearing one:
//!
//! 1. An announce is on the DHT's timer, and `list` is a scan of a puzzle hash anyone may add to.
//!    Performing it per announce would make discovery cost a chain scan per content id.
//! 2. A second read is a second ANSWER. A pointer derived independently could name a different coin
//!    from the one §25.8's surface reports for the same bond, and an operator comparing the two
//!    would be looking at a disagreement this node manufactured.
//!
//! The snapshot already carries exactly what is needed: `BondState::Bonded` holds the coin id, and
//! it is produced only from a coin the chain observation actually resolved.
//!
//! # Only a CURRENT-epoch `Bonded` row yields a pointer
//!
//! A mirror coin bonds `(store, root, owner, epoch)`, and **dig-dht has no clock** — `republish`
//! re-attaches whatever pointer was recorded at announce time. A row bonded under a previous epoch
//! therefore names a coin that no longer advertises anything, and publishing it would make a
//! correctly-collateralised node read as uncollateralised. Every other state — `Pending`,
//! `Reclaiming`, `Unfunded`, `Withheld`, … — has no coin that is bonding this capsule right now, and
//! answering `None` for them is the honest and fully supported case.

use std::sync::atomic::{AtomicU64, Ordering};

use dig_node_core::dht::MirrorCoinPointers;
use dig_node_core::dig_dht;

use super::lifecycle::BondSnapshot;
use super::pass::BondState;

/// The epoch reported before any pass has published an observation.
///
/// `u64::MAX` rather than `0`, because `0` is a real epoch number and colliding with it would make
/// the rollover comparison miss a genuine rollover exactly once. A sentinel no real epoch can take
/// makes the first pointer-bearing observation always look like a change, which is what it is.
const EPOCH_UNKNOWN: u64 = u64::MAX;

/// This node's mirror-coin pointers, read from the last published bond observation.
#[derive(Debug)]
pub struct SnapshotMirrorPointers {
    snapshot: BondSnapshot,
    /// The last epoch successfully READ, so a momentarily unreadable snapshot reports the epoch it
    /// last knew rather than an "unknown" that would trigger a pointless full re-announce.
    last_known_epoch: AtomicU64,
}

impl SnapshotMirrorPointers {
    /// Read pointers from the observation `snapshot` publishes.
    pub fn new(snapshot: BondSnapshot) -> Self {
        Self {
            snapshot,
            last_known_epoch: AtomicU64::new(EPOCH_UNKNOWN),
        }
    }
}

impl MirrorCoinPointers for SnapshotMirrorPointers {
    fn epoch(&self) -> u64 {
        let read = self
            .snapshot
            .read()
            .ok()
            .and_then(|slot| slot.as_ref().map(|o| o.epoch))
            // A negative epoch is not an epoch. Reported as unknown rather than coerced, because
            // coercing it to `0` would silently claim the first epoch.
            .and_then(|epoch| u64::try_from(epoch).ok());

        match read {
            Some(epoch) => {
                self.last_known_epoch.store(epoch, Ordering::Relaxed);
                epoch
            }
            None => self.last_known_epoch.load(Ordering::Relaxed),
        }
    }

    fn coin_id_for(&self, content: &dig_dht::ContentId) -> Option<[u8; 32]> {
        let slot = self.snapshot.read().ok()?;
        let observation = slot.as_ref()?;

        observation.states.iter().find_map(|(bond, state)| {
            let BondState::Bonded { coin_id, epoch, .. } = state else {
                return None; // no coin is bonding this capsule right now
            };
            if *epoch != observation.epoch {
                return None; // a previous epoch's coin advertises nothing today
            }
            let (Some(store), Some(root)) = (hex32(&bond.store_id), hex32(&bond.root)) else {
                return None;
            };
            if dig_dht::ContentId::capsule(store, root) != *content {
                return None;
            }
            hex32(coin_id)
        })
    }
}

/// Decode a canonical lowercase 64-hex id into 32 bytes.
///
/// A malformed id yields `None` — no pointer — never a panic and never a truncated guess. The ids in
/// an observation are canonicalised by the mirror pass, so this failing at all would mean a producer
/// changed; answering `None` publishes a pointer-less record, which is the same fully supported
/// state a node with no coins is in — a verifier withholds credit for it rather than demoting the
/// holder.
fn hex32(id: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(id).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mirror::lifecycle::new_snapshot;
    use crate::mirror::plan::Bond;
    use crate::mirror::states::BondObservation;

    fn id(tag: &str) -> String {
        let mut s = tag.to_string();
        while s.len() < 64 {
            s.push('0');
        }
        s.truncate(64);
        s
    }

    fn bytes(tag: &str) -> [u8; 32] {
        hex32(&id(tag)).expect("a 64-hex fixture id")
    }

    fn publish(states: Vec<(Bond, BondState)>, epoch: i64) -> BondSnapshot {
        let snapshot = new_snapshot();
        *snapshot.write().expect("snapshot") = Some(BondObservation {
            states,
            locked_dig_base_units: 0,
            epoch,
        });
        snapshot
    }

    fn bonded(coin: &str, epoch: i64) -> BondState {
        BondState::Bonded {
            coin_id: id(coin),
            epoch,
            amount_dig_base_units: 1_010,
        }
    }

    /// **Proves:** an announce for a capsule this node has bonded in the CURRENT epoch carries that
    /// coin's id, and an announce for a capsule it has not carries none.
    ///
    /// **Catches:** the defect the whole ticket is about — a production source that answers `None`
    /// for everything, which is indistinguishable from the shipped `DhtHandle::new` behaviour and
    /// which a fixture with no bonded row could not tell apart.
    ///
    /// The fixture deliberately holds THREE rows: the bonded one, a `Pending` one for a different
    /// capsule, and a bonded row for a different capsule. Without the third, "return the only coin
    /// you have, whatever was asked" — the nearest wrong implementation — passes; with it, a
    /// pointer source that ignores the requested `ContentId` returns the wrong coin.
    #[test]
    fn a_current_epoch_bonded_capsule_publishes_its_coin_and_only_its_coin() {
        let snapshot = publish(
            vec![
                (Bond::new(id("aa"), id("11")), bonded("c1", 7)),
                (Bond::new(id("bb"), id("22")), bonded("c2", 7)),
                (Bond::new(id("cc"), id("33")), BondState::Pending),
            ],
            7,
        );
        let pointers = SnapshotMirrorPointers::new(snapshot);

        assert_eq!(
            pointers.coin_id_for(&dig_dht::ContentId::capsule(bytes("aa"), bytes("11"))),
            Some(bytes("c1")),
            "the pointer must name the coin bonding the capsule that was ASKED about"
        );
        assert_eq!(
            pointers.coin_id_for(&dig_dht::ContentId::capsule(bytes("bb"), bytes("22"))),
            Some(bytes("c2")),
            "a second bonded capsule gets its own coin, not the first one's"
        );
        assert_eq!(
            pointers.coin_id_for(&dig_dht::ContentId::capsule(bytes("cc"), bytes("33"))),
            None,
            "a create that has not confirmed bonds nothing yet, and claiming a coin for it would \
             send a verifier to fetch a coin that does not exist"
        );
    }

    /// **Proves:** a coin bonded under a PREVIOUS epoch publishes no pointer.
    ///
    /// **Catches:** the failure `reannounce_on_epoch_rollover` was written for, arriving through the
    /// other door. dig-dht has no clock, so a stale pointer is re-attached by `republish` forever;
    /// a verifier then fetches a coin that no longer advertises the current epoch and reads a
    /// correctly-collateralised node as uncollateralised. A source that returned the coin id
    /// whenever a row is `Bonded` looks perfectly correct on the day it ships and is wrong from the
    /// next rollover onwards, which is precisely why it is asserted rather than left to the
    /// re-announce.
    ///
    /// The same capsule is asserted twice — once against the epoch it was bonded in and once
    /// against the epoch that followed — so this cannot pass against a source that answers `None`
    /// for everything.
    #[test]
    fn a_coin_from_a_previous_epoch_publishes_no_pointer() {
        let capsule = dig_dht::ContentId::capsule(bytes("aa"), bytes("11"));
        let row = vec![(Bond::new(id("aa"), id("11")), bonded("c1", 7))];

        let current = SnapshotMirrorPointers::new(publish(row.clone(), 7));
        assert_eq!(
            current.coin_id_for(&capsule),
            Some(bytes("c1")),
            "the control: in its own epoch this coin is exactly the right pointer"
        );

        let rolled = SnapshotMirrorPointers::new(publish(row, 8));
        assert_eq!(
            rolled.coin_id_for(&capsule),
            None,
            "one epoch later the same coin advertises nothing, and pointing at it is worse than \
             pointing at nothing"
        );
        assert_eq!(
            rolled.epoch(),
            8,
            "the epoch reported is the observation's, so the rollover re-announce can see it change"
        );
    }

    /// **Proves:** before any pass has published, the source answers no pointers and an epoch no
    /// real epoch can equal.
    ///
    /// **Catches:** seeding the epoch to `0`. `0` is a real epoch number, so a node whose first
    /// observation lands in epoch 0 would compare equal to its pre-observation state and SKIP the
    /// re-announce that first attaches its pointers — the mechanism silently never starting, which
    /// is the same class of defect as it never being fed at all.
    #[test]
    fn before_the_first_pass_there_are_no_pointers_and_the_epoch_cannot_collide_with_a_real_one() {
        let pointers = SnapshotMirrorPointers::new(new_snapshot());

        assert_eq!(
            pointers.coin_id_for(&dig_dht::ContentId::capsule(bytes("aa"), bytes("11"))),
            None,
            "an unobserved node claims nothing; announcing without a pointer is ordinary"
        );
        assert_eq!(
            pointers.epoch(),
            EPOCH_UNKNOWN,
            "the pre-observation epoch must differ from every epoch a pass can publish"
        );
        assert_ne!(
            EPOCH_UNKNOWN, 0,
            "epoch 0 is a real epoch, so it cannot double as the sentinel"
        );
    }

    /// **Proves:** a store-level content id gets no pointer.
    ///
    /// **Catches:** matching on the store id alone. A mirror coin bonds one `(store, root, epoch)`
    /// tuple, so a pointer attached to the whole-store announce would claim that one root's coin
    /// collateralises every generation of that store — a claim this node does not hold and cannot
    /// support, on the announce a fetcher of ANY generation would read.
    #[test]
    fn the_whole_store_announce_carries_no_coin_because_no_coin_bonds_a_whole_store() {
        let pointers = SnapshotMirrorPointers::new(publish(
            vec![(Bond::new(id("aa"), id("11")), bonded("c1", 7))],
            7,
        ));

        assert_eq!(
            pointers.coin_id_for(&dig_dht::ContentId::capsule(bytes("aa"), bytes("11"))),
            Some(bytes("c1")),
            "the control: the capsule announce does carry the coin"
        );
        assert_eq!(
            pointers.coin_id_for(&dig_dht::ContentId::store(bytes("aa"))),
            None,
            "a coin bonds one generation, never the store"
        );
    }
}
