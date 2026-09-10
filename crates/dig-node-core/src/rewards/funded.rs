//! The funder-ownership registry: WHICH reward distributors this node funds (dig_ecosystem#3285).
//!
//! [`port`](super::port)'s module doc names this as blocker 2 of two:
//! `RewardsChainPort::funded_distributors` needs an identity set to start from, because there is no
//! chain-wide "list every distributor and filter to mine" call. This module is that identity set,
//! and nothing else.
//!
//! # Identity only — never an amount
//!
//! A record here is a launcher id plus, when the funding act knew it, the store id it rewards. It
//! carries no reserve balance, no accrued figure and no paid-out total, and there is deliberately
//! nowhere in [`FundedDistributor`] to put one, for two independent reasons:
//!
//! 1. Every money figure in this subsystem is chain-derived (see
//!    [`port::DistributorChainState`](super::port::DistributorChainState), which is read, never
//!    stored) and goes stale the moment the chain moves. A persisted amount is a wrong number with
//!    a convincing timestamp.
//! 2. dig_ecosystem#3286: upstream `chia-sdk-driver`'s `withdraw_incentives` multiplies
//!    `rewards * withdrawal_share_bps` in `u64` and wraps in release builds, so a figure crossing
//!    this boundary can already be wrong. Durable storage would make such a figure permanent.
//!
//! The store id is identity; the merkle ROOT that
//! [`port::DistributorRef`](super::port::DistributorRef) also carries is not — it names one
//! generation of a store and is superseded on every update, so persisting it would be persisting a
//! value guaranteed to go stale. A caller that needs the current root reads it from the chain.
//!
//! # Persistence mirrors the claim engine, and holds no state between calls
//!
//! An optional directory, exactly like `rewards_claim::engine::ClaimEngine`'s
//! `fee_window_state_dir`: `None` keeps this registry inert, so tests and every default build need
//! no disk. The set itself is NEVER cached on [`FundedDistributorRegistry`] — every read re-reads
//! the file and every write is a read-modify-write of it, the discipline that engine's F16/F18
//! notes arrived at after one mechanism (a per-call value held as process-lifetime state) produced
//! three separate defects. With no field to go stale, an operator who repairs the file underneath
//! a running node is observed on the very next read rather than only on the next restart.
//!
//! # A corrupt, missing or unreadable record MUST NOT read as "funds nothing"
//!
//! `dig-rewards-coin`'s SPEC §2.4 clause 1 ("absence is not silence") applies here in the place it
//! costs most: `dig.listRewardDistributors` is how an operator sees which distributors it funds, so
//! rendering a failed read as `[]` would make a funded distributor invisible and tell the operator
//! it funds none. [`FundedDistributorsRead`] therefore names the legitimate empty case
//! ([`FundedDistributorsRead::FundsNothing`]) separately from every not-an-answer case, the same
//! way `rewards_claim::types::ClaimOutcome` names its legitimate not-paid cases separately from
//! `Faulted`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::port::Bytes32;

/// The record file, inside the registry's state directory.
pub const FUNDED_DISTRIBUTORS_FILE: &str = "funded-distributors.json";

/// Where a corrupt record is COPIED for the operator, next to the record itself. A copy, not a
/// move: see [`FundedDistributorRegistry::read`] for why moving it aside would recreate the exact
/// "a funded distributor became invisible" failure this module exists to prevent.
pub const FUNDED_DISTRIBUTORS_QUARANTINE_FILE: &str = "funded-distributors.json.corrupt";

/// On-disk format version. A record written by a different version is CORRUPT to this one —
/// unreadable is unreadable, and guessing at a format we do not know is how a wrong answer gets
/// rendered confidently.
const RECORD_FORMAT_VERSION: u32 = 1;

/// One distributor this node funds — identity only. See the module doc for why there is nowhere
/// here to record an amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundedDistributor {
    /// The distributor singleton's launcher id: the one identifier that never changes.
    pub launcher_id: Bytes32,
    /// The store this distributor rewards, when the funding act knew it. `None` means "not
    /// recorded", never "no store".
    pub store_id: Option<Bytes32>,
}

/// Why a read could not answer with a set. Never a stand-in for "the set is empty".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotConfiguredReason {
    /// The registry has no state directory, so persistence is off and this node has no record to
    /// consult. The ordinary state of a default build and of every test that wants no disk.
    NoStateDirectory,
    /// A state directory is configured but does not exist on disk. The answer lives somewhere this
    /// node cannot see, which is unknown, not empty.
    StateDirectoryMissing,
    /// The state directory exists and holds no record file: nothing has ever been recorded through
    /// this registry. Distinct from [`FundedDistributorsRead::FundsNothing`], which is a record
    /// that exists and says "none".
    NoRecordWritten,
}

/// The closed outcome of reading the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundedDistributorsRead {
    /// A record exists and names these distributors, in recorded order. Never empty — an empty
    /// record is [`Self::FundsNothing`].
    Funded(Vec<FundedDistributor>),
    /// A record exists, is intact, and names no distributor: this node has funded none. The one
    /// outcome a caller may render as an empty list.
    FundsNothing,
    /// No record could be consulted. The answer is UNKNOWN.
    NotConfigured(NotConfiguredReason),
    /// The record exists and could not be trusted — unparseable, malformed, or written by a format
    /// version this build does not know. `quarantined_to` is where its bytes were copied for the
    /// operator, or `None` if even the copy failed (which changes nothing about the verdict).
    PersistedStateCorrupt {
        path: PathBuf,
        quarantined_to: Option<PathBuf>,
    },
    /// The record could not be read at all.
    IoFailed { path: PathBuf, error: String },
}

impl FundedDistributorsRead {
    /// The funded set when — and only when — this read actually determined one: `Some(&[])` for
    /// [`Self::FundsNothing`], `None` for every outcome that did not answer.
    ///
    /// A caller that renders a list MUST distinguish `None` from `Some(&[])`: `None` is "unknown",
    /// and rendering it as an empty list is the failure this module's doc opens with.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn determined(&self) -> Option<&[FundedDistributor]> {
        match self {
            Self::Funded(set) => Some(set),
            Self::FundsNothing => Some(&[]),
            Self::NotConfigured(_) | Self::PersistedStateCorrupt { .. } | Self::IoFailed { .. } => {
                None
            }
        }
    }
}

/// The closed outcome of recording a funding act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    /// A launcher id this record had not seen was appended.
    Recorded,
    /// This launcher id was already recorded with the same identity; the file is unchanged.
    AlreadyRecorded,
    /// This launcher id was already recorded and its `store_id` was learned (`None` -> `Some`).
    /// Refining identity is allowed; contradicting it is [`Self::IdentityConflict`].
    IdentityRefined,
    /// The record already names this launcher id with a DIFFERENT store id. One of the two is wrong
    /// and this registry cannot tell which, so it overwrites neither.
    IdentityConflict { recorded: Bytes32, offered: Bytes32 },
    /// Persistence is off: nothing was recorded and nothing will be readable later.
    NotConfigured(NotConfiguredReason),
    /// The record on disk is corrupt, so it was NOT overwritten — the same refusal
    /// `rewards_claim::engine::ClaimEngine::persist_fee_window` makes, for the same reason: writing
    /// over corruption produces a file that looks clean and has silently lost whatever it held.
    PersistedStateCorrupt {
        path: PathBuf,
        quarantined_to: Option<PathBuf>,
    },
    /// The record could not be read or written.
    IoFailed { path: PathBuf, error: String },
}

/// The durable record of which distributors this node funds.
///
/// Holds a path and nothing else — see the module doc's "holds no state between calls".
#[derive(Debug, Clone)]
pub struct FundedDistributorRegistry {
    /// `None` = persistence off; every read answers [`NotConfiguredReason::NoStateDirectory`] and
    /// every write records nothing.
    state_dir: Option<PathBuf>,
}

impl FundedDistributorRegistry {
    /// A registry with persistence off. The default for any build with no state directory to give
    /// it, including the FFI/browser path.
    #[must_use]
    pub fn disabled() -> Self {
        Self { state_dir: None }
    }

    /// A registry persisting to `dir`. The directory is created on first write, not here, so
    /// constructing one is infallible and side-effect free.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn with_state_dir(dir: &Path) -> Self {
        Self {
            state_dir: Some(dir.to_path_buf()),
        }
    }

    /// The record file path, when persistence is on.
    fn record_path(&self) -> Option<PathBuf> {
        self.state_dir
            .as_ref()
            .map(|dir| dir.join(FUNDED_DISTRIBUTORS_FILE))
    }

    /// Read the funded set fresh from disk.
    ///
    /// # A corrupt record is quarantined by COPY, and stays where it is
    /// Moving the corrupt file aside would leave the next read finding no file at all — i.e.
    /// reporting [`NotConfiguredReason::NoRecordWritten`] and, one honest-looking render later, an
    /// empty list. So the bytes are copied to [`FUNDED_DISTRIBUTORS_QUARANTINE_FILE`] for the
    /// operator and the original is left in place, which keeps every subsequent read reporting
    /// [`FundedDistributorsRead::PersistedStateCorrupt`] until a human resolves it. That is the
    /// same "leave the corrupt file exactly as it is on disk" posture
    /// `rewards_claim::engine::ClaimEngine::persist_fee_window` takes, plus a forensic copy.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub fn read(&self) -> FundedDistributorsRead {
        let Some(path) = self.record_path() else {
            return FundedDistributorsRead::NotConfigured(NotConfiguredReason::NoStateDirectory);
        };
        match self.load(&path) {
            Ok(Some(record)) => match record.into_distributors() {
                Ok(set) if set.is_empty() => FundedDistributorsRead::FundsNothing,
                Ok(set) => FundedDistributorsRead::Funded(set),
                Err(reason) => self.report_corrupt(&path, &reason),
            },
            Ok(None) => FundedDistributorsRead::NotConfigured(self.absent_record_reason()),
            Err(LoadFailure::Corrupt(reason)) => self.report_corrupt(&path, &reason),
            Err(LoadFailure::Io(error)) => FundedDistributorsRead::IoFailed { path, error },
        }
    }

    /// Record that this node funds `distributor`, creating the state directory and the record file
    /// if they do not exist. Idempotent per launcher id.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn record(&self, distributor: &FundedDistributor) -> RecordOutcome {
        let Some(path) = self.record_path() else {
            return RecordOutcome::NotConfigured(NotConfiguredReason::NoStateDirectory);
        };
        let mut set = match self.load(&path) {
            Ok(Some(record)) => match record.into_distributors() {
                Ok(set) => set,
                Err(reason) => return self.refuse_corrupt(&path, &reason),
            },
            Ok(None) => Vec::new(),
            Err(LoadFailure::Corrupt(reason)) => return self.refuse_corrupt(&path, &reason),
            Err(LoadFailure::Io(error)) => return RecordOutcome::IoFailed { path, error },
        };

        let outcome = match merge(&mut set, distributor) {
            Ok(outcome) => outcome,
            Err(conflict) => return conflict,
        };
        if matches!(outcome, RecordOutcome::AlreadyRecorded) {
            return outcome;
        }
        match self.save(&path, &set) {
            Ok(()) => outcome,
            Err(error) => RecordOutcome::IoFailed { path, error },
        }
    }

    /// Whether an absent record file means "directory gone" or "nothing recorded yet" — two
    /// different unknowns, and neither of them "funds nothing".
    fn absent_record_reason(&self) -> NotConfiguredReason {
        match &self.state_dir {
            None => NotConfiguredReason::NoStateDirectory,
            Some(dir) if !dir.is_dir() => NotConfiguredReason::StateDirectoryMissing,
            Some(_) => NotConfiguredReason::NoRecordWritten,
        }
    }

    /// Read and parse the record. `Ok(None)` = no record file (the directory may or may not exist;
    /// [`Self::absent_record_reason`] tells those apart).
    fn load(&self, path: &Path) -> Result<Option<PersistedRecord>, LoadFailure> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(LoadFailure::Io(e.to_string())),
        };
        let record: PersistedRecord =
            serde_json::from_str(&text).map_err(|e| LoadFailure::Corrupt(e.to_string()))?;
        if record.version != RECORD_FORMAT_VERSION {
            return Err(LoadFailure::Corrupt(format!(
                "record format version {} is not {RECORD_FORMAT_VERSION}",
                record.version
            )));
        }
        Ok(Some(record))
    }

    /// Write the set ATOMICALLY: to a temp file beside the record, then renamed over it, so a crash
    /// mid-write cannot leave a torn file the next read would have to call corrupt. The same
    /// pattern `rewards_claim::config::RewardsClaimConfig::save_to` uses for the claim side's
    /// persisted state.
    fn save(&self, path: &Path, set: &[FundedDistributor]) -> Result<(), String> {
        let dir = path.parent().ok_or_else(|| {
            format!(
                "the funded-distributor record path {} has no parent directory",
                path.display()
            )
        })?;
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let record = PersistedRecord::from_distributors(set);
        let text = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text.as_bytes()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    /// Log, quarantine-copy, and report a corrupt record to a READER.
    fn report_corrupt(&self, path: &Path, reason: &str) -> FundedDistributorsRead {
        let quarantined_to = self.quarantine(path);
        tracing::error!(
            path = %path.display(),
            reason,
            quarantined_to = ?quarantined_to,
            "the funded-distributor record is corrupt; reporting corrupt rather than an empty \
             funded set"
        );
        FundedDistributorsRead::PersistedStateCorrupt {
            path: path.to_path_buf(),
            quarantined_to,
        }
    }

    /// Log, quarantine-copy, and report a corrupt record to a WRITER, which leaves the file alone.
    fn refuse_corrupt(&self, path: &Path, reason: &str) -> RecordOutcome {
        let quarantined_to = self.quarantine(path);
        tracing::error!(
            path = %path.display(),
            reason,
            quarantined_to = ?quarantined_to,
            "the funded-distributor record is corrupt; refusing to overwrite it with a new funding \
             record"
        );
        RecordOutcome::PersistedStateCorrupt {
            path: path.to_path_buf(),
            quarantined_to,
        }
    }

    /// Copy the corrupt record beside itself for the operator, leaving the original in place.
    /// `None` when the copy failed — the corrupt verdict does not depend on it.
    fn quarantine(&self, path: &Path) -> Option<PathBuf> {
        let target = path.with_file_name(FUNDED_DISTRIBUTORS_QUARANTINE_FILE);
        match std::fs::copy(path, &target) {
            Ok(_) => Some(target),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    target = %target.display(),
                    error = %e,
                    "the corrupt funded-distributor record could not be copied to quarantine"
                );
                None
            }
        }
    }
}

/// Add `distributor` to `set`, or refine the identity already there. `Err` carries the conflict
/// outcome, so a caller cannot forget to stop.
fn merge(
    set: &mut Vec<FundedDistributor>,
    distributor: &FundedDistributor,
) -> Result<RecordOutcome, RecordOutcome> {
    let Some(existing) = set
        .iter_mut()
        .find(|d| d.launcher_id == distributor.launcher_id)
    else {
        set.push(distributor.clone());
        return Ok(RecordOutcome::Recorded);
    };
    match (existing.store_id, distributor.store_id) {
        (Some(recorded), Some(offered)) if recorded != offered => {
            Err(RecordOutcome::IdentityConflict { recorded, offered })
        }
        (None, Some(offered)) => {
            existing.store_id = Some(offered);
            Ok(RecordOutcome::IdentityRefined)
        }
        _ => Ok(RecordOutcome::AlreadyRecorded),
    }
}

/// Why [`FundedDistributorRegistry::load`] could not hand back a record.
enum LoadFailure {
    /// The file exists and cannot be trusted.
    Corrupt(String),
    /// The file could not be read.
    Io(String),
}

/// The on-disk shape: a version plus hex-string ids, so an operator can read and repair the file by
/// hand. `[u8; 32]` would serialize as 32 JSON numbers, which nobody can check by eye.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedRecord {
    version: u32,
    distributors: Vec<PersistedDistributor>,
}

/// One record line: hex ids, `store_id` omitted entirely when it was never learned.
#[derive(Debug, Serialize, Deserialize)]
struct PersistedDistributor {
    launcher_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store_id: Option<String>,
}

impl PersistedRecord {
    fn from_distributors(set: &[FundedDistributor]) -> Self {
        Self {
            version: RECORD_FORMAT_VERSION,
            distributors: set
                .iter()
                .map(|d| PersistedDistributor {
                    launcher_id: hex::encode(d.launcher_id),
                    store_id: d.store_id.map(hex::encode),
                })
                .collect(),
        }
    }

    /// `Err` carries why the record is corrupt. A malformed id is corruption, never an entry to
    /// skip: silently dropping one would under-report the funded set, which is the same lie as
    /// reporting it empty, only harder to notice.
    fn into_distributors(self) -> Result<Vec<FundedDistributor>, String> {
        self.distributors
            .into_iter()
            .map(|d| {
                Ok(FundedDistributor {
                    launcher_id: parse_id(&d.launcher_id, "launcher_id")?,
                    store_id: d
                        .store_id
                        .as_deref()
                        .map(|s| parse_id(s, "store_id"))
                        .transpose()?,
                })
            })
            .collect()
    }
}

/// Parse one 32-byte hex id, naming the field in the error so a corrupt-record log points at the
/// thing to fix.
fn parse_id(text: &str, field: &str) -> Result<Bytes32, String> {
    let bytes = hex::decode(text).map_err(|e| format!("{field} is not hex: {e}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("{field} is {len} bytes, not 32"))
}

#[cfg(test)]
mod tests {
    //! Every persistence test round-trips against a REAL temporary directory
    //! (`tempfile::TempDir`, removed on drop), never a mock: the thing under test is what survives
    //! a restart, and a mock filesystem cannot answer that. "Restart" is simulated the only way it
    //! can be without spawning a process — by dropping the registry that wrote and constructing a
    //! FRESH one over the same directory, which is exactly the state a new process starts from,
    //! since [`FundedDistributorRegistry`] caches nothing.

    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::*;

    /// A distinguishable 32-byte id.
    fn id(seed: u8) -> Bytes32 {
        [seed; 32]
    }

    fn record_path(dir: &TempDir) -> PathBuf {
        dir.path().join(FUNDED_DISTRIBUTORS_FILE)
    }

    /// **Catches:** a write that persists nothing, or a read that drops the store id.
    #[test]
    fn records_then_reads_back_the_same_identity() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        let funded = FundedDistributor {
            launcher_id: id(1),
            store_id: Some(id(2)),
        };

        assert_eq!(registry.record(&funded), RecordOutcome::Recorded);

        assert_eq!(
            registry.read(),
            FundedDistributorsRead::Funded(vec![funded]),
            "a recorded distributor must read back with its identity intact"
        );
    }

    /// The ticket's actual requirement: the set survives the process that recorded it.
    /// **Catches:** an in-memory-only registry, or a write that never reached disk.
    #[test]
    fn a_fresh_registry_over_the_same_directory_still_sees_the_set() {
        let dir = TempDir::new().expect("temp dir");
        let with_store = FundedDistributor {
            launcher_id: id(3),
            store_id: Some(id(4)),
        };
        let without_store = FundedDistributor {
            launcher_id: id(5),
            store_id: None,
        };
        {
            // Scoped so the writing registry is dropped before the reading one exists: nothing but
            // the directory carries information across the boundary, which is what a restart is.
            let writer = FundedDistributorRegistry::with_state_dir(dir.path());
            assert_eq!(writer.record(&with_store), RecordOutcome::Recorded);
            assert_eq!(writer.record(&without_store), RecordOutcome::Recorded);
        }

        let after_restart = FundedDistributorRegistry::with_state_dir(dir.path());

        assert_eq!(
            after_restart.read(),
            FundedDistributorsRead::Funded(vec![with_store, without_store]),
            "the funded set must survive the process that recorded it, in recorded order"
        );
    }

    /// **Catches:** an amount finding its way into the durable record, and ids persisted as raw
    /// byte arrays no operator can check by eye.
    #[test]
    fn the_persisted_record_is_hex_and_carries_no_amount() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        registry.record(&FundedDistributor {
            launcher_id: id(0xab),
            store_id: Some(id(0xcd)),
        });

        let text = std::fs::read_to_string(record_path(&dir)).expect("record readable");

        assert!(
            text.contains(&"ab".repeat(32)) && text.contains(&"cd".repeat(32)),
            "ids must persist as operator-readable hex, got: {text}"
        );
        for money in [
            "amount",
            "mojos",
            "base_units",
            "reserve",
            "accrued",
            "paid_out",
            "balance",
        ] {
            assert!(
                !text.contains(money),
                "the record must carry no money figure, found {money:?} in: {text}"
            );
        }
    }

    /// **Catches:** a duplicate record line per funding act, and a refinement that is silently
    /// dropped instead of persisted.
    #[test]
    fn recording_the_same_launcher_twice_is_idempotent_and_refines_identity() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        let unknown_store = FundedDistributor {
            launcher_id: id(7),
            store_id: None,
        };
        let learned_store = FundedDistributor {
            launcher_id: id(7),
            store_id: Some(id(8)),
        };

        assert_eq!(registry.record(&unknown_store), RecordOutcome::Recorded);
        assert_eq!(
            registry.record(&unknown_store),
            RecordOutcome::AlreadyRecorded
        );
        assert_eq!(
            registry.record(&learned_store),
            RecordOutcome::IdentityRefined
        );
        assert_eq!(
            registry.record(&learned_store),
            RecordOutcome::AlreadyRecorded
        );

        assert_eq!(
            registry.read(),
            FundedDistributorsRead::Funded(vec![learned_store]),
            "one launcher id must occupy one record line, with the identity it refined to"
        );
    }

    /// **Catches:** a second, contradicting store id overwriting recorded identity.
    #[test]
    fn a_contradicting_store_id_is_a_conflict_and_overwrites_nothing() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        let recorded = FundedDistributor {
            launcher_id: id(9),
            store_id: Some(id(10)),
        };
        registry.record(&recorded);

        let outcome = registry.record(&FundedDistributor {
            launcher_id: id(9),
            store_id: Some(id(11)),
        });

        assert_eq!(
            outcome,
            RecordOutcome::IdentityConflict {
                recorded: id(10),
                offered: id(11),
            }
        );
        assert_eq!(
            registry.read(),
            FundedDistributorsRead::Funded(vec![recorded]),
            "a conflicting offer must leave the recorded identity exactly as it was"
        );
    }

    /// The requirement everything else serves.
    /// **Catches:** a corrupt read rendering as an empty funded set, a quarantine that does not
    /// preserve the bytes, and a quarantine that MOVES the record so the next read reads empty.
    #[test]
    fn a_corrupt_record_reports_corrupt_and_quarantines_and_is_never_empty() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        registry.record(&FundedDistributor {
            launcher_id: id(12),
            store_id: None,
        });
        let path = record_path(&dir);
        let corrupt_bytes = b"{\"version\": 1, \"distributors\": [ truncated";
        std::fs::write(&path, corrupt_bytes).expect("corrupt the record");

        let read = registry.read();

        let FundedDistributorsRead::PersistedStateCorrupt {
            path: reported,
            quarantined_to,
        } = &read
        else {
            panic!("a corrupt record must report PersistedStateCorrupt, got {read:?}");
        };
        assert_eq!(reported, &path);
        let quarantine = quarantined_to
            .as_ref()
            .expect("the corrupt record must be quarantined");
        assert_eq!(
            quarantine,
            &dir.path().join(FUNDED_DISTRIBUTORS_QUARANTINE_FILE)
        );
        assert_eq!(
            std::fs::read(quarantine).expect("quarantine readable"),
            corrupt_bytes,
            "quarantine must preserve the corrupt bytes verbatim"
        );
        assert_eq!(
            std::fs::read(&path).expect("original still readable"),
            corrupt_bytes,
            "the original must stay in place so the NEXT read is corrupt too, not empty"
        );
        assert_eq!(
            read.determined(),
            None,
            "corrupt must never present as a determined (and therefore renderable) set"
        );
        assert_ne!(read, FundedDistributorsRead::FundsNothing);
        assert!(
            matches!(
                registry.read(),
                FundedDistributorsRead::PersistedStateCorrupt { .. }
            ),
            "quarantining must not let the following read decay into an empty answer"
        );
    }

    /// **Catches:** a parser that skips a malformed entry, which under-reports the funded set.
    #[test]
    fn a_malformed_id_inside_a_parseable_record_is_corrupt_not_a_skipped_entry() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        std::fs::write(
            record_path(&dir),
            r#"{"version": 1, "distributors": [{"launcher_id": "beef"}]}"#,
        )
        .expect("write a short id");

        let read = registry.read();

        assert!(
            matches!(read, FundedDistributorsRead::PersistedStateCorrupt { .. }),
            "a 2-byte launcher id must be corruption, not an entry to drop, got {read:?}"
        );
        assert_eq!(read.determined(), None);
    }

    /// **Catches:** a future format version read as an empty set by a version-blind parser.
    #[test]
    fn an_unknown_format_version_is_corrupt_not_empty() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        std::fs::write(record_path(&dir), r#"{"version": 2, "distributors": []}"#)
            .expect("write a future record");

        let read = registry.read();

        assert!(
            matches!(read, FundedDistributorsRead::PersistedStateCorrupt { .. }),
            "a version this build cannot read must be corrupt, got {read:?}"
        );
        assert_eq!(read.determined(), None);
    }

    /// **Catches:** a write that papers over corruption with a clean-looking file, losing whatever
    /// the corrupt record held.
    #[test]
    fn a_corrupt_record_is_never_overwritten_by_a_new_funding_record() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        let path = record_path(&dir);
        let corrupt_bytes = b"not json at all";
        std::fs::write(&path, corrupt_bytes).expect("seed a corrupt record");

        let outcome = registry.record(&FundedDistributor {
            launcher_id: id(13),
            store_id: None,
        });

        assert!(
            matches!(outcome, RecordOutcome::PersistedStateCorrupt { .. }),
            "recording over corruption must refuse, got {outcome:?}"
        );
        assert_eq!(
            std::fs::read(&path).expect("original still readable"),
            corrupt_bytes,
            "the corrupt record must be left exactly as it was found"
        );
    }

    /// **Catches:** persistence-off reading as an empty funded set, and an inert registry claiming
    /// it recorded something.
    #[test]
    fn no_state_directory_reports_not_configured_never_empty() {
        let registry = FundedDistributorRegistry::disabled();

        let read = registry.read();

        assert_eq!(
            read,
            FundedDistributorsRead::NotConfigured(NotConfiguredReason::NoStateDirectory)
        );
        assert_eq!(
            read.determined(),
            None,
            "persistence off is unknown, not an empty funded set"
        );
        assert_ne!(read, FundedDistributorsRead::FundsNothing);
        assert_eq!(
            registry.record(&FundedDistributor {
                launcher_id: id(14),
                store_id: None,
            }),
            RecordOutcome::NotConfigured(NotConfiguredReason::NoStateDirectory),
            "an inert registry must say it recorded nothing rather than pretend it did"
        );
    }

    /// **Catches:** a vanished state directory rendering as an empty funded set.
    #[test]
    fn a_missing_state_directory_reports_not_configured_distinctly_from_empty() {
        let dir = TempDir::new().expect("temp dir");
        let gone = dir.path().join("never-created");
        let registry = FundedDistributorRegistry::with_state_dir(&gone);

        let read = registry.read();

        assert_eq!(
            read,
            FundedDistributorsRead::NotConfigured(NotConfiguredReason::StateDirectoryMissing),
            "a directory this node cannot see is unknown, not empty"
        );
        assert_eq!(read.determined(), None);
        assert_ne!(read, FundedDistributorsRead::FundsNothing);
    }

    /// **Catches:** "nothing written yet" collapsed into the one renderable empty answer.
    #[test]
    fn an_existing_directory_with_no_record_is_not_configured_not_empty() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());

        let read = registry.read();

        assert_eq!(
            read,
            FundedDistributorsRead::NotConfigured(NotConfiguredReason::NoRecordWritten),
            "nothing ever written is a different unknown from a record that says none"
        );
        assert_eq!(read.determined(), None);
        assert_ne!(read, FundedDistributorsRead::FundsNothing);
    }

    /// **Catches:** a genuinely-empty record that cannot be told apart from a failure, which would
    /// make an honest empty list unrenderable.
    #[test]
    fn a_genuinely_empty_record_reports_funds_nothing_and_is_renderable() {
        let dir = TempDir::new().expect("temp dir");
        let registry = FundedDistributorRegistry::with_state_dir(dir.path());
        std::fs::write(record_path(&dir), r#"{"version": 1, "distributors": []}"#)
            .expect("write an empty record");

        let read = registry.read();

        assert_eq!(
            read,
            FundedDistributorsRead::FundsNothing,
            "an intact record naming nobody is the ONE legitimate empty answer"
        );
        assert_eq!(
            read.determined(),
            Some(&[][..]),
            "funds-nothing is the only outcome a caller may render as an empty list"
        );
    }

    /// **Catches:** a future variant added to the not-an-answer half of
    /// [`FundedDistributorsRead`] that `determined` reports as a renderable set.
    #[test]
    fn every_not_an_answer_outcome_is_undetermined() {
        let undetermined = [
            FundedDistributorsRead::NotConfigured(NotConfiguredReason::NoStateDirectory),
            FundedDistributorsRead::NotConfigured(NotConfiguredReason::StateDirectoryMissing),
            FundedDistributorsRead::NotConfigured(NotConfiguredReason::NoRecordWritten),
            FundedDistributorsRead::PersistedStateCorrupt {
                path: PathBuf::from("x"),
                quarantined_to: None,
            },
            FundedDistributorsRead::IoFailed {
                path: PathBuf::from("x"),
                error: "denied".to_owned(),
            },
        ];

        for read in undetermined {
            assert_eq!(
                read.determined(),
                None,
                "{read:?} must not be renderable as a funded set"
            );
        }
    }
}
