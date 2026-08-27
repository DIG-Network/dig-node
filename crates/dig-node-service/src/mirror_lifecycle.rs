//! The mirror-coin lifecycle (dig-node#377) — WIP scaffold.
//!
//! Presence of a `.dig` file on disk is the trigger: a store+root this node serves gets an
//! on-chain mirror coin locking 20 $DIG, and a coin whose `.dig` is gone gets reclaimed.
