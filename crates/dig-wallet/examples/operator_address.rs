//! Print ONLY the node operator wallet's public puzzle hash. Read-only, scratch, uncommitted.
//! No seed, phrase, or private key is printed or returned.
use chia_protocol::Bytes32;
use dig_wallet::autoseed;
use dig_wallet::operator_wallet::OperatorWallet;

fn main() {
    let paths = autoseed::default_paths();
    eprintln!("seed:       {}", paths.seed.display());
    eprintln!("device key: {}", paths.device_key.display());
    match OperatorWallet::open(&paths, Bytes32::from([0u8; 32])) {
        Some(w) => println!("owner_puzzle_hash={}", hex::encode(w.owner_puzzle_hash())),
        None => println!("UNAVAILABLE (seed absent, Locked, or Orphaned)"),
    }
}
