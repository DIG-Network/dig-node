//! Scratch tool (not committed): print each watched public key's p2 puzzle hash, its bech32m
//! address, and the $DIG CAT outer puzzle hash it owns coins at.

use chia_bls::PublicKey;
use chia_puzzle_types::standard::StandardArgs;

const KEYS: [&str; 3] = [
    "82a042f2a57c2863862a061700d9cf2650adede6f90aff662a73ed31c47f60511ac9dc4b8f276477c606ba9272a43de9",
    "91e72e437529e82ebea7e4f973939791b5c7bca07a28862cfe2b96dbe4c8785650fbf4d37cfc7ee35632c028bf90a899",
    "a652cdf7278788fc26be31b2a7935ebca074ae352d2dbf098e78a0ad3568fc48002cc6f02af37591f721e7d67a76ba64",
];

#[test]
fn print_addresses() {
    for k in KEYS {
        let bytes: [u8; 48] = hex::decode(k).unwrap().try_into().unwrap();
        let pk = PublicKey::from_bytes(&bytes).unwrap();
        let ph = StandardArgs::curry_tree_hash(pk);
        let ph32 = chia_protocol::Bytes32::from(ph.to_bytes());
        let cat = digstore_chain::cat::cat_puzzle_hash(ph32, digstore_chain::dig::DIG_ASSET_ID);
        println!(
            "key={k}\n  p2={}\n  addr={}\n  cat={}",
            hex::encode(ph32),
            chia_wallet_sdk::utils::Address::new(ph32, "xch".to_string())
                .encode()
                .unwrap(),
            hex::encode(cat)
        );
    }
}
