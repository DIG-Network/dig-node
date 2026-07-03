//! dig-wallet standalone binary — a thin wrapper over the `dig_wallet` library's
//! [`dig_wallet::run`]. The SAME wallet runs natively in-process inside the DIG
//! browser via the `dig-runtime` cdylib (no sidecar); this binary is for
//! standalone use and testing.

fn main() {
    let rt = tokio::runtime::Runtime::new().expect("dig-wallet: tokio runtime");
    rt.block_on(dig_wallet::run());
}
