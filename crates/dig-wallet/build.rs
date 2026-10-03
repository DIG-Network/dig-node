//! Build script: on Windows, embed the branded DIG application icon
//! (`../../assets/dig.rc`, dig_ecosystem#2917) into the `dig-wallet` binary.
//!
//! This crate has a single bin (`dig-wallet`), so the unscoped
//! `embed_resource::compile` -- which links to every bin the crate produces --
//! is safe to use here (contrast `dig-node-service`, which must exclude its
//! `fake_beacon_cli` test fixture and therefore uses `compile_for` instead).
//!
//! `.manifest_required()`/`.expect(..)` is deliberate: an environment that
//! cannot compile a resource must fail the build loudly rather than silently
//! ship an unbranded binary.
//!
//! No-op on non-Windows.

fn main() {
    #[cfg(windows)]
    embed_icon();
}

#[cfg(windows)]
fn embed_icon() {
    embed_resource::compile("../../assets/dig.rc", embed_resource::NONE)
        .manifest_required()
        .expect("failed to compile assets/dig.rc — no usable Windows resource compiler?");

    println!("cargo:rerun-if-changed=../../assets/dig.rc");
    println!("cargo:rerun-if-changed=../../assets/dig.ico");
}
