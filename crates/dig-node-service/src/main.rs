//! The `dig-node` binary — a thin shim over the shared entrypoint
//! [`dig_node_service::run`]. The `dign` alias binary (`src/bin/dign.rs`, issue #548)
//! shares this exact codepath, so the two binaries are identical modulo the invoked
//! program name (which clap derives from arg0).

fn main() -> std::process::ExitCode {
    dig_node_service::run()
}
