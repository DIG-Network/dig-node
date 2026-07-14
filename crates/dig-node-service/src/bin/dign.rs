//! `dign` — a FIRST-CLASS alias binary for the `dig-node` service CLI (issue #548).
//!
//! `dign <args>` behaves IDENTICALLY to `dig-node <args>`: same subcommands, flags,
//! `--json`, exit codes, and help. It is a real installed binary (not a shell alias)
//! that shares the SINGLE entrypoint [`dig_node_service::run`] with `dig-node` — there is
//! no duplicated logic. clap derives the displayed program name from arg0, so
//! `dign --help`/`--version` all read `dign`.

fn main() -> std::process::ExitCode {
    dig_node_service::run()
}
