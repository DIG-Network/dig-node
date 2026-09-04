# Contributing to dig-node

Thanks for your interest in improving dig-node. This is the **canonical local DIG node**: a
self-contained, cross-platform Rust binary (`dig-node`, with a first-class `dign` alias) that
installs as a Windows/Linux/macOS OS service and serves the same `rpc.dig.net` JSON-RPC contract
locally for the DIG Chrome extension and other clients.

## Reporting an issue

File at [github.com/DIG-Network/dig-node/issues](https://github.com/DIG-Network/dig-node/issues).
Since this ships as an OS-service binary, a useful report usually needs:

- **observed vs. expected** behaviour;
- **OS** (Windows/Linux/macOS) and **how it was installed** (dig-installer, a downloaded release
  binary, built from source) and at what **scope** (`user` or `system`);
- **repro steps** — the exact `dig-node`/`dign` subcommand(s) run, ideally with `--json`;
- relevant **logs** and, for a service-registration problem, the output of `dig-node status --json`
  and the OS's own service state (`sc.exe qc net.dignetwork.dig-node` on Windows,
  `systemctl --user status dignetwork-dig-node.service` / `systemctl status` on Linux,
  `launchctl print gui/<uid>/net.dignetwork.dig-node` on macOS).

## Prerequisites

- **Rust — no pinned toolchain version.** There is no `rust-toolchain.toml` in this repo; CI
  installs Rust via `dtolnay/rust-toolchain@stable` (i.e. whatever `stable` currently resolves to).
  Use a recent stable toolchain via [rustup](https://rustup.rs).
- **No wasm build step needed.** This workspace depends on digstore's store-format crates, whose
  build script embeds the digstore guest wasm. That artifact is **vendored** in this repo
  (`vendor/digstore_guest.wasm`) and pointed at via `.cargo/config.toml`'s `DIGSTORE_GUEST_WASM`
  override, so a clean checkout builds without touching the digstore repo or a wasm target. If you
  bump the digstore git dependency, rebuild the vendored wasm from `digstore-guest` at the new pinned
  rev and replace the file (see `vendor/README.md`).
- **No extra system libraries.** OS-service registration goes through the pure-Rust
  `service-manager` crate (Windows SCM / systemd / launchd) — nothing beyond the Rust toolchain is
  needed to build. Running the service-registration integration test locally does need a real
  service manager for your OS (see below).

## Build & test

This is a Cargo workspace of five crates (`dig-node-core` the engine library,
`dig-node-service` the OS-service binary, `dig-chat-protocol`, `dig-runtime` and `dig-wallet` for
the DIG Browser's in-process host):

```bash
cargo build --release          # -> target/release/dig-node[.exe] (+ the dign alias)
cargo test --workspace         # routing, config, cache-key, service helpers, in-process server tests
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The first build fetches the digstore store-format crates as git dependencies (plus their
`wasmtime` tree), so it takes a few minutes; subsequent builds are fast.

**Service install/start/stop/uninstall against the real OS service manager is not exercised by
`cargo test`** — those are mocked in `crates/dig-node-service/src/service.rs`'s unit tests. The
real end-to-end proof lives in `.github/workflows/service-smoke.yml`, which builds a release
binary and runs `install` → `start` → a second `install` (proving clean reinstall) → `stop` →
`uninstall` against the actual Windows SCM / systemd / launchd on each OS, plus a second job that
proves the `--scope system` path (root-owned install, boot-enabled unit, the privileged-target
gate refusing an install from a user-writable path). It is **not** a required check (build infra
can flake independently of your change), and most of it needs root/admin plus a real service
manager, so it is honestly not something you can fully reproduce in an unprivileged local shell —
CI is the practical way to see it exercised. If your change touches
`crates/dig-node-service/src/{service,user_scope,security,config,hosts}.rs` or `packaging/**`, it
runs automatically on your PR.

## The gate (must pass before a PR is merged)

Everything below is a **required status check** read from `.github/workflows/ci.yml` — run it
locally first:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo llvm-cov nextest --workspace --locked --retries 2 --fail-under-lines 80 --summary-only
```

Notes on the exact shape of that last one, since it differs from a plain `cargo test`:

- It runs via `cargo-nextest` (`cargo install cargo-llvm-cov cargo-nextest` if you don't have them),
  with `--retries 2` so a flaky test gets a second chance before failing the job.
- **Coverage is gated at ≥80% lines across the whole workspace** (`--fail-under-lines 80`) — a run
  below that fails the check, not just reports it.
- Clippy carries **no allow-list** in this repo — `-D warnings` applies to the full, unfiltered
  lint set. If clippy complains, fix it rather than reaching for `#[allow(...)]`.

Two more required checks run on every PR:

- **`scripts` (Release-script tests)** — a workflow-pipefail lint (`scripts/check-workflow-pipefail.sh`,
  which checks that no CI step swallows a real command's exit code behind a pipe) plus
  `scripts/tests/*.test.sh`, the release-script test suite (glibc floor checks, version→MSI mapping,
  etc.). Run `bash scripts/tests/<name>.test.sh` for any script you touch under `scripts/`.
- **Check Version Increment** (`ensure-version-increment.yml`) — `Cargo.toml`'s
  `[workspace.package].version` on your branch must be **strictly greater** than on `main`. It also
  validates that the bumped version can produce a legal MSI `ProductVersion` via
  `scripts/package-version.sh` (this repo's `0.<minor>.<patch>` scheme has hit a documented
  minor-field ceiling before — see that script's comments if you're ever near a round number).

Not required, but will run and should stay green if your change touches the files it covers:

- **Service smoke test** (`service-smoke.yml`) — described above; runs on every push to `main` and
  on `workflow_dispatch`, and on PRs that touch the service-registration source or `packaging/**`.

## PR conventions

- **Conventional Commits**, commitlint-enforced (`commitlint.yml` lints both your commits and the
  PR title against `commitlint.config.mjs`) — `type(scope): summary`, e.g. `feat(rpc): ...`,
  `fix(service): ...`, `docs: ...`.
- **Bump `[workspace.package].version` in the root `Cargo.toml`** as part of your PR — patch for a
  compatible fix, minor for a compatible new capability, major for a breaking change. This is the
  ONE version the binary, the nightly-release tag and the version-increment gate all read.
- `main` is a protected branch: PR required, every required check green, **zero unresolved review
  threads** (including any CodeQL/GHAS comment), squash-merge only.

### What merging actually does — read this before you merge

dig-node releases on **two channels**, both driven by `.github/workflows/nightly-release.yml`, and
the stable one is **not purely manual**:

- **Nightly** — every night at 00:00 UTC, a cron builds `main` HEAD and publishes it as a GitHub
  **pre-release** under a dated `nightly-YYYYMMDD` tag plus a rolling `nightly` tag. This always
  happens, whether or not the version changed.
- **Stable** — the same job resolves `Cargo.toml`'s version and cuts a real `vX.Y.Z` tag (which
  fires the binary build + publish in `release.yml`) whenever that tag doesn't already exist yet —
  i.e. whenever the version has been bumped since the last stable release. The workflow's own
  `stable` job condition, verbatim:

  ```yaml
  if: >-
    ${{
      !startsWith(github.event.head_commit.message, 'chore(release):') &&
      (github.event_name == 'schedule' || inputs.channel == 'stable' || inputs.channel == 'both')
    }}
  ```

  `github.event_name == 'schedule'` is the same midnight cron that cuts nightlies — **it is not
  gated to manual dispatch**. So merging a PR that bumped the version means the next midnight UTC
  cron cuts a real stable release automatically, with no separate approval step. There is no
  "merge now, decide when to release later" — the version bump you make on this PR IS the release
  decision. (A manual `workflow_dispatch(channel: stable)` can also cut it immediately, or
  `channel: nightly`/`both` to control which channel runs on demand.)

This is worth internalizing before merging anything: get the gate green, get the version bump
right, and know that main's next merge cycle through this workflow ships it.
