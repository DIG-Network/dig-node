# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.6.0] - 2026-07-09

### Features
- **sync:** Wire §14 autonomous chain-watch + proactive gap-fill into service bring-up (#7)

## [0.5.1] - 2026-07-06

### Documentation
- **dig-node:** Reconcile the two cache-method families in the control contract (#6)

## [0.5.0] - 2026-07-06

### Features
- **dig-node:** Canonical node-control contract + uncommon default port 9778 (#5)

## [0.4.1] - 2026-07-05

### #168
- Rename DIG_COMPANION_* env vars to DIG_NODE_*

### #209
- Dig-node is now the CANONICAL node — first-party node + browser-host cluster

### Features
- Serve dig.getManifest locally from the embedded public manifest (#1)- Throttle outgoing bandwidth and redirect saturated serves to peers (#3)- **dig-runtime:** Wallet-only start + native read-crypto FFI (#4)

### Documentation
- Chia:// content scheme + canonical Discord/docs links

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Changelog + tag on merge feeding the existing tag-driven binary release (#230)- Add PR quality gates (fmt/clippy/test/build) [#230] (#2)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog

### SPEC
- Dig-rpc + dig-rpc-types are the canonical RPC interface (§1.4, §5, §10)

### Dig-node
- Unify control error codes to -32030/31/32, drop dead run(), fill SPEC gaps

## [0.3.0] - 2026-06-29

### CI
- Fix rustup component install syntax


