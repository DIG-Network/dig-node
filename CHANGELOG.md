# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.31.3] - 2026-07-15

### CI
- **release:** Nightlies system (cron + dispatch, nightly channel) (#592) (#38)- **release:** Nightlies polish (#39)

## [0.31.1] - 2026-07-14

### Testing
- **updater:** Make not-installed test hermetic (force empty resolution dir) (#571) (#37)

## [0.31.0] - 2026-07-14

### Features
- **cli:** Dign first-class alias binary for dig-node (mirror digs #434) (#36)

## [0.30.0] - 2026-07-14

### Features
- **control:** DIG auto-update beacon RPC proxy (control.updater.*) (#35)

## [0.29.0] - 2026-07-13

### Features
- Windows display name, clean-reinstall, macOS ensure-hosts, 3-OS service smoke CI (#34)

## [0.28.0] - 2026-07-13

### Features
- **packaging:** Native OS install packages — .msi / .pkg / .deb (#503) (#33)

## [0.27.0] - 2026-07-13

### Features
- Machine-wide control-token state dir + `dig-node open` handler (#501, #389) (#32)

## [0.26.0] - 2026-07-12

### Features
- **serve:** Add serve-metadata headers; harden CI against flaky tests (#31)

## [0.25.1] - 2026-07-12

### Bug Fixes
- **dig-node:** Correct Discord invite (imposter link -> official) (#30)

## [0.25.0] - 2026-07-12

### Features
- **dig-wallet:** Node-managed unlock auth + per-transaction sign-unlock (#432) (#29)

## [0.24.0] - 2026-07-12

### Features
- Node multi-wallet custody (#427) (#28)

## [0.23.0] - 2026-07-12

### Features
- **wallet:** Sync node-custodied coin DB from chain so live $DIG spends select coins (#27)

## [0.22.0] - 2026-07-12

### Features
- **node:** Live wallet broadcaster + confirm — real push_tx behind a config gate (#428) (#26)

## [0.21.0] - 2026-07-12

### Features
- **node:** Tipping subsystem — owner lookup + auto-tip engine + $DIG spend + tip ledger (#378) (#25)

## [0.20.0] - 2026-07-12

### Features
- **node:** Serve Sage-parity wallet RPC + bidirectional WS wallet/control transport (#368, #369) (#24)

## [0.19.0] - 2026-07-11

### Features
- **p2p:** Wire dig-node to its P2P crates (full ladder, DHT locator, address book, dials) (#23)

## [0.18.0] - 2026-07-11

### Features
- **wallet:** Node-custodied wallet + paired-token authz + sign/broadcast on behalf (#370, #371) (#22)

## [0.17.0] - 2026-07-11

### Features
- **wallet:** Identity-scoped Sage-parity reads + CAT asset_id attribution + honest sync (#407) (#21)

## [0.16.0] - 2026-07-11

### Features
- **verify:** Server-side verification ledger + GET /verify endpoint (#307) (#20)

## [0.15.0] - 2026-07-11

### Features
- **server:** Local plaintext content-serve surface + local-first cache (#289, #290) (#19)

## [0.14.0] - 2026-07-11

### Features
- **server:** Dual-stack loopback bind (127.0.0.1 AND [::1]:9778) (#18)

## [0.13.0] - 2026-07-11

### Features
- **server:** PNA preflight header + DIG_NETWORK_GENESIS override (#17)

## [0.12.0] - 2026-07-10

### Features
- **control:** Dig-node control-panel surface — WS status, cache-LRU, token pairing (#16)

### Bug Fixes
- **deps:** Re-pin DIG git deps to rewritten (co-author history) revs- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

## [0.11.1] - 2026-07-10

### Bug Fixes
- **release:** Sync Cargo.lock and run --locked in PR CI (#14)

## [0.11.0] - 2026-07-10

### Features
- **service:** Configure Windows SCM restart-on-crash recovery actions (#13)

## [0.10.0] - 2026-07-10

### Features
- **sage:** Options/actions/themes/network-settings, SyncEvent stream, dig-keystore seed migration (#12)

## [0.9.0] - 2026-07-09

### Features
- **dig-wallet:** Sage-parity offer suite + DID/NFT mint & transfer (#205 PR3) (#11)

## [0.8.1] - 2026-07-09

### Bug Fixes
- **release:** Sync Cargo.lock with bumped versions for --locked release build (#10)

## [0.8.0] - 2026-07-09

### Features
- **wallet:** Complete NFT/DID/CAT wallet-data + send/spend methods (#9)

## [0.7.0] - 2026-07-09

### Features
- **wallet:** Sage-parity wallet RPC foundation: sync + SQLite DB + fallback + core reads (#8)

## [0.6.0] - 2026-07-09

### Features
- **sync:** Wire §14 autonomous chain-watch + proactive gap-fill into service bring-up (#7)

## [0.5.1] - 2026-07-06

### Documentation
- **dig-node:** Reconcile the two cache-method families in the control contract (#6)

## [0.5.0] - 2026-07-06

### #168
- Rename DIG_COMPANION_* env vars to DIG_NODE_*

### #209
- Dig-node is now the CANONICAL node — first-party node + browser-host cluster

### Features
- Serve dig.getManifest locally from the embedded public manifest (#1)- Throttle outgoing bandwidth and redirect saturated serves to peers (#3)- **dig-runtime:** Wallet-only start + native read-crypto FFI (#4)- **dig-node:** Canonical node-control contract + uncommon default port 9778 (#5)

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


