# Runbook — releasing dig-node (nightly cron + manual dispatch)

How this repo's `dig-node` binary (+ the `dign` alias) is built and released. The shape is copied from the ecosystem's **reference nightlies system**
(`dig-updater`, dig_ecosystem #590/#592); the normative contract is `SPEC.md` §11.

## TL;DR

- Releases are **NOT cut on merge to `main`**. Nightlies are batched to a **cron at midnight UTC**; a
  **stable release is cut ONLY by a manual dispatch** (CLAUDE.md §3.6-A — the cron must never cut a
  stable `vX.Y.Z`).
- **Stable** (`vX.Y.Z`): cut on demand via `workflow_dispatch(channel: stable|both)`, and then only
  when the `[workspace.package].version` in the root `Cargo.toml` was bumped (detected as "the
  `vX.Y.Z` tag doesn't exist yet"). `prerelease: false`, marked `latest`. Every per-OS/arch binary
  ships under the canonical `dig-node-*` name, plus the `dign-*` alias.
- **Nightly**: built every night from `main` HEAD as a **pre-release** under a dated tag
  `nightly-YYYYMMDD` + a rolling `nightly` tag. `prerelease: true`, never `latest`. Keeps 14.
- **BOTH channels also publish the three native install packages** — `dig-node_<ver>_amd64.deb`,
  `dig-node-<ver>-macos.pkg`, `dig-node-<ver>-windows-x64.msi`. These are what the beacon actually
  installs (it hands a native package to `msiexec`/`installer`/`dpkg`) and what dig-updater's feed
  resolves dig-node by, so a release without them is a release nobody on that channel can install —
  the nightly publish step fails rather than shipping an incomplete set. The nightly `.deb` is
  amd64-only; the stable one also ships arm64 for apt.dig.net (SPEC §11.5a).

## If a stable cut is refused: "dig-constants X predates 0.4.0"

The stable job runs `scripts/check-dig-constants-current.sh` before it resolves a version, so a
breach means the run stops with NO tag cut and nothing to clean up. It refuses because a
`dig-constants` below 0.4.0 carries the all-zeros PLACEHOLDER DIG L2 genesis challenge (SPEC §11.3a),
which no test can see — every runtime check compares that constant against itself.

The error names the package that pulls the bad copy in. Bump that consumer and re-lock; a 0.x minor
gap is semver-BREAKING, so a caret range will never resolve forward on its own. Reproduce locally
with `bash scripts/check-dig-constants-current.sh` and confirm the holder with
`cargo tree -i dig-constants@<version>`.

The same step also emits `::warning::` annotations when several `dig-constants` versions resolve at
once, or when a newer one is published. **Neither blocks a release, and neither should be "fixed"
here** — the duplicate copies are pinned by published metadata this repo cannot edit
(dig_ecosystem#2072), and the published tip periodically moves to a `chia-protocol`/`chia-wallet-sdk`
line this repo cannot build against while the `dig-gossip` fork is patched in. A green run with those
warnings is the expected steady state.

## Prerequisites / credentials

- **`RELEASE_TOKEN`** — an org-level classic PAT (the ecosystem release token). Both channels no-op
  with a warning if it is absent. Used to push the changelog commit past branch protection and to
  push tags that trigger downstream workflows (`GITHUB_TOKEN` cannot do either).

## If nightlies silently stop — check for the 60-day cron auto-disable

GitHub disables a `schedule:` trigger after **60 days of no repo activity** on a public repo, with
**no automatic re-enable** — and since this cron is the only thing that publishes a nightly, a
quiet repo can go dark with no error. (Stable is unaffected: it is dispatched by hand, and a
dispatch also resets the 60-day counter.) If nightlies stop appearing:

```bash
gh api repos/DIG-Network/dig-node/actions/workflows/nightly-release.yml --jq .state
# "disabled_inactivity" means GitHub turned it off — re-enable it:
gh workflow enable nightly-release.yml --repo DIG-Network/dig-node
```

Any repo activity (a merged PR, a manual dispatch) resets the 60-day counter.

## Cut a STABLE release (the normal path)

1. In your feature PR, bump `[workspace.package].version` in the root `Cargo.toml` per SemVer and run
   `cargo update --workspace` so `Cargo.lock` matches. Merge the PR (squash).
2. Nothing releases on merge, and **the midnight cron will not release it either** — the `stable` job
   requires `workflow_dispatch`. When you want the release: Actions → **Nightly + stable release** →
   **Run workflow** → `channel: stable` (or `both`) → Run. The job sees the new version has no
   `vX.Y.Z` tag, regenerates `CHANGELOG.md`, commits `chore(release): vX.Y.Z` to `main`, tags it, and
   pushes with `RELEASE_TOKEN`. An already-tagged version is a no-op, so re-dispatching is safe.
3. The pushed `v*` tag fires `release.yml`, which builds every OS/arch and publishes the stable
   GitHub Release (dual-named binaries + the `dign` alias, changelog as notes).

> **Nothing reminds you to do step 2.** A merged version bump sits on `main` untagged until someone
> dispatches, and the failure mode is silent — `releases/latest` keeps serving the previous version
> and no check goes red. Compare the root `Cargo.toml` version against
> `git describe --tags --abbrev=0 --match 'v*'`: if they differ, a stable cut is overdue.

### Re-cut a stable release (failed build)

The same dispatch, with **`force: true`**. `force` REFUSES (non-zero exit) when the tag already has a
PUBLISHED release AND points at a different commit than this run would build — it only proceeds for a
same-commit retry or a tag with no published release. To ship new code, bump the version instead. (A
force-moved tag breaks tag-immutability; the dig-updater signed feed, not the tag, is dig-node's
integrity anchor — SPEC §11.1.)

## Cut a NIGHTLY on demand

Actions → **Nightly + stable release** → **Run workflow** → `channel: nightly` (or `both`) → Run.

## Verify a release went live

- **Stable:** `gh release view vX.Y.Z --repo DIG-Network/dig-node` — 5 platforms × (`dig-node-*` +
  `dign-*`) plus the 4 native packages, 14 assets, `prerelease: false`, marked latest. Watch:
  `gh run watch <id>`.
- **A stable release is marked `latest` LAST, by `release.yml`'s `promote` job, and only after the
  asset guard has read the real asset list.** So a stable release that is published but NOT latest
  means the guard has not passed yet — either a build is still running, or a publisher never
  landed. That is working as designed: the previous complete release keeps serving installs rather
  than a half-built one taking over. Read the guard's step summary before doing anything by hand.
- **Gotcha — re-running `package.yml` by hand after a release is already latest will DEMOTE it.**
  Both publishers deliberately set `make_latest: false` (dig-node#335), so an out-of-band re-run
  un-marks `latest`. Re-promote with
  `gh release edit vX.Y.Z --repo DIG-Network/dig-node --latest`, or re-dispatch `release.yml`
  against the tag, which verifies and promotes in the right order.
- **Nightly:** `gh release view nightly --repo DIG-Network/dig-node` (rolling) or
  `gh release view nightly-YYYYMMDD` — `prerelease: true`.
- **The native packages, on EITHER channel** — the single check that tells you the update system can
  actually resolve the release:

  ```bash
  gh release view nightly --repo DIG-Network/dig-node --json assets --jq '[.assets[].name | select(endswith(".deb") or endswith(".pkg") or endswith(".msi"))]'
  ```

  Expect three names on nightly (four on stable, which also carries `arm64.deb`). Fewer means
  dig-updater's `Feed` workflow will fail that channel with `no matching release assets` — the
  failure mode dig_ecosystem#618 fixed.
- **The raw binaries, on stable** — the check dig-installer depends on, and the one whose absence
  caused dig-node#335:

  ```bash
  gh release view vX.Y.Z --repo DIG-Network/dig-node --json assets --jq '[.assets[].name | select(startswith("dign-") or test("^dig-node-[0-9].*(linux|macos|windows)"))] | length'
  ```

  Expect ten. Fewer means a fresh install 404s, because `dig-installer` resolves both the
  `dig-node` and `dign` stems through `releases/latest`.

## Gotcha — moving a Windows host from `nightly` back to `stable`

A nightly `.msi` carries `ProductVersion = X.Y.<days since 2020-01-01>` (MSI accepts no prerelease
suffix; the full version lives in the file name). The day count sits above every real patch number,
so a nightly `0.96.2407` outranks every stable `0.96.z`. Consequences to expect, neither of which is
a bug in the beacon:

- **`msiexec` aborts installing a stable `0.96.z` over a nightly**, with "A newer version of DIG
  NETWORK: NODE is already installed." The beacon cannot pre-empt it — anti-rollback state is per
  channel. **Uninstall the nightly package first** (Add/Remove Programs, or
  `msiexec /x` with the nightly's ProductCode), then let the stable install proceed. A stable release
  in a HIGHER `major.minor` installs normally.
- **Two nightly builds on one UTC day share a ProductVersion** (a `force` re-cut, or a manual
  `channel: nightly` dispatch on a day the cron already ran). That is handled:
  `AllowSameVersionUpgrades="yes"` makes the second upgrade in place instead of installing as a
  second product. Do not remove that attribute — see SPEC §11.5c.

## Workflows

| File | Trigger | Role |
|---|---|---|
| `nightly-release.yml` | midnight-UTC cron + `workflow_dispatch` | Orchestrator. The cron runs the NIGHTLY channel only (build + pre-release + prune); the STABLE channel (changelog + tag) requires `workflow_dispatch` and is never cut by the cron. |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the stable Release for a `vX.Y.Z` tag, then verifies the asset set and promotes it to `latest`. Attaching assets never moves `latest` by itself. |
| `build-binaries.yml` | `workflow_call` | Reusable cross-OS build, dual-named + `dign` (both channels call it). |
| `package.yml` | PR + `push: tags: v*` + `workflow_call` | Builds the `.deb`/`.pkg`/`.msi`. Attaches them itself on a `v*` tag; on a `workflow_call` (the nightly channel) it leaves them as run artifacts for the caller to publish. |
| `verify-release-assets.yml` | `workflow_call` (stable path) + `workflow_dispatch` + PR self-test | Asserts a `vX.Y.Z` release carries all fourteen consumer-resolvable assets: the four native install packages dig-updater's feedsign resolves dig-node by, plus the five `dig-node-*` and five `dign-*` raw binaries dig-installer fetches through `releases/latest`. `release.yml` waits on it before promoting the release to `latest`, so an incomplete release never becomes the one users install from. Dispatch it at any tag to check a release by hand. The expected set lives in `.github/actions/check-release-assets`; a PR self-test drives that same action over a deliberately incomplete list and requires it to fail. |
| `ci.yml` | PR + push to main | fmt/clippy + `cargo llvm-cov nextest --workspace` (pre-merge). NOTE: `ubuntu-latest` only — Windows/macOS build breaks are first caught by the nightly channel, not PR CI (SPEC §11 / follow-up). |

## Local build (dev)

```bash
cargo build --workspace --release --locked
cargo test  --workspace --locked        # includes the workflow-shape guard tests
```
