# Runbook — releasing dig-node (nightly cron + manual dispatch)

How this repo's `dig-node` binary (+ the `dign` alias) is built and released. The shape is copied from the ecosystem's **reference nightlies system**
(`dig-updater`, dig_ecosystem #590/#592); the normative contract is `SPEC.md` §11.

## TL;DR

- Releases are **NOT cut on merge to `main`**. They are batched to a **nightly cron at midnight UTC**
  plus **manual dispatch**.
- **Stable** (`vX.Y.Z`): cut automatically when the `[workspace.package].version` in the root
  `Cargo.toml` was bumped (detected as "the `vX.Y.Z` tag doesn't exist yet"), or on demand.
  `prerelease: false`, marked `latest`. Every per-OS/arch binary ships under the canonical
  `dig-node-*` name, plus the `dign-*` alias.
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
**no automatic re-enable** — and since this cron is the *only* automatic release trigger, a quiet
repo can go dark with no error. If nightlies (or a long-overdue stable release) stop appearing:

```bash
gh api repos/DIG-Network/dig-node/actions/workflows/nightly-release.yml --jq .state
# "disabled_inactivity" means GitHub turned it off — re-enable it:
gh workflow enable nightly-release.yml --repo DIG-Network/dig-node
```

Any repo activity (a merged PR, a manual dispatch) resets the 60-day counter.

## Cut a STABLE release (the normal path)

1. In your feature PR, bump `[workspace.package].version` in the root `Cargo.toml` per SemVer and run
   `cargo update --workspace` so `Cargo.lock` matches. Merge the PR (squash).
2. Nothing releases on merge. At the next **midnight UTC** the `nightly-release.yml` cron runs its
   **stable** job: it sees the new version has no `vX.Y.Z` tag, regenerates `CHANGELOG.md`, commits
   `chore(release): vX.Y.Z` to `main`, tags it, and pushes with `RELEASE_TOKEN`.
3. The pushed `v*` tag fires `release.yml`, which builds every OS/arch and publishes the stable
   GitHub Release (dual-named binaries + the `dign` alias, changelog as notes).

### Cut a stable release NOW / re-cut

- Now: Actions → **Nightly + stable release** → **Run workflow** → `channel: stable` (or `both`).
- Re-cut (failed build): same, with **`force: true`**. `force` REFUSES (non-zero exit) when the tag
  already has a PUBLISHED release AND points at a different commit than this run would build — it
  only proceeds for a same-commit retry or a tag with no published release. To ship new code, bump
  the version instead. (A force-moved tag breaks tag-immutability; the dig-updater signed feed, not
  the tag, is dig-node's integrity anchor — SPEC §11.1.)

## Cut a NIGHTLY on demand

Actions → **Nightly + stable release** → **Run workflow** → `channel: nightly` (or `both`) → Run.

## Verify a release went live

- **Stable:** `gh release view vX.Y.Z --repo DIG-Network/dig-node` — 4 OS/arch × (`dig-node-*` +
  `dign-*`), `prerelease: false`, marked latest. Watch: `gh run watch <id>`.
- **Nightly:** `gh release view nightly --repo DIG-Network/dig-node` (rolling) or
  `gh release view nightly-YYYYMMDD` — `prerelease: true`.
- **The native packages, on EITHER channel** — the single check that tells you the update system can
  actually resolve the release:

  ```bash
  gh release view nightly --repo DIG-Network/dig-node --json assets --jq '[.assets[].name | select(endswith(".deb") or endswith(".pkg") or endswith(".msi"))]'
  ```

  Expect three names. Fewer means dig-updater's `Feed` workflow will fail that channel with
  `no matching release assets` — the failure mode dig_ecosystem#618 fixed.

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
| `nightly-release.yml` | midnight-UTC cron + `workflow_dispatch` | Orchestrator: stable (changelog + tag) + nightly (build + pre-release + prune). |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the stable Release for a `vX.Y.Z` tag. |
| `build-binaries.yml` | `workflow_call` | Reusable cross-OS build, dual-named + `dign` (both channels call it). |
| `package.yml` | PR + `push: tags: v*` + `workflow_call` | Builds the `.deb`/`.pkg`/`.msi`. Attaches them itself on a `v*` tag; on a `workflow_call` (the nightly channel) it leaves them as run artifacts for the caller to publish. |
| `verify-release-assets.yml` | `workflow_call` (stable path) + `workflow_dispatch` | Asserts a `vX.Y.Z` release carries the four native install packages dig-updater's feedsign resolves dig-node by. Dispatch it at any tag to check a release by hand — a package-less release freezes the stable signed feed for every product. |
| `ci.yml` | PR + push to main | fmt/clippy + `cargo llvm-cov nextest --workspace` (pre-merge). NOTE: `ubuntu-latest` only — Windows/macOS build breaks are first caught by the nightly channel, not PR CI (SPEC §11 / follow-up). |

## Local build (dev)

```bash
cargo build --workspace --release --locked
cargo test  --workspace --locked        # includes the workflow-shape guard tests
```
