# Runbook — releasing dig-node (nightly cron + manual dispatch)

How this repo's `dig-node` binary (+ the `dig-companion` legacy-named copy + the `dign` alias) is
built and released. The shape is copied from the ecosystem's **reference nightlies system**
(`dig-updater`, dig_ecosystem #590/#592); the normative contract is `SPEC.md` §11.

## TL;DR

- Releases are **NOT cut on merge to `main`**. They are batched to a **nightly cron at midnight UTC**
  plus **manual dispatch**.
- **Stable** (`vX.Y.Z`): cut automatically when the `[workspace.package].version` in the root
  `Cargo.toml` was bumped (detected as "the `vX.Y.Z` tag doesn't exist yet"), or on demand.
  `prerelease: false`, marked `latest`. Every per-OS/arch binary ships under BOTH `dig-node-*` and
  legacy `dig-companion-*` names, plus the `dign-*` alias.
- **Nightly**: built every night from `main` HEAD as a **pre-release** under a dated tag
  `nightly-YYYYMMDD` + a rolling `nightly` tag. `prerelease: true`, never `latest`. Keeps 14.

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
  `dig-companion-*` + `dign-*`), `prerelease: false`, marked latest. Watch: `gh run watch <id>`.
- **Nightly:** `gh release view nightly --repo DIG-Network/dig-node` (rolling) or
  `gh release view nightly-YYYYMMDD` — `prerelease: true`.

## Workflows

| File | Trigger | Role |
|---|---|---|
| `nightly-release.yml` | midnight-UTC cron + `workflow_dispatch` | Orchestrator: stable (changelog + tag) + nightly (build + pre-release + prune). |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the stable Release for a `vX.Y.Z` tag. |
| `build-binaries.yml` | `workflow_call` | Reusable cross-OS build, dual-named + `dign` (both channels call it). |
| `ci.yml` | PR + push to main | fmt/clippy + `cargo llvm-cov nextest --workspace` (pre-merge). NOTE: `ubuntu-latest` only — Windows/macOS build breaks are first caught by the nightly channel, not PR CI (SPEC §11 / follow-up). |

## Local build (dev)

```bash
cargo build --workspace --release --locked
cargo test  --workspace --locked        # includes the workflow-shape guard tests
```
