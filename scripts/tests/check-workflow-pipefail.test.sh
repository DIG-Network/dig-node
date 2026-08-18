#!/usr/bin/env bash
#
# Tests for scripts/check-workflow-pipefail.sh — the gate that refuses a workflow step whose pipe
# discards the exit code of the command that matters (dig_ecosystem#2513).
#
# Each case is built against the NEAREST WRONG gate rather than merely against the right one. The
# four nearest wrong gates for this rule, each ruled out below, are:
#   * one that greps the FILE for "pipefail" instead of the STEP (case: mixed-steps) — the most
#     tempting implementation and the one that would have passed dig-node's real broken ci.yml the
#     day a neighbouring step happened to set pipefail;
#   * one that flags any `|`, so a block-scalar `run: |`, a `||` fallback, or a quoted `grep -E
#     'a|b'` alternation reads as a pipeline (cases: block-scalar, or-fallback, quoted-alternation);
#   * one that ignores an INHERITED shell, so `defaults: run: shell: bash` reads as unsafe (case:
#     inherited-default);
#   * one that only understands a block `run: |`, so a single-line `run: cmd | tee x` escapes
#     (case: inline-run).
#
# The first case is the REAL historical defect, verbatim in shape: dig-node's required "Test +
# coverage" step as it stood before 5735c06. A gate that cannot fail on the byte pattern that
# actually shipped is not a gate.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/../check-workflow-pipefail.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0

# Runs the gate over a directory holding exactly one workflow written from stdin.
# expect: "pass" (exit 0) or "fail" (exit 1).
case_() {
  local name="$1" expect="$2"
  local dir="$WORK/$name"
  mkdir -p "$dir"
  cat > "$dir/wf.yml"
  local out rc
  out="$(bash "$GATE" "$dir" 2>&1)"; rc=$?
  if [ "$expect" = "pass" ] && [ "$rc" -ne 0 ]; then
    echo "FAIL [$name]: expected the gate to accept this workflow, it refused:"; echo "$out"
    failures=$((failures + 1)); return
  fi
  if [ "$expect" = "fail" ] && [ "$rc" -eq 0 ]; then
    echo "FAIL [$name]: expected the gate to refuse this workflow, it accepted it."
    failures=$((failures + 1)); return
  fi
  echo "ok   [$name]"
}

# The real defect: dig-node's required "Test + coverage" step before 5735c06. Default shell,
# `cargo ... | tee`, so the step reported tee's success.
case_ historical-defect fail <<'YML'
name: CI
jobs:
  test:
    name: Test + coverage
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: cargo llvm-cov nextest (test + coverage)
        run: |
          cargo llvm-cov nextest --workspace --locked --summary-only | tee coverage-summary.txt
YML

# `shell: bash` expands to `bash --noprofile --norc -eo pipefail {0}` — already safe. A gate that
# flagged this would be noise, and noise is how a gate gets disabled.
case_ explicit-shell-bash pass <<'YML'
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: piped but safe
        shell: bash
        run: |
          cargo test | tee out.txt
YML

case_ explicit-set-pipefail pass <<'YML'
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: piped but safe
        run: |
          set -euo pipefail
          cargo test | tee out.txt
YML

# THE case that separates a per-STEP gate from a per-FILE grep: step one is safe, step two is the
# defect. A file-level `grep -q pipefail` reports this workflow clean.
case_ mixed-steps fail <<'YML'
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: safe neighbour
        run: |
          set -o pipefail
          echo hi | tee a.txt
      - name: the real defect
        run: |
          cargo test | tee b.txt
YML

# `run: |` is a YAML block-scalar indicator, not a shell pipe; the body has no pipeline at all.
case_ block-scalar-not-a-pipe pass <<'YML'
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: no pipeline here
        run: |
          cargo test --workspace
          echo done
YML

case_ or-fallback-not-a-pipe pass <<'YML'
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: fallback, not a pipeline
        run: |
          cargo test || echo "failed"
YML

# A `|` inside quotes is data — a regex alternation — not a pipeline.
case_ quoted-alternation pass <<'YML'
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: alternation in a pattern
        run: |
          grep -E 'alpha|beta' notes.txt
YML

# An inherited shell is as good as a locally declared one.
case_ inherited-default pass <<'YML'
name: CI
defaults:
  run:
    shell: bash
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: piped, safe by inheritance
        run: |
          cargo test | tee out.txt
YML

# pwsh has its own status rules; this gate makes no claim about them.
case_ non-bash-shell-out-of-scope pass <<'YML'
name: CI
jobs:
  test:
    runs-on: windows-latest
    steps:
      - name: powershell pipeline
        shell: pwsh
        run: |
          Get-ChildItem | Out-File list.txt
YML

# A single-line `run:` hides the same defect and must not escape.
case_ inline-run fail <<'YML'
name: CI
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: inline and unsafe
        run: cargo test | tee out.txt
YML

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed"
  exit 1
fi
echo "all cases passed"
