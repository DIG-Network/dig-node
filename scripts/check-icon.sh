#!/usr/bin/env bash
# Assert the vendored DIG application icon is the canonical, byte-identical one.
#
# `assets/dig.ico` is deliberately vendored rather than pulled from a shared
# package: it changes approximately never, and a vendored copy costs no
# release-first cascade. The trade is that drift becomes possible, so this
# check makes drift LOUD — any re-save, re-export or "optimization" changes the
# hash and fails the build here instead of shipping a subtly different mark.
#
# The same literal is pinned in every DIG repo that vendors these bytes, so a
# mismatch means either this repo drifted or the icon was regenerated and every
# sibling repo must be updated in the same unit of work.
#
# Run from the repo root: scripts/check-icon.sh
set -euo pipefail

readonly ICON="assets/dig.ico"
readonly EXPECTED_SHA256="2f0fb11a1254fc9275248dc340b7aa9c7236484a9531f8aaad2e4bcdf8900096"

if [[ ! -f "$ICON" ]]; then
  echo "FAIL: $ICON is missing." >&2
  exit 1
fi

actual="$(sha256sum "$ICON" | cut -d' ' -f1)"

if [[ "$actual" != "$EXPECTED_SHA256" ]]; then
  echo "FAIL: $ICON has drifted from the canonical DIG icon." >&2
  echo "  expected sha256: $EXPECTED_SHA256" >&2
  echo "  actual   sha256: $actual" >&2
  echo "Restore the canonical bytes; do not re-save or re-export the icon." >&2
  exit 1
fi

echo "OK: $ICON matches the canonical DIG icon ($EXPECTED_SHA256)."
