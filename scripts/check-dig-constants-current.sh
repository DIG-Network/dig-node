#!/usr/bin/env bash
# check-dig-constants-current.sh — refuse a release if any dig-constants copy predates the real
# DIG L2 genesis challenge. Warn, but do not block, on duplication or on a newer published release.
#
# WHY THIS EXISTS — the defect it is built around
#
# dig-constants 0.1.0 shipped an all-zeros PLACEHOLDER `DIG_MAINNET_GENESIS_CHALLENGE`, and derived
# all six AGG_SIG additional-data domains FROM that placeholder. The result was self-consistent: every
# runtime check reads `dig_constants::DIG_MAINNET.genesis_challenge()` on both sides of its own
# comparison, so the placeholder passed identically to the real value. No test could see it. It
# reached production through a `dig-clvm` git rev into dig-wallet's spend validator (dig_ecosystem#2316).
#
# 0.4.0 is the first release carrying the real value (`0af98186…`, the header hash of DIG L2 block
# 9021277) with all six domains recomputed from it. That is the FLOOR this gate blocks on.
#
# WHY A FLOOR, NOT `!= "0.1.0"`, AND NOT "EQUALS THE PUBLISHED TIP"
#
#   • Not an equality check against one bad release: 0.2.x and 0.3.x carry the same placeholder, so
#     `!= "0.1.0"` is bypassed by the next pre-0.4.0 version to appear. The property is "no copy
#     predating the real genesis", and it is stated over that CLASS.
#
#   • Not "equals the published tip": that condition is structurally unreachable here, so a gate
#     keyed to it does not protect a property — it periodically bans releasing. dig-constants 0.10.0
#     moved to chia-protocol 0.36.1 / chia-wallet-sdk 0.34 while dig-node builds on 0.26 / 0.30,
#     including the chia-protocol fork dig-gossip vendors through `[patch.crates-io]`. Depending on
#     0.10 links a SECOND chia_protocol and produces 11 type errors of the form
#     `expected BytesImpl<32>, found chia_protocol::bytes::BytesImpl<32>`. That recurs on every
#     chia-line jump, for every consumer, forever.
#
#   • And it costs nothing to drop: every release from 0.4.0 up is value-NEUTRAL for dig-node — the
#     full `DIG_MAINNET` const body is byte-identical across 0.4.0 / 0.5.1 / 0.8.0 / 0.9.0. So the
#     floor catches the real defect exactly, and tip-equality only ever caught it incidentally.
#
# This is the same rule `crates/dig-node-core/tests/dependency_tree.rs` asserts at lock level
# (`no_dig_constants_copy_predates_the_real_genesis_challenge`) — ONE property, enforced at two
# levels, worded the same way on purpose.
#
# WHY DUPLICATION ONLY WARNS
#
# Duplication is real: cargo cannot unify semver-incompatible 0.x minors, so several copies link into
# one binary, each serving a different subsystem. But dig-node cannot fix it — the copies are pinned
# by PUBLISHED metadata a consumer cannot edit (dig-gossip `>=0.2,<0.5`, dig-nat 0.18.0,
# digstore-chain `^0.5`, dig-download 0.17.0); collapsing them needs five cross-repo publishes
# (dig_ecosystem#2072). A gate that blocks on a condition only ANOTHER repo can fix gets bypassed the
# first time someone needs a release, and a bypassed gate is worse than a warning: it teaches its
# readers that the gate is noise. So this reports duplication loudly, NAMES THE HOLDERS so it is
# actionable, and lets the release proceed. Promote it to blocking once #2072 lands.
#
# WHAT IT READS — the LOCK, not the manifest range. `dig-constants = "0.4"` is "satisfied" by a lock
# at 0.4.0 forever; only the lock says what actually compiles in. The holder names in the warning are
# derived from that same lock (cargo disambiguates `"dig-constants 0.5.1"` in a dependency list
# precisely when more than one version resolves), never from a hand-maintained second list that could
# drift away from what is really in the graph.
#
# FAIL-CLOSED, and on WHICH input. The blocking check reads only the lock, so the lock is what fails
# closed: a missing lockfile, or one with no dig-constants in it at all, is REFUSED rather than
# vacuously passed ("no copy is below the floor" is trivially true of no copies). The crates.io index
# now feeds only the advisory newer-release notice, so an unreadable index degrades to a warning —
# blocking a release on a network blip for a purely informational clause would reintroduce exactly
# the unsatisfiability this gate was re-scoped to remove.
#
# Usage:  bash scripts/check-dig-constants-current.sh [path/to/Cargo.lock]
# Exit:   0 = every copy is at or above the floor;  1 = a copy predates it, or the lock is unusable.

set -uo pipefail

LOCK="${1:-Cargo.lock}"
CRATE="dig-constants"
UA="dig-node-ci/1.0 (https://github.com/DIG-Network/dig-node; release gate)"

# The release in which dig-constants replaced the placeholder genesis challenge with the real one.
FLOOR="0.4.0"

[ -f "$LOCK" ] || { echo "::error::$LOCK not found"; exit 1; }

# Every version of the crate present in the resolved graph. Matched on the package NAME field by
# equality, so a neighbour like `dig-constants-derive` cannot register as a phantom extra copy.
mapfile -t FOUND < <(awk -v c="$CRATE" '
  /^\[\[package\]\]/ { name=""; ver="" }
  /^name = / { gsub(/^name = "|"$/,""); name=$0 }
  /^version = / { gsub(/^version = "|"$/,""); ver=$0; if (name==c) print ver }
' "$LOCK" | sort -uV)

if [ "${#FOUND[@]}" -eq 0 ]; then
  echo "::error::$CRATE does not appear in $LOCK at all. If dig-node genuinely no longer depends on it, delete this gate deliberately rather than letting it pass silently."
  exit 1
fi

# Which packages depend on which copy, read out of the lock itself.
#
# Cargo writes a bare `"dig-constants"` in a dependency list when the version is unambiguous, and
# `"dig-constants 0.5.1"` when more than one resolves — so the disambiguated form is available in
# exactly the case the duplicate warning needs it. The bare form is emitted as `?` and resolved
# below against the single version that must then be present.
holders_of() {
  local want="$1"
  awk -v c="$CRATE" -v want="$want" -v sole="${FOUND[0]}" '
    /^\[\[package\]\]/ { name=""; indeps=0 }
    /^name = / { n=$0; gsub(/^name = "|"$/,"",n); name=n }
    /^dependencies = \[/ { indeps=1; next }
    indeps && /^\]/ { indeps=0; next }
    indeps {
      dep=$0
      gsub(/^[ \t]*"/,"",dep); gsub(/",?[ \t]*$/,"",dep)
      if (dep == c) { if (sole == want) print name }
      else if (index(dep, c " ") == 1 && substr(dep, length(c)+2) == want) print name
    }
  ' "$LOCK" | sort -u | paste -sd, - | sed 's/,/, /g'
}

# Numeric major.minor.patch compare: prints "lt" if $1 sorts strictly below $2.
version_lt() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]
}

echo "in this lock  : ${FOUND[*]}"

rc=0

# --- BLOCKING: the genesis floor ----------------------------------------------------------------
for v in "${FOUND[@]}"; do
  if version_lt "$v" "$FLOOR"; then
    holders="$(holders_of "$v")"
    echo "::error::$CRATE $v predates $FLOOR, the release that replaced the PLACEHOLDER all-zeros DIG L2 genesis challenge with the real one. A copy below that floor puts a different chain identity — and six differently-derived AGG_SIG domains — inside this binary, and no test can see it, because every runtime check compares the constant against itself."
    echo "::error::pulled in by: ${holders:-<no dependent found in $LOCK; it is a direct or root dependency>}. Bump that consumer; a 0.x minor gap is semver-BREAKING, so a caret range will never resolve forward on its own."
    rc=1
  fi
done

# --- ADVISORY: more than one copy in one binary --------------------------------------------------
if [ "${#FOUND[@]}" -gt 1 ]; then
  echo "::warning::$CRATE resolves to ${#FOUND[@]} DIFFERENT versions in one binary: ${FOUND[*]}"
  for v in "${FOUND[@]}"; do
    echo "::warning::  $v <- $(holders_of "$v")"
  done
  echo "::warning::cargo cannot unify semver-incompatible 0.x minors, so each copy is linked into a different subsystem and they can disagree about a value that is meant to be canonical by construction. This does not block the release: the holders above pin their copies in PUBLISHED metadata that dig-node cannot edit, and collapsing them takes a cross-repo publish cascade (dig_ecosystem#2072). Every copy at or above $FLOOR agrees on the chain identity, which is why this is a warning and the floor above is not."
fi

# --- ADVISORY: a newer release exists ------------------------------------------------------------
# The published tip, from the sparse index. A bare curl 403s here — the descriptive User-Agent is
# mandatory, not decoration. `$CURL_BIN` is a test seam, matching check-glibc-floor.sh's
# `$READELF_BIN`; it lets the tests pin an exact index response, including the read FAILURE that a
# live network cannot be asked to produce on demand.
name_len=${#CRATE}
if   [ "$name_len" -le 2 ]; then path="$name_len/$CRATE"
elif [ "$name_len" -eq 3 ]; then path="3/${CRATE:0:1}/$CRATE"
else path="${CRATE:0:2}/${CRATE:2:2}/$CRATE"
fi

body="$("${CURL_BIN:-curl}" -sS --max-time 30 -A "$UA" "https://index.crates.io/$path" 2>/dev/null)" || body=""
LATEST="$(printf '%s' "$body" | grep -v '"yanked":true' | sed -n 's/.*"vers":"\([^"]*\)".*/\1/p' | sort -V | tail -1)"

if [ -z "$LATEST" ]; then
  echo "::warning::could not read the crates.io sparse index for $CRATE, so this run cannot say whether a newer release exists. Advisory only — the blocking check above reads the lock alone and has already run."
else
  echo "published tip : $LATEST"
  newest="${FOUND[${#FOUND[@]}-1]}"
  if version_lt "$newest" "$LATEST"; then
    echo "::warning::$CRATE $LATEST is published; the newest copy here is $newest. Adopt it only if it stays on this repo's chia line — a dig-constants release that jumps chia-protocol/chia-wallet-sdk links a second chia_protocol into the graph and will not compile against the vendored fork."
  fi
fi

if [ "$rc" -eq 0 ]; then
  echo "OK: every $CRATE copy is at or above the $FLOOR genesis floor."
fi
exit "$rc"
