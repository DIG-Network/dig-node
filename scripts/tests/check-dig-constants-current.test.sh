#!/usr/bin/env bash
#
# Tests for scripts/check-dig-constants-current.sh — the release gate that refuses a stable tag when
# any dig-constants copy predates 0.4.0, the release carrying the real DIG L2 genesis challenge, and
# that WARNS (without blocking) on duplication or on a newer published release.
#
# The gate reads two things it does not own: a Cargo.lock and the crates.io sparse index. The lock is
# a plain file, so these tests write real ones. The index read is substituted with a STUB curl
# (`$CURL_BIN`) so every case is deterministic, runs offline, and can express the one input a live
# network can never be asked for on demand: a read FAILURE.
#
# Each case is built to fail against the nearest WRONG gate, not merely to pass against the right
# one — the specific wrong gate each case rules out is named at that case. The three nearest wrong
# gates for THIS rule, each covered below, are: one that checks `!= "0.1.0"` instead of a floor; one
# that still blocks on duplication; and one that reports the floor breach without saying which
# package pulled the bad copy in, which is the only part of the message that makes it actionable.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/../check-dig-constants-current.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0

# The published state of dig-constants that the advisory cases are measured against: 9.9.0 is the
# tip, and a LATER 9.10.0 exists but is YANKED. Both facts are load-bearing (see the yanked case).
# Shape matches the real sparse index: one JSON object per line, ascending by publish order.
#
# The versions are deliberately OUT OF BAND of anything dig-constants will really publish. That is
# what keeps the `$CURL_BIN` stub load-bearing: if the seam were ever removed and the gate went back
# to reading the live index, it would compute the real tip and the `published tip : 9.9.0` assertion
# below would stop matching — instead of the case quietly passing against the network.
INDEX_TIP="$WORK/index-tip-9.9.0"
cat >"$INDEX_TIP" <<'EOF'
{"name":"dig-constants","vers":"9.7.0","yanked":false}
{"name":"dig-constants","vers":"9.9.0","yanked":false}
{"name":"dig-constants","vers":"9.10.0","yanked":true}
EOF

# An index read that FAILS the way a real one does: no body, non-zero exit.
INDEX_UNREACHABLE="$WORK/index-unreachable"
: >"$INDEX_UNREACHABLE"

# Writes a stub `curl` that emits the given fixture file and echoes the stub's path. A fixture of
# INDEX_UNREACHABLE makes the stub exit 22 with no output, as curl does on an HTTP error.
stub_curl() {
  local name="$1" fixture="$2" path="$WORK/curl-$1"
  {
    echo '#!/usr/bin/env bash'
    if [ "$fixture" = "$INDEX_UNREACHABLE" ]; then
      echo 'exit 22'
    else
      printf 'cat %q\n' "$fixture"
    fi
  } >"$path"
  chmod +x "$path"
  echo "$path"
}

# stub_lock <fixture-name> <holder>=<version> ...
#
# Writes a Cargo.lock holding one dig-constants package per given version, plus the named holder
# package depending on it, and echoes the path. The dependency entry is written the way CARGO writes
# it: BARE (`"dig-constants"`) when exactly one version resolves, DISAMBIGUATED
# (`"dig-constants 0.5.1"`) when several do. Both forms are therefore exercised, which matters —
# holder attribution that only handled the disambiguated form would silently name nobody in the
# single-copy case, the one where a floor breach is most likely to be a direct dependency.
#
# Every fixture is padded with NEIGHBOURING packages, including `dig-constants-derive` — a name that
# CONTAINS the crate's name. A gate matching the package name by substring instead of equality would
# see a phantom extra version and fail even the honest case.
stub_lock() {
  local name="$1" path="$WORK/lock-$1" pair holder ver
  shift
  local -a holders=() vers=()
  for pair in "$@"; do
    holders+=("${pair%%=*}")
    vers+=("${pair##*=}")
  done
  {
    echo 'version = 4'
    echo
    echo '[[package]]'
    echo 'name = "dig-constants-derive"'
    echo 'version = "0.3.0"'
    echo ' dependencies = ['
    echo ' "serde",'
    echo ']'
    echo
    for ver in "${vers[@]}"; do
      echo '[[package]]'
      echo 'name = "dig-constants"'
      echo "version = \"$ver\""
      echo 'source = "registry+https://github.com/rust-lang/crates.io-index"'
      echo
    done
    local i
    for i in "${!holders[@]}"; do
      [ -n "${holders[$i]}" ] || continue
      echo '[[package]]'
      echo "name = \"${holders[$i]}\""
      echo 'version = "1.0.0"'
      echo 'dependencies = ['
      # Cargo omits the version when it is unambiguous, and only then.
      if [ "${#vers[@]}" -eq 1 ]; then
        echo ' "dig-constants",'
      else
        echo " \"dig-constants ${vers[$i]}\","
      fi
      echo ' "serde",'
      echo ']'
      echo
    done
    echo '[[package]]'
    echo 'name = "serde"'
    echo 'version = "1.0.200"'
  } >"$path"
  echo "$path"
}

run_gate() {
  local name="$1" lock="$2" fixture="$3" curl_bin
  curl_bin="$(stub_curl "$name" "$fixture")"
  CURL_BIN="$curl_bin" bash "$GATE" "$lock" 2>&1
}

# expect <name> <expected-exit> <lock> <index-fixture> [required-output-substring]
#
# The substring is what keeps a case load-bearing. An exit code alone cannot tell WHICH check fired,
# so a gate that had lost one check entirely would still satisfy an exit-code-only assertion via
# another. Asserting the reason pins the individual check.
expect() {
  local name="$1" want="$2" lock="$3" fixture="$4" needle="${5:-}"
  local out status
  out="$(run_gate "$name" "$lock" "$fixture")"
  status=$?
  if [ "$status" -ne "$want" ]; then
    printf 'FAIL %s: exit %s, want %s\n%s\n' "$name" "$status" "$want" "$out"
    failures=$((failures + 1))
    return
  fi
  if [ -n "$needle" ] && ! printf '%s' "$out" | grep -qF -- "$needle"; then
    printf 'FAIL %s: output missing %q\n%s\n' "$name" "$needle" "$out"
    failures=$((failures + 1))
    return
  fi
  printf 'ok   %s\n' "$name"
}

check() { # check <name> <condition-description> <0-or-1 from a test expression>
  if [ "$3" -eq 0 ]; then
    printf 'ok   %s\n' "$1"
  else
    printf 'FAIL %s: %s\n' "$1" "$2"
    failures=$((failures + 1))
  fi
}

# --- the honest control -------------------------------------------------------------------------
# One copy, above the floor, PASSES. Without this case a gate that refused everything unconditionally
# would satisfy every blocking case in this file.
expect 'a single copy above the floor passes' \
  0 "$(stub_lock ok dig-node-core=0.9.0)" "$INDEX_TIP" 'OK: every'

# --- the floor blocks ----------------------------------------------------------------------------
# The placeholder-genesis release itself. This is the defect the gate exists for.
expect 'the 0.1.0 placeholder-genesis copy is refused' \
  1 "$(stub_lock placeholder dig-clvm=0.1.0)" "$INDEX_TIP" 'predates 0.4.0'

# THE CLASS, NOT THE INSTANCE. 0.3.0 was never the release anyone talked about, and it carries the
# same all-zeros placeholder. This case is what separates the shipped floor from the nearest wrong
# gate — a `!= "0.1.0"` check — which passes this lock happily and lets the placeholder through
# under a different version number.
expect 'a 0.3.0 copy is refused too: the rule is a floor, not != 0.1.0' \
  1 "$(stub_lock threedotoh dig-clvm=0.3.0)" "$INDEX_TIP" 'predates 0.4.0'

# THE BOUND, FROM BOTH SIDES. 0.3.9 is one release under the floor and must FAIL; 0.4.0 is the floor
# itself and must PASS. A bound tested only from below can confirm nothing but itself — an
# off-by-one floor of 0.5.0 would satisfy the failing half of this pair and be caught only here.
expect 'one release under the floor fails' \
  1 "$(stub_lock justunder dig-clvm=0.3.9)" "$INDEX_TIP" 'predates 0.4.0'
expect 'the floor release itself passes' \
  0 "$(stub_lock atfloor dig-clvm=0.4.0)" "$INDEX_TIP" 'OK: every'

# --- the floor names the holder ------------------------------------------------------------------
# Single copy: cargo writes the dependency entry BARE, so attribution has to resolve it against the
# one resolved version rather than parse a version out of the string.
expect 'a floor breach names the holder even when the lock entry is unversioned' \
  1 "$(stub_lock namedsingle dig-clvm=0.1.0)" "$INDEX_TIP" 'pulled in by: dig-clvm'

# Multiple copies, ONE of them below the floor. Two properties at once, and the second is the one a
# looser assertion would miss: the error must name dig-clvm — the holder OF THE BAD COPY — and must
# NOT name dig-gossip, which holds a perfectly fine 0.9.0. A gate that simply printed every
# dig-constants consumer would satisfy a "contains dig-clvm" check while telling the reader nothing
# about which dependency to bump, and dig-gossip appears elsewhere in this same output (in the
# duplicate warning), so the assertion is scoped to the ::error:: lines.
mixed_out="$(run_gate mixed "$(stub_lock mixed dig-clvm=0.1.0 dig-gossip=0.9.0)" "$INDEX_TIP")"
mixed_status=$?
mixed_errors="$(printf '%s\n' "$mixed_out" | grep '::error::')"
check 'a mixed lock is refused for the sub-floor copy' \
  "exit $mixed_status, want 1" "$([ "$mixed_status" -eq 1 ] && echo 0 || echo 1)"
check 'the error attributes the breach to the holder of the BAD copy' \
  "::error:: lines did not name dig-clvm: $mixed_errors" \
  "$(printf '%s' "$mixed_errors" | grep -q 'pulled in by: dig-clvm' && echo 0 || echo 1)"
check 'the error does NOT name the holder of the healthy copy' \
  "::error:: lines wrongly named dig-gossip: $mixed_errors" \
  "$(printf '%s' "$mixed_errors" | grep -q 'dig-gossip' && echo 1 || echo 0)"

# --- duplication warns, and does not block -------------------------------------------------------
# Four copies, ALL at or above the floor — the shape of dig-node's real lock today (0.4.0 / 0.5.1 /
# 0.8.0 / 0.9.0, after #199 removed the 0.1.0 copy). It must report the duplication and still exit 0.
#
# Two things are asserted here that an exit-code check alone would not distinguish. First, that the
# duplication is REPORTED at all: a gate that had simply deleted the duplicate check would also exit
# 0 on this lock. Second, that it is reported as a ::warning:: and not an ::error::, since a GitHub
# annotation typed as an error reads as a failure to every human looking at the run even when the
# step is green.
dup_lock="$(stub_lock dup dig-gossip=0.4.0 dig-nat=0.5.1 dig-download=0.8.0 dig-node-core=0.9.0)"
dup_out="$(run_gate dup "$dup_lock" "$INDEX_TIP")"
dup_status=$?
check "today's real four-copy lock does NOT block the release" \
  "exit $dup_status, want 0" "$([ "$dup_status" -eq 0 ] && echo 0 || echo 1)"
check 'the duplication is still reported' \
  'no duplicate report in output' \
  "$(printf '%s' "$dup_out" | grep -q 'resolves to 4 DIFFERENT versions' && echo 0 || echo 1)"
check 'the duplicate report is a warning annotation, not an error one' \
  "duplication was annotated ::error::: $dup_out" \
  "$(printf '%s' "$dup_out" | grep -q '::error::.*DIFFERENT versions' && echo 1 || echo 0)"
# And it is ACTIONABLE: each copy is attributed to the package that pins it, from this same lock.
# Without this, the warning tells a reader that four copies exist and gives them nowhere to start.
for holder in dig-gossip dig-nat dig-download dig-node-core; do
  check "the duplicate warning names $holder" \
    "$holder missing from the warning" \
    "$(printf '%s' "$dup_out" | grep -q "::warning::.*$holder" && echo 0 || echo 1)"
done

# --- the index is advisory only ------------------------------------------------------------------
# An unreadable index must NOT block. The gate's blocking input is the lock alone, and this lock is
# healthy; refusing here would hand anyone who can induce a network error the power to stop releases,
# which is the same unsatisfiability the floor re-scope exists to remove. It must still SAY that it
# could not check, so a silently-degraded run is distinguishable from a clean one.
expect 'an unreadable crates.io index warns but does not block' \
  0 "$(stub_lock ok2 dig-node-core=0.9.0)" "$INDEX_UNREACHABLE" 'could not read the crates.io sparse index'

# A newer published release is reported, and does not block. This is the whole point of the
# re-scope: 9.9.0 is published, the lock is at 0.9.0, and the release proceeds.
expect 'a newer published release is reported without blocking' \
  0 "$(stub_lock ok3 dig-node-core=0.9.0)" "$INDEX_TIP" '::warning::dig-constants 9.9.0 is published'

# 9.10.0 is published but yanked, so the tip is 9.9.0. A gate taking the last index line without
# filtering would report 9.10.0 — advising an upgrade to a version nobody should depend on. This is
# also the case that keeps the `$CURL_BIN` seam load-bearing for the file: the asserted tip is
# out of band, so it can only have come from the stub.
expect 'a yanked later version is not treated as the tip' \
  0 "$(stub_lock ok4 dig-node-core=0.9.0)" "$INDEX_TIP" 'published tip : 9.9.0'

# --- the lock, in contrast, fails closed ---------------------------------------------------------
# The crate missing from the lock is refused, not silently passed. An empty result set is the classic
# vacuous green: "no copy is below the floor" is trivially TRUE of no copies at all.
expect 'a lock with no dig-constants at all is refused, not vacuously passed' \
  1 "$(stub_lock absent)" "$INDEX_TIP" 'does not appear in'

expect 'a missing lockfile is refused' \
  1 "$WORK/no-such-lock" "$INDEX_TIP" 'not found'

if [ "$failures" -ne 0 ]; then
  printf '\n%s case(s) failed\n' "$failures"
  exit 1
fi
printf '\nall cases passed\n'
