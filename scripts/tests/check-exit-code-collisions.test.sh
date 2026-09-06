#!/usr/bin/env bash
#
# Tests for scripts/check-exit-code-collisions.sh -- the guard that refuses a dign exit code
# colliding with a diga one (or the reverse), and refuses either side drawing a code from the
# reserved shell signal range.
#
# The gate reads two things it does not own: its OWN file (a plain path, so these tests write real
# fixture files) and diga's outcome.rs (fetched live in production). The fetch is substituted with
# $DIGA_FILE (a local path, bypassing curl entirely) for every case that only needs to exercise the
# parsing/collision logic, and with a stubbed $CURL_BIN for the two cases that exist specifically to
# prove the real network path is wired correctly: a live fetch that succeeds, and one that fails.
#
# Every fixture uses NUMBERS AND NAMES OUT OF BAND of anything either real enum actually assigns
# (in the 40s-50s, spelled ZEROTH/SOLO/etc.) rather than copies of the real tables. This is
# deliberate: if the $DIGA_FILE/$CURL_BIN seam were ever silently bypassed and a case actually hit
# dig-app's live source, an assertion built on REAL numbers/names could coincidentally still pass
# (dig-app really does have 0=OK, 2=USAGE, ...). An assertion built on fictional data can only pass
# by reading the fixture, so a broken seam fails loudly instead of by coincidence.
#
# Each case is built to fail against the nearest WRONG gate, not merely to pass against the right
# one -- named at the case.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/../check-exit-code-collisions.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0

# write_fixture <path> <EnumName> <Variant>=<number>:<NAME> ...
#
# Writes a minimal Rust snippet shaped exactly like cli.rs/outcome.rs's own impl block: a code()
# match and a name() match, one arm per given variant, IN THE GIVEN ORDER for both functions.
write_fixture() {
  local path="$1" enum="$2"
  shift 2
  {
    echo "impl $enum {"
    echo "    pub const fn code(self) -> u8 {"
    echo "        match self {"
    local pair var rest num
    for pair in "$@"; do
      var="${pair%%=*}"; rest="${pair#*=}"; num="${rest%%:*}"
      echo "            $enum::$var => $num,"
    done
    echo "        }"
    echo "    }"
    echo
    echo "    pub const fn name(self) -> &'static str {"
    echo "        match self {"
    for pair in "$@"; do
      var="${pair%%=*}"; rest="${pair#*=}"
      local name="${rest#*:}"
      echo "            $enum::$var => \"$name\","
    done
    echo "        }"
    echo "    }"
    echo "}"
  } >"$path"
  echo "$path"
}

# Writes a stub `curl` that either `cat`s the given fixture (any arguments) or, when fixture is the
# sentinel path "UNREACHABLE", exits 22 -- the code curl's own `-f` returns on an HTTP error, so the
# gate sees the same failure shape a real network outage would produce.
stub_curl() {
  local name="$1" fixture="$2" path="$WORK/curl-$1"
  {
    echo '#!/usr/bin/env bash'
    if [ "$fixture" = "UNREACHABLE" ]; then
      echo 'exit 22'
    else
      # The stub is invoked as: curl -fsS --max-time 30 -A "$UA" "$URL" -o "$OUT". Find the -o
      # argument and copy the fixture there, exactly as a real fetch would deposit it.
      printf 'out=""\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done\ncat %q >"$out"\n' "$fixture"
    fi
  } >"$path"
  chmod +x "$path"
  echo "$path"
}

run_gate() {
  local dign="$1" diga_mode="$2" diga_arg="$3"
  case "$diga_mode" in
    file) DIGA_FILE="$diga_arg" bash "$GATE" "$dign" 2>&1 ;;
    curl) CURL_BIN="$diga_arg" bash "$GATE" "$dign" "https://example.invalid/outcome.rs" 2>&1 ;;
    *) echo "bad diga_mode $diga_mode" >&2; return 2 ;;
  esac
}

# expect <name> <expected-exit> <dign-fixture> <diga-mode> <diga-arg> [required-output-substring]
#
# The substring is what keeps a case load-bearing -- an exit code alone cannot say WHICH check
# fired, so a gate missing one check entirely could still satisfy an exit-code-only assertion via
# another.
expect() {
  local name="$1" want="$2" dign="$3" diga_mode="$4" diga_arg="$5" needle="${6:-}"
  local out status
  out="$(run_gate "$dign" "$diga_mode" "$diga_arg")"
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

check() { # check <name> <failure-message> <0-or-1>
  if [ "$3" -eq 0 ]; then
    printf 'ok   %s\n' "$1"
  else
    printf 'FAIL %s: %s\n' "$1" "$2"
    failures=$((failures + 1))
  fi
}

# --- shared control fixtures -----------------------------------------------------------------
# dign: one number shared-by-design with diga (Nought=40), two dign-exclusive numbers.
DIGN_OK="$(write_fixture "$WORK/dign-ok.rs" ExitCode Nought=40:NOUGHT Solo=41:SOLO Dozen=53:DOZEN)"
# diga: the SAME shared number under the SAME name, plus two diga-exclusive numbers -- no overlap
# with dign's exclusive numbers (41, 53).
DIGA_OK="$(write_fixture "$WORK/diga-ok.rs" ErrorCode Nought=40:NOUGHT Attached=48:ATTACHED Vexed=49:VEXED)"

# --- the honest control ------------------------------------------------------------------------
# Today's real shape (some shared-by-design numbers, some exclusive on each side) passes. Without
# this case, a gate that refused everything unconditionally would satisfy every failing case below.
expect 'today-shaped tables with no real collision pass' \
  0 "$DIGN_OK" file "$DIGA_OK" 'OK: no exit-code collision'

# --- a shared-by-design number must NOT be flagged ----------------------------------------------
# Nought=40 appears in BOTH tables under the SAME name. The nearest wrong gate here is one that
# flags any number appearing twice regardless of name -- which would fail on 0=OK/2=USAGE/6=IO_ERROR
# today and make the guard block every real PR. Covered by the same control case above; asserted
# explicitly here so it cannot be satisfied by chance.
out_ok="$(run_gate "$DIGN_OK" file "$DIGA_OK")"
check 'the shared-by-design number 40 is not reported as a collision' \
  'output mentions exit 40 as a problem' \
  "$(printf '%s' "$out_ok" | grep -q '::error::.*exit 40' && echo 1 || echo 0)"

# --- a number exclusive to one side must NOT be flagged -----------------------------------------
# The nearest wrong gate here requires every number to appear in BOTH tables -- which would fail on
# the real state today, where most numbers are exclusive to one binary.
check 'a dign-exclusive number (41) is not reported as a collision' \
  '::error:: mentioned exit 41' \
  "$(printf '%s' "$out_ok" | grep -q '::error::.*exit 41' && echo 1 || echo 0)"
check 'a diga-exclusive number (48) is not reported as a collision' \
  '::error:: mentioned exit 48' \
  "$(printf '%s' "$out_ok" | grep -q '::error::.*exit 48' && echo 1 || echo 0)"

# --- the actual defect class: the SAME number, a DIFFERENT name on each side --------------------
# Reproduces the dig-node#407 shape: dign adds 53 = DOZEN, unaware diga already holds 53 under a
# different name. Only ONE thing changes from the control fixture (diga gains one entry at the
# already-dign-occupied number 53) -- everything else stays the honest control, so the failure is
# attributable to that one change and not to some other difference between the fixtures.
DIGA_COLLIDE="$(write_fixture "$WORK/diga-collide.rs" ErrorCode Nought=40:NOUGHT Attached=48:ATTACHED Vexed=49:VEXED Cardinal=53:CARDINAL)"
collide_out="$(run_gate "$DIGN_OK" file "$DIGA_COLLIDE")"
collide_status=$?
check 'a real collision (53 = DOZEN vs 53 = CARDINAL) is refused' \
  "exit $collide_status, want 1" "$([ "$collide_status" -eq 1 ] && echo 0 || echo 1)"
check 'the message names the colliding number' \
  "$collide_out" "$(printf '%s' "$collide_out" | grep -q '::error::.*exit 53' && echo 0 || echo 1)"
check 'the message names BOTH conflicting names' \
  "$collide_out" "$(printf '%s' "$collide_out" | grep -q 'DOZEN' && printf '%s' "$collide_out" | grep -q 'CARDINAL' && echo 0 || echo 1)"

# --- variant-order independence -----------------------------------------------------------------
# code() and name() list their arms in DIFFERENT orders. The nearest wrong gate here is a positional
# zip (pairing the Nth code() arm with the Nth name() arm) instead of a join by variant -- which
# would silently cross-wire Solo's number with Nought's name. Written by hand rather than through
# write_fixture, which always emits both functions in the same order.
DIGN_REORDERED="$WORK/dign-reordered.rs"
cat >"$DIGN_REORDERED" <<'RUST'
impl ExitCode {
    pub const fn code(self) -> u8 {
        match self {
            ExitCode::Solo => 41,
            ExitCode::Nought => 40,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            ExitCode::Nought => "NOUGHT",
            ExitCode::Solo => "SOLO",
        }
    }
}
RUST
reordered_out="$(run_gate "$DIGN_REORDERED" file "$DIGA_OK")"
reordered_status=$?
check 'reordered code()/name() arms still pass (join by variant, not position)' \
  "exit $reordered_status, want 0" "$([ "$reordered_status" -eq 0 ] && echo 0 || echo 1)"
check 'the printed table pairs 41 with SOLO, not with NOUGHT' \
  "$reordered_out" "$(printf '%s' "$reordered_out" | grep -q '41 SOLO' && echo 0 || echo 1)"
check 'the printed table pairs 40 with NOUGHT, not with SOLO' \
  "$reordered_out" "$(printf '%s' "$reordered_out" | grep -q '40 NOUGHT' && echo 0 || echo 1)"

# --- arm-count mismatch inside one file is refused, not silently under-read --------------------
# code() lists two arms; name() lists only one (Solo's name arm is missing). A parser that silently
# drops the unmatched arm would report a false "no collision" for a code it never actually saw --
# the same enumeration-blind-spot risk a gate over an incomplete list always has.
DIGN_MISSING_NAME="$WORK/dign-missing-name.rs"
cat >"$DIGN_MISSING_NAME" <<'RUST'
impl ExitCode {
    pub const fn code(self) -> u8 {
        match self {
            ExitCode::Nought => 40,
            ExitCode::Solo => 41,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            ExitCode::Nought => "NOUGHT",
        }
    }
}
RUST
expect 'an arm missing from name() is refused, not silently dropped' \
  1 "$DIGN_MISSING_NAME" file "$DIGA_OK" 'missing from one function'

# --- the reserved shell range, pinned from BOTH sides -------------------------------------------
# 125 is one below the first reserved value and MUST pass; 126 is the first reserved value and MUST
# fail. A bound tested only from below (only 125, or only some number well above 126) could not
# distinguish the shipped floor of 126 from an off-by-one at 127.
DIGN_125="$(write_fixture "$WORK/dign-125.rs" ExitCode Nought=40:NOUGHT Reach=125:REACH)"
expect 'exit 125 (one below the reserved floor) passes' \
  0 "$DIGN_125" file "$DIGA_OK" 'OK: no exit-code collision'

DIGN_126="$(write_fixture "$WORK/dign-126.rs" ExitCode Nought=40:NOUGHT Over=126:OVER)"
expect 'exit 126 (the reserved floor itself) is refused' \
  1 "$DIGN_126" file "$DIGA_OK" 'shell-reserved range'

DIGN_200="$(write_fixture "$WORK/dign-200.rs" ExitCode Nought=40:NOUGHT Signalled=200:SIGNALLED)"
expect 'exit 200 (deep in 128+N) is refused -- the rule is a RANGE, not just 126/127' \
  1 "$DIGN_200" file "$DIGA_OK" 'shell-reserved range'

# --- the live-fetch path itself, not just the $DIGA_FILE bypass ---------------------------------
# Every case above skips curl entirely via $DIGA_FILE. These two exercise the REAL default code
# path (the -o argument parsing, the URL being passed through) so a bug in the fetch wiring itself
# -- not just the parsing logic -- cannot hide behind the test seam.
expect 'a live fetch that succeeds is read and checked like any other source' \
  0 "$DIGN_OK" curl "$(stub_curl ok "$DIGA_OK")" 'OK: no exit-code collision'

expect 'a live fetch that fails closes the gate rather than passing vacuously' \
  1 "$DIGN_OK" curl "$(stub_curl down UNREACHABLE)" 'could not fetch'

# --- fail-closed on bad local inputs --------------------------------------------------------------
EMPTY_DIGA="$WORK/empty-diga.rs"
: >"$EMPTY_DIGA"
expect 'an empty diga fixture is refused, not read as "diga has no codes"' \
  1 "$DIGN_OK" file "$EMPTY_DIGA" 'empty'

expect 'a missing dign file is refused' \
  1 "$WORK/no-such-file.rs" file "$DIGA_OK" 'not found'

if [ "$failures" -ne 0 ]; then
  printf '\n%s case(s) failed\n' "$failures"
  exit 1
fi
printf '\nall cases passed\n'
