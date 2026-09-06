#!/usr/bin/env bash
# check-exit-code-collisions.sh -- refuse a dign exit code that collides with a diga one (or the
# reverse), and refuse either side drawing a code from the reserved shell signal range.
#
# WHY THIS EXISTS (dig_ecosystem#3189)
#
# `dign` (this repo's ExitCode, crates/dig-node-service/src/cli.rs) and `diga` (dig-app's
# ErrorCode, crates/dig-app-core/src/gateway/outcome.rs) deliberately share ONE numbering -- the
# diga source says so in its own doc comment ("share the engine CLI's numbers so the two command
# lines agree") -- which means a number is free only if it is unoccupied ECOSYSTEM-WIDE. Checking
# only this repo's own table proves nothing about the other one.
#
# dig-node#407 assigned exit 7 to NODE_UNREACHABLE by reading only this file's own table, where 7
# genuinely was the next free number. It was not free: dig-app's gateway already held 7 =
# NOT_CONNECTED. A reviewer caught it by hand; nothing failed automatically. The identical mistake
# already cost a real yank in a different number space (dig-rpc-protocol's JSON-RPC `-32015`,
# chosen as "the next free code" from its own list, collided with a released
# `METADATA_TOO_LARGE`). Twice is a pattern, and this is the gate instead of the third note.
#
# WHAT IT READS -- THE LIVE SOURCE, NEVER A TRANSCRIPTION
#
# Both tables are parsed straight out of each enum's own code()/name() match arms, at the moment
# this runs. This repo's test suite ALSO carries a hand-transcribed copy of the diga table
# (cli.rs's `no_exit_code_collides_with_the_dig_app_gateway_numbering`) -- correct the day it was
# written, and silently stale the moment diga's table changes without that copy being updated
# too. Reading the live source removes that copy instead of merely re-checking it: dig-node MUST
# NOT take a Cargo dependency on dig-app (cli.rs says so -- it is the engine, not a consumer of its
# own client), so "live" here means a CI-time read of dig-app's published source, not a compiled
# one.
#
# A THIRD NUMBER SPACE EXISTS AND IS DELIBERATELY NOT COVERED HERE: the extension's
# `WALLET_WS_ERR.NOT_CONNECTED = -33001` is a JSON-RPC error code, not a process exit code. It is
# not a rival of this namespace -- it is a separate space with no shared table at all, and nothing
# above should be read as claiming otherwise.
#
# Usage:  bash scripts/check-exit-code-collisions.sh [dign-cli-rs] [diga-outcome-rs-url]
#           dign-cli-rs          default: crates/dig-node-service/src/cli.rs
#           diga-outcome-rs-url  default: dig-app's outcome.rs, raw, at its default branch
# Env:    DIGA_FILE  read diga's table from this LOCAL file instead of fetching the URL argument
#                    (the scripts/tests harness uses this to stay hermetic).
#         CURL_BIN   use this in place of `curl` for the live fetch (tests use this to stub the
#                    network, including the one input a live network cannot be asked to produce on
#                    demand: a read failure).
# Exit:   0 = no collision and no reserved-range violation.
#         1 = a collision, a reserved-range violation, an unreadable table, or a fetch failure -- a
#             fetch failure MUST NOT be read as "diga has no codes", which would silently disable
#             the whole guard the moment GitHub's raw-content endpoint has a bad day.

set -uo pipefail

DIGN_FILE="${1:-crates/dig-node-service/src/cli.rs}"
DIGA_URL="${2:-https://raw.githubusercontent.com/DIG-Network/dig-app/main/crates/dig-app-core/src/gateway/outcome.rs}"
UA="dig-node-ci/1.0 (https://github.com/DIG-Network/dig-node; exit-code collision gate)"

[ -f "$DIGN_FILE" ] || { echo "::error::$DIGN_FILE not found -- dign's own ExitCode table is unreadable"; exit 1; }

WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT

if [ -n "${DIGA_FILE:-}" ]; then
  diga_file="$DIGA_FILE"
  [ -f "$diga_file" ] || { echo "::error::\$DIGA_FILE=$diga_file not found"; exit 1; }
else
  WORK="$(mktemp -d)"
  diga_file="$WORK/outcome.rs"
  # --retry: this check becomes a REQUIRED status check, so a single transient GitHub outage
  # must not be indistinguishable from a real collision -- two retries buys resilience without
  # weakening the fail-closed contract (a fetch that still fails after retrying still exits 1).
  if ! "${CURL_BIN:-curl}" -fsS --max-time 30 --retry 2 --retry-delay 2 -A "$UA" "$DIGA_URL" -o "$diga_file" 2>/dev/null; then
    echo "::error::could not fetch $DIGA_URL -- refusing to pass on an unreadable diga table (a fetch failure must never be read as \"diga has no codes\")"
    exit 1
  fi
fi
[ -s "$diga_file" ] || { echo "::error::diga source ($diga_file) is empty"; exit 1; }

# extract_table <file> <EnumName>
#
# Prints "NUMBER NAME" pairs read from the enum's own code()/name() match arms, joined by VARIANT
# -- not by position -- so the two functions are never required to list their arms in the same
# order. Fails (return 1, message on stderr) rather than silently returning a partial table when
# either function is unreadable or the two disagree on how many variants they cover: an
# enumeration check can only be as complete as the enumeration it read, and a parser that quietly
# dropped an arm would report a false "no collision" for the code it never saw.
extract_table() {
  local file="$1" enum="$2" numbers names n_count m_count joined j_count

  numbers="$(sed -n "/pub const fn code(/,/^    }\$/p" "$file" \
    | grep -oE "${enum}::[A-Za-z0-9_]+[[:space:]]*=>[[:space:]]*[0-9]+" \
    | sed -E "s/${enum}::([A-Za-z0-9_]+)[[:space:]]*=>[[:space:]]*([0-9]+)/\1 \2/" \
    | sort)"
  names="$(sed -n "/pub const fn name(/,/^    }\$/p" "$file" \
    | grep -oE "${enum}::[A-Za-z0-9_]+[[:space:]]*=>[[:space:]]*\"[A-Z_]+\"" \
    | sed -E "s/${enum}::([A-Za-z0-9_]+)[[:space:]]*=>[[:space:]]*\"([A-Z_]+)\"/\1 \2/" \
    | sort)"

  n_count="$(printf '%s\n' "$numbers" | grep -c .)"
  m_count="$(printf '%s\n' "$names" | grep -c .)"
  if [ "$n_count" -eq 0 ] || [ "$m_count" -eq 0 ]; then
    echo "::error::found no $enum arms in $file (code(): $n_count, name(): $m_count) -- the parser or the file has drifted" >&2
    return 1
  fi

  joined="$(join <(printf '%s\n' "$numbers") <(printf '%s\n' "$names") | awk '{print $2, $3}')"
  j_count="$(printf '%s\n' "$joined" | grep -c .)"
  if [ "$n_count" -ne "$m_count" ] || [ "$j_count" -ne "$n_count" ]; then
    echo "::error::$enum in $file: code() has $n_count arm(s), name() has $m_count, only $j_count joined by variant -- some variant is missing from one function" >&2
    return 1
  fi

  printf '%s\n' "$joined"
}

DIGN_TABLE="$(extract_table "$DIGN_FILE" ExitCode)" || exit 1
DIGA_TABLE="$(extract_table "$diga_file" ErrorCode)" || exit 1

echo "dign table ($DIGN_FILE):"
printf '%s\n' "$DIGN_TABLE" | sed 's/^/  /'
echo "diga table ($diga_file):"
printf '%s\n' "$DIGA_TABLE" | sed 's/^/  /'

rc=0

# --- collisions: a number occupied on BOTH sides must carry the SAME name ----------------------
# The merge is symmetric by construction (numbers from both tables are sorted together and
# compared in one pass), so a collision introduced by EITHER side is caught the same way -- there
# is no separate "dign changed" vs "diga changed" code path to keep in sync.
collisions="$({ printf '%s\n' "$DIGN_TABLE" | awk '{print $1, "dign", $2}'; printf '%s\n' "$DIGA_TABLE" | awk '{print $1, "diga", $2}'; } | sort -k1,1n | awk '
  {
    num=$1; side=$2; name=$3
    if (num in seen_name && seen_name[num] != name) {
      printf "::error::exit %s is %s in %s and %s in %s -- a shared number must carry the SAME meaning on both command lines, or a caller branching on it is reading two different failures as one\n", num, seen_name[num], seen_side[num], name, side
      bad=1
    }
    seen_name[num]=name; seen_side[num]=side
  }
  END { exit bad }
')"
if [ -n "$collisions" ]; then
  printf '%s\n' "$collisions"
  rc=1
fi

# --- reserved shell range: 126, 127, 128+N belong to the shell, never to either binary ----------
check_reserved() {
  local label="$1" table="$2" num rest
  while read -r num rest; do
    [ -n "$num" ] || continue
    if [ "$num" -ge 126 ]; then
      echo "::error::$label exit $num falls in the shell-reserved range (126, 127, 128+N) -- these are never available to either binary"
      rc=1
    fi
  done <<<"$table"
}
check_reserved dign "$DIGN_TABLE"
check_reserved diga "$DIGA_TABLE"

if [ "$rc" -eq 0 ]; then
  echo "OK: no exit-code collision and no reserved-range violation between dign and diga."
fi
exit "$rc"
