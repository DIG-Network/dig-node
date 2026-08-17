#!/usr/bin/env bash
# Witness the #3061 late-joiner re-announce across TWO REAL dig-node PROCESSES (dig_ecosystem#3091).
#
# WHY this script exists: the fix (dig-node v0.124.0, PR #234) is unit-proven at the transport seam
# against a REGISTERED STUB PEER, which measures fan-out accounting after the seen-set gate but not
# the socket write to a second process. §2.6's acceptance bar is a person seeing it work, so this
# drives two OS processes with real dig-gossip sockets, separate state dirs and separate ports.
#
# The scenario, which is exactly the condition that poisoned the seen entry under #3061:
#   1. Node A holds a profile body and announces its root (opcode 223) with ZERO peers connected.
#   2. Node B starts AFTERWARDS and dials A.
#   3. A's next periodic re-announce of the SAME (store_id, root) must reach B, and B must log it.
# Under the defect step 3 never happens: the announce is byte-identical, so dig-gossip's seen set
# suppresses every repeat for the life of the process.
#
# Seeding is a DIRECT WRITE of `<cache>/profiles/<store_hex>/<root_hex>.dpb`, because that is
# precisely and only what the re-announce loop reads (`ProfileBodyStore::held_pairs()` is a disk
# scan). `control.profile.putBody` is NOT usable here: it chain-resolves the root and refuses a
# root the chain does not confirm, so an unanchored test root cannot travel that way. Both paths
# call the same `GossipHandle::broadcast_local`.
#
# Both nodes run on a private DIG_NETWORK_ID so they can only ever see each other, never the real
# network — which is what makes "zero peers" a fact rather than a hope.
#
# Usage: two-node-reannounce.sh --bin PATH [--work DIR] [--interval SECS] [--json]
set -uo pipefail

BIN=""
WORK=""
INTERVAL=60          # profile_sync::ANNOUNCE_INTERVAL
JSON=0

while [ $# -gt 0 ]; do
  case "$1" in
    --bin)      BIN="$2"; shift 2 ;;
    --work)     WORK="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --json)     JSON=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$BIN" ] || { echo "--bin PATH (a dig-node binary) is required" >&2; exit 2; }
[ -x "$BIN" ] || { echo "no executable dig-node at $BIN" >&2; exit 2; }
WORK="${WORK:-$(mktemp -d)}"

# Distinct ports per node so the two processes never share a listener. 9891/9892 are the gossip
# pool listeners the nodes dial each other on; 9791/9792 are the loopback control planes.
A_CTRL=9791; A_GOSSIP=9891
B_CTRL=9792; B_GOSSIP=9892
NETWORK_ID="dig-3091-two-node-$$"

# The seeded profile: a fixed store id and root, so both logs can be grepped for the same hex.
STORE_ID="aa11$(printf 'bb%.0s' {1..30})"
ROOT="cc22$(printf 'dd%.0s' {1..30})"

say() { [ "$JSON" = 1 ] || echo "$@"; }

# --- Layout + seed ------------------------------------------------------------------------------
for n in a b; do mkdir -p "$WORK/$n/cache" "$WORK/$n/state" "$WORK/$n/logs"; done
mkdir -p "$WORK/a/cache/profiles/$STORE_ID"
printf 'dig_ecosystem#3091 two-node re-announce witness body' > "$WORK/a/cache/profiles/$STORE_ID/$ROOT.dpb"
say "work dir: $WORK"
say "seeded A: profiles/$STORE_ID/$ROOT.dpb"

start_node() {  # start_node <a|b> <ctrl-port> <gossip-port>
  local n="$1" ctrl="$2" gossip="$3"
  DIG_NODE_PORT="$ctrl" \
  DIG_GOSSIP_PORT="$gossip" \
  DIG_NODE_CACHE="$WORK/$n/cache" \
  DIG_NODE_STATE_DIR="$WORK/$n/state" \
  DIG_LOG_DIR="$WORK/$n/logs" \
  DIG_NETWORK_ID="$NETWORK_ID" \
  DIG_NODE_ADVERTISE_LOOPBACK=1 \
  DIG_NODE_DIGLOCAL=0 \
  DIG_WALLET_ENABLE_CHAIN_SYNC=0 \
  DIG_LOG="info,dig_node_core=info,dig_gossip=info" \
    "$BIN" run > "$WORK/$n/stdout.log" 2> "$WORK/$n/stderr.log" &
  echo $!
}

ctl() {  # ctl <a|b> <ctrl-port> <method> <params-json>
  local n="$1" port="$2" method="$3" params="$4"
  curl -s --max-time 10 -X POST "http://127.0.0.1:$port/" \
    -H "X-Dig-Control-Token: $(cat "$WORK/$n/state/control-token" 2>/dev/null)" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

wait_up() {  # wait_up <a|b> <ctrl-port>; returns 0 once control.status answers
  local n="$1" port="$2" i
  for i in $(seq 1 60); do
    if ctl "$n" "$port" control.status '{}' | grep -q '"result"'; then return 0; fi
    sleep 1
  done
  return 1
}

# Every announce line A emits, with its `peers=` count. This is the discriminator.
announce_lines() { grep -h 'announced a held profile root' "$WORK/a/stderr.log" 2>/dev/null; }
heard_lines()    { grep -h 'heard a root announce'         "$WORK/b/stderr.log" 2>/dev/null; }

cleanup() { [ -n "${A_PID:-}" ] && kill "$A_PID" 2>/dev/null; [ -n "${B_PID:-}" ] && kill "$B_PID" 2>/dev/null; }
trap cleanup EXIT

# --- Step 1: A alone, announcing to nobody ------------------------------------------------------
say "=== step 1: start A (control $A_CTRL, gossip $A_GOSSIP), zero peers"
A_PID=$(start_node a "$A_CTRL" "$A_GOSSIP")
wait_up a "$A_CTRL" || { echo "A never came up; see $WORK/a/stderr.log" >&2; exit 1; }
say "A up (pid $A_PID)"
# The interval ticker fires immediately, so the zero-peer announce lands within seconds.
for i in $(seq 1 30); do [ "$(announce_lines | wc -l)" -ge 1 ] && break; sleep 1; done
FIRST_ANNOUNCE=$(announce_lines | head -1)
say "A's zero-peer announce: ${FIRST_ANNOUNCE:-<none>}"
[ -n "$FIRST_ANNOUNCE" ] || { echo "A never announced; see $WORK/a/stderr.log" >&2; exit 1; }

# --- Step 2: B joins LATE and dials A -----------------------------------------------------------
say "=== step 2: start B (control $B_CTRL, gossip $B_GOSSIP) and dial A"
B_PID=$(start_node b "$B_CTRL" "$B_GOSSIP")
wait_up b "$B_CTRL" || { echo "B never came up; see $WORK/b/stderr.log" >&2; exit 1; }
say "B up (pid $B_PID)"
CONNECT=$(ctl b "$B_CTRL" control.peers.connect "{\"peer\":\"127.0.0.1:$A_GOSSIP\"}")
say "B -> A connect: $CONNECT"

# --- Step 3: the re-announce must cross the socket ----------------------------------------------
BEFORE=$(announce_lines | wc -l)
say "=== step 3: waiting up to $((INTERVAL + 30))s for A's next re-announce tick"
for i in $(seq 1 $((INTERVAL + 30))); do
  [ "$(heard_lines | wc -l)" -ge 1 ] && break
  sleep 1
done
WAITED=$i

REACHED_LINE=$(announce_lines | tail -1)
HEARD=$(heard_lines | head -1)
ALL_PEERS=$(announce_lines | grep -o 'peers=[0-9]*' | tr '\n' ' ')

if [ -n "$HEARD" ]; then VERDICT="CONVERGED"; RC=0; else VERDICT="DID_NOT_CONVERGE"; RC=1; fi

if [ "$JSON" = 1 ]; then
  printf '{"verdict":"%s","store_id":"%s","root":"%s","announce_peer_counts":"%s","seconds_to_converge":%s,"a_first_announce":%s,"a_last_announce":%s,"b_heard":%s,"work_dir":"%s"}\n' \
    "$VERDICT" "$STORE_ID" "$ROOT" "$(echo "$ALL_PEERS" | sed 's/ *$//')" "$WAITED" \
    "$(printf '%s' "$FIRST_ANNOUNCE" | python -c 'import json,sys;print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')" \
    "$(printf '%s' "$REACHED_LINE" | python -c 'import json,sys;print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')" \
    "$(printf '%s' "$HEARD" | python -c 'import json,sys;print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '""')" \
    "$WORK"
else
  echo
  echo "=== verdict: $VERDICT (after ${WAITED}s)"
  echo "A announce peers= sequence: $ALL_PEERS"
  echo "A last announce: $REACHED_LINE"
  echo "B heard:         ${HEARD:-<nothing — B never received a 223>}"
  echo "logs: $WORK/a/stderr.log  $WORK/b/stderr.log"
fi
exit $RC
