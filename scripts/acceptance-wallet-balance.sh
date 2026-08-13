#!/usr/bin/env bash
# acceptance-wallet-balance.sh — prove the WHOLE balance path against a running node.
#
# WHY THIS EXISTS, and why it is one assertion rather than a suite:
#
# The balance has four independent gates, each written by a different concern, each able to refuse
# on its own, and each historically rendering its refusal as a different plausible sentence:
#
#   1. does the node hold Chia peers?                      (dig_ecosystem#2806)
#   2. does it FOLLOW this address?                        (#2823 enrolment, #2848 app-side)
#   3. does the replica keep up once it has caught up?     (#2851 froze for hours)
#   4. does a read actually ROUTE to the replica?          (#2866 / #2234)
#
# Every one of those shipped with green unit tests while the wallet was unusable end to end. Gate 4
# was even DOCUMENTED as unreachable in production, in a comment on the very test that covered it,
# and sat that way. Layer tests cannot see this class of failure: each layer is correct and the path
# is broken.
#
# So the guard is a single end-to-end claim: with an address enrolled through the real control
# method, a balance read must be answered BY THE REPLICA. `source: "db"` is only reachable when all
# four gates hold, and no layer-level test can pass in its place.
#
# Usage:  scripts/acceptance-wallet-balance.sh <xch-address> [port]     # port defaults to 9778
# Exit:   0 = the whole path works; 1 = a named gate failed; 2 = usage/environment error.
set -uo pipefail

ADDRESS="${1:-}"
PORT="${2:-9778}"
[ -n "$ADDRESS" ] || { echo "usage: $0 <xch-address> [port]" >&2; exit 2; }
command -v dign >/dev/null 2>&1 || { echo "dign not on PATH" >&2; exit 2; }
export DIG_NODE_PORT="$PORT"

fail() { echo "FAIL (gate $1): $2" >&2; exit 1; }

status_json=$(dign wallet sync-status --json 2>/dev/null) || fail 0 "the node did not answer sync-status"

field() { printf '%s' "$status_json" | python -c "import json,sys;print(json.load(sys.stdin).get('$1'))"; }

peers=$(field chia_peer_count)
watched=$(field watched_addresses)
replica=$(field peak_height)
tip=$(field chia_peer_peak_height)

# GATE 1 — peers held. Corroboration draws on these; with none, nothing downstream can be trusted.
[ "$peers" != "None" ] && [ "${peers:-0}" -ge 1 ] || fail 1 "the node holds no Chia peers"

# GATE 2 — addresses followed. A measured zero here means nothing was ever enrolled.
[ "$watched" != "None" ] && [ "${watched:-0}" -ge 1 ] || fail 2 "the node follows no addresses (watched_addresses=$watched)"

# GATE 3 — the replica is keeping up, not merely once-caught-up. A frozen replica reported `synced`
# for three hours across a 312-block drift, so the phase alone is not the test: the DISTANCE is.
[ "$replica" != "None" ] && [ "$tip" != "None" ] || fail 3 "a height is unobservable (replica=$replica tip=$tip)"
behind=$(( tip - replica ))
[ "$behind" -le 50 ] || fail 3 "the replica is $behind blocks behind the chain tip"

# GATE 4 — the read reaches the replica. This is the one that cannot be faked by a layer test.
bal_json=$(dign wallet balance "$ADDRESS" --json 2>/dev/null) || fail 4 "the balance read failed"
source=$(printf '%s' "$bal_json" | python -c "import json,sys;print(json.load(sys.stdin).get('source'))")
synced=$(printf '%s' "$bal_json" | python -c "import json,sys;print(json.load(sys.stdin).get('synced'))")

if [ "$source" != "db" ]; then
    # Two very different causes land here, and naming the wrong one sends the next person to the
    # wrong layer — which is how this defect family stayed alive for two days. Ask the node which
    # addresses it follows and say which case this is.
    if dign wallet watched --json 2>/dev/null | grep -qi "$(printf '%s' "$ADDRESS" | tail -c 12)"; then
        fail 4 "'$ADDRESS' is followed, yet the balance was answered by '$source' — the read did not route to the replica"
    fi
    fail 4 "the balance was answered by '$source'. This address is not among the ones the node follows, so the replica holds no coins for it — enrol it, or pass an address that is enrolled"
fi
[ "$synced" = "True" ] || fail 4 "a db-tier answer reported synced=$synced; only a replica read may claim a synced view"

echo "PASS: peers=$peers watched=$watched behind=$behind source=$source synced=$synced"
