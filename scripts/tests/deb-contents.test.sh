#!/usr/bin/env bash
#
# Tests for packaging/linux/build-deb.sh — what the Ubuntu/Debian package actually SHIPS and
# what its postinst actually DOES.
#
# Two acceptance properties are under test, both measured on a real built `.deb` rather than on
# the script's source text, because the failure both tickets describe is a package whose contents
# do not match what the documentation promises.
#
#   1. dig-node#316 — the package ships `dign`. Every doc, runbook and issue in the ecosystem
#      names `dign capsule fetch`; a package install that provides only `dig-node` makes the
#      documented command `command not found`, which is a surface lying about a capability.
#      `dign` is asserted to be a SYMLINK to `dig-node`, not a second copy: the two binaries are
#      identical modulo arg0 (both are one-line shims over `dig_node_service::run`, and clap
#      derives the displayed program name from arg0), so a copy would double the package for no
#      behavioural difference AND would be free to drift.
#
#   2. dig-node#317 — an operator can install WITHOUT first joining the public network. The
#      postinst is EXECUTED here, twice, against a recording stub `systemctl`, so the test sees
#      the behavioural difference rather than a comment that describes it. The marker-absent run
#      is the control: it must still `enable --now`, because dig_ecosystem#923 requires an
#      unconfigured node to find peers and this change must not alter that default.
#
# The BIND hazard is asserted directly: `/usr/bin/dig` is BIND's DNS lookup tool, present on
# essentially every Ubuntu host. Shipping a file at that path — the obvious wrong spelling of
# "ship the short name" — would hijack it. The package must never contain it.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BUILD="$REPO/packaging/linux/build-deb.sh"

# dpkg-deb is what makes this test real. It is present on the ubuntu runner that gates every PR,
# so an ABSENT dpkg-deb under CI is a broken gate, not a reason to pass. Fail loudly there; a
# developer on a non-Debian host gets an honest SKIP instead of a false green.
if ! command -v dpkg-deb >/dev/null 2>&1; then
  if [ -n "${CI:-}" ]; then
    echo "FAIL: dpkg-deb is unavailable under CI — this gate cannot run and must not pass"
    exit 1
  fi
  echo "SKIP: dpkg-deb unavailable (non-Debian host); this gate runs in CI"
  exit 0
fi

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
ok() { echo "ok: $*"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# A stand-in for the release binary. Its CONTENT is irrelevant to both properties: the package
# either carries a `dign` path or it does not, and the postinst either honours the marker or it
# does not. Using a stub keeps the gate a packaging gate rather than a 20-minute cargo build.
printf '#!/bin/sh\necho stub-dig-node\n' > "$TMP/dig-node"
chmod 0755 "$TMP/dig-node"

bash "$BUILD" "$TMP/dig-node" "9.9.9" "amd64" "$TMP/dist" >/dev/null 2>"$TMP/build.err" || {
  echo "FAIL: build-deb.sh did not build"; sed -n '1,20p' "$TMP/build.err"; exit 1
}
DEB="$TMP/dist/dig-node_9.9.9_amd64.deb"
[ -f "$DEB" ] || { echo "FAIL: expected $DEB"; exit 1; }

# --- 1. dig-node#316: the package ships `dign` --------------------------------------------
CONTENTS="$(dpkg-deb -c "$DEB")"

if grep -qE '(^|[[:space:]])\./usr/bin/dign( -> |$)' <<<"$CONTENTS"; then
  ok "the package ships /usr/bin/dign (#316)"
else
  fail "the package ships no /usr/bin/dign — the documented \`dign capsule fetch\` is command-not-found (#316)"
fi

# A SYMLINK, and one that resolves to the sibling `dig-node`. `dpkg-deb -c` renders a symlink as
# `./usr/bin/dign -> dig-node`, and its mode line begins with `l`.
DIGN_LINE="$(grep -E '(^|[[:space:]])\./usr/bin/dign( |$|-)' <<<"$CONTENTS" | head -1)"
case "$DIGN_LINE" in
  l*"./usr/bin/dign -> dig-node") ok "dign is a symlink to dig-node, so the two cannot diverge" ;;
  "") : ;;  # already reported above
  *) fail "dign is not a symlink to dig-node: $DIGN_LINE" ;;
esac

# The BIND hazard. /usr/bin/dig belongs to dnsutils; shipping anything there hijacks DNS lookup
# for every user on the host.
if grep -qE '(^|[[:space:]])\./usr/bin/dig($|[[:space:]])' <<<"$CONTENTS"; then
  fail "the package ships /usr/bin/dig — that is BIND's DNS tool and must never be shadowed"
else
  ok "the package does not ship /usr/bin/dig (BIND's tool is untouched)"
fi

# --- 2. dig-node#317: configure-before-joining --------------------------------------------
# Extract the maintainer scripts and RUN the postinst against a recording stub `systemctl`, with
# every filesystem write redirected under a scratch root.
dpkg-deb --control "$DEB" "$TMP/ctl" >/dev/null 2>&1 || { echo "FAIL: cannot extract control"; exit 1; }

mkdir -p "$TMP/stub"
cat > "$TMP/stub/systemctl" <<'STUB'
#!/bin/sh
echo "systemctl $*" >> "$SYSTEMCTL_LOG"
STUB
chmod 0755 "$TMP/stub/systemctl"

# run_postinst <root> -> echoes the recorded systemctl invocations
run_postinst() {
  local root="$1"
  export SYSTEMCTL_LOG="$root/systemctl.log"
  : > "$SYSTEMCTL_LOG"
  mkdir -p "$root/etc" "$root/var/lib" "$root/usr/share/applications"
  PATH="$TMP/stub:$PATH" DIG_NODE_PKG_ROOT="$root" sh "$TMP/ctl/postinst" configure \
    >"$root/postinst.out" 2>&1
  cat "$SYSTEMCTL_LOG"
}

# Every maintainer script must PARSE under /bin/sh before anything else is asserted about it.
# These scripts are generated from a heredoc, run as root by dpkg, and are the one part of the
# package with no compiler behind it — a quoting slip here is a broken install on every host,
# and it presents as a mid-configure failure rather than as a build error.
for script in postinst prerm postrm; do
  if sh -n "$TMP/ctl/$script" 2>"$TMP/syntax.err"; then
    ok "DEBIAN/$script parses"
  else
    fail "DEBIAN/$script has a syntax error: $(head -1 "$TMP/syntax.err")"
  fi
done

# Control: no marker. The default MUST be unchanged — dig_ecosystem#923 says a node with no
# configuration still finds peers, so an ordinary install still enables and starts the service.
CONTROL_ROOT="$TMP/plain"; mkdir -p "$CONTROL_ROOT"
CONTROL_LOG="$(run_postinst "$CONTROL_ROOT")"
if grep -q 'enable --now net.dignetwork.dig-node.service' <<<"$CONTROL_LOG"; then
  ok "an ordinary install still enables + starts the node (#923 default preserved)"
else
  fail "an ordinary install no longer starts the node — that is a regression of the #923 default"
fi

# Under test: the marker is present before install. The node must be left not-started.
MARKED_ROOT="$TMP/marked"; mkdir -p "$MARKED_ROOT/etc/dig-node"
touch "$MARKED_ROOT/etc/dig-node/no-autostart"
MARKED_LOG="$(run_postinst "$MARKED_ROOT")"
if grep -q 'enable --now' <<<"$MARKED_LOG" || grep -qE 'systemctl (start|enable)' <<<"$MARKED_LOG"; then
  fail "the no-autostart marker did not prevent the node joining the network on install (#317)"
else
  ok "the no-autostart marker leaves the node not-started (#317)"
fi

# `daemon-reload` is a local, network-free operation and is still wanted so the unit is visible to
# `systemctl start` afterwards. Asserting it keeps the fix from degrading into "skip the whole
# configure branch", which would satisfy the check above while leaving the unit unregistered.
if grep -q 'daemon-reload' <<<"$MARKED_LOG"; then
  ok "the unit is still registered with systemd under the marker"
else
  fail "the marker suppressed daemon-reload — the unit is not registered and cannot be started later"
fi

# The redirect seam must default to the real root. A postinst that defaulted DIG_NODE_PKG_ROOT to
# anything non-empty would pass every check above while installing into a scratch directory on a
# real host.
if grep -qE 'DIG_NODE_PKG_ROOT:-\}' "$TMP/ctl/postinst"; then
  ok "the packaging-root seam defaults to the real filesystem root"
else
  fail "postinst does not default DIG_NODE_PKG_ROOT to empty — an install could write outside /"
fi

echo
if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all deb-contents checks passed"
