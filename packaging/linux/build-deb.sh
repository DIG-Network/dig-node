#!/usr/bin/env bash
# Build the dig-node Ubuntu/Debian .deb from an already-built release binary.
#
# The .deb IS the install architecture on Ubuntu (#503): it installs the binary, registers
# the systemd system service `net.dignetwork.dig-node` (auto-start, started on install,
# stopped+disabled on remove), and registers the `chia://` OS scheme handler → `dig-node
# open` (#389). The dig-installer just fetches + `apt install`s this package.
#
# Usage: build-deb.sh <binary-path> <version> <arch> [out-dir]
#   <arch> = amd64 | arm64 (dpkg arch names)
# Emits: <out-dir>/dig-node_<version>_<arch>.deb
set -euo pipefail

BIN="${1:?binary path required}"
VERSION="${2:?version required}"
ARCH="${3:?dpkg arch required (amd64|arm64)}"
OUT_DIR="${4:-dist}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# --- Layout ----------------------------------------------------------------
install -d -m 0755 "$STAGE/DEBIAN"
install -d -m 0755 "$STAGE/usr/bin"
install -d -m 0755 "$STAGE/lib/systemd/system"
install -d -m 0755 "$STAGE/usr/share/applications"
# The operator's configuration surface (#317): an EnvironmentFile the unit reads, plus the
# directory the `no-autostart` marker is dropped into BEFORE the package is installed.
install -d -m 0755 "$STAGE/etc/dig-node"

install -m 0755 "$BIN" "$STAGE/usr/bin/dig-node"
# `dign` is the name every doc, runbook and issue uses (`dign capsule fetch`), so a package that
# ships only `dig-node` makes the documented command `command not found` (#316). It is a SYMLINK
# rather than a second copy because the two binaries are one-line shims over the same
# `dig_node_service::run` and clap derives the displayed program name from arg0 — so the symlink
# is behaviourally identical, cannot drift from its target, and does not double the package.
#
# The link is RELATIVE (`dig-node`, not `/usr/bin/dig-node`) so it resolves correctly when the
# package tree is inspected or unpacked somewhere other than `/`.
#
# Note the name: `/usr/bin/dig` belongs to BIND's dnsutils and is present on essentially every
# Ubuntu host. Nothing here may occupy or shadow that path.
ln -s dig-node "$STAGE/usr/bin/dign"
install -m 0644 "$HERE/dig-node.env" "$STAGE/etc/dig-node/dig-node.env"
install -m 0644 "$HERE/systemd/net.dignetwork.dig-node.service" \
  "$STAGE/lib/systemd/system/net.dignetwork.dig-node.service"
install -m 0644 "$HERE/dig-node.desktop" \
  "$STAGE/usr/share/applications/dig-node.desktop"

INSTALLED_SIZE="$(du -ks "$STAGE/usr" "$STAGE/lib" "$STAGE/etc" | awk '{s+=$1} END {print s}')"

# --- control ----------------------------------------------------------------
cat > "$STAGE/DEBIAN/control" <<EOF
Package: dig-node
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: DIG Network <dev@dig.net>
Installed-Size: ${INSTALLED_SIZE}
Depends: libc6
Homepage: https://dig.net
Description: DIG NETWORK: NODE — the local DIG node OS service
 The canonical DIG node: serves chia:// (DIG) content locally over loopback and
 resolves DIG links for the browser + extension. Installs as a systemd system
 service (net.dignetwork.dig-node) and registers the chia:// OS scheme handler.
EOF

# The env file is operator-owned: dpkg must never silently overwrite an isolation config on
# upgrade, which is exactly the surprise #317 is about.
printf '/etc/dig-node/dig-node.env\n' > "$STAGE/DEBIAN/conffiles"

# --- maintainer scripts -----------------------------------------------------
# postinst: pre-create the restrictive machine-wide state dir (#501 — root-owned 0700 so
# the control token is not world-readable), enable+start the service, cycle it on upgrade
# (#305), and register the scheme handler as the system default.
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

# Every path this script touches is prefixed with $ROOT, which is EMPTY on a real install and is
# only ever set by the packaging test so it can exercise the marker logic without writing to the
# host. A non-empty default here would silently install into a scratch directory, so the default
# is empty and the packaging test asserts that it is.
ROOT="${DIG_NODE_PKG_ROOT:-}"

# dig-node#317 — configure before joining.
#
# The package starts the node on install, which is correct for an ordinary user: an unconfigured
# node must still find peers (dig_ecosystem#923). But it leaves an operator standing up an
# ISOLATED network no supported way in — between `apt install` and their configuration landing the
# node is on the public DHT, where it mints an identity, announces itself, and leaves a
# provider record whose TTL outlives the window.
#
# So: an operator who creates this marker BEFORE installing gets a package that installs and
# registers the unit but does not start it. Nothing changes for anyone who does not create it.
#
#   mkdir -p /etc/dig-node
#   printf 'DIG_BOOTSTRAP_PEERS=off\nDIG_RELAY_URL=off\n' > /etc/dig-node/dig-node.env
#   touch /etc/dig-node/no-autostart
#   apt install ./dig-node_<version>_<arch>.deb
#   systemctl start net.dignetwork.dig-node.service
#
# `off` rather than an empty value is deliberate and is the documented spelling: an empty
# assignment is fragile across the tooling that carries it (on Windows an empty environment
# variable is DELETED rather than emptied, which reads back as "unset" and therefore as the
# public anchor), whereas `off` is a non-empty token that means the same thing everywhere.
NO_AUTOSTART="$ROOT/etc/dig-node/no-autostart"

case "$1" in
  configure)
    # #501: machine-wide auth-state dir, owner (root) only. The service inherits it.
    install -d -m 0700 "$ROOT/var/lib/dig-node" || true
    # dig.local → 127.0.0.2 so `http://dig.local` reaches the node (best-effort, idempotent).
    if ! grep -qE '^[[:space:]]*127\.0\.0\.2[[:space:]]+dig\.local([[:space:]]|$)' "$ROOT/etc/hosts" 2>/dev/null; then
      printf '127.0.0.2\tdig.local\n' >> "$ROOT/etc/hosts" || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
      # daemon-reload happens either way: it is local and network-free, and it is what makes the
      # unit visible to a later `systemctl start`. Skipping it under the marker would leave the
      # operator with a package that registered nothing.
      systemctl daemon-reload || true
      if [ -e "$NO_AUTOSTART" ]; then
        echo "dig-node: /etc/dig-node/no-autostart present — the service is installed but NOT started."
        echo "dig-node: configure /etc/dig-node/dig-node.env, then: systemctl enable --now net.dignetwork.dig-node.service"
      else
        systemctl enable --now net.dignetwork.dig-node.service || true
      fi
      # dig-node#305 — an UPGRADE must cycle the unit, or the old process keeps serving.
      #
      # `enable --now` above is a no-op on a unit that is already enabled and running, so before
      # this the upgrade replaced /usr/bin/dig-node and left the OLD binary executing. That is
      # silent in both directions an operator would check: `dig-node --version` reads the on-disk
      # image and reports the NEW version immediately, and `systemctl is-active` reports active
      # because the old process is genuinely healthy. Only MainPID moves, and nobody reads it. A
      # security fix shipped through the .deb therefore did not take effect on upgrade.
      #
      # dpkg passes the previously-configured version as $2 only on an upgrade, so this is scoped
      # to the case that needs it: on a first install `enable --now` has already started the new
      # binary and a restart would be redundant churn.
      #
      # `try-restart` rather than `restart`: it cycles the unit ONLY if it is already running, so
      # a node the operator deliberately stopped — including one held back by the #317
      # no-autostart marker — stays stopped across every future upgrade.
      if [ -n "${2:-}" ]; then
        systemctl try-restart net.dignetwork.dig-node.service || true
      fi
    fi
    # Register the chia:// handler as the system default + refresh the desktop DB.
    if command -v update-desktop-database >/dev/null 2>&1; then
      update-desktop-database "$ROOT/usr/share/applications" || true
    fi
    mkdir -p "$ROOT/etc/xdg"
    if [ ! -f "$ROOT/etc/xdg/mimeapps.list" ] || ! grep -q 'x-scheme-handler/chia=' "$ROOT/etc/xdg/mimeapps.list" 2>/dev/null; then
      printf '[Default Applications]\nx-scheme-handler/chia=dig-node.desktop\n' >> "$ROOT/etc/xdg/mimeapps.list" || true
    fi
    ;;
esac
exit 0
EOF

# prerm: stop + disable the service before removal.
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  remove|deconfigure)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now net.dignetwork.dig-node.service || true
    fi
    ;;
esac
exit 0
EOF

# postrm: reload systemd after files are gone (purge leaves /var/lib/dig-node for reinstall
# safety; a full purge removes it).
cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  remove)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
    fi
    ;;
  purge)
    rm -rf /var/lib/dig-node || true
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
    fi
    ;;
esac
exit 0
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

# --- build ------------------------------------------------------------------
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/dig-node_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"
echo "built: $OUT"
