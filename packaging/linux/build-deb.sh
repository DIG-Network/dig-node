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

install -m 0755 "$BIN" "$STAGE/usr/bin/dig-node"
install -m 0644 "$HERE/systemd/net.dignetwork.dig-node.service" \
  "$STAGE/lib/systemd/system/net.dignetwork.dig-node.service"
install -m 0644 "$HERE/dig-node.desktop" \
  "$STAGE/usr/share/applications/dig-node.desktop"

INSTALLED_SIZE="$(du -ks "$STAGE/usr" "$STAGE/lib" | awk '{s+=$1} END {print s}')"

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

# --- maintainer scripts -----------------------------------------------------
# postinst: pre-create the restrictive machine-wide state dir (#501 — root-owned 0700 so
# the control token is not world-readable), enable+start the service, register the scheme
# handler as the system default.
cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
case "$1" in
  configure)
    # #501: machine-wide auth-state dir, owner (root) only. The service inherits it.
    install -d -m 0700 /var/lib/dig-node || true
    # dig.local → 127.0.0.2 so `http://dig.local` reaches the node (best-effort, idempotent).
    if ! grep -qE '^[[:space:]]*127\.0\.0\.2[[:space:]]+dig\.local([[:space:]]|$)' /etc/hosts 2>/dev/null; then
      printf '127.0.0.2\tdig.local\n' >> /etc/hosts || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload || true
      systemctl enable --now net.dignetwork.dig-node.service || true
    fi
    # Register the chia:// handler as the system default + refresh the desktop DB.
    if command -v update-desktop-database >/dev/null 2>&1; then
      update-desktop-database /usr/share/applications || true
    fi
    mkdir -p /etc/xdg
    if [ ! -f /etc/xdg/mimeapps.list ] || ! grep -q 'x-scheme-handler/chia=' /etc/xdg/mimeapps.list 2>/dev/null; then
      printf '[Default Applications]\nx-scheme-handler/chia=dig-node.desktop\n' >> /etc/xdg/mimeapps.list || true
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
