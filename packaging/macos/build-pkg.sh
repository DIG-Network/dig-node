#!/usr/bin/env bash
# Build the dig-node macOS .pkg from an already-built release binary (runs on a macOS runner).
#
# The .pkg IS the install architecture on macOS (#503): it installs the binary to
# /usr/local/bin, a LaunchDaemon (net.dignetwork.dig-node, RunAtLoad+KeepAlive) to
# /Library/LaunchDaemons, and a tiny AppleScript app that registers the chia:// URL scheme →
# `dig-node open` (#389). postinstall creates the restrictive state dir (#501) + starts the daemon.
#
# Usage: build-pkg.sh <binary-path> <version> [out-dir]
# Emits: <out-dir>/dig-node-<version>-macos.pkg  (universal binary if <binary-path> is a fat binary)
#
# NOTE: the .pkg is NOT code-signed/notarized here (that needs a paid Apple Developer ID). Gatekeeper
# will warn on first open until signing is added; tracked as a follow-up (SPEC §9). The binary + all
# install behavior are correct + complete regardless.
set -euo pipefail

BIN="${1:?binary path required}"
VERSION="${2:?version required}"
OUT_DIR="${3:-dist}"
IDENTIFIER="net.dignetwork.dig-node"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="$(mktemp -d)"
ROOT="$STAGE/root"
SCRIPTS="$STAGE/scripts"
trap 'rm -rf "$STAGE"' EXIT

# --- Payload layout ---------------------------------------------------------
mkdir -p "$ROOT/usr/local/bin" "$ROOT/Library/LaunchDaemons" "$ROOT/Applications"
install -m 0755 "$BIN" "$ROOT/usr/local/bin/dig-node"
install -m 0644 "$HERE/net.dignetwork.dig-node.plist" \
  "$ROOT/Library/LaunchDaemons/net.dignetwork.dig-node.plist"

# --- Build the chia:// URL-handler .app from the AppleScript ---------------
APP="$ROOT/Applications/DIG Network.app"
osacompile -o "$APP" "$HERE/dig-url-handler.applescript"
PLIST="$APP/Contents/Info.plist"
# Declare the `chia` URL scheme + a stable bundle id so LaunchServices resolves it.
# Set-or-Add: newer osacompile output may omit CFBundleIdentifier, so a bare Set fails
# ("Does Not Exist"); fall back to Add (mirrors the LSUIElement pattern below).
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier ${IDENTIFIER}.urlhandler" "$PLIST" 2>/dev/null || \
  /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string ${IDENTIFIER}.urlhandler" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes array" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0 dict" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLName string net.dignetwork.chia" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes array" "$PLIST"
/usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string chia" "$PLIST"
/usr/libexec/PlistBuddy -c "Set :LSUIElement true" "$PLIST" 2>/dev/null || \
  /usr/libexec/PlistBuddy -c "Add :LSUIElement bool true" "$PLIST"

# --- Scripts ----------------------------------------------------------------
mkdir -p "$SCRIPTS"
install -m 0755 "$HERE/scripts/preinstall" "$SCRIPTS/preinstall"
install -m 0755 "$HERE/scripts/postinstall" "$SCRIPTS/postinstall"

# --- Build the component pkg, then wrap for distribution --------------------
mkdir -p "$OUT_DIR"
COMPONENT="$STAGE/dig-node-component.pkg"
pkgbuild \
  --root "$ROOT" \
  --scripts "$SCRIPTS" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location "/" \
  "$COMPONENT"

OUT="$OUT_DIR/dig-node-${VERSION}-macos.pkg"
productbuild --package "$COMPONENT" "$OUT"
echo "built: $OUT"
