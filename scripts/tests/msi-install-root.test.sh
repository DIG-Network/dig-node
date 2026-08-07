#!/usr/bin/env bash
#
# Tests for the install LOCATION and the upgrade SEQUENCING declared by
# packaging/windows/dig-node.wxs (dig_ecosystem#2251).
#
# The defect these pin was measured on a real machine twice: the MSI installed dig-node.exe to
# `%ProgramFiles%\DIG Network\dig-node\`, added THAT directory to the machine PATH, and pointed the
# `net.dignetwork.dig-node` service image at it. dig-installer places its copy in the canonical
# protected root `%ProgramFiles%\DIG\bin` and then verifies the service image and the PATH
# resolution against that root — so every install failed a safety check against a directory its own
# payload had just created, and deleting the directory by hand did not survive the next install.
#
# Three properties, each stated as a property and each pinned against the implementation that is
# nearest to it and still wrong:
#
#   1. INSTALLFOLDER resolves to the CANONICAL root `%ProgramFiles%\DIG\bin`. The nearest wrong
#      implementations are a different manufacturer folder and a `DIG\<component>` leaf that merely
#      contains the right word, so the whole directory CHAIN is composed and compared, not grepped
#      for a substring.
#   2. The package declares NO machine-PATH entry. Two owners of one PATH entry is how the shadowing
#      arose, and an MSI `Environment` row is removed on uninstall — which, once the package points
#      at the SHARED bin root, would strip that root from PATH out from under every other component
#      dig-installer put there. Absence is the property; a component that merely adds the *right*
#      directory still has the wrong owner.
#   3. The major upgrade removes the old product BEFORE installing the new one. This is the property
#      most easily broken by a plausible "improvement": scheduling RemoveExistingProducts late
#      (afterInstallExecute / afterInstallFinalize) is the standard advice for preserving files, but
#      the OLD package's `ServiceControl Remove="uninstall"` owns the SAME service name, so a late
#      removal deletes the service the new product just installed and leaves the machine with files
#      and no `net.dignetwork.dig-node`. Files and the service must be recreated by the same
#      transaction that removed them, which is what the early schedule plus `Start="install"` gives.
#
# These run on ubuntu CI. They assert the SHIPPED package source — not a copy of it — but they
# cannot execute msiexec, so the on-machine upgrade evidence is recorded in the PR, not here.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WXS="$HERE/../../packaging/windows/dig-node.wxs"

failures=0

fail() {
  printf 'FAIL %s\n' "$1"
  failures=$((failures + 1))
}

pass() {
  printf 'ok   %s\n' "$1"
}

# The canonical protected install root, spelled once (the `canonical` skill / SYSTEM.md install-root
# section; dig-installer's `install_root`). A second spelling of this root is the bug under test.
CANONICAL_ROOT='%ProgramFiles%\DIG\bin'

# Compose the Windows path INSTALLFOLDER resolves to, by walking the <Directory> nesting from the
# <StandardDirectory> that anchors it. Emits nothing when INSTALLFOLDER is not reachable that way.
#
# A hand-rolled walk over a known-shaped document, because CI has no XML toolchain and the shape is
# fixed by WiX: <StandardDirectory Id="…"> then a chain of <Directory Id="…" Name="…"> either nested
# or self-closing.
installfolder_path() {
  awk '
    /<StandardDirectory[^>]*Id="ProgramFiles64Folder"/ { inpf = 1; next }
    inpf && /<\/StandardDirectory>/ { inpf = 0; next }
    inpf && /<Directory[^>]*Name="/ {
      match($0, /Name="[^"]*"/); name = substr($0, RSTART + 6, RLENGTH - 7)
      chain = chain "\\" name
      if ($0 ~ /Id="INSTALLFOLDER"/) { print "%ProgramFiles%" chain; exit }
    }
  ' "$WXS"
}

printf '== the package installs into the canonical protected root ==\n'
got="$(installfolder_path)"
if [ -z "$got" ]; then
  fail "INSTALLFOLDER is not reachable from <StandardDirectory Id=\"ProgramFiles64Folder\"> — the
     install location could not be determined, so it cannot be held to the canonical root."
elif [ "$got" != "$CANONICAL_ROOT" ]; then
  fail "INSTALLFOLDER resolves to $got, want $CANONICAL_ROOT.
     dig-installer verifies the service image and PATH resolution against $CANONICAL_ROOT, so any
     other location makes every install fail a check against this package's own payload (#2251)."
else
  pass "INSTALLFOLDER = $CANONICAL_ROOT"
fi

# The old root must not survive anywhere in the package — not as a directory, not in a registry
# value, not in a custom-action path. This is the substring check the composed comparison above
# deliberately is not: it catches a SECOND, leftover reference that the primary chain hides.
if grep -q 'Name="DIG Network"' "$WXS"; then
  fail 'the package still declares a "DIG Network" directory — the superseded root (#2251).'
else
  pass 'no "DIG Network" install directory remains'
fi

printf '\n== the package declares no machine-PATH entry ==\n'
# Flattened before matching: WiX attributes are routinely wrapped across lines, and a line-oriented
# `grep` fails OPEN on exactly that — a real <Environment Name="PATH" …> component split over two
# lines would reinstate the defect while this assertion passed. Verified: the same component on one
# line FAILs, wrapped it did not, until this flatten.
if tr '\n' ' ' < "$WXS" | grep -qi '<Environment[^>]*Name="PATH"'; then
  fail 'the package still owns a machine-PATH Environment row. dig-installer owns PATH for the
     shared install root; an MSI-owned row is removed on uninstall and would strip that root from
     PATH for every other component installed there (#2251).'
else
  pass 'PATH is left to dig-installer, the single owner of the shared root'
fi

printf '\n== a foreign dig-node.exe in the shared root is cleared before install ==\n'
# The root is shared and this package is not its only writer (dig-installer drops a raw binary
# there). Windows Installer KEEPS a foreign unversioned-looking file rather than overwrite it, so
# without this removal the package completes over a binary it did not install and dig-updater then
# probes the STALE version — the non-convergent update loop, not a cosmetic issue.
remove_file="$(tr '\n' ' ' < "$WXS" | grep -o '<RemoveFile[^>]*>')"
if [ -z "$remove_file" ]; then
  fail 'no <RemoveFile>: an msiexec /i over a foreign dig-node.exe in the shared root can leave that
     file in place, and the version dig-updater probes afterwards is the stale one (#2251).'
elif ! printf '%s' "$remove_file" | grep -q 'Name="dig-node.exe"'; then
  fail "the <RemoveFile> does not name dig-node.exe: $remove_file"
elif ! printf '%s' "$remove_file" | grep -qE 'On="(install|both)"'; then
  fail "the <RemoveFile> does not run on INSTALL, so it cannot clear the file before the install
     writes: $remove_file"
else
  pass 'a pre-existing dig-node.exe is removed before the package installs its own'
fi

# The removal must stay scoped to ONE file. The shared root also holds digstore, dig-dns,
# dig-updater and dig-app, so a directory-wide removal (a <RemoveFile> with no Name, or a wildcard)
# would delete another component's binary — a far worse defect than the one being fixed.
unscoped=''
while IFS= read -r el; do
  [ -n "$el" ] || continue
  # A <RemoveFile> with no Name, or a Name carrying a wildcard, removes more than one file.
  if ! printf '%s' "$el" | grep -q 'Name="'; then
    unscoped="$unscoped $el"
  elif printf '%s' "$el" | grep -q 'Name="[^"]*[*?]'; then
    unscoped="$unscoped $el"
  fi
done <<EOF
$(tr '\n' ' ' < "$WXS" | grep -o '<RemoveFile[^>]*>')
EOF
if [ -n "$unscoped" ]; then
  fail "a removal is not scoped to a single named file, and the install root is SHARED:$unscoped"
elif tr '\n' ' ' < "$WXS" | grep -q '<RemoveFolder[^>]*Directory="INSTALLFOLDER"'; then
  fail 'the package removes the shared install DIRECTORY, which other components live in.'
else
  pass 'every removal is scoped to a single named file, never the shared directory'
fi

printf '\n== the upgrade never leaves the machine without net.dignetwork.dig-node ==\n'

# MajorUpgrade may be written across several lines; flatten the element to inspect its attributes.
major_upgrade="$(tr '\n' ' ' < "$WXS" | grep -o '<MajorUpgrade[^>]*>')"
if [ -z "$major_upgrade" ]; then
  fail 'no <MajorUpgrade> element — an in-place upgrade would install a SECOND product, two
     Add/Remove entries both owning net.dignetwork.dig-node.'
else
  schedule="$(printf '%s' "$major_upgrade" | grep -o 'Schedule="[^"]*"' | cut -d'"' -f2)"
  case "${schedule:-afterInstallValidate}" in
    afterInstallValidate)
      pass "RemoveExistingProducts runs BEFORE the new files install (${schedule:-default})"
      ;;
    *)
      fail "MajorUpgrade Schedule=\"$schedule\" removes the old product AFTER the new one installs.
     The old package's ServiceControl Remove=\"uninstall\" owns the SAME service name, so it would
     delete the net.dignetwork.dig-node the new product just registered, leaving files and no
     service (#2251)."
      ;;
  esac
fi

# The service must be reinstalled AND started by the same transaction that removed the old one —
# otherwise the early schedule above is exactly the window the migration must not open.
if grep -q 'Name="net.dignetwork.dig-node"' "$WXS" \
  && grep -q '<ServiceInstall' "$WXS" \
  && tr '\n' ' ' < "$WXS" | grep -q '<ServiceControl[^>]*Start="install"'; then
  pass 'the same transaction reinstalls and STARTS net.dignetwork.dig-node'
else
  fail 'the package does not both install and start net.dignetwork.dig-node — an early-scheduled
     RemoveExistingProducts would then leave an upgraded machine with no service (#2251).'
fi

# The service NAME is itself a migration hazard: renaming it would leave the old product'"'"'s service
# behind (its ServiceControl matches by name) while the new one registers a second.
if [ "$(grep -c 'net\.dignetwork\.dig-node' "$WXS")" -ge 2 ]; then
  pass 'the service name is unchanged across the migration'
else
  fail 'the service name appears fewer than twice (ServiceInstall + ServiceControl) — a renamed or
     half-declared service orphans the one the previous version registered.'
fi

if [ "$failures" -ne 0 ]; then
  printf '\n%s MSI install-root test(s) FAILED\n' "$failures"
  exit 1
fi
printf '\nall MSI install-root tests passed\n'
