#!/usr/bin/env bash
#
# Tests for scripts/package-version.sh — the ONE validation + mapping boundary every native
# package build passes its version through (dig_ecosystem#618).
#
# Two properties are under test, and they pull in opposite directions:
#
#   1. The package FILE NAME must keep the full version verbatim, including a nightly
#      prerelease suffix — dig-updater's feedsign resolves a rolling-nightly release's version by
#      stripping a fixed head/tail off the asset file name, so a truncated name is an unresolvable
#      nightly (the RED that motivated this: `no matching release assets`).
#   2. The MSI ProductVersion must be NUMERIC `x.y.z` within Windows Installer's field limits, so
#      the same nightly version string cannot be handed to WiX unchanged.
#
# Plus the security property: the version reaches a `dpkg` control file, `pkgbuild --version` and a
# WiX `-d Version=` argument on hosts that run the resulting package ELEVATED, so anything that
# could carry shell or control-file meaning must be REJECTED at this boundary, not escaped later.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAP="$HERE/../package-version.sh"

failures=0

# The number of days from 2020-01-01 (the MSI build-field epoch) to the dates used below, so the
# expectations read as intent rather than as magic numbers.
DAYS_20260804=2407
DAYS_20260805=2408

# ok <name> <version> <expected-file_version> <expected-msi_product_version>
ok() {
  local name="$1" version="$2" want_file="$3" want_msi="$4"
  local out status
  out="$(bash "$MAP" "$version" 2>&1)"
  status=$?
  if [ "$status" -ne 0 ]; then
    printf 'FAIL %s: exited %s, want 0\n%s\n' "$name" "$status" "$out"
    failures=$((failures + 1))
    return
  fi
  local got_file got_msi
  got_file="$(printf '%s\n' "$out" | sed -n 's/^file_version=//p')"
  got_msi="$(printf '%s\n' "$out" | sed -n 's/^msi_product_version=//p')"
  if [ "$got_file" != "$want_file" ] || [ "$got_msi" != "$want_msi" ]; then
    printf 'FAIL %s: file_version=%s msi_product_version=%s, want %s / %s\n' \
      "$name" "$got_file" "$got_msi" "$want_file" "$want_msi"
    failures=$((failures + 1))
  else
    printf 'ok   %s\n' "$name"
  fi
}

# rejects <name> <version>
rejects() {
  local name="$1" version="$2"
  local out status
  out="$(bash "$MAP" "$version" 2>&1)"
  status=$?
  if [ "$status" -eq 0 ]; then
    printf 'FAIL %s: accepted %q (exit 0) — it must be rejected at the boundary\n%s\n' \
      "$name" "$version" "$out"
    failures=$((failures + 1))
  else
    printf 'ok   %s (rejected)\n' "$name"
  fi
}

printf '== stable versions map to themselves (the stable path must not change) ==\n'
ok 'stable release' '0.96.0' '0.96.0' '0.96.0'
ok 'stable with a large patch' '1.2.345' '1.2.345' '1.2.345'

printf '\n== a nightly keeps its full version in the FILE name, numeric only for the MSI ==\n'
ok 'nightly' \
  '0.93.9-nightly.20260804.603187a' \
  '0.93.9-nightly.20260804.603187a' \
  "0.93.${DAYS_20260804}"

# The build field must be COMPARISON-SIGNIFICANT, not a cosmetic 4th field: Windows Installer
# compares only major.minor.build, and the beacon installs with a bare `msiexec /i /qn`. Two
# nightlies whose ProductVersion compares EQUAL are not detected by MajorUpgrade at all, so the
# second one installs side-by-side instead of upgrading. Distinguishing this from the nearest wrong
# implementation (`X.Y.Z.<days>`, which is well-formed and keeps the patch, but which MSI ignores)
# needs TWO different nights of the SAME base version, compared as MSI compares them.
printf '\n== consecutive nights of the same base version differ in a field MSI compares ==\n'
night_a="$(bash "$MAP" '0.93.9-nightly.20260804.603187a' | sed -n 's/^msi_product_version=//p')"
night_b="$(bash "$MAP" '0.93.9-nightly.20260805.deadbee' | sed -n 's/^msi_product_version=//p')"
compared() { printf '%s\n' "$1" | cut -d. -f1-3; }
if [ "$(compared "$night_a")" = "$(compared "$night_b")" ]; then
  printf 'FAIL two nights compare EQUAL to msiexec (%s vs %s) — the second nightly would install \n' \
    "$night_a" "$night_b"
  printf '     side-by-side rather than upgrade. Put the date in major.minor.build.\n'
  failures=$((failures + 1))
else
  printf 'ok   nights are distinguishable to msiexec (%s < %s)\n' "$night_a" "$night_b"
fi
if [ "$night_b" != "0.93.${DAYS_20260805}" ]; then
  printf 'FAIL later night: %s, want 0.93.%s\n' "$night_b" "$DAYS_20260805"
  failures=$((failures + 1))
else
  printf 'ok   a later night sorts ABOVE the earlier one\n'
fi

printf '\n== the MSI field limits are pinned from BOTH sides ==\n'
ok 'minor at the MSI ceiling' '0.255.0' '0.255.0' '0.255.0'
rejects 'minor one over the MSI ceiling' '0.256.0'
ok 'major at the MSI ceiling' '255.0.0' '255.0.0' '255.0.0'
rejects 'major one over the MSI ceiling' '256.0.0'
ok 'patch at the MSI ceiling' '0.1.65535' '0.1.65535' '0.1.65535'
rejects 'patch one over the MSI ceiling' '0.1.65536'

printf '\n== anything that could carry shell or control-file meaning is REJECTED ==\n'
rejects 'empty'                  ''
# A missing positional is distinct from an empty one: a caller that forgot the argument entirely
# must not fall through to a default version.
if bash "$MAP" >/dev/null 2>&1; then
  printf 'FAIL no argument at all: accepted (exit 0) — a missing version must be rejected\n'
  failures=$((failures + 1))
else
  printf 'ok   no argument at all (rejected)\n'
fi
rejects 'command substitution'   '0.1.0$(id)'
rejects 'backticks'              '0.1.0`id`'
rejects 'semicolon'              '0.1.0; rm -rf /'
rejects 'pipe'                   '0.1.0|id'
rejects 'ampersand'              '0.1.0 && id'
rejects 'embedded space'         '0.1.0 extra'
rejects 'embedded newline'       "$(printf '0.1.0\nVersion: evil')"
rejects 'leading dash'           '-0.1.0'
rejects 'path traversal'         '../../etc/passwd'
rejects 'redirection'            '0.1.0>out'
rejects 'a v prefix'             'v0.1.0'
rejects 'two components only'    '0.1'
rejects 'four components'        '0.1.0.1'
rejects 'unknown prerelease'     '0.1.0-alpha.1'
rejects 'nightly, bad date'      '0.1.0-nightly.2026804.603187a'
rejects 'nightly, no sha'        '0.1.0-nightly.20260804'
rejects 'nightly, non-hex sha'   '0.1.0-nightly.20260804.zzzzzzz'
rejects 'nightly build metadata' '0.1.0-nightly.20260804.603187a+dirty'

printf '\n== the emitted values are themselves safe to interpolate ==\n'
emitted="$(bash "$MAP" '0.93.9-nightly.20260804.603187a')"
if printf '%s' "$emitted" | grep -qE '[^A-Za-z0-9._=-]|^$'; then
  # `=` and a single newline separator are the only structure; anything else means the mapping
  # can smuggle a metacharacter through even from an ACCEPTED input.
  if printf '%s' "$emitted" | tr -d '\n' | grep -qE '[^A-Za-z0-9._=-]'; then
    printf 'FAIL emitted output contains a metacharacter:\n%s\n' "$emitted"
    failures=$((failures + 1))
  else
    printf 'ok   emitted output is metacharacter-free\n'
  fi
else
  printf 'ok   emitted output is metacharacter-free\n'
fi

if [ "$failures" -ne 0 ]; then
  printf '\n%s package-version test(s) FAILED\n' "$failures"
  exit 1
fi
printf '\nall package-version tests passed\n'
