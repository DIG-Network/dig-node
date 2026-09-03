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

# ── The invariant every distinct nightly BUILD must satisfy ───────────────────────────────────────
#
# The property the beacon needs is not "two hand-picked dates differ" — it is a statement about the
# whole CLASS of nightly builds:
#
#   For any two distinct nightly builds, the later one MUST NOT compare LOWER than the earlier, and
#   any pair that compares EQUAL must be made safe by an explicit same-version-upgrade policy.
#
# Both halves matter, because Windows Installer compares only major.minor.build and the beacon
# installs with a bare `msiexec /i /qn`:
#
#   * compares LOWER  → msiexec aborts on DowngradeErrorMessage and the host is stuck;
#   * compares EQUAL  → MajorUpgrade's range is [0.0.0, ProductVersion), so the build matches neither
#     the upgrade nor the downgrade case and installs as a SECOND product, two entries both owning
#     the `net.dignetwork.dig-node` service.
#
# The mapping alone CANNOT eliminate the EQUAL case: the synthesized nightly version carries a DATE
# and a commit sha and nothing else, so it is day-granular by construction, and 16 bits of build
# field cannot hold a finer monotonic counter over any useful epoch (minute resolution exhausts the
# field in 45 days; a sha-derived tiebreak is not ordered, which would produce the far worse LOWER
# case). Same-day builds are reachable — the `force` re-cut, and a manual `channel: nightly` dispatch
# on a day the cron already ran. So the invariant is held JOINTLY by the mapping (never decreasing)
# and by packaging/windows/dig-node.wxs (equal versions upgrade in place), and this asserts both
# together — asserting either alone passes over the defect.
printf '\n== no distinct nightly build ever compares LOWER, and EQUAL pairs are policy-safe ==\n'

WXS="$HERE/../../packaging/windows/dig-node.wxs"

# Only the fields Windows Installer actually compares. Taking `cut -f1-3` is the point: an
# implementation that hides the date in an ignored 4th field is invisible here, exactly as it is to
# msiexec.
msi_compared() { bash "$MAP" "$1" | sed -n 's/^msi_product_version=//p' | cut -d. -f1-3; }

# Distinct builds in BUILD ORDER, spanning the cases that break a date mapping: the same UTC day
# with a different commit, consecutive days, a month rollover, a year rollover, and a base-version
# bump. Every adjacent pair is checked, so this covers the class rather than one lucky comparison.
nightly_builds=(
  '0.93.9-nightly.20260804.603187a'   # the cron run
  '0.93.9-nightly.20260804.deadbee'   # SAME UTC DAY, different commit — a force re-cut or a dispatch
  '0.93.9-nightly.20260805.f00ba12'   # the next night
  '0.93.9-nightly.20260831.aaaaaaa'   # end of month
  '0.93.9-nightly.20260901.bbbbbbb'   # month rollover
  '0.93.9-nightly.20261231.ccccccc'   # end of year
  '0.94.0-nightly.20270101.ddddddd'   # year rollover + a base-version bump
)

saw_equal_pair=0
for i in $(seq 1 $((${#nightly_builds[@]} - 1))); do
  earlier="${nightly_builds[$((i - 1))]}"
  later="${nightly_builds[$i]}"
  a="$(msi_compared "$earlier")"
  b="$(msi_compared "$later")"
  # Compare as msiexec does — field by field, numerically.
  order="$(awk -v a="$a" -v b="$b" 'BEGIN {
    split(a, x, "."); split(b, y, ".");
    for (i = 1; i <= 3; i++) {
      if ((y[i] + 0) > (x[i] + 0)) { print "greater"; exit }
      if ((y[i] + 0) < (x[i] + 0)) { print "lower"; exit }
    }
    print "equal";
  }')"
  case "$order" in
    greater)
      printf 'ok   %s -> %s upgrades (%s < %s)\n' "$earlier" "$later" "$a" "$b"
      ;;
    equal)
      saw_equal_pair=1
      printf 'note %s -> %s compares EQUAL (%s) — requires the same-version-upgrade policy\n' \
        "$earlier" "$later" "$a"
      ;;
    lower)
      printf 'FAIL %s -> %s compares LOWER to msiexec (%s > %s) — msiexec would abort on\n' \
        "$earlier" "$later" "$a" "$b"
      printf '     DowngradeErrorMessage and the host could never take another nightly.\n'
      failures=$((failures + 1))
      ;;
  esac
done

# The EQUAL case is only safe because the package declares it safe. If a future mapping DOES
# distinguish every build, `saw_equal_pair` is 0 and this requirement lifts on its own — which is
# what makes this an assertion about the invariant rather than about today's implementation.
if [ "$saw_equal_pair" -eq 1 ]; then
  if grep -q 'AllowSameVersionUpgrades="yes"' "$WXS"; then
    printf 'ok   equal-versioned builds upgrade in place (AllowSameVersionUpgrades="yes")\n'
  else
    printf 'FAIL the mapping produces EQUAL ProductVersions for distinct nightly builds, but\n'
    printf '     packaging/windows/dig-node.wxs does not set AllowSameVersionUpgrades="yes" — so the\n'
    printf '     second build of a UTC day installs as a SECOND product and its ServiceInstall of\n'
    printf '     net.dignetwork.dig-node fails or clobbers the one already registered.\n'
    failures=$((failures + 1))
  fi
fi

# The 4th-field implementation is still caught: it makes EVERY pair above compare equal, including
# ones a whole year apart, so the date stops being comparison-significant at all.
printf '\n== the date occupies a field msiexec compares (not an ignored 4th) ==\n'
first="$(msi_compared '0.93.9-nightly.20260804.603187a')"
last="$(msi_compared '0.93.9-nightly.20261231.ccccccc')"
if [ "$first" = "$last" ]; then
  printf 'FAIL builds five months apart compare EQUAL (%s) — the date is in a field msiexec\n' "$first"
  printf '     ignores. Windows Installer reads only major.minor.build.\n'
  failures=$((failures + 1))
else
  printf 'ok   the date moves a compared field (%s < %s)\n' "$first" "$last"
fi
if [ "$(msi_compared '0.93.9-nightly.20260805.deadbee')" != "0.93.${DAYS_20260805}" ]; then
  printf 'FAIL 20260805 maps to %s, want 0.93.%s\n' \
    "$(msi_compared '0.93.9-nightly.20260805.deadbee')" "$DAYS_20260805"
  failures=$((failures + 1))
else
  printf 'ok   the build field is the day count from 2020-01-01\n'
fi

printf '\n== the MSI field limits are pinned from BOTH sides ==\n'
ok 'minor at the pre-carry passthrough boundary' '0.255.0' '0.255.0' '0.255.0'
ok 'major at the MSI ceiling' '255.0.0' '255.0.0' '255.0.0'
rejects 'major one over the MSI ceiling' '256.0.0'
ok 'patch at the MSI ceiling' '0.1.65535' '0.1.65535' '0.1.65535'
rejects 'patch one over the MSI ceiling' '0.1.65536'

# ── MINOR exceeding 255 carries into the otherwise-idle MSI major field (dig_ecosystem#521/#522) ──
#
# dig-node's `0.<minor>.<patch>` scheme puts an ever-incrementing feat/breaking counter in MINOR
# (CLAUDE.md §2.4), which ran out at 0.255.x — `0.256.0` used to `die` here, which made every native
# package (.deb amd64/arm64, .msi, .pkg) unbuildable for every release after it. The fix folds MINOR
# into a legal MSI (major, minor) pair in base 256, reusing the MSI major field, which is otherwise
# idle at 0 for this repo's whole pre-1.0 lifetime. This must stay a byte-identical passthrough for
# every already-released version (MINOR <= 255) and must newly SUCCEED, not die, the instant it
# crosses 255.
printf '\n== minor exceeding 255 carries into the otherwise-idle MSI major field (dig_ecosystem#521/#522) ==\n'
ok 'last value before the carry activates' '0.255.9' '0.255.9' '0.255.9'
ok 'first carried value -- this used to die' '0.256.0' '0.256.0' '1.0.0'
ok 'carry mid-range' '0.511.0' '0.511.0' '1.255.0'
ok 'carry rolls the MSI major again' '0.512.3' '0.512.3' '2.0.3'
ok 'minor at the new outer ceiling' '0.65535.100' '0.65535.100' '255.255.100'
rejects 'minor one over the new ceiling' '0.65536.0'
rejects 'a real nonzero major collides with an overflowed minor' '1.256.0'
ok 'a nightly with an overflowed minor carries the same way; BUILD stays the day count' \
  '0.256.0-nightly.20260804.603187a' \
  '0.256.0-nightly.20260804.603187a' \
  "1.0.${DAYS_20260804}"

# The carry must be MONOTONIC across the boundary it exists for, exactly like the nightly day-count
# mapping above — not merely "each value individually looks right". `msi_compared` (defined above)
# strips to the fields msiexec actually reads, so this is the real comparison, not an assumption
# about it.
printf '\n== the carry is strictly increasing across the 255/256 boundary and beyond ==\n'
carry_boundary_versions=(
  '0.255.9'
  '0.256.0'
  '0.511.0'
  '0.512.3'
  '0.65535.100'
)
for i in $(seq 1 $((${#carry_boundary_versions[@]} - 1))); do
  earlier="${carry_boundary_versions[$((i - 1))]}"
  later="${carry_boundary_versions[$i]}"
  a="$(msi_compared "$earlier")"
  b="$(msi_compared "$later")"
  order="$(awk -v a="$a" -v b="$b" 'BEGIN {
    split(a, x, "."); split(b, y, ".");
    for (i = 1; i <= 3; i++) {
      if ((y[i] + 0) > (x[i] + 0)) { print "greater"; exit }
      if ((y[i] + 0) < (x[i] + 0)) { print "lower"; exit }
    }
    print "equal";
  }')"
  if [ "$order" = "greater" ]; then
    printf 'ok   %s -> %s upgrades (%s < %s)\n' "$earlier" "$later" "$a" "$b"
  else
    printf 'FAIL %s -> %s does not compare greater under msiexec (%s vs %s, order=%s)\n' \
      "$earlier" "$later" "$a" "$b" "$order"
    failures=$((failures + 1))
  fi
done

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
