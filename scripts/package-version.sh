#!/usr/bin/env bash
#
# The ONE validation + mapping boundary for a native-package version (dig_ecosystem#618).
#
# Every .deb/.pkg/.msi build passes its version through here before that string reaches a place
# where it stops being data:
#
#   * packaging/linux/build-deb.sh writes it into the `Version:` field of a dpkg CONTROL file;
#   * packaging/macos/build-pkg.sh hands it to `pkgbuild --version`;
#   * the WiX build passes it as `-d Version=<v>` and it becomes the MSI ProductVersion.
#
# Those packages are executed ELEVATED (msiexec / installer / dpkg) on every host that tracks the
# channel, so the version is validated by WHITELIST here — at the boundary, once — rather than
# escaped at each of three call sites. Nothing outside `[0-9a-f.-]` in the accepted grammar can
# survive, so the emitted values are safe to interpolate anywhere downstream.
#
# It also resolves the one genuine conflict between the two consumers of the version:
#
#   * the package FILE NAME must carry the version VERBATIM, prerelease suffix included, because
#     dig-updater's feedsign recovers a rolling-nightly release's version by stripping a fixed
#     head/tail off the asset file name (`dig-node_<version>_amd64.deb` and friends);
#   * the MSI ProductVersion must be NUMERIC `major.minor.build` — Windows Installer rejects
#     anything else — so `0.93.9-nightly.20260804.603187a` cannot be handed to WiX unchanged.
#
# For a nightly the mapping is `X.Y.<days since 2020-01-01>`. The date lands in the BUILD field, not
# a fourth field, because Windows Installer compares only major.minor.build: a fourth field is parsed
# and then ignored, so the date would stop being comparison-significant at all.
#
# This mapping is day-granular, and deliberately so: its INPUT carries a date and a commit sha and
# nothing else, and 16 bits of build field cannot hold a finer monotonic counter over any useful
# epoch (minute resolution exhausts the field in 45 days; a sha-derived tiebreak is not ordered,
# which would make a later build compare LOWER — far worse). Two builds on one UTC day therefore map
# to the SAME ProductVersion, which is reachable via the `force` re-cut and via a manual
# `channel: nightly` dispatch on a day the cron already ran. The required upgrade invariant is
# consequently held JOINTLY with packaging/windows/dig-node.wxs, whose
# `MajorUpgrade/@AllowSameVersionUpgrades="yes"` makes an equal version upgrade in place rather than
# install as a second product. Neither half is sufficient alone — see SPEC §11.5c, asserted by
# scripts/tests/package-version.test.sh.
#
# Usage: package-version.sh <version>
# Emits (stdout, `key=value` lines suitable for appending to $GITHUB_OUTPUT):
#   file_version=<version verbatim>
#   msi_product_version=<numeric major.minor.build>
# Exits non-zero, with the reason on stderr, for any version outside the accepted grammar.
set -euo pipefail

VERSION="${1-}"

die() {
  printf 'package-version: %s\n' "$1" >&2
  exit 1
}

# The accepted grammar, deliberately narrow: a plain `X.Y.Z` release, or that plus exactly the
# nightly suffix nightly-release.yml synthesizes (`-nightly.YYYYMMDD.<shortsha>`). No `v` prefix, no
# build metadata, no other prerelease shape — an unrecognised version is a bug in the caller, and
# failing closed here is cheaper than shipping an elevated package built from an unexpected string.
NIGHTLY_RE='-nightly\.([0-9]{8})\.[0-9a-f]{7,40}'
if [[ ! $VERSION =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)($NIGHTLY_RE)?$ ]]; then
  die "refusing version '$VERSION' — expected X.Y.Z or X.Y.Z-nightly.YYYYMMDD.<shortsha>"
fi
MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"
PATCH="${BASH_REMATCH[3]}"
NIGHTLY_DATE="${BASH_REMATCH[5]-}"

# Windows Installer's ProductVersion field limits. Exceeding one is not a rounding error: msiexec
# either rejects the package or silently truncates the field, which would make two versions compare
# equal. Checked for BOTH channels — a stable `0.256.0` is just as unbuildable as a nightly one.
[ "$MAJOR" -le 255 ] || die "major version $MAJOR exceeds the MSI ProductVersion limit of 255"
[ "$MINOR" -le 255 ] || die "minor version $MINOR exceeds the MSI ProductVersion limit of 255"
[ "$PATCH" -le 65535 ] || die "patch version $PATCH exceeds the MSI ProductVersion limit of 65535"

# Days from 2020-01-01 to YYYYMMDD, via Howard Hinnant's days_from_civil. Computed in awk rather
# than `date -d` because the three package jobs run on three different hosts — a debian:11 container
# (GNU coreutils, but no guaranteed python3), a macOS runner (BSD `date`, which has no `-d`), and a
# Windows runner — and a portable pure-arithmetic answer is identical on all of them.
days_since_2020() {
  awk -v ymd="$1" 'BEGIN {
    y = substr(ymd, 1, 4) + 0; m = substr(ymd, 5, 2) + 0; d = substr(ymd, 7, 2) + 0;
    if (m <= 2) y -= 1;
    era = int(y / 400);
    yoe = y - era * 400;
    doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
    doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy;
    print era * 146097 + doe - 719468 - 18262;   # 18262 = days from 1970-01-01 to 2020-01-01
  }'
}

if [ -n "$NIGHTLY_DATE" ]; then
  BUILD="$(days_since_2020 "$NIGHTLY_DATE")"
  # The epoch runs out when the build field would overflow (2199-06-06). Fail loudly rather than
  # emit a version msiexec would truncate.
  [ "$BUILD" -gt 0 ] && [ "$BUILD" -le 65535 ] \
    || die "nightly date $NIGHTLY_DATE maps to build field $BUILD, outside 1..65535"
  MSI_PRODUCT_VERSION="${MAJOR}.${MINOR}.${BUILD}"
else
  MSI_PRODUCT_VERSION="${MAJOR}.${MINOR}.${PATCH}"
fi

printf 'file_version=%s\n' "$VERSION"
printf 'msi_product_version=%s\n' "$MSI_PRODUCT_VERSION"
