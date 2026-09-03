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
# STABLE-CHANNEL MINOR OVERFLOW (dig_ecosystem#521, dig_ecosystem#522). This repo's `0.<minor>.<patch>`
# scheme puts an ever-incrementing feat/breaking counter (CLAUDE.md §2.4) in MINOR, which is not
# bounded the way MSI's field is — it ran out at 0.255.x. Rather than reset MAJOR to 1 (a public
# maturity signal this pre-release repo should not make as a side effect of a packaging limit) or
# freeze MINOR and abandon the ecosystem's feat->minor SemVer convention, the overflow is carried
# into MSI's MAJOR field, which is otherwise idle at 0 for this repo's whole pre-1.0 lifetime:
#
#   MINOR <= 255:  MSI_MAJOR, MSI_MINOR = MAJOR, MINOR          (unchanged passthrough)
#   MINOR >  255:  MSI_MAJOR, MSI_MINOR = MINOR div 256, MINOR mod 256   (requires real MAJOR == 0)
#
# This is a strict backward-compatible extension: every version released before this carry existed
# has MINOR <= 255 and maps identically to today. msiexec compares ProductVersion as a numeric
# (major, minor, build) tuple in that priority order, which is exactly what a base-256 big-endian
# split needs to stay monotonic — so this buys headroom up to MINOR 65535 (a ~257x increase) with no
# new state and no change to how engineers pick MAJOR/MINOR/PATCH day to day. The carry only has a
# defined answer while the real MAJOR is 0; if MAJOR ever becomes nonzero (a deliberate 1.0.0
# decision) while MINOR is ALSO over 255, the two would collide in the same field, so that
# combination fails closed rather than guessing. See SPEC §11.5c.
#
# CRITICAL CAVEAT — monotonicity holds ONLY while real MAJOR remains 0 throughout this repo's
# release history. If MAJOR is ever bumped to nonzero (e.g., to 1.0.0) AFTER MINOR has exceeded
# 255 at any point in prior releases, the pre-bump release with a carried encoding (e.g., 0.600.0
# mapping to MSI 2.88.0) can compare HIGHER under msiexec's numeric comparison than the post-bump
# release's passthrough encoding (e.g., 1.0.0 mapping to MSI 1.0.0). This is a cross-release
# sequencing hazard, not caught by the in-version MAJOR==0 guard. Any future MAJOR bump that
# occurs after MINOR has overflowed requires re-deriving this mapping BEFORE that release to avoid
# the downgrade-class collision. This does not affect the current pre-release repo (MINOR has never
# exceeded 255 as of this PR); when it becomes relevant, the decision is a user-call, not something
# this script guesses.
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
#
# MINOR's ceiling is 65535, not 255: it is the field this repo's ever-incrementing counter lives in,
# and above 255 it is mapped into the MSI major field rather than emitted directly (see the header
# comment and dig_ecosystem#521/#522) — 65535 = 256*255+255 is the largest value that mapping can
# still express as a legal (major<=255, minor<=255) MSI pair.
[ "$MAJOR" -le 255 ] || die "major version $MAJOR exceeds the MSI ProductVersion limit of 255"
[ "$MINOR" -le 65535 ] || die "minor version $MINOR exceeds the MSI-mappable limit of 65535 (256*255+255 -- the overflow-carry ceiling from dig_ecosystem#521/#522)"
[ "$PATCH" -le 65535 ] || die "patch version $PATCH exceeds the MSI ProductVersion limit of 65535"

# Fold MINOR into a legal (<=255, <=255) MSI major/minor pair. Below the old ceiling this is a pure
# passthrough — identical to every version released before dig_ecosystem#521/#522 existed. Above it,
# the overflow carries into MSI's MAJOR field, which is otherwise idle at 0 for this repo's whole
# pre-1.0 lifetime; that only has a defined answer while the REAL major is 0; a real major bump
# combined with an overflowed minor is a fresh decision, not a guess, so it fails closed.
if [ "$MINOR" -le 255 ]; then
  MSI_MAJOR="$MAJOR"
  MSI_MINOR="$MINOR"
else
  if [ "$MAJOR" -ne 0 ]; then
    CARRY_COLLISION_MSG="minor version $MINOR needs the overflow-carry MSI mapping (dig_ecosystem#521/#522), "
    CARRY_COLLISION_MSG+="which is only defined for MAJOR==0 — got MAJOR=$MAJOR; this combination needs a "
    CARRY_COLLISION_MSG+="fresh decision, not a guess"
    die "$CARRY_COLLISION_MSG"
  fi
  MSI_MAJOR=$(( MINOR / 256 ))
  MSI_MINOR=$(( MINOR % 256 ))
fi

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
  MSI_PRODUCT_VERSION="${MSI_MAJOR}.${MSI_MINOR}.${BUILD}"
else
  MSI_PRODUCT_VERSION="${MSI_MAJOR}.${MSI_MINOR}.${PATCH}"
fi

printf 'file_version=%s\n' "$VERSION"
printf 'msi_product_version=%s\n' "$MSI_PRODUCT_VERSION"
