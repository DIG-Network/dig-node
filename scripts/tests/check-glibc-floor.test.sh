#!/usr/bin/env bash
#
# Tests for scripts/check-glibc-floor.sh — the CI gate that keeps the shipped Linux binaries
# runnable on the oldest supported distro (#1736).
#
# The gate reads glibc symbol-version requirements out of a binary via `readelf`. These tests
# substitute a STUB readelf (`$READELF_BIN`) so they exercise the comparison logic on exact,
# adversarial inputs without needing a real ELF file — and so they run on any host, including
# the Windows dev boxes this repo is developed on.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/../check-glibc-floor.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0

# Writes a stub `readelf` whose output is the given fixture text, and echoes its path.
stub_readelf() {
  local path="$WORK/readelf-$1"
  shift
  {
    echo '#!/usr/bin/env bash'
    echo 'cat <<"FIXTURE_EOF"'
    printf '%s\n' "$@"
    echo 'FIXTURE_EOF'
  } >"$path"
  chmod +x "$path"
  echo "$path"
}

# expect <name> <expected-exit> <readelf-stub> <floor> [VAR=value ...]
# Trailing `VAR=value` arguments are exported into the gate's environment only for that case.
expect() {
  local name="$1" want="$2" stub="$3" floor="$4"
  shift 4
  local out status
  out="$(READELF_BIN="$stub" env "$@" bash "$GATE" "$WORK/fake-binary" "$floor" 2>&1)"
  status=$?
  if [ "$status" -ne "$want" ]; then
    printf 'FAIL %s: exit %s, want %s\n%s\n' "$name" "$status" "$want" "$out"
    failures=$((failures + 1))
  else
    printf 'ok   %s\n' "$name"
  fi
}

: >"$WORK/fake-binary"

# A binary needing exactly the floor is ACCEPTED — the at-bound side of the bound. Without this
# case a gate could reject everything and still look green on the over-bound case alone.
at_bound="$(stub_readelf at-bound \
  '  0000: 0x0b792650 0x00 04 GLIBC_2.31' \
  '   4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.14 (3)')"
expect 'at the floor passes' 0 "$at_bound" 2.31

# One minor OVER the floor is REJECTED — this is the regression the gate exists to catch: it is
# exactly what `ubuntu-latest` moving to 24.04 did to v0.64.0 (2.39 against a 2.35 target).
over_bound="$(stub_readelf over-bound \
  '  0000: 0x0b792650 0x00 04 GLIBC_2.32' \
  '   4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.14 (3)')"
expect 'one minor over the floor fails' 1 "$over_bound" 2.31

# VERSION-ORDER trap: glibc 2.4 is OLDER than 2.31, but a LEXICAL string comparison says
# "2.4" > "2.31" and would reject this binary. Only a numeric/version-aware comparison passes,
# so this fixture is what distinguishes the correct gate from the nearest wrong one.
lexical_trap="$(stub_readelf lexical-trap \
  '  0000: 0x0b792650 0x00 04 GLIBC_2.4' \
  '  0010: 0x09691a75 0x00 03 GLIBC_2.17')"
expect 'a 2.4 requirement is older than a 2.31 floor' 0 "$lexical_trap" 2.31

# GLIBC_PRIVATE carries no version number. An implementation that swept it into the requirement
# set would take it as the maximum (it sorts above any digit) and reject a binary that is in fact
# well under the floor. The other requirement here is DELIBERATELY below the floor so the expected
# result is PASS: expecting a failure here would be satisfied by the swallowing implementation too.
private_tag="$(stub_readelf private-tag \
  '  0000: 0x09691f71 0x00 04 GLIBC_PRIVATE' \
  '  0010: 0x09691a75 0x00 03 GLIBC_2.17')"
expect 'GLIBC_PRIVATE is not mistaken for a requirement' 0 "$private_tag" 2.31

# A binary with NO versioned glibc symbols FAILS CLOSED. This is the musl escape hatch the other
# two floor gates cannot see: the container assert only measures the CONTAINER's glibc (which a musl
# TARGET built inside it still satisfies) and `verify-linux-floor` goes green because a musl binary
# starts everywhere. Returning OK here would let a switch to `*-musl` pass all three gates while
# silently swapping the DNS resolver the node seeds from (SPEC.md §11.3).
no_glibc="$(stub_readelf no-glibc '  There is no dynamic section in this file.')"
expect 'no versioned glibc symbols fails closed' 3 "$no_glibc" 2.31

# ...unless the caller DECLARES a deliberate no-glibc build. Without this case the fail-closed
# behaviour above could only be satisfied by a gate that rejects every static binary unconditionally,
# leaving no way to ship one.
expect 'a declared no-glibc build is allowed' 0 "$no_glibc" 2.31 ALLOW_NO_GLIBC=1

# A missing floor argument is a MISUSE, not a pass — a gate invoked wrongly must never be
# silently green, which is how a CI gate rots into a no-op.
expect 'a missing floor is a usage error' 2 "$at_bound" ''

if [ "$failures" -ne 0 ]; then
  printf '\n%s test(s) failed\n' "$failures"
  exit 1
fi
printf '\nall check-glibc-floor tests passed\n'
