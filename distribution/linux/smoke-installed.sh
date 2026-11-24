#!/usr/bin/env bash
# Starts the installed Orcel binaries inside a throwaway container that has
# the deb or the rpm, and fails unless every library and symbol they need is
# there. Needs no display or network.
#
# Usage: smoke-installed.sh daemon   (orceld's libraries; orcel-contain)
#        smoke-installed.sh helper   (the approval helper; needs GTK 4)
set -euo pipefail

dir=/usr/lib/orcel

fail() {
  echo "smoke test: $*" >&2
  exit 1
}

# Every library and symbol version is found, and so is every symbol the
# binary itself needs (ldd -r also reports those of other libraries).
resolves() {
  local out
  out=$(LC_ALL=C ldd -r "$1" 2>&1) || fail "ldd refuses $1: $out"
  echo "$out"
  case $out in *"not found"*) fail "$1 needs something this system lacks" ;; esac
  if grep -F "undefined symbol" <<< "$out" | grep -F "($1)"; then
    fail "$1 needs a symbol this system lacks"
  fi
  case $out in *libc.so.6*) ;; *) fail "ldd lists no libc for $1" ;; esac
}

case ${1:-} in
  daemon)
    resolves "$dir/orceld"
    resolves "$dir/orcel-contain"
    sum=$(sha256sum "$dir/orcel-contain" | cut -d ' ' -f 1)
    [ "$(cat "$dir/orcel-contain.sha256")" = "$sum" ] || fail "the pin does not name the installed orcel-contain"
    # With no spec it starts and refuses (exit 3) without launching anything.
    code=0
    out=$(timeout 60 "$dir/orcel-contain" < /dev/null) || code=$?
    echo "orcel-contain: exit $code: $out"
    [ "$code" -eq 3 ] || fail "orcel-contain exited $code, not 3"
    case $out in *" refused "*) ;; *) fail "orcel-contain wrote no refusal" ;; esac
    ;;
  helper)
    resolves "$dir/orcel-approval-helper-linux"
    # With no display it starts, reads a request and exits 3 with no answer.
    request='{"protocol":"orcel-approval-helper/1","nonce":"00000000000000000000000000000000","class":"SOFT","title":"smoke test","body":"smoke test","timeout_secs":2}'
    code=0
    out=$(printf '%s\n' "$request" | env -i PATH=/usr/bin:/bin timeout 60 "$dir/orcel-approval-helper-linux") || code=$?
    echo "orcel-approval-helper-linux: exit $code, answer '$out'"
    [ "$code" -eq 3 ] || fail "the approval helper exited $code, not 3"
    [ -z "$out" ] || fail "the approval helper answered without a display"
    ;;
  *)
    echo "usage: $0 daemon|helper" >&2
    exit 2
    ;;
esac
