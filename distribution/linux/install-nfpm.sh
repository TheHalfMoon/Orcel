#!/usr/bin/env bash
# XP-17: installs the pinned nfpm (MIT, build tool only) into <bin-dir> after
# checking the archive against the digest recorded here, which was copied
# from the release's checksums.txt.
#
# Usage: distribution/linux/install-nfpm.sh <bin-dir>
set -euo pipefail

version=2.47.0
sha256=0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783
archive="nfpm_${version}_Linux_x86_64.tar.gz"

bin=${1:?usage: $0 <bin-dir>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  -o "$work/$archive" "https://github.com/goreleaser/nfpm/releases/download/v${version}/${archive}"
echo "$sha256  $work/$archive" | sha256sum --check --strict
tar -xzf "$work/$archive" -C "$work" nfpm
mkdir -p "$bin"
install -m 0755 "$work/nfpm" "$bin/nfpm"
"$bin/nfpm" --version
