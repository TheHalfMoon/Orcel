#!/usr/bin/env bash
# Builds an UNSIGNED macOS development tarball of Orcel from a release build
# of orceld and of the orcel-contain helper (its own workspace in
# apps/orcel-contain), and writes SHA256SUMS-macos.txt over it.
#
# This is not a release. Signing, notarization and the app bundle are XP-16,
# which waits on FD-05. The binaries carry only the ad-hoc signature the
# linker gives them on Apple Silicon. See README.md.
#
# It holds the MCP server too, so a local client can connect from the unpacked
# folder (bin/orcel-mcp). Run `npm ci` and the edge's build first.
#
# Usage (from anywhere, on macOS):
#   distribution/macos/package-dev.sh <version> <orceld-binary> <orcel-contain-binary> <out-dir>
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <version> <orceld-binary> <orcel-contain-binary> <out-dir>" >&2
  exit 2
fi
version=$1
if [ -z "$version" ]; then
  echo "the version is empty" >&2
  exit 2
fi
orceld=$2
contain=$3
out=$4

if [ "$(uname -s)" != "Darwin" ]; then
  echo "this builds the macOS tarball and runs on macOS" >&2
  exit 2
fi
repo=$(cd "$(dirname "$0")/../.." && pwd)
case "$(uname -m)" in
  arm64) tar_arch=aarch64 ;;
  x86_64) tar_arch=x86_64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

name="orcel-$version-macos-$tar_arch-unsigned-dev"
tree="$stage/$name"
mkdir -p "$tree/bin" "$tree/doc"
install -m 0755 "$orceld" "$tree/bin/orceld"
install -m 0755 "$contain" "$tree/bin/orcel-contain"
install -m 0755 "$repo/distribution/dev/orcel-mcp" "$tree/bin/orcel-mcp"
# orceld pins the helper beside it by this file (apps/orcel-contain/README.md).
shasum -a 256 "$tree/bin/orcel-contain" | cut -d ' ' -f 1 > "$tree/bin/orcel-contain.sha256"
chmod 0644 "$tree/bin/orcel-contain.sha256"
node "$repo/scripts/mcp-payload.mjs" "$tree"
node "$repo/scripts/third-party-notices.mjs" --release "$tree" \
  --out "$tree/doc/THIRD_PARTY_NOTICES.txt" --target "$tar_arch-apple-darwin"
install -m 0644 "$repo/LICENSE" "$repo/distribution/macos/README.md" "$tree/doc/"

# No resource forks or extended attributes in the archive.
COPYFILE_DISABLE=1 tar --no-xattrs -C "$stage" -czf "$out/$name.tar.gz" "$name"

cd "$out"
shasum -a 256 "$name.tar.gz" > SHA256SUMS-macos.txt
cat SHA256SUMS-macos.txt
