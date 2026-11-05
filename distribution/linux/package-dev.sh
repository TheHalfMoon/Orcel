#!/usr/bin/env bash
# Builds an UNSIGNED Linux development tarball of Orcel with its MCP server, so a
# local client can connect from an unpacked folder. Separate from the deb, rpm and
# per-user tarball of package.sh, which are the release packages.
#
# Usage (from anywhere on Linux, after `npm ci` and the edge's build):
#   distribution/linux/package-dev.sh <version> <orceld-binary> <orcel-contain-binary> \
#     <approval-helper-binary> <out-dir>
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <version> <orceld-binary> <orcel-contain-binary> <approval-helper-binary> <out-dir>" >&2
  exit 2
fi
version=$1
orceld=$2
contain=$3
approval=$4
out=$5

repo=$(cd "$(dirname "$0")/../.." && pwd)
case "$(uname -m)" in
  x86_64) tar_arch=x86_64 ;;
  aarch64) tar_arch=aarch64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

name="orcel-$version-linux-$tar_arch-unsigned-dev"
tree="$stage/$name"
mkdir -p "$tree/bin" "$tree/doc"
install -m 0755 "$orceld" "$tree/bin/orceld"
install -m 0755 "$contain" "$tree/bin/orcel-contain"
install -m 0755 "$approval" "$tree/bin/orcel-approval-helper-linux"
install -m 0755 "$repo/distribution/dev/orcel-mcp" "$tree/bin/orcel-mcp"
sha256sum "$tree/bin/orcel-contain" | cut -d ' ' -f 1 > "$tree/bin/orcel-contain.sha256"
chmod 0644 "$tree/bin/orcel-contain.sha256"
node "$repo/scripts/mcp-payload.mjs" "$tree"
node "$repo/scripts/third-party-notices.mjs" --release "$tree" \
  --out "$tree/doc/THIRD_PARTY_NOTICES.txt" --target "$tar_arch-unknown-linux-gnu"
install -m 0644 "$repo/LICENSE" "$repo/distribution/linux/README.md" "$tree/doc/"

SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct)
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
  -C "$stage" -czf "$out/$name.tar.gz" "$name"

cd "$out"
sha256sum "$name.tar.gz" > SHA256SUMS-linux-dev.txt
cat SHA256SUMS-linux-dev.txt
