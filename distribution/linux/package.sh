#!/usr/bin/env bash
# XP-17: builds the Linux deb, rpm and per-user tarball of Orcel from a
# release build of orceld, and writes SHA256SUMS-linux.txt over them.
#
# Usage (from anywhere; nfpm must be on PATH):
#   distribution/linux/package.sh <version> <orceld-binary> <out-dir>
#
# The deb and rpm come from distribution/linux/nfpm.yaml. The tarball holds
# the same orceld and units for a per-user install under
# ~/.local/share/orcel (see README.md), with the service's ExecStart pointed
# there. Archive timestamps come from the last commit, so equal inputs give
# equal archives.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <version> <orceld-binary> <out-dir>" >&2
  exit 2
fi
version=$1
orceld=$2
out=$3

repo=$(cd "$(dirname "$0")/../.." && pwd)
case "$(uname -m)" in
  x86_64) deb_arch=amd64 tar_arch=x86_64 ;;
  aarch64) deb_arch=arm64 tar_arch=aarch64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

mkdir -p "$out"
out=$(cd "$out" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

install -m 0755 "$orceld" "$stage/orceld"
node "$repo/scripts/third-party-notices.mjs" --release "$stage" \
  --out "$stage/THIRD_PARTY_NOTICES.txt" --target "$tar_arch-unknown-linux-gnu"

SOURCE_DATE_EPOCH=$(git -C "$repo" log -1 --format=%ct)
export SOURCE_DATE_EPOCH

cd "$repo"
install -m 0644 distribution/linux/orceld.socket distribution/linux/orceld@.service \
  distribution/linux/README.md LICENSE "$stage/"
for packager in deb rpm; do
  (cd "$stage" && ORCEL_VERSION=$version ORCEL_ARCH=$deb_arch \
    nfpm package --config "$repo/distribution/linux/nfpm.yaml" --packager "$packager" --target "$out/")
done

name="orcel-$version-linux-$tar_arch"
tree="$stage/$name"
mkdir -p "$tree/bin" "$tree/systemd" "$tree/doc"
install -m 0755 "$stage/orceld" "$tree/bin/orceld"
install -m 0644 distribution/linux/orceld.socket "$tree/systemd/orceld.socket"
sed 's#^ExecStart=/usr/lib/orcel/orceld$#ExecStart=%h/.local/share/orcel/bin/orceld#' \
  distribution/linux/orceld@.service > "$tree/systemd/orceld@.service"
chmod 0644 "$tree/systemd/orceld@.service"
if ! grep -qx 'ExecStart=%h/.local/share/orcel/bin/orceld' "$tree/systemd/orceld@.service"; then
  echo "the tarball unit's ExecStart was not rewritten" >&2
  exit 1
fi
install -m 0644 LICENSE distribution/linux/README.md "$stage/THIRD_PARTY_NOTICES.txt" "$tree/doc/"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
  -C "$stage" -czf "$out/$name.tar.gz" "$name"

cd "$out"
sha256sum -- *.deb *.rpm "$name.tar.gz" > SHA256SUMS-linux.txt
cat SHA256SUMS-linux.txt
