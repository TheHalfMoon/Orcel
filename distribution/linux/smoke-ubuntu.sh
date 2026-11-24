#!/usr/bin/env bash
# Installs the built deb in a clean Ubuntu 24.04 container, the oldest Ubuntu
# the packages support, and starts what it installs. Ubuntu 24.04 has glibc
# 2.39 and GTK 4.14.
#
# Usage (needs docker):
#   distribution/linux/smoke-ubuntu.sh <version> <dist-dir>
#
# First without the recommended packages, as on a headless server: orceld
# answers for an unprivileged user and orcel-contain starts. Then with GTK 4:
# the approval helper starts. No display, systemd, polkit or approval is
# involved; the CI job `Linux packages` covers the units on the runner itself.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <version> <dist-dir>" >&2
  exit 2
fi
version=$1
dist=$(cd "$2" && pwd)
repo=$(cd "$(dirname "$0")/../.." && pwd)

# The multi-platform index of ubuntu:24.04, read from registry-1.docker.io on
# 2026-11-24 (amd64 image of 2026-11-10).
image=docker.io/library/ubuntu@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b

docker run --rm --platform linux/amd64 -v "$dist:/dist:ro" -v "$repo:/repo:ro" \
  -e "ORCEL_VERSION=$version" -e DEBIAN_FRONTEND=noninteractive "$image" \
  bash -euxo pipefail -c '
    . /etc/os-release
    test "$ID $VERSION_ID" = "ubuntu 24.04"
    # The image leaves documentation out of every package; a real install does not.
    rm -f /etc/dpkg/dpkg.cfg.d/excludes
    apt-get update
    apt-get install -y --no-install-recommends "/dist/orcel_${ORCEL_VERSION}-1_amd64.deb" python3
    verify=$(dpkg --verify orcel)
    test -z "$verify"
    bash /repo/distribution/linux/smoke-installed.sh daemon
    useradd --create-home orcelci
    runuser -u orcelci -- mkdir /home/orcelci/ws
    runuser -u orcelci -- env -i HOME=/home/orcelci PATH=/usr/bin:/bin \
      ORCEL_WORKSPACES_JSON="[{\"id\":\"ci\",\"root\":\"/home/orcelci/ws\"}]" \
      python3 /repo/scripts/linux-orceld-probe.py exec /usr/lib/orcel/orceld ci
    test "$(stat -c "%a %U" /home/orcelci/.local/state/orcel)" = "700 orcelci"
    apt-get install -y --no-install-recommends libgtk-4-1
    bash /repo/distribution/linux/smoke-installed.sh helper
    apt-get remove -y orcel
    test ! -e /usr/lib/orcel
    test ! -e /usr/share/doc/orcel
    # User state is kept.
    test -d /home/orcelci/.local/state/orcel
  '
