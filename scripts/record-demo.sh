#!/bin/sh
# Record assets/demo.gif from docs/demo.tape with VHS in Docker, using the Linux
# build of hush (built first if missing). The values in it are fake.
set -eu
here="$(cd "$(dirname "$0")/.." && pwd)"
arch="$(docker version --format '{{.Server.Arch}}' 2>/dev/null || uname -m)"
case "$arch" in arm64|aarch64) target=linux-arm64 ;; *) target=linux-x64 ;; esac
[ -x "$here/release/hush-$target" ] || node "$here/scripts/build-binaries.mjs" --target "$target"
docker run --rm \
  -v "$here:/vhs" -w /vhs \
  -v "$here/release/hush-$target:/usr/local/bin/hush:ro" \
  ghcr.io/charmbracelet/vhs:latest docs/demo.tape
echo "wrote assets/demo.gif"
