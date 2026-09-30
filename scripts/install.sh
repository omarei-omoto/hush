#!/bin/sh
# Install hush — the single-file binary, no Node needed.
#
#   curl -fsSL https://raw.githubusercontent.com/omarei-omoto/hush/main/scripts/install.sh | sh
#
# What it does, all of it:
#   1. works out this machine's build (macOS/Linux, x64/arm64, glibc/musl);
#   2. downloads that binary and the release's SHA256SUMS from GitHub;
#   3. refuses to install unless the binary's sha256 is the one SHA256SUMS lists;
#   4. if the GitHub CLI is installed and signed in, also checks the build's
#      provenance attestation (which workflow, which commit, built it);
#   5. puts it at ~/.local/bin/hush. Never sudo, never a shell profile edit.
#
# Settings, all optional:
#   HUSH_VERSION=1.0.0          a release to install (default: the latest)
#   HUSH_INSTALL_DIR=~/bin      where to put it (default: ~/.local/bin)
#   HUSH_VERIFY_ATTESTATION=0   skip the gh attestation check even if gh is there
#   HUSH_DOWNLOAD_BASE=<url>    a mirror holding the release's files
#
# Windows: scripts/install.ps1. Or skip all this: `npm i -g @omarei/hush`.

set -eu

REPO="omarei-omoto/hush"

say() { printf '%s\n' "$*"; }
fail() { printf 'hush install: %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------ which build

os="$(uname -s)"
case "$os" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  MINGW* | MSYS* | CYGWIN*) fail "on Windows, use PowerShell: irm https://raw.githubusercontent.com/$REPO/main/scripts/install.ps1 | iex" ;;
  *) fail "no hush binary for $os — install with npm instead: npm i -g @omarei/hush" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64 | amd64) arch=x64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "no hush binary for $arch — install with npm instead: npm i -g @omarei/hush" ;;
esac

# A shell running under Rosetta reports x86_64 on an Apple silicon Mac; the
# native build is the right one there.
if [ "$os" = darwin ] && [ "$arch" = x64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
  arch=arm64
fi

target="$os-$arch"
if [ "$os" = linux ]; then
  # Alpine and other musl systems cannot start the glibc build.
  if ls /lib/ld-musl-* >/dev/null 2>&1 || (ldd --version 2>&1 | grep -qi musl); then
    target="$target-musl"
  fi
fi
file="hush-$target"

version="${HUSH_VERSION:-}"
version="${version#v}"
if [ -n "${HUSH_DOWNLOAD_BASE:-}" ]; then
  base="${HUSH_DOWNLOAD_BASE%/}"
elif [ -n "$version" ]; then
  base="https://github.com/$REPO/releases/download/v$version"
else
  base="https://github.com/$REPO/releases/latest/download"
fi

dir="${HUSH_INSTALL_DIR:-$HOME/.local/bin}"

# ------------------------------------------------------------ download

fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https,file' --retry 2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    fail "needs curl or wget"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    fail "needs sha256sum or shasum to check the download"
  fi
}

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t hush)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "hush: downloading $file${version:+ $version}"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download SHA256SUMS from $base"
fetch "$base/$file" "$tmp/$file" || fail "could not download $file from $base"

# ------------------------------------------------------------ verify

expected="$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$expected" ] || fail "SHA256SUMS does not list $file — not installing"
actual="$(sha256 "$tmp/$file")"
if [ "$actual" != "$expected" ]; then
  fail "checksum mismatch for $file — not installing
  expected $expected
  got      $actual"
fi
say "hush: sha256 ok ($actual)"

if [ "${HUSH_VERIFY_ATTESTATION:-1}" != 0 ] && command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  if gh attestation verify "$tmp/$file" --repo "$REPO" >/dev/null 2>&1; then
    say "hush: provenance ok (built by $REPO's release workflow)"
  else
    fail "the GitHub attestation for $file does not verify — not installing (HUSH_VERIFY_ATTESTATION=0 skips this check)"
  fi
fi

# ------------------------------------------------------------ install

mkdir -p "$dir"
chmod 755 "$tmp/$file"
mv -f "$tmp/$file" "$dir/hush"

installed="$("$dir/hush" --version 2>/dev/null)" || {
  if [ "$os" = linux ] && [ "${target%-musl}" != "$target" ]; then
    fail "installed, but it does not start — on Alpine: apk add libstdc++ libgcc"
  fi
  fail "installed at $dir/hush, but it does not start"
}
say "hush: installed $installed at $dir/hush"

case ":$PATH:" in
  *":$dir:"*) ;;
  *) say ""; say "  $dir is not on your PATH. Add it, e.g.:"; say "    echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile" ;;
esac
say ""
say "  Next: cd into a project and run  hush start"
