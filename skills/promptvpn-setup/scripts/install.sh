#!/bin/sh
# Verified install of a Prompt VPN release archive into ~/.local/bin (no sudo).
#   install.sh --archive <file-or-https-url> --sums <SHA256SUMS> --sig <SHA256SUMS.sig> [--prefix DIR]
# Verification: ssh-keygen -Y verify of SHA256SUMS against the pinned release key,
# then the archive's sha256 must appear in SHA256SUMS. Any failure aborts.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
prefix="$HOME/.local/bin"
archive=""; sums=""; sig=""
while [ $# -gt 0 ]; do
  case "$1" in
    --archive) archive=$2; shift 2 ;;
    --sums) sums=$2; shift 2 ;;
    --sig) sig=$2; shift 2 ;;
    --prefix) prefix=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done
[ -n "$archive" ] && [ -n "$sums" ] && [ -n "$sig" ] || { echo "usage: install.sh --archive A --sums SHA256SUMS --sig SHA256SUMS.sig" >&2; exit 64; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # fetch SRC DEST (local path or https URL only)
  case "$1" in
    https://*) curl -fsSL --proto '=https' --max-time 300 -o "$2" "$1" ;;
    http://*) echo "refusing plain http download: $1" >&2; exit 65 ;;
    *) cp "$1" "$2" ;;
  esac
}
fetch "$archive" "$work/archive.tar.gz"
fetch "$sums" "$work/SHA256SUMS"
fetch "$sig" "$work/SHA256SUMS.sig"

printf 'promptvpn-release %s\n' "$(cat "$here/release-key.pub")" > "$work/allowed_signers"
if ! ssh-keygen -Y verify -f "$work/allowed_signers" -I promptvpn-release -n promptvpn-release -s "$work/SHA256SUMS.sig" < "$work/SHA256SUMS" >/dev/null 2>&1; then
  echo "SIGNATURE VERIFICATION FAILED: SHA256SUMS is not signed by the pinned Prompt VPN release key. Nothing installed." >&2
  exit 66
fi

if command -v sha256sum >/dev/null 2>&1; then h=$(sha256sum "$work/archive.tar.gz" | awk '{print $1}'); else h=$(shasum -a 256 "$work/archive.tar.gz" | awk '{print $1}'); fi
if ! grep -q "^$h " "$work/SHA256SUMS"; then
  echo "CHECKSUM MISMATCH: archive sha256 $h is not listed in the signed SHA256SUMS. Nothing installed." >&2
  exit 67
fi

mkdir -p "$work/x"
tar -xzf "$work/archive.tar.gz" -C "$work/x"
bin=$(find "$work/x" -type f -name promptvpn | head -n 1)
[ -n "$bin" ] || { echo "archive does not contain a promptvpn binary" >&2; exit 68; }
mkdir -p "$prefix"
install -m 0755 "$bin" "$prefix/promptvpn"
echo "installed $prefix/promptvpn ($("$prefix/promptvpn" --version))"
case ":$PATH:" in *":$prefix:"*) ;; *) echo "note: add $prefix to PATH" ;; esac
