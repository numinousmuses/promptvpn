#!/bin/sh
# Build signed release archives for the given Rust targets (default: host).
#   scripts/package.sh [target ...]
# Produces dist/promptvpn-<version>-<os>-<arch>.tar.gz, dist/SHA256SUMS and,
# when a release key is available, dist/SHA256SUMS.sig (ssh-keygen -Y sign).
# The dashboard is built first and embedded; no Node runtime is needed at install.
set -eu
. "$HOME/.cargo/env" 2>/dev/null || true
root=$(cd "$(dirname "$0")/.." && pwd); cd "$root"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
targets=${*:-$(rustc -vV | sed -n 's/host: //p')}
key=${PROMPTVPN_RELEASE_KEY:-$HOME/.promptvpn-release/release_key}

if [ -f apps/dashboard/package.json ]; then
  (cd apps/dashboard && npm ci --no-audit --no-fund && npm run build)
fi
mkdir -p dist
for t in $targets; do
  case "$t" in
    aarch64-apple-darwin) name=macos-arm64 ;;
    x86_64-apple-darwin) name=macos-x86_64 ;;
    x86_64-unknown-linux-gnu) name=linux-x86_64 ;;
    aarch64-unknown-linux-gnu) name=linux-arm64 ;;
    *) echo "unsupported target $t" >&2; exit 1 ;;
  esac
  cargo build --release --locked -p pv-cli --target "$t"
  stage="dist/promptvpn-$version-$name"
  rm -rf "$stage"; mkdir -p "$stage"
  cp "target/$t/release/promptvpn" "$stage/"
  cp README.md LICENSE models.lock.json "$stage/"
  cp -R skills "$stage/skills"
  tar -czf "$stage.tar.gz" -C dist "promptvpn-$version-$name"
  rm -rf "$stage"
  echo "built $stage.tar.gz"
done
(cd dist && (sha256sum promptvpn-*.tar.gz 2>/dev/null || shasum -a 256 promptvpn-*.tar.gz) > SHA256SUMS)
if [ -f "$key" ]; then
  rm -f dist/SHA256SUMS.sig
  ssh-keygen -q -Y sign -f "$key" -n promptvpn-release dist/SHA256SUMS </dev/null
  echo "signed dist/SHA256SUMS"
else
  echo "warning: no release key at $key; SHA256SUMS is unsigned" >&2
fi
cat dist/SHA256SUMS
