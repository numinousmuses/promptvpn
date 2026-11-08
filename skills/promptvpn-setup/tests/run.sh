#!/bin/sh
# Tests for the promptvpn-setup skill scripts. Runs in a temporary HOME and
# PV_HOME; never touches the user's real configuration.
#   PROMPTVPN_BIN=target/debug/promptvpn sh skills/promptvpn-setup/tests/run.sh
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
skill="$root/skills/promptvpn-setup"
PV=${PROMPTVPN_BIN:-$root/target/debug/promptvpn}
[ -x "$PV" ] || { echo "build first: cargo build -p pv-cli" >&2; exit 1; }
export PROMPTVPN_BIN="$PV"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
pass=0; fail=0
ok() { pass=$((pass+1)); echo "ok   - $1"; }
no() { fail=$((fail+1)); echo "FAIL - $1"; }

# 1. discover: valid JSON, read-only
HOME="$tmp/home" sh "$skill/scripts/discover.sh" > "$tmp/d.json"
python3 -I -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['os'] in ('macos','linux'); assert len(d['clients'])==4" "$tmp/d.json" && ok "discover emits valid JSON" || no "discover JSON"
[ ! -e "$tmp/home" ] && ok "discover wrote nothing" || no "discover created files"

# 2. install: signed release accepted; tampering and bad signatures rejected
rel="$tmp/rel"; mkdir -p "$rel/promptvpn-test"
cp "$PV" "$rel/promptvpn-test/promptvpn"
tar -czf "$rel/promptvpn-test.tar.gz" -C "$rel" promptvpn-test
(cd "$rel" && (sha256sum promptvpn-test.tar.gz 2>/dev/null || shasum -a 256 promptvpn-test.tar.gz) > SHA256SUMS)
key=${PROMPTVPN_RELEASE_KEY:-$HOME/.promptvpn-release/release_key}
if [ -f "$key" ]; then
  ssh-keygen -q -Y sign -f "$key" -n promptvpn-release "$rel/SHA256SUMS"
  mv "$rel/SHA256SUMS.sig" "$rel/good.sig"
  sh "$skill/scripts/install.sh" --archive "$rel/promptvpn-test.tar.gz" --sums "$rel/SHA256SUMS" --sig "$rel/good.sig" --prefix "$tmp/bin" >/dev/null && [ -x "$tmp/bin/promptvpn" ] && ok "install verifies signature + checksum" || no "install of valid release"
  cp "$rel/promptvpn-test.tar.gz" "$rel/bad.tar.gz"; printf 'x' >> "$rel/bad.tar.gz"
  set +e; sh "$skill/scripts/install.sh" --archive "$rel/bad.tar.gz" --sums "$rel/SHA256SUMS" --sig "$rel/good.sig" --prefix "$tmp/bin2" >/dev/null 2>&1; rc=$?; set -e
  [ $rc -eq 67 ] && [ ! -e "$tmp/bin2/promptvpn" ] && ok "tampered archive rejected" || no "tampered archive rc=$rc"
  ssh-keygen -q -t ed25519 -N "" -f "$tmp/otherkey" </dev/null >/dev/null
  ssh-keygen -q -Y sign -f "$tmp/otherkey" -n promptvpn-release "$rel/SHA256SUMS" </dev/null 2>/dev/null; mv "$rel/SHA256SUMS.sig" "$rel/forged.sig"
  set +e; sh "$skill/scripts/install.sh" --archive "$rel/promptvpn-test.tar.gz" --sums "$rel/SHA256SUMS" --sig "$rel/forged.sig" --prefix "$tmp/bin3" >/dev/null 2>&1; rc=$?; set -e
  [ $rc -eq 66 ] && ok "signature from another key rejected" || no "forged signature rc=$rc"
else
  echo "skip - install tests (no release key at $key)"
fi
set +e; sh "$skill/scripts/install.sh" --archive http://example.com/x.tgz --sums x --sig y >/dev/null 2>&1; rc=$?; set -e
[ $rc -eq 65 ] && ok "plain http refused" || no "plain http rc=$rc"

# 3. egress test passes (synthetic secrets never reach the mock)
sh "$skill/scripts/egress_test.sh" > "$tmp/egress.txt" 2>&1 && grep -q PASS "$tmp/egress.txt" && ok "egress test passes" || { cat "$tmp/egress.txt"; no "egress test"; }

# 4. client configure is reversible and idempotent (temp HOME and PV_HOME)
export PV_HOME="$tmp/pvhome"; mkdir -p "$PV_HOME/apps"; printf 'pvk_test' > "$PV_HOME/apps/default.key"
mkdir -p "$tmp/h/.config/opencode"; printf '{"theme": "dark"}\n' > "$tmp/h/.config/opencode/opencode.json"
orig=$(cat "$tmp/h/.config/opencode/opencode.json")
HOME="$tmp/h" "$PV" --port 1 client configure opencode --yes >/dev/null
HOME="$tmp/h" "$PV" --port 1 client configure opencode --yes >/dev/null
grep -q promptvpn "$tmp/h/.config/opencode/opencode.json" && grep -q '"theme"' "$tmp/h/.config/opencode/opencode.json" && ok "opencode configured, existing keys kept" || no "opencode configure"
HOME="$tmp/h" sh "$skill/scripts/rollback.sh" opencode >/dev/null
[ "$(cat "$tmp/h/.config/opencode/opencode.json")" = "$orig" ] && ok "rollback restores original after repeated configure" || no "rollback"
set +e; HOME="$tmp/h" "$PV" --port 1 client configure vscode --yes >/dev/null 2>&1; rc=$?; set -e
[ $rc -ne 0 ] && ok "unsupported client refused" || no "unsupported client accepted"

echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
