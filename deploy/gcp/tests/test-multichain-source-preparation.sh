#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
repo="$tmp/repo"
profile="$repo/deploy/multi-chain/gcp"
mkdir -p "$profile" "$repo/deploy/scripts" "$tmp/bin"
cp "$ROOT/deploy/multi-chain/gcp/prepare-sources.sh" "$profile/"
export TEST_CALLS="$tmp/calls"
cat > "$tmp/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo "$*" >> "$TEST_CALLS"
[[ "$*" == *'submodule update --init '* ]] || exit 3
repo="$2"
child="${!#}"
mkdir -p "$repo/$child"
touch "$repo/$child/.git"
SH
chmod +x "$tmp/bin/git"
cat > "$repo/deploy/scripts/prepare-profile-sources.sh" <<'SH'
echo "pins=$1" >> "$TEST_CALLS"
exit "${TEST_PREPARE_EXIT:-0}"
SH
cat > "$profile/prepare-psy-services-source.sh" <<'SH'
echo services >> "$TEST_CALLS"
SH
export PATH="$tmp/bin:$PATH" DEPLOY_SOURCE_VERSIONS_FILE="$tmp/pins.env"
bash "$profile/prepare-sources.sh"
[ "$(grep -c 'submodule update --init' "$TEST_CALLS")" = 3 ]
for child in psy-genesis psy-contracts psy-dapp; do
  grep -Fq "submodule update --init $child" "$TEST_CALLS"
done
grep -Fxq "pins=$DEPLOY_SOURCE_VERSIONS_FILE" "$TEST_CALLS"
grep -Fxq services "$TEST_CALLS"

# Existing children reach the shared dirty/source gate without git update.
: > "$TEST_CALLS"
if TEST_PREPARE_EXIT=7 bash "$profile/prepare-sources.sh"; then exit 1; fi
[ "$(wc -l < "$TEST_CALLS")" = 1 ]
grep -Fxq "pins=$DEPLOY_SOURCE_VERSIONS_FILE" "$TEST_CALLS"
echo '[ok] only missing submodules are initialized; source overrides and failed source gates are preserved'
