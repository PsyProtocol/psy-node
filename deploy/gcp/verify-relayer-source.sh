#!/usr/bin/env bash
set -euo pipefail

repo="${1:?usage: verify-relayer-source.sh PSY_NODE_CHECKOUT}"
expected="${EXPECTED_PARTH_RUNTIME_COMMIT:?pin EXPECTED_PARTH_RUNTIME_COMMIT}"
package=psy_cli/psy_relayer_cli
fail() { echo "[relayer-source] $*" >&2; exit 1; }

[[ "$expected" =~ ^[0-9a-f]{40}$ ]] || fail 'the node runtime pin must be a full commit SHA'
[ "${EXPECTED_PARTH_RUNTIME_REPOSITORY:-}" = PsyProtocol/psy-node ] \
  || fail 'the node runtime repository must be PsyProtocol/psy-node'
[ "${EXPECTED_RELAYER_COMMIT:-$expected}" = "$expected" ] \
  || fail 'relayer must use the node runtime commit, not an independent source pin'
[ "${EXPECTED_RELAYER_REPOSITORY:-PsyProtocol/psy-node}" = PsyProtocol/psy-node ] \
  || fail 'relayer must use the node runtime repository'

origin="$(git -C "$repo" remote get-url origin)"
origin="${origin%.git}"
case "$origin" in
  git@github.com:PsyProtocol/psy-node|https://github.com/PsyProtocol/psy-node|ssh://git@github.com/PsyProtocol/psy-node) ;;
  *) fail 'checkout origin is not PsyProtocol/psy-node' ;;
esac
git -C "$repo" cat-file -e "$expected:$package/src/main.rs" \
  || fail 'pinned node revision does not contain the relayer executable'
git -C "$repo" merge-base --is-ancestor "$expected" HEAD \
  || fail 'deployment branch must contain the pinned node source revision'
git -C "$repo" diff --quiet "$expected" HEAD -- "$package" \
  || fail 'deployment branch contains relayer source changes absent from the node runtime pin'

dirty="$(git -C "$repo" status --porcelain --untracked-files=all -- "$package")"
if [ -n "$dirty" ]; then
  printf '%s\n' "$dirty" >&2
  fail 'uncommitted relayer files are forbidden; publish fixes to psy-node:multi_chain first'
fi
echo "[relayer-source] relayer matches PsyProtocol/psy-node@$expected; no local relayer patches"
