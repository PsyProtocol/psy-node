#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
repo="$tmp/node"
git init -q "$repo"
git -C "$repo" config user.name 'Source Gate Test'
git -C "$repo" config user.email 'source-gate@example.invalid'
git -C "$repo" remote add origin git@github.com:PsyProtocol/psy-node.git
package=psy_cli/psy_relayer_cli
mkdir -p "$repo/$package/src" "$repo/deploy"
printf 'fn main() {}\n' > "$repo/$package/src/main.rs"
git -C "$repo" add "$package/src/main.rs"
git -C "$repo" commit -qm 'fixture runtime'
export EXPECTED_PARTH_RUNTIME_REPOSITORY=PsyProtocol/psy-node
EXPECTED_PARTH_RUNTIME_COMMIT="$(git -C "$repo" rev-parse HEAD)"
export EXPECTED_PARTH_RUNTIME_COMMIT
unset EXPECTED_RELAYER_COMMIT EXPECTED_RELAYER_REPOSITORY

check() { bash "$ROOT/deploy/gcp/verify-relayer-source.sh" "$repo"; }
reject() {
  if check >"$tmp/result" 2>&1; then
    echo "expected source gate rejection: $1" >&2
    exit 1
  fi
  grep -Fq "$1" "$tmp/result"
}

check
printf '# deployment-only change\n' > "$repo/deploy/config.env"
git -C "$repo" add deploy/config.env
git -C "$repo" commit -qm 'fixture deployment'
check

EXPECTED_RELAYER_COMMIT=0000000000000000000000000000000000000000
export EXPECTED_RELAYER_COMMIT
reject 'not an independent source pin'
export EXPECTED_RELAYER_COMMIT="$EXPECTED_PARTH_RUNTIME_COMMIT"
check

printf '// unpublished patch\n' >> "$repo/$package/src/main.rs"
reject 'uncommitted relayer files are forbidden'
ALLOW_DIRTY_DEPLOY_SOURCES=1 reject 'uncommitted relayer files are forbidden'
git -C "$repo" add "$package/src/main.rs"
reject 'uncommitted relayer files are forbidden'
git -C "$repo" commit -qm 'fixture private runtime patch'
reject 'relayer source changes absent from the node runtime pin'

EXPECTED_PARTH_RUNTIME_COMMIT="$(git -C "$repo" rev-parse HEAD)"
export EXPECTED_RELAYER_COMMIT="$EXPECTED_PARTH_RUNTIME_COMMIT"
check
printf '// untracked source\n' > "$repo/$package/src/new.rs"
reject 'uncommitted relayer files are forbidden'
git -C "$repo" add "$package/src/new.rs"
git -C "$repo" commit -qm 'fixture publish new source'
EXPECTED_PARTH_RUNTIME_COMMIT="$(git -C "$repo" rev-parse HEAD)"
export EXPECTED_RELAYER_COMMIT="$EXPECTED_PARTH_RUNTIME_COMMIT"
check

git -C "$repo" remote set-url origin git@github.com:QEDProtocol/psy-node.git
reject 'checkout origin is not PsyProtocol/psy-node'

(
  # The profile exposes legacy relayer variable names only as aliases of node pins.
  source "$ROOT/deploy/multi-chain/gcp/source-versions.env"
  [ "$EXPECTED_RELAYER_COMMIT" = "$EXPECTED_PARTH_RUNTIME_COMMIT" ]
  [ "$EXPECTED_RELAYER_REPOSITORY" = "$EXPECTED_PARTH_RUNTIME_REPOSITORY" ]
)
echo 'relayer source gate tests passed'
