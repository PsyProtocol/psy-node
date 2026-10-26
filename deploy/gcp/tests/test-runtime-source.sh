#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=../lib/runtime-source.sh
source "$ROOT/deploy/gcp/lib/runtime-source.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git init -q "$tmp"
git -C "$tmp" config user.name 'Source Gate Test'
git -C "$tmp" config user.email 'source-gate@example.invalid'
mkdir -p "$tmp/.github/workflows" "$tmp/deploy"
printf 'runtime\n' > "$tmp/runtime.rs"
printf '[workspace]\n' > "$tmp/Cargo.toml"
printf '/target/\n' > "$tmp/.gitignore"
printf 'obsolete publisher\n' > "$tmp/.github/workflows/deploy-shield-frontends.yml"
git -C "$tmp" add runtime.rs Cargo.toml .gitignore .github/workflows/deploy-shield-frontends.yml
git -C "$tmp" commit -qm runtime
base="$(git -C "$tmp" rev-parse HEAD)"
verify_deployment_runtime_tree "$tmp" "$base"

# These are fixture mutations, never operations on a real release checkout.
printf '/.private/\n' >> "$tmp/.gitignore"
git -C "$tmp" rm -q .github/workflows/deploy-shield-frontends.yml
printf 'deployment only\n' > "$tmp/deploy/README.md"
git -C "$tmp" add .gitignore deploy/README.md
git -C "$tmp" commit -qm 'allowed deployment metadata'
verify_deployment_runtime_tree "$tmp" "$base"
good="$(git -C "$tmp" rev-parse HEAD)"
reject() {
  if verify_deployment_runtime_tree "$tmp" "$base" > "$tmp/result" 2>&1; then
    echo "source gate accepted $1" >&2
    exit 1
  fi
  grep -Fq "$1" "$tmp/result"
  git -C "$tmp" reset --hard -q "$good"
}
for path in runtime.rs Cargo.toml .gitignore .github/workflows/deploy-shield-frontends.yml; do
  mkdir -p "$(dirname "$tmp/$path")"
  printf 'unreviewed change\n' >> "$tmp/$path"
  git -C "$tmp" add "$path"
  git -C "$tmp" commit -qm "bad $path"
  reject "$path"
done
printf 'not a gitlink\n' > "$tmp/psy-dapp"
git -C "$tmp" add psy-dapp
git -C "$tmp" commit -qm 'bad submodule type'
reject psy-dapp
echo '[ok] runtime code and Cargo changes fail closed; only exact security metadata exceptions are accepted'
