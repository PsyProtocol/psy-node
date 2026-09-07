#!/usr/bin/env bash

# Verify runtime bytes while retaining narrowly defined deployment metadata.
# Submodule revisions and cleanliness are checked separately by the profile.
verify_deployment_runtime_tree() {
  local repo="$1" expected="$2" path mode
  git -C "$repo" merge-base --is-ancestor "$expected" HEAD || return 1
  while IFS= read -r -d '' path; do
    case "$path" in
      deploy/*) continue ;;
      psy-genesis|psy-contracts|psy-dapp)
        mode="$(git -C "$repo" ls-tree HEAD -- "$path" | awk '{print $1}')"
        [ "$mode" = 160000 ] && continue
        ;;
      .github/workflows/deploy-shield-frontends.yml)
        # Removing the obsolete publisher prevents psy-node from overwriting
        # DApp-owned frontend releases. An edited or added workflow is forbidden.
        if ! git -C "$repo" cat-file -e "HEAD:$path" 2>/dev/null; then
          continue
        fi
        ;;
      .gitignore)
        mode="$(git -C "$repo" ls-tree HEAD -- "$path" | awk '{print $1}')"
        if [ "$mode" = 100644 ] &&
          git -C "$repo" show "HEAD:$path" | grep -Fxq '/.private/' &&
          cmp -s \
            <(git -C "$repo" show "$expected:$path" | sed '\|^/\.private/$|d') \
            <(git -C "$repo" show "HEAD:$path" | sed '\|^/\.private/$|d'); then
          continue
        fi
        ;;
    esac
    echo "[runtime-source] unpinned product change outside deploy/: $path" >&2
    return 1
  done < <(git -C "$repo" diff --name-only -z "$expected" HEAD)
  echo "[runtime-source] runtime matches $expected (deployment metadata checked separately)"
}
