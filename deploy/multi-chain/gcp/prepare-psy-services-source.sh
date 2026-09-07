#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"
CONFIG_FILE="${GCP_DEPLOY_CONFIG:-$SCRIPT_DIR/config.env}"
SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$SCRIPT_DIR/source-versions.env}"

fail() {
  echo "[prepare-psy-services] $*" >&2
  exit 1
}

normalize_github_repository() {
  local url="$1"
  url="${url%.git}"
  case "$url" in
    git@github.com:*) printf '%s\n' "${url#git@github.com:}" ;;
    ssh://git@github.com/*) printf '%s\n' "${url#ssh://git@github.com/}" ;;
    https://github.com/*) printf '%s\n' "${url#https://github.com/}" ;;
    http://github.com/*) printf '%s\n' "${url#http://github.com/}" ;;
    *) printf '%s\n' "$url" ;;
  esac
}

[ -f "$SOURCE_VERSIONS_FILE" ] || fail "missing source versions: $SOURCE_VERSIONS_FILE"
# shellcheck disable=SC1090
source "$SOURCE_VERSIONS_FILE"
if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

: "${EXPECTED_PSY_SERVICES_REPOSITORY:?missing EXPECTED_PSY_SERVICES_REPOSITORY}"
: "${EXPECTED_PSY_SERVICES_BRANCH:?missing EXPECTED_PSY_SERVICES_BRANCH}"
: "${EXPECTED_PSY_SERVICES_COMMIT:?missing EXPECTED_PSY_SERVICES_COMMIT}"

PSY_SERVICES_DIR="${PSY_SERVICES_DIR:-$WORKSPACE_HOME/psy-services-merge-multi-chain}"
expected_url="git@github.com:${EXPECTED_PSY_SERVICES_REPOSITORY}.git"

if [ ! -e "$PSY_SERVICES_DIR/.git" ]; then
  [ ! -e "$PSY_SERVICES_DIR" ] || fail "path exists but is not a Git checkout: $PSY_SERVICES_DIR"
  mkdir -p "$(dirname "$PSY_SERVICES_DIR")"
  git clone --branch "$EXPECTED_PSY_SERVICES_BRANCH" "$expected_url" "$PSY_SERVICES_DIR"
fi

actual_repository="$(normalize_github_repository "$(git -C "$PSY_SERVICES_DIR" remote get-url origin)")"
[ "$actual_repository" = "$EXPECTED_PSY_SERVICES_REPOSITORY" ] \
  || fail "wrong psy-services origin: expected $EXPECTED_PSY_SERVICES_REPOSITORY, got $actual_repository"

dirty="$(git -C "$PSY_SERVICES_DIR" status --porcelain --untracked-files=normal)"
[ -z "$dirty" ] || {
  echo "[prepare-psy-services] checkout contains local changes: $PSY_SERVICES_DIR" >&2
  printf '%s\n' "$dirty" >&2
  exit 1
}

git -C "$PSY_SERVICES_DIR" fetch --prune origin "$EXPECTED_PSY_SERVICES_BRANCH"
git -C "$PSY_SERVICES_DIR" cat-file -e "$EXPECTED_PSY_SERVICES_COMMIT^{commit}" 2>/dev/null \
  || fail "pinned commit was not fetched: $EXPECTED_PSY_SERVICES_COMMIT"
git -C "$PSY_SERVICES_DIR" merge-base --is-ancestor \
  "$EXPECTED_PSY_SERVICES_COMMIT" "origin/$EXPECTED_PSY_SERVICES_BRANCH" \
  || fail "$EXPECTED_PSY_SERVICES_COMMIT is not on origin/$EXPECTED_PSY_SERVICES_BRANCH"

git -C "$PSY_SERVICES_DIR" checkout --quiet --detach "$EXPECTED_PSY_SERVICES_COMMIT"
git -C "$PSY_SERVICES_DIR" submodule update --init --recursive

actual_commit="$(git -C "$PSY_SERVICES_DIR" rev-parse HEAD)"
[ "$actual_commit" = "$EXPECTED_PSY_SERVICES_COMMIT" ] \
  || fail "checkout mismatch: expected $EXPECTED_PSY_SERVICES_COMMIT, got $actual_commit"

echo "[prepare-psy-services] repository=$actual_repository"
echo "[prepare-psy-services] branch=$EXPECTED_PSY_SERVICES_BRANCH"
echo "[prepare-psy-services] commit=$actual_commit"
echo "[prepare-psy-services] directory=$PSY_SERVICES_DIR"
