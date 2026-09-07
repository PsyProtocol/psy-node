#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
: "${WORKSPACE_HOME:=$(cd "$REPO_ROOT/.." && pwd)}"
SOURCE_VERSIONS_FILE="${DEPLOY_SOURCE_VERSIONS_FILE:-$REPO_ROOT/deploy/source-versions.env}"

fail() {
  echo "[build-psy-services-release] $*" >&2
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

: "${EXPECTED_PSY_SERVICES_REPOSITORY:?missing EXPECTED_PSY_SERVICES_REPOSITORY}"
: "${EXPECTED_PSY_SERVICES_COMMIT:?missing EXPECTED_PSY_SERVICES_COMMIT}"
PSY_SERVICES_DIR="${PSY_SERVICES_DIR:-$WORKSPACE_HOME/psy-services}"
[ -e "$PSY_SERVICES_DIR/.git" ] || fail "missing psy-services checkout: $PSY_SERVICES_DIR"

actual_repository="$(normalize_github_repository "$(git -C "$PSY_SERVICES_DIR" remote get-url origin)")"
actual_commit="$(git -C "$PSY_SERVICES_DIR" rev-parse HEAD)"
dirty="$(git -C "$PSY_SERVICES_DIR" status --porcelain --untracked-files=normal)"
[ "$actual_repository" = "$EXPECTED_PSY_SERVICES_REPOSITORY" ] \
  || fail "repository mismatch: expected $EXPECTED_PSY_SERVICES_REPOSITORY, got $actual_repository"
[ "$actual_commit" = "$EXPECTED_PSY_SERVICES_COMMIT" ] \
  || fail "commit mismatch: expected $EXPECTED_PSY_SERVICES_COMMIT, got $actual_commit"
[ -z "$dirty" ] || fail "psy-services checkout contains local changes"

echo "[build-psy-services-release] building $actual_repository@$actual_commit"
PSY_SERVICES_DIR="$PSY_SERVICES_DIR" \
BUILD_PARTH_BINARIES=0 \
VERIFY_PARTH_GENESIS=0 \
PACKAGE_ARTIFACTS=0 \
BUILD_PARTH_BUNDLE=0 \
  bash "$REPO_ROOT/deploy/scripts/build-linux-artifacts-bookworm.sh"

for binary in psy-services psy-indexer; do
  [ -x "$PSY_SERVICES_DIR/target/release/$binary" ] \
    || fail "missing built binary: $PSY_SERVICES_DIR/target/release/$binary"
done
[ -d "$PSY_SERVICES_DIR/migrations" ] || fail "missing migrations directory"

output_dir="${PSY_SERVICES_RELEASE_OUTPUT_DIR:-$REPO_ROOT/dist/psy-services}"
archive="${PSY_SERVICES_RELEASE_ARCHIVE:-$output_dir/psy-services-${actual_commit}.tar.gz}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

install -d "$stage/target/release" "$stage/migrations"
install -m 0755 "$PSY_SERVICES_DIR/target/release/psy-services" "$stage/target/release/psy-services"
install -m 0755 "$PSY_SERVICES_DIR/target/release/psy-indexer" "$stage/target/release/psy-indexer"
rsync -a --delete "$PSY_SERVICES_DIR/migrations/" "$stage/migrations/"
if [ -d "$PSY_SERVICES_DIR/genesis_contracts" ]; then
  install -d "$stage/genesis_contracts"
  rsync -a --delete "$PSY_SERVICES_DIR/genesis_contracts/" "$stage/genesis_contracts/"
fi

commit_timestamp="$(git -C "$PSY_SERVICES_DIR" show -s --format=%ct "$actual_commit")"
services_sha="$(sha256sum "$stage/target/release/psy-services" | awk '{print $1}')"
indexer_sha="$(sha256sum "$stage/target/release/psy-indexer" | awk '{print $1}')"
cat >"$stage/BUILD-MANIFEST.env" <<EOF
PSY_SERVICES_REPOSITORY=$actual_repository
PSY_SERVICES_BRANCH=${EXPECTED_PSY_SERVICES_BRANCH:-unknown}
PSY_SERVICES_COMMIT=$actual_commit
SOURCE_COMMIT_TIMESTAMP=$commit_timestamp
PSY_SERVICES_BINARY_SHA256=$services_sha
PSY_INDEXER_BINARY_SHA256=$indexer_sha
EOF

mkdir -p "$(dirname "$archive")"
tar --sort=name --mtime="@$commit_timestamp" --owner=0 --group=0 --numeric-owner \
  -C "$stage" -czf "$archive" .
archive_sha="$(sha256sum "$archive" | awk '{print $1}')"

printf '%s  %s\n' "$archive_sha" "$(basename "$archive")" >"${archive}.sha256"
echo "[build-psy-services-release] archive=$archive"
echo "[build-psy-services-release] sha256=$archive_sha"
