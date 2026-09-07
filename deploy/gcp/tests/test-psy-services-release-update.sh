#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROFILE="$ROOT/deploy/multi-chain/gcp"
VERSIONS="$PROFILE/source-versions.env"
DEPLOY="$PROFILE/deploy-psy-services-update.sh"
INSTALLER="$ROOT/deploy/gcp/remote/install-psy-services-release.sh"

# shellcheck disable=SC1090
source "$VERSIONS"
[ "$EXPECTED_PSY_SERVICES_REPOSITORY" = "PsyProtocol/psy-services" ]
[ "$EXPECTED_PSY_SERVICES_BRANCH" = "multi_chain" ]
[ "$EXPECTED_PSY_SERVICES_COMMIT" = "9122e5de2d33ea6aba6d7bef101e742198879836" ]

dry_run="$(DRY_RUN=1 bash "$DEPLOY")"
grep -Fq 'build psy-services and psy-indexer only' <<<"$dry_run"
grep -Fq 'untouched: /opt/parth/current' <<<"$dry_run"

grep -Fq 'SKIP_PARTH_BUNDLE_UPLOAD=1' "$DEPLOY"
if grep -Eq 'deploy_all\.sh|deploy-cp-ce-stack\.sh|deploy-relayer\.sh|deploy-prove-proxy\.sh|deploy-cf-' "$DEPLOY"; then
  echo "psy-services-only update references a broad deployment entrypoint" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/stage/target/release" "$tmp/stage/migrations"
mkdir -p "$tmp/legacy/target/release" "$tmp/legacy/migrations"
mkdir -p "$tmp/install/releases/stale"
ln -s "$tmp/install/releases/stale" "$tmp/install/current"
printf '#!/usr/bin/env bash\n' >"$tmp/stage/target/release/psy-services"
printf '#!/usr/bin/env bash\n' >"$tmp/stage/target/release/psy-indexer"
chmod 0755 "$tmp/stage/target/release/psy-services" "$tmp/stage/target/release/psy-indexer"
cp "$tmp/stage/target/release/psy-services" "$tmp/legacy/target/release/psy-services"
cp "$tmp/stage/target/release/psy-indexer" "$tmp/legacy/target/release/psy-indexer"
cat >"$tmp/stage/BUILD-MANIFEST.env" <<EOF
PSY_SERVICES_REPOSITORY=$EXPECTED_PSY_SERVICES_REPOSITORY
PSY_SERVICES_BRANCH=$EXPECTED_PSY_SERVICES_BRANCH
PSY_SERVICES_COMMIT=$EXPECTED_PSY_SERVICES_COMMIT
EOF
tar -C "$tmp/stage" -czf "$tmp/release.tar.gz" .
archive_sha="$(sha256sum "$tmp/release.tar.gz" | awk '{print $1}')"

PSY_SERVICES_RELEASE_ARCHIVE="$tmp/release.tar.gz" \
PSY_SERVICES_RELEASE_ROOT="$tmp/install" \
PSY_SERVICES_ACTIVE_HOME="$tmp/legacy" \
PSY_SERVICES_LEGACY_HOME="$tmp/legacy" \
PSY_SERVICES_RELEASE_SHA256="$archive_sha" \
EXPECTED_PSY_SERVICES_REPOSITORY="$EXPECTED_PSY_SERVICES_REPOSITORY" \
EXPECTED_PSY_SERVICES_COMMIT="$EXPECTED_PSY_SERVICES_COMMIT" \
  bash "$INSTALLER" >/dev/null

[ -x "$tmp/install/current/target/release/psy-services" ]
[ -x "$tmp/install/current/target/release/psy-indexer" ]
# The live process path must win over a stale independent current symlink.
[ "$(readlink -f "$tmp/install/previous")" = "$(readlink -f "$tmp/legacy")" ]
grep -Fxq "PSY_SERVICES_COMMIT=$EXPECTED_PSY_SERVICES_COMMIT" \
  "$tmp/install/current/BUILD-MANIFEST.env"

echo "[ok] psy-services update is pinned, isolated, and release-addressed"
