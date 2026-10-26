#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/deploy/gcp/build-parth-bundle.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

source_root="$tmp/source"
bundle_root="$tmp/bundle"
mkdir -p \
  "$source_root/deploy/bin" \
  "$source_root/deploy/multi-chain/gcp" \
  "$source_root/deploy/artifacts" \
  "$source_root/deploy/local-acceptance"
printf '#!/usr/bin/env bash\nexit 0\n' > "$source_root/deploy/bin/run-parth-service"
printf 'PRIVATE_KEY=must-not-be-packaged\n' > "$source_root/deploy/multi-chain/gcp/config.env"
printf 'artifact recursion sentinel\n' > "$source_root/deploy/artifacts/nested.tar.gz"
printf 'local acceptance sentinel\n' > "$source_root/deploy/local-acceptance/result.log"

copy_runtime_deploy_files "$source_root" "$tmp/missing-fallback" "$bundle_root"

[ -x "$bundle_root/deploy/bin/run-parth-service" ] || {
  echo "runtime launcher was not copied as executable" >&2
  exit 1
}
mapfile -t bundled_deploy_files < <(find "$bundle_root/deploy" -type f -printf '%P\n' | sort)
if [ "${#bundled_deploy_files[@]}" -ne 1 ] || [ "${bundled_deploy_files[0]}" != 'bin/run-parth-service' ]; then
  echo "runtime deploy allowlist copied unexpected files:" >&2
  printf '  %s\n' "${bundled_deploy_files[@]}" >&2
  exit 1
fi

printf 'BUILD_COMMIT=fixture\n' > "$bundle_root/BUILD-MANIFEST.env"
reject_secret_files "$bundle_root"

mkdir -p "$bundle_root/leaked-profile"
printf 'PRIVATE_KEY=fixture\n' > "$bundle_root/leaked-profile/config.env"
if reject_secret_files "$bundle_root" >/dev/null 2>&1; then
  echo "secret-like bundle file was not rejected" >&2
  exit 1
fi

echo "[ok] Parth bundle runtime allowlist excludes deploy state and rejects secret files"
