#!/usr/bin/env bash
set -euo pipefail

GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$GCP_DIR/lib/common.sh"

SOURCE_PSY_ROOT="${TRUST_SETUP_SOURCE_PSY_ROOT:-$HOME/.psy}"
OUT_DIR="${TRUST_SETUP_DIST_DIR:-$REPO_ROOT/dist/trust-setup}"
ARCHIVE_NAME="${TRUST_SETUP_ARCHIVE_NAME:-psy-groth16-trust-setup.tar.gz}"
ARCHIVE_PATH="$OUT_DIR/$ARCHIVE_NAME"
SHA_PATH="$ARCHIVE_PATH.sha256"
PUBLIC_HOST="${TRUST_SETUP_PUBLIC_HOST:-${NOSTR_VM_NAME:-gcp-nostr}}"
PUBLIC_ROOT="${TRUST_SETUP_PUBLIC_ROOT:-${NOSTR_HOME:-/opt/nostr-relay}/public/trust-setup}"
TRUST_SETUP_DISTRIBUTION_MODE="${TRUST_SETUP_DISTRIBUTION_MODE:-${GROTH16_SETUP_DISTRIBUTION_MODE:-cache-host}}"
TRUST_SETUP_CACHE_HOST="${TRUST_SETUP_CACHE_HOST:-${GROTH16_SETUP_CACHE_HOST:-${PARTH_BUNDLE_CACHE_HOST:-${NODE_VM_NAME:-gcp-cp-ce}}}}"
TRUST_SETUP_CACHE_DIR="${TRUST_SETUP_CACHE_DIR:-/tmp/parth-public-trust-setup-cache}"
TRUST_SETUP_CACHE_PORT="${TRUST_SETUP_CACHE_PORT:-18091}"
TRUST_SETUP_CACHE_BIND_ADDR="${TRUST_SETUP_CACHE_BIND_ADDR:-}"
UPLOAD=0
REUSE_ARCHIVE="${TRUST_SETUP_REUSE_ARCHIVE:-0}"

usage() {
  cat <<'EOF'
Package the public Groth16 trust setup tarball for users.

Default behavior is local-only:
  - validate the 9 required *_groth16.bin files under $HOME/.psy
  - create dist/trust-setup/psy-groth16-trust-setup.tar.gz
  - create dist/trust-setup/psy-groth16-trust-setup.tar.gz.sha256
  - print the manual upload and config deploy commands

Options:
  --upload         Also upload to TRUST_SETUP_PUBLIC_HOST with rsync/ssh.
  --reuse-archive  Reuse an existing archive and only recalculate sha256.
  -h, --help      Show this help.

Useful env:
  TRUST_SETUP_SOURCE_PSY_ROOT="$HOME/.psy"
  TRUST_SETUP_DIST_DIR="dist/trust-setup"
  TRUST_SETUP_ARCHIVE_NAME="psy-groth16-trust-setup.tar.gz"
  TRUST_SETUP_PUBLIC_HOST="gcp-nostr"
  TRUST_SETUP_PUBLIC_ROOT="/opt/nostr-relay/public/trust-setup"
  TRUST_SETUP_DISTRIBUTION_MODE="cache-host"
  TRUST_SETUP_CACHE_HOST="gcp-cp-ce"
  TRUST_SETUP_CACHE_PORT="18091"
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --upload)
      UPLOAD=1
      shift
      ;;
    --reuse-archive)
      REUSE_ARCHIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

setup_files=(
  "keystore/circuit_groth16.bin"
  "keystore/pk_groth16.bin"
  "keystore/vk_groth16.bin"
  "keystore/deposit_append/circuit_groth16.bin"
  "keystore/deposit_append/pk_groth16.bin"
  "keystore/deposit_append/vk_groth16.bin"
  "keystore/withdrawal_claim/circuit_groth16.bin"
  "keystore/withdrawal_claim/pk_groth16.bin"
  "keystore/withdrawal_claim/vk_groth16.bin"
)

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

for file in "${setup_files[@]}"; do
  [ -s "$SOURCE_PSY_ROOT/$file" ] || {
    echo "missing trust setup file: $SOURCE_PSY_ROOT/$file" >&2
    exit 1
  }
done

mkdir -p "$OUT_DIR"

if [ "$REUSE_ARCHIVE" = "1" ] && [ -s "$ARCHIVE_PATH" ]; then
  echo "[trust-setup] reusing archive: $ARCHIVE_PATH"
else
  echo "[trust-setup] packaging ${#setup_files[@]} files from $SOURCE_PSY_ROOT"
  tar -C "$SOURCE_PSY_ROOT" -czf "$ARCHIVE_PATH" "${setup_files[@]}"
fi

archive_sha="$(sha256_file "$ARCHIVE_PATH")"
archive_size="$(du -h "$ARCHIVE_PATH" | awk '{print $1}')"
printf '%s  %s\n' "$archive_sha" "$ARCHIVE_NAME" > "$SHA_PATH"

echo "[trust-setup] archive: $ARCHIVE_PATH"
echo "[trust-setup] size:    $archive_size"
echo "[trust-setup] sha256:  $archive_sha"

public_domain="${PUBLIC_TRUST_SETUP_DOMAIN:-${NOSTR_DOMAIN}}"
public_path="${PUBLIC_TRUST_SETUP_PATH:-/trust-setup}"
public_path="${public_path%/}"
public_url="https://${public_domain}${public_path}/${ARCHIVE_NAME}"
public_sha_url="${public_url}.sha256"

if [ "$UPLOAD" != "1" ]; then
  cat <<EOF
[trust-setup] local package is ready.

Manual upload commands:
  rsync -av --progress "$ARCHIVE_PATH" "$PUBLIC_HOST:/tmp/$ARCHIVE_NAME"
  rsync -av --progress "$SHA_PATH" "$PUBLIC_HOST:/tmp/$ARCHIVE_NAME.sha256"
  ssh "$PUBLIC_HOST" "sudo install -d -m 0755 '$PUBLIC_ROOT' && test \\\$(sha256sum '/tmp/$ARCHIVE_NAME' | awk '{ print \\\$1 }') = '$archive_sha' && sudo install -m 0644 '/tmp/$ARCHIVE_NAME' '$PUBLIC_ROOT/$ARCHIVE_NAME' && sudo install -m 0644 '/tmp/$ARCHIVE_NAME.sha256' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'"

Then update public Caddy/static route:
  bash deploy/gcp/fresh-staging/17_deploy_caddy_entrypoints.sh

Then regenerate/deploy the config page:
  bash deploy/gcp/fresh-staging/27_deploy_cf_staging_config.sh

Published URLs after upload:
  $public_url
  $public_sha_url
EOF
  exit 0
fi

remote_archive="/tmp/$ARCHIVE_NAME"
remote_sha="/tmp/$ARCHIVE_NAME.sha256"

if [ "$TRUST_SETUP_DISTRIBUTION_MODE" = "cache-host" ]; then
  cache_dir="$TRUST_SETUP_CACHE_DIR/$archive_sha"
  cache_archive="$cache_dir/$ARCHIVE_NAME"
  cache_sha="$cache_dir/$ARCHIVE_NAME.sha256"
  cache_bind_addr="${TRUST_SETUP_CACHE_BIND_ADDR:-$(ssh_service_endpoint "$TRUST_SETUP_CACHE_HOST")}"
  cache_endpoint="${TRUST_SETUP_CACHE_ENDPOINT:-$(ssh_service_endpoint "$TRUST_SETUP_CACHE_HOST")}"
  cache_url="http://${cache_endpoint}:${TRUST_SETUP_CACHE_PORT}/${archive_sha}"

  provision_vm "$TRUST_SETUP_CACHE_HOST"
  run_remote_command "$TRUST_SETUP_CACHE_HOST" "missing=''; command -v rsync >/dev/null 2>&1 || missing=\"\$missing rsync\"; command -v python3 >/dev/null 2>&1 || missing=\"\$missing python3\"; command -v ss >/dev/null 2>&1 || missing=\"\$missing iproute2\"; if [ -n \"\$missing\" ]; then sudo env DEBIAN_FRONTEND=noninteractive sh -lc \"apt-get update && apt-get install -y \$missing\"; fi"
  run_remote_command "$TRUST_SETUP_CACHE_HOST" "mkdir -p '$cache_dir'"

  if run_remote_command "$TRUST_SETUP_CACHE_HOST" "[ -s '$cache_archive' ] && [ \"\$(sha256sum '$cache_archive' | awk '{ print \$1 }')\" = '$archive_sha' ] && [ -s '$cache_sha' ]" >/dev/null 2>&1; then
    echo "[trust-setup] archive already staged on cache host: $TRUST_SETUP_CACHE_HOST:$cache_archive"
  else
    echo "[trust-setup] staging archive on cache host: $ARCHIVE_PATH -> $TRUST_SETUP_CACHE_HOST:$cache_archive"
    rsync_to_remote "$TRUST_SETUP_CACHE_HOST" "$ARCHIVE_PATH" "$cache_archive"
    rsync_to_remote "$TRUST_SETUP_CACHE_HOST" "$SHA_PATH" "$cache_sha"
  fi

  run_remote_command "$TRUST_SETUP_CACHE_HOST" "find '$TRUST_SETUP_CACHE_DIR' -mindepth 1 -maxdepth 1 -type d ! -name '$archive_sha' -print -exec rm -rf {} +"
  if run_remote_command "$TRUST_SETUP_CACHE_HOST" "ss -ltn | awk '{ print \$4 }' | grep -Eq '(^|:)${TRUST_SETUP_CACHE_PORT}$'" >/dev/null 2>&1; then
    echo "[trust-setup] cache server already listening on $TRUST_SETUP_CACHE_HOST:$TRUST_SETUP_CACHE_PORT"
  else
    echo "[trust-setup] starting cache server on $TRUST_SETUP_CACHE_HOST:$cache_bind_addr:$TRUST_SETUP_CACHE_PORT"
    run_remote_command "$TRUST_SETUP_CACHE_HOST" "nohup python3 -m http.server '$TRUST_SETUP_CACHE_PORT' --bind '$cache_bind_addr' --directory '$TRUST_SETUP_CACHE_DIR' >/tmp/parth-public-trust-setup-cache-http.log 2>&1 &"
  fi

  provision_vm "$PUBLIC_HOST"
  run_remote_command "$PUBLIC_HOST" "sudo install -d -m 0755 '$PUBLIC_ROOT'"
  if [ "$PUBLIC_HOST" = "$TRUST_SETUP_CACHE_HOST" ]; then
    echo "[trust-setup] installing archive from local cache: $PUBLIC_HOST:$cache_archive -> $PUBLIC_ROOT"
    run_remote_command "$PUBLIC_HOST" "
      set -e
      test \"\$(sha256sum '$cache_archive' | awk '{ print \$1 }')\" = '$archive_sha'
      sudo install -m 0644 '$cache_archive' '$PUBLIC_ROOT/$ARCHIVE_NAME'
      sudo install -m 0644 '$cache_sha' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'
      sudo ls -lh '$PUBLIC_ROOT/$ARCHIVE_NAME' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'
"
  else
    echo "[trust-setup] downloading archive from cache host over VPC: $cache_url -> $PUBLIC_HOST:$PUBLIC_ROOT/"
    run_remote_command "$PUBLIC_HOST" "
      set -e
      command -v curl >/dev/null 2>&1 || sudo env DEBIAN_FRONTEND=noninteractive sh -lc 'apt-get update && apt-get install -y curl'
      curl -fL --retry 3 --connect-timeout 10 '$cache_url/$ARCHIVE_NAME' -o '$remote_archive'
      curl -fL --retry 3 --connect-timeout 10 '$cache_url/$ARCHIVE_NAME.sha256' -o '$remote_sha'
      test \"\$(sha256sum '$remote_archive' | awk '{ print \$1 }')\" = '$archive_sha'
      sudo mv '$remote_archive' '$PUBLIC_ROOT/$ARCHIVE_NAME'
      sudo mv '$remote_sha' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'
      sudo chmod 0644 '$PUBLIC_ROOT/$ARCHIVE_NAME' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'
      sudo ls -lh '$PUBLIC_ROOT/$ARCHIVE_NAME' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'
"
  fi
else
  provision_vm "$PUBLIC_HOST"
  run_remote_command "$PUBLIC_HOST" "sudo install -d -m 0755 '$PUBLIC_ROOT'"

  echo "[trust-setup] uploading archive to $PUBLIC_HOST:$remote_archive"
  rsync_to_remote "$PUBLIC_HOST" "$ARCHIVE_PATH" "$remote_archive"
  rsync_to_remote "$PUBLIC_HOST" "$SHA_PATH" "$remote_sha"

  run_remote_command "$PUBLIC_HOST" "
    set -e
    test \"\$(sha256sum '$remote_archive' | awk '{ print \$1 }')\" = '$archive_sha'
    sudo mv '$remote_archive' '$PUBLIC_ROOT/$ARCHIVE_NAME'
    sudo mv '$remote_sha' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'
    sudo chmod 0644 '$PUBLIC_ROOT/$ARCHIVE_NAME' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'
    sudo ls -lh '$PUBLIC_ROOT/$ARCHIVE_NAME' '$PUBLIC_ROOT/$ARCHIVE_NAME.sha256'
"
fi

echo "[trust-setup] published:"
echo "  $public_url"
echo "  $public_sha_url"
