#!/usr/bin/env bash
set -euo pipefail

GCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$GCP_DIR/lib/common.sh"
# shellcheck source=lib/groth16-setup.sh
source "$GCP_DIR/lib/groth16-setup.sh"

usage() {
  cat <<'EOF'
Generate a bridge Groth16 setup locally from wrapped Plonky2 JSON files, then optionally upload it to staging.

Default source:
  Pull the latest complete wrapper proof directory from gcp-cp-ce:/tmp/plonky2_proof.

Default local output:
  dist/groth16-keystore/<kind>/

Default upload target:
  bridge               -> gcp-cp-ce:/var/lib/parth/.psy/keystore/
  deposit_batch_append -> gcp-cp-ce:/var/lib/parth/.psy/keystore/deposit_append/
  withdrawal_claim     -> gcp-cp-ce:/var/lib/parth/.psy/keystore/withdrawal_claim/

Usage:
  bash deploy/gcp/generate-upload-groth16-setup.sh [options]

Options:
  --kind <kind>                bridge | deposit_batch_append | withdrawal_claim (default: bridge)
  --host <ssh-host>            SSH host that has /tmp/plonky2_proof and receives upload (default: gcp-cp-ce)
  --wrapped-dir <dir>          Local dir containing common_circuit_data.json, proof_with_public_inputs.json, verifier_only_circuit_data.json
  --pull-remote                Pull wrapped JSONs from the remote host (default when --wrapped-dir is omitted)
  --remote-wrapped-dir <dir>   Exact remote wrapper proof dir to pull instead of auto-selecting latest
  --remote-proof-base <dir>    Remote base dir to search for wrapper proof dirs (default: /tmp/plonky2_proof)
  --keystore-dir <dir>         Local keystore dir to write setup into
  --upload-existing            Upload existing local setup files without regenerating from wrapped JSONs
  --skip-missing-existing      With --upload-existing, skip instead of failing when local setup files are missing
  --no-upload                  Only generate locally; do not upload to the remote host
  --force                      Remove existing local setup files before generation
  --skip-freshness-check       Allow uploading/reusing setup files older than relevant circuit sources
  --stop-relayer               Stop parth-relayer.service before pulling/generating/uploading
  --restart-relayer            Restart parth-relayer.service after upload
  -h, --help                   Show this help

Examples:
  bash deploy/gcp/generate-upload-groth16-setup.sh --kind bridge
  bash deploy/gcp/generate-upload-groth16-setup.sh --kind bridge --upload-existing
  bash deploy/gcp/generate-upload-groth16-setup.sh --kind bridge --no-upload
  bash deploy/gcp/generate-upload-groth16-setup.sh --kind bridge --wrapped-dir /tmp/plonky2_proof/<hash>
EOF
}

log() {
  printf '[groth16-setup] %s\n' "$*"
}

die() {
  printf '[groth16-setup] failed: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return 0
  fi
  shasum -a 256 "$1" | awk '{print $1}'
}

ensure_groth16_setup_cache() {
  local fingerprint="$1"
  local remote_cache_dir="$setup_cache_dir/$local_kind_dir/$fingerprint"
  local remote_manifest="$remote_cache_dir/.manifest.sha256"
  local cache_bind_addr

  provision_vm "$setup_cache_host"
  cache_bind_addr="${setup_cache_bind_addr:-$(ssh_service_endpoint "$setup_cache_host")}"
  run_remote_command "$setup_cache_host" "missing=''; command -v rsync >/dev/null 2>&1 || missing=\"\$missing rsync\"; command -v python3 >/dev/null 2>&1 || missing=\"\$missing python3\"; command -v ss >/dev/null 2>&1 || missing=\"\$missing iproute2\"; if [ -n \"\$missing\" ]; then sudo env DEBIAN_FRONTEND=noninteractive sh -lc \"apt-get update && apt-get install -y \$missing\"; fi"
  run_remote_command "$setup_cache_host" "mkdir -p '$remote_cache_dir'"

  if run_remote_command "$setup_cache_host" "[ -f '$remote_manifest' ] && [ \"\$(sha256sum '$remote_manifest' | awk '{ print \$1 }')\" = '$fingerprint' ] && [ -s '$remote_cache_dir/circuit_groth16.bin' ] && [ -s '$remote_cache_dir/pk_groth16.bin' ] && [ -s '$remote_cache_dir/vk_groth16.bin' ]" >/dev/null 2>&1; then
    log "Groth16 setup already staged on cache host: $setup_cache_host:$remote_cache_dir"
  else
    log "staging Groth16 setup on cache host with rsync --checksum: $upload_dir/ -> $setup_cache_host:$remote_cache_dir/"
    rsync_to_remote "$setup_cache_host" "$upload_dir/" "$remote_cache_dir/"
  fi

  run_remote_command "$setup_cache_host" "find '$setup_cache_dir/$local_kind_dir' -mindepth 1 -maxdepth 1 -type d ! -name '$fingerprint' -print -exec rm -rf {} +"

  if run_remote_command "$setup_cache_host" "ss -ltn | awk '{ print \$4 }' | grep -Eq '(^|:)${setup_cache_port}$'" >/dev/null 2>&1; then
    log "Groth16 setup cache server already listening on $setup_cache_host:$setup_cache_port"
  else
    log "starting Groth16 setup cache server on $setup_cache_host:$cache_bind_addr:$setup_cache_port"
    run_remote_command "$setup_cache_host" "nohup python3 -m http.server '$setup_cache_port' --bind '$cache_bind_addr' --directory '$setup_cache_dir' >/tmp/parth-groth16-setup-cache-http.log 2>&1 &"
  fi
}

groth16_setup_cache_url() {
  local fingerprint="$1"
  local cache_endpoint

  cache_endpoint="${GROTH16_SETUP_CACHE_ENDPOINT:-$(ssh_service_endpoint "$setup_cache_host")}"
  printf 'http://%s:%s/%s/%s\n' "$cache_endpoint" "$setup_cache_port" "$local_kind_dir" "$fingerprint"
}

kind="bridge"
host="${GROTH16_SETUP_HOST:-gcp-cp-ce}"
remote_proof_base="${REMOTE_PLONKY2_PROOF_BASE:-/tmp/plonky2_proof}"
setup_distribution_mode="${GROTH16_SETUP_DISTRIBUTION_MODE:-${PARTH_BUNDLE_DISTRIBUTION_MODE:-cache-host}}"
setup_cache_host="${GROTH16_SETUP_CACHE_HOST:-${PARTH_BUNDLE_CACHE_HOST:-${NODE_VM_NAME:-gcp-cp-ce}}}"
setup_cache_dir="${GROTH16_SETUP_CACHE_DIR:-/tmp/parth-groth16-setup-cache}"
setup_cache_port="${GROTH16_SETUP_CACHE_PORT:-18089}"
setup_cache_bind_addr="${GROTH16_SETUP_CACHE_BIND_ADDR:-}"
remote_wrapped_dir=""
wrapped_dir=""
pull_remote=""
upload=1
upload_existing=0
skip_missing_existing=0
force=0
stop_relayer=0
restart_relayer=0
keystore_dir=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --kind)
      kind="${2:?missing value for --kind}"
      shift 2
      ;;
    --host)
      host="${2:?missing value for --host}"
      shift 2
      ;;
    --wrapped-dir)
      wrapped_dir="${2:?missing value for --wrapped-dir}"
      shift 2
      ;;
    --pull-remote)
      pull_remote=1
      shift
      ;;
    --remote-wrapped-dir)
      remote_wrapped_dir="${2:?missing value for --remote-wrapped-dir}"
      pull_remote=1
      shift 2
      ;;
    --remote-proof-base)
      remote_proof_base="${2:?missing value for --remote-proof-base}"
      shift 2
      ;;
    --keystore-dir)
      keystore_dir="${2:?missing value for --keystore-dir}"
      shift 2
      ;;
    --upload-existing)
      upload_existing=1
      shift
      ;;
    --skip-missing-existing)
      skip_missing_existing=1
      shift
      ;;
    --no-upload)
      upload=0
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    --skip-freshness-check)
      export GROTH16_SKIP_SETUP_FRESHNESS_CHECK=1
      shift
      ;;
    --stop-relayer)
      stop_relayer=1
      shift
      ;;
    --restart-relayer)
      restart_relayer=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

case "$kind" in
  bridge)
    local_kind_dir="bridge"
    remote_target="/var/lib/parth/.psy/keystore"
    expected_public_inputs="${GROTH16_EXPECTED_PUBLIC_INPUTS:-1152}"
    ;;
  deposit_batch_append)
    local_kind_dir="deposit_batch_append"
    remote_target="/var/lib/parth/.psy/keystore/deposit_append"
    expected_public_inputs="${GROTH16_EXPECTED_PUBLIC_INPUTS:-256}"
    ;;
  withdrawal_claim)
    local_kind_dir="withdrawal_claim"
    remote_target="/var/lib/parth/.psy/keystore/withdrawal_claim"
    expected_public_inputs="${GROTH16_EXPECTED_PUBLIC_INPUTS:-576}"
    ;;
  *)
    die "--kind must be one of: bridge, deposit_batch_append, withdrawal_claim"
    ;;
esac

if [ "$upload_existing" != "1" ] && [ -z "$wrapped_dir" ]; then
  pull_remote=1
fi

bin="${PSY_GROTH16_CLI:-${PSY_RELAYER_CLI:-$PARTH_DIR/target/release/psy_relayer_cli}}"
if [ "$upload_existing" != "1" ] && [ ! -x "$bin" ]; then
  die "missing executable: $bin; run: cd $PARTH_DIR && cargo build -p psy_relayer_cli --release"
fi
if [ "$upload_existing" != "1" ]; then
  bin_help="$("$bin" --help 2>/dev/null || true)"
  case "$bin_help" in
    *generate-groth16*) ;;
    *) die "$bin does not support generate-groth16; rebuild it with: cd $PARTH_DIR && cargo build -p psy_relayer_cli --release" ;;
  esac
fi

require_cmd rsync
require_cmd awk
require_cmd sort
require_cmd find
if [ -n "$expected_public_inputs" ]; then
  require_cmd python3
fi

if [ "$stop_relayer" = "1" ]; then
  wait_ssh_ready "$host" >/dev/null
  log "stopping parth-relayer.service on $host"
  run_remote_command "$host" "sudo systemctl stop parth-relayer.service"
fi

work_root="${GROTH16_SETUP_WORK_ROOT:-$REPO_ROOT/dist/groth16-setup-work}"
keystore_root="${GROTH16_SETUP_KEYSTORE_ROOT:-$REPO_ROOT/dist/groth16-keystore}"
if [ -z "$keystore_dir" ]; then
  keystore_dir="$keystore_root/$local_kind_dir"
fi
out_dir="$work_root/out/$local_kind_dir"
upload_dir="$work_root/upload/$local_kind_dir"

if [ "$upload_existing" = "1" ]; then
  missing=0
  for setup_file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    if [ ! -s "$keystore_dir/$setup_file" ]; then
      missing=1
      break
    fi
  done

  if [ "$missing" = "1" ]; then
    if [ "$skip_missing_existing" = "1" ]; then
      log "skipping $kind because local setup files are missing in $keystore_dir"
      exit 0
    fi
    die "missing local setup files in $keystore_dir; generate first with this script without --upload-existing"
  fi

  groth16_setup_validate_freshness "$kind" "$keystore_dir" "$host"
  log "using existing local Groth16 setup: $keystore_dir"
else
if [ "$pull_remote" = "1" ]; then
  wait_ssh_ready "$host" >/dev/null
  mkdir -p "$work_root/wrapped"

  if [ -z "$remote_wrapped_dir" ]; then
    log "searching latest wrapped proof under $host:$remote_proof_base"
    remote_wrapped_dir="$(
      run_remote_command "$host" "
        set -e
        find '$remote_proof_base' -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
          | sort -nr \
          | awk '{print \$2}' \
          | while IFS= read -r d; do
              if [ -f \"\$d/common_circuit_data.json\" ] \
                 && [ -f \"\$d/proof_with_public_inputs.json\" ] \
                 && [ -f \"\$d/verifier_only_circuit_data.json\" ]; then
                if [ -n '$expected_public_inputs' ]; then
                  public_inputs=\$(python3 - \"\$d/common_circuit_data.json\" <<'PY'
import json
import sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    print(json.load(f).get('num_public_inputs', ''))
PY
)
                  [ \"\$public_inputs\" = '$expected_public_inputs' ] || continue
                fi
                printf '%s\n' \"\$d\"
                exit 0
              fi
            done
      "
    )"
  fi

  [ -n "$remote_wrapped_dir" ] || die "no complete wrapped proof dir found under $host:$remote_proof_base"
  wrapped_dir="$work_root/wrapped/${kind}-$(basename "$remote_wrapped_dir")"
  mkdir -p "$wrapped_dir"

  log "pulling wrapped proof JSONs: $host:$remote_wrapped_dir -> $wrapped_dir"
  rsync -az --checksum --human-readable --progress \
    "$host:$remote_wrapped_dir/common_circuit_data.json" \
    "$host:$remote_wrapped_dir/proof_with_public_inputs.json" \
    "$host:$remote_wrapped_dir/verifier_only_circuit_data.json" \
    "$wrapped_dir/"
fi

[ -n "$wrapped_dir" ] || die "missing --wrapped-dir or --pull-remote source"
for required in common_circuit_data.json proof_with_public_inputs.json verifier_only_circuit_data.json; do
  [ -s "$wrapped_dir/$required" ] || die "missing wrapped proof file: $wrapped_dir/$required"
done
if [ -n "$expected_public_inputs" ]; then
  actual_public_inputs="$(python3 - "$wrapped_dir/common_circuit_data.json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    print(json.load(f).get("num_public_inputs", ""))
PY
)"
  [ "$actual_public_inputs" = "$expected_public_inputs" ] || {
    die "$kind expects num_public_inputs=$expected_public_inputs, got $actual_public_inputs from $wrapped_dir"
  }
fi

mkdir -p "$keystore_dir" "$out_dir" "$upload_dir"

if [ "$force" = "1" ]; then
  log "removing existing local setup files from $keystore_dir"
  rm -f \
    "$keystore_dir/circuit_groth16.bin" \
    "$keystore_dir/pk_groth16.bin" \
    "$keystore_dir/vk_groth16.bin"
fi

if [ -f "$keystore_dir/circuit_groth16.bin" ] \
   && [ -f "$keystore_dir/pk_groth16.bin" ] \
   && [ -f "$keystore_dir/vk_groth16.bin" ]; then
  groth16_setup_validate_freshness "$kind" "$keystore_dir" "$host"
  log "local setup already exists in $keystore_dir; CLI will reuse it. Use --force to regenerate."
fi

log "generating Groth16 setup locally"
log "wrapped dir: $wrapped_dir"
log "keystore:    $keystore_dir"
"$bin" generate-groth16 \
  "$wrapped_dir/common_circuit_data.json" \
  "$wrapped_dir/proof_with_public_inputs.json" \
  "$wrapped_dir/verifier_only_circuit_data.json" \
  "$keystore_dir" \
  "$out_dir/out_proof.json" \
  "$out_dir/out_vk.json"

for setup_file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
  [ -s "$keystore_dir/$setup_file" ] || die "setup generation did not create $keystore_dir/$setup_file"
done
fi

metadata_file="$keystore_dir/.setup-metadata.env"
if [ "$upload_existing" != "1" ]; then
  {
    printf 'kind=%q\n' "$kind"
    printf 'generated_at=%q\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'generator=%q\n' "$bin"
    if [ -x "$bin" ]; then
      printf 'generator_sha256=%q\n' "$(sha256_file "$bin")"
    fi
    if [ -n "${wrapped_dir:-}" ]; then
      printf 'wrapped_dir=%q\n' "$wrapped_dir"
      for wrapped_file in common_circuit_data.json proof_with_public_inputs.json verifier_only_circuit_data.json; do
        [ -s "$wrapped_dir/$wrapped_file" ] && printf '%s_sha256=%q\n' "${wrapped_file//[^A-Za-z0-9]/_}" "$(sha256_file "$wrapped_dir/$wrapped_file")"
      done
    fi
    for setup_file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
      printf '%s_sha256=%q\n' "${setup_file//[^A-Za-z0-9]/_}" "$(sha256_file "$keystore_dir/$setup_file")"
    done
  } > "$metadata_file"
else
  if [ ! -s "$metadata_file" ]; then
    log "no setup metadata found in $keystore_dir; upload will include setup binaries only"
  fi
fi

rm -rf "$upload_dir"
mkdir -p "$upload_dir"
cp \
  "$keystore_dir/circuit_groth16.bin" \
  "$keystore_dir/pk_groth16.bin" \
  "$keystore_dir/vk_groth16.bin" \
  "$upload_dir/"
[ ! -s "$metadata_file" ] || cp "$metadata_file" "$upload_dir/"

log "local setup files:"
manifest_file="$upload_dir/.manifest.sha256"
: > "$manifest_file"
for setup_file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
  size="$(du -h "$upload_dir/$setup_file" | awk '{print $1}')"
  sha="$(sha256_file "$upload_dir/$setup_file")"
  printf '%s  %s\n' "$sha" "$setup_file" >> "$manifest_file"
  printf '  %s  %s  sha256=%s\n' "$size" "$setup_file" "$sha"
done
setup_fingerprint="$(sha256_file "$manifest_file")"
log "setup fingerprint: $setup_fingerprint"

if [ "$upload" != "1" ]; then
  log "skipping upload because --no-upload was set"
  log "manual upload target: $host:$remote_target"
  exit 0
fi

wait_ssh_ready "$host" >/dev/null

log "ensuring remote parth service user exists: $host"
run_remote_command "$host" "
  set -e
  if ! getent group parth >/dev/null 2>&1; then
    sudo groupadd --system parth
  fi
  if ! id parth >/dev/null 2>&1; then
    sudo useradd --system --gid parth --home-dir /var/lib/parth --create-home --shell /usr/sbin/nologin parth
  fi
"

log "ensuring remote setup directory exists: $host:$remote_target"
run_remote_command "$host" "
  sudo mkdir -p '$remote_target'
"

if [ "$setup_distribution_mode" = "cache-host" ]; then
  ensure_groth16_setup_cache "$setup_fingerprint"
  remote_cache_dir="$setup_cache_dir/$local_kind_dir/$setup_fingerprint"
  cache_url="$(groth16_setup_cache_url "$setup_fingerprint")"
  if [ "$host" = "$setup_cache_host" ]; then
    log "installing setup files from cache host local cache: $host:$remote_cache_dir -> $remote_target/"
    run_remote_command "$host" "
set -e
sudo mkdir -p '$remote_target'
sudo rsync -a --checksum --exclude='.manifest.sha256' '$remote_cache_dir/' '$remote_target/'
"
  else
    log "downloading setup files from cache host over VPC: $cache_url -> $host:$remote_target/"

    download_script="
set -e
missing=''
command -v curl >/dev/null 2>&1 || missing=\"\$missing curl\"
if [ -n \"\$missing\" ]; then
  sudo env DEBIAN_FRONTEND=noninteractive sh -lc \"apt-get update && apt-get install -y \$missing\"
fi
sudo mkdir -p '$remote_target'
"
    for setup_file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
      sha="$(awk -v file="$setup_file" '$2 == file { print $1; exit }' "$manifest_file")"
      download_script+="
if [ -f '$remote_target/$setup_file' ] && [ \"\$(sudo sha256sum '$remote_target/$setup_file' | awk '{ print \$1 }')\" = '$sha' ]; then
  echo 'setup file already present: $remote_target/$setup_file'
else
  sudo curl -fL --retry 3 --connect-timeout 10 '$cache_url/$setup_file' -o '$remote_target/$setup_file.tmp'
  test \"\$(sudo sha256sum '$remote_target/$setup_file.tmp' | awk '{ print \$1 }')\" = '$sha'
  sudo mv '$remote_target/$setup_file.tmp' '$remote_target/$setup_file'
fi
"
    done
    run_remote_command "$host" "$download_script"
  fi
else
  rsync_delete_args=()
  if [ "$kind" != "bridge" ]; then
    rsync_delete_args=(--delete)
  fi

  log "syncing setup files with rsync --checksum via sudo rsync: $upload_dir/ -> $host:$remote_target/"
  rsync -az --checksum "${rsync_delete_args[@]}" --exclude='.manifest.sha256' --human-readable --progress \
    --rsync-path="sudo rsync" \
    "$upload_dir/" "$host:$remote_target/"
fi

log "removing stale remote staging cache if present: $host:/tmp/parth-groth16-keystore/$local_kind_dir"
run_remote_command "$host" "
  sudo rm -rf '/tmp/parth-groth16-keystore/$local_kind_dir'
"

log "fixing setup file ownership and permissions: $host:$remote_target"
run_remote_command "$host" "
  set -e
  sudo chown -R parth:parth /var/lib/parth/.psy/keystore
  sudo chmod -R u+rwX,go-rwx /var/lib/parth/.psy/keystore
  sudo ls -lh '$remote_target'/circuit_groth16.bin '$remote_target'/pk_groth16.bin '$remote_target'/vk_groth16.bin
"

if [ "$restart_relayer" = "1" ]; then
  log "restarting parth-relayer.service"
  run_remote_command "$host" "sudo systemctl restart parth-relayer.service && sudo systemctl status parth-relayer.service --no-pager --full -n 20"
else
  log "upload complete. Restart relayer when ready:"
  log "ssh $host 'sudo systemctl restart parth-relayer.service'"
fi
