#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Recreate Redis/Valkey and NATS staging VMs on GCP.

Default mode is dry-run. Pass --apply and CONFIRM_RECREATE_REDIS_NATS=1 to
execute destructive commands.

This script:
  - deletes the existing redis VM and recreates it as Ubuntu 24 n2-highmem-4
  - deletes the existing nats VM and recreates it as Ubuntu 24 n2-standard-4
  - preserves private IPs expected by deploy/gcp/config.env:
      redis: 10.148.0.12
      nats:  10.148.0.20
  - adds both operator SSH public keys to the ubuntu login user
  - does not create tyree, zilong, or long Linux users
  - ensures internal firewall rules for Redis and NATS exist
  - uses ephemeral public IPs by default

WARNING:
  Recreating redis deletes the current Redis/Valkey VM and its boot disk.
  This is intended for a fresh redeploy / staging recovery path.

Usage:
  bash deploy/gcp/admin/recreate-redis-nats.sh
  CONFIRM_RECREATE_REDIS_NATS=1 bash deploy/gcp/admin/recreate-redis-nats.sh --apply

Override example:
  PROJECT_ID=psy-testnet ZONE_B=asia-southeast1-b \
    CONFIRM_RECREATE_REDIS_NATS=1 bash deploy/gcp/admin/recreate-redis-nats.sh --apply
USAGE
}

APPLY=0
if [ "${1:-}" = "--apply" ]; then
  APPLY=1
elif [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
elif [ -n "${1:-}" ]; then
  echo "unknown argument: $1" >&2
  usage >&2
  exit 2
fi

PROJECT_ID="${PROJECT_ID:-psy-testnet}"
REGION="${REGION:-asia-southeast1}"
ZONE_B="${ZONE_B:-asia-southeast1-b}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"

IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"

REDIS_NAME="${REDIS_NAME:-redis}"
REDIS_PRIVATE_IP="${REDIS_PRIVATE_IP:-10.148.0.12}"
REDIS_MACHINE_TYPE="${REDIS_MACHINE_TYPE:-n2-highmem-4}"
REDIS_BOOT_DISK_SIZE="${REDIS_BOOT_DISK_SIZE:-300GB}"
REDIS_BOOT_DISK_TYPE="${REDIS_BOOT_DISK_TYPE:-pd-balanced}"

NATS_NAME="${NATS_NAME:-nats}"
NATS_PRIVATE_IP="${NATS_PRIVATE_IP:-10.148.0.20}"
NATS_MACHINE_TYPE="${NATS_MACHINE_TYPE:-n2-standard-4}"
NATS_BOOT_DISK_SIZE="${NATS_BOOT_DISK_SIZE:-100GB}"
NATS_BOOT_DISK_TYPE="${NATS_BOOT_DISK_TYPE:-pd-balanced}"

SSH_LOGIN_USER="${SSH_LOGIN_USER:-ubuntu}"
SSH_PUBLIC_KEYS="${SSH_PUBLIC_KEYS:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKm6g1EsF/bkEDZiDxqoPU1iCeFKbNe9xMXdQBL+xCrU tyree@psy.com
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICpdEuNTTwQ5Gm9v/PdOs/iDo/K6Tlw7d/p7UVNzY4ym long@longerM.local}"
SSH_KEYS="${SSH_KEYS:-}"
SSH_METADATA_FILE="${SSH_METADATA_FILE:-}"

tmp_files=()
cleanup() {
  if [ "${#tmp_files[@]}" -gt 0 ]; then
    rm -f "${tmp_files[@]}"
  fi
}
trap cleanup EXIT

ssh_metadata_file() {
  if [ -n "$SSH_METADATA_FILE" ]; then
    printf '%s\n' "$SSH_METADATA_FILE"
    return
  fi

  local tmp
  tmp="$(mktemp)"
  tmp_files+=("$tmp")
  if [ -n "$SSH_KEYS" ]; then
    printf '%s\n' "$SSH_KEYS" >"$tmp"
  else
    while IFS= read -r key; do
      [ -n "$key" ] || continue
      printf '%s:%s\n' "$SSH_LOGIN_USER" "$key"
    done <<<"$SSH_PUBLIC_KEYS" >"$tmp"
  fi
  printf '%s\n' "$tmp"
}

run() {
  echo "+ $*"
  if [ "$APPLY" = "1" ]; then
    "$@"
  fi
}

section() {
  printf '\n== %s ==\n' "$1"
}

instance_exists() {
  local name="$1"
  local zone="$2"

  gcloud compute instances describe "$name" \
    --project="$PROJECT_ID" \
    --zone="$zone" \
    --format='value(name)' >/dev/null 2>&1
}

delete_instance_if_exists() {
  local name="$1"
  local zone="$2"

  if [ "$APPLY" = "1" ] && ! instance_exists "$name" "$zone"; then
    echo "skip delete: $name does not exist in $zone"
    return
  fi

  run gcloud compute instances delete "$name" \
    --project="$PROJECT_ID" \
    --zone="$zone" \
    --quiet
}

create_instance_if_missing() {
  local name="$1"
  local machine_type="$2"
  local private_ip="$3"
  local boot_disk_size="$4"
  local boot_disk_type="$5"
  local tag="$6"
  local ssh_keys_file

  ssh_keys_file="$(ssh_metadata_file)"

  if [ "$APPLY" = "1" ] && instance_exists "$name" "$ZONE_B"; then
    echo "skip create: $name already exists in $ZONE_B"
    return
  fi

  run gcloud compute instances create "$name" \
    --project="$PROJECT_ID" \
    --zone="$ZONE_B" \
    --machine-type="$machine_type" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$boot_disk_size" \
    --boot-disk-type="$boot_disk_type" \
    --network="$NETWORK" \
    --subnet="$SUBNET" \
    --private-network-ip="$private_ip" \
    --tags="$tag" \
    "--metadata-from-file=ssh-keys=$ssh_keys_file"
}

ensure_firewall_rule() {
  local name="$1"
  local rules="$2"
  local target_tag="$3"

  if [ "$APPLY" = "1" ] && gcloud compute firewall-rules describe "$name" \
    --project="$PROJECT_ID" >/dev/null 2>&1; then
    echo "skip firewall create: $name already exists"
    return
  fi

  run gcloud compute firewall-rules create "$name" \
    --project="$PROJECT_ID" \
    --network="$NETWORK" \
    --direction=INGRESS \
    --priority=1000 \
    --action=ALLOW \
    --rules="$rules" \
    --source-ranges="${INTERNAL_SOURCE_RANGES:-10.148.0.0/20}" \
    --target-tags="$target_tag"
}

if [ "$APPLY" = "1" ] && [ "${CONFIRM_RECREATE_REDIS_NATS:-0}" != "1" ]; then
  cat >&2 <<'EOF'
Refusing to apply destructive Redis/NATS recreation.

Set CONFIRM_RECREATE_REDIS_NATS=1 to confirm that deleting the current redis
and nats VMs is intended.
EOF
  exit 1
fi

section "Plan"
cat <<EOF
project:          $PROJECT_ID
region:           $REGION
zone:             $ZONE_B
network/subnet:   $NETWORK / $SUBNET
image:            $IMAGE_PROJECT / $IMAGE_FAMILY
mode:             $([ "$APPLY" = "1" ] && echo "APPLY" || echo "DRY-RUN")
ssh login user:   $SSH_LOGIN_USER
ssh keys:         all public keys are injected under $SSH_LOGIN_USER only; no extra Linux users are created

delete/create:
  $REDIS_NAME
    machine:       $REDIS_MACHINE_TYPE
    boot disk:     $REDIS_BOOT_DISK_SIZE $REDIS_BOOT_DISK_TYPE
    private IP:    $REDIS_PRIVATE_IP
    tag:           parth-redis

  $NATS_NAME
    machine:       $NATS_MACHINE_TYPE
    boot disk:     $NATS_BOOT_DISK_SIZE $NATS_BOOT_DISK_TYPE
    private IP:    $NATS_PRIVATE_IP
    tag:           parth-nats

firewall:
  allow-parth-redis-internal tcp:6379 from ${INTERNAL_SOURCE_RANGES:-10.148.0.0/20}
  allow-parth-nats-internal  tcp:4222,6222,8222 from ${INTERNAL_SOURCE_RANGES:-10.148.0.0/20}
EOF

section "Set project"
run gcloud config set project "$PROJECT_ID"

section "Current target VMs"
run gcloud compute instances list \
  --project="$PROJECT_ID" \
  --filter="name=(\"$REDIS_NAME\",\"$NATS_NAME\")" \
  --format="table(name,zone.basename(),machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)"

section "Check machine type availability"
run gcloud compute machine-types list \
  --project="$PROJECT_ID" \
  --zones="$ZONE_B" \
  --filter="name=(\"$REDIS_MACHINE_TYPE\",\"$NATS_MACHINE_TYPE\")" \
  --format="table(name,zone.basename(),guestCpus,memoryMb)"

section "Delete existing Redis and NATS VMs"
delete_instance_if_exists "$REDIS_NAME" "$ZONE_B"
delete_instance_if_exists "$NATS_NAME" "$ZONE_B"

section "Create Redis and NATS VMs"
create_instance_if_missing "$REDIS_NAME" "$REDIS_MACHINE_TYPE" "$REDIS_PRIVATE_IP" "$REDIS_BOOT_DISK_SIZE" "$REDIS_BOOT_DISK_TYPE" "parth-redis"
create_instance_if_missing "$NATS_NAME" "$NATS_MACHINE_TYPE" "$NATS_PRIVATE_IP" "$NATS_BOOT_DISK_SIZE" "$NATS_BOOT_DISK_TYPE" "parth-nats"

section "Ensure internal firewall rules"
ensure_firewall_rule allow-parth-redis-internal tcp:6379 parth-redis
ensure_firewall_rule allow-parth-nats-internal tcp:4222,tcp:6222,tcp:8222 parth-nats

section "Set guest hostnames"
run gcloud compute ssh "$REDIS_NAME" \
  --project="$PROJECT_ID" \
  --zone="$ZONE_B" \
  --command="sudo hostnamectl set-hostname $REDIS_NAME"

run gcloud compute ssh "$NATS_NAME" \
  --project="$PROJECT_ID" \
  --zone="$ZONE_B" \
  --command="sudo hostnamectl set-hostname $NATS_NAME"

section "Final VM list"
run gcloud compute instances list \
  --project="$PROJECT_ID" \
  --filter="name=(\"$REDIS_NAME\",\"$NATS_NAME\")" \
  --format="table(name,zone.basename(),machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)"

if [ "$APPLY" != "1" ]; then
  cat <<'EOF'

Dry-run complete. Re-run with:
  CONFIRM_RECREATE_REDIS_NATS=1 bash deploy/gcp/admin/recreate-redis-nats.sh --apply
EOF
else
  cat <<EOF

Apply complete.

Expected deploy/gcp/config.env endpoint values:
  REDIS_HOST="$REDIS_PRIVATE_IP"
  NATS_HOST="$NATS_PRIVATE_IP"

Next steps:
  1. Update local ~/.ssh/config with the new external IPs from the final VM list.
  2. Redeploy Redis/Valkey:
       bash deploy/gcp/create-redis.sh
  3. Redeploy NATS:
       bash deploy/gcp/create-nats.sh
  4. Restart Parth services that connect to Redis/NATS.
EOF
fi
