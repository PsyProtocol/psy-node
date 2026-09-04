#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Create a dedicated coordinator-worker VM and restart the NATS VM.

Default mode is dry-run. Pass --apply to execute gcloud mutations.

This script:
  - creates one Ubuntu 24 coordinator-worker VM
  - uses c4-highcpu-8 by default
  - injects both operator SSH public keys under the ubuntu login user
  - restarts the nats VM with gcloud compute instances reset
  - does not create tyree, zilong, or long Linux users

Usage:
  bash deploy/gcp/admin/create-coordinator-worker-and-restart-nats.sh
  bash deploy/gcp/admin/create-coordinator-worker-and-restart-nats.sh --apply

Override examples:
  COORDINATOR_WORKER_PRIVATE_IP=10.148.0.32 \
    bash deploy/gcp/admin/create-coordinator-worker-and-restart-nats.sh --apply

  RESTART_NATS_NAME=redis \
    bash deploy/gcp/admin/create-coordinator-worker-and-restart-nats.sh --apply
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
ZONE_A="${ZONE_A:-asia-southeast1-a}"
ZONE_B="${ZONE_B:-asia-southeast1-b}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"

IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"

COORDINATOR_WORKER_NAME="${COORDINATOR_WORKER_NAME:-coordinator-worker}"
COORDINATOR_WORKER_MACHINE_TYPE="${COORDINATOR_WORKER_MACHINE_TYPE:-c4-highcpu-8}"
COORDINATOR_WORKER_PRIVATE_IP="${COORDINATOR_WORKER_PRIVATE_IP:-10.148.0.31}"
COORDINATOR_WORKER_BOOT_DISK_SIZE="${COORDINATOR_WORKER_BOOT_DISK_SIZE:-50GB}"
COORDINATOR_WORKER_BOOT_DISK_TYPE="${COORDINATOR_WORKER_BOOT_DISK_TYPE:-pd-balanced}"
COORDINATOR_WORKER_TAGS="${COORDINATOR_WORKER_TAGS:-parth-worker,parth-coordinator-worker}"

RESTART_NATS_NAME="${RESTART_NATS_NAME:-nats}"
RESTART_NATS_ZONE="${RESTART_NATS_ZONE:-$ZONE_B}"
RESTART_NATS="${RESTART_NATS:-1}"

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

create_coordinator_worker_if_missing() {
  local ssh_keys_file
  ssh_keys_file="$(ssh_metadata_file)"

  if [ "$APPLY" = "1" ] && instance_exists "$COORDINATOR_WORKER_NAME" "$ZONE_A"; then
    echo "skip create: $COORDINATOR_WORKER_NAME already exists in $ZONE_A"
    return
  fi

  run gcloud compute instances create "$COORDINATOR_WORKER_NAME" \
    --project="$PROJECT_ID" \
    --zone="$ZONE_A" \
    --machine-type="$COORDINATOR_WORKER_MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$COORDINATOR_WORKER_BOOT_DISK_SIZE" \
    --boot-disk-type="$COORDINATOR_WORKER_BOOT_DISK_TYPE" \
    --network="$NETWORK" \
    --subnet="$SUBNET" \
    --private-network-ip="$COORDINATOR_WORKER_PRIVATE_IP" \
    --tags="$COORDINATOR_WORKER_TAGS" \
    "--metadata-from-file=ssh-keys=$ssh_keys_file"
}

restart_nats_if_requested() {
  if [ "$RESTART_NATS" != "1" ]; then
    echo "skip restart: RESTART_NATS=$RESTART_NATS"
    return
  fi

  if [ "$APPLY" = "1" ] && ! instance_exists "$RESTART_NATS_NAME" "$RESTART_NATS_ZONE"; then
    echo "skip restart: $RESTART_NATS_NAME does not exist in $RESTART_NATS_ZONE" >&2
    return 1
  fi

  run gcloud compute instances reset "$RESTART_NATS_NAME" \
    --project="$PROJECT_ID" \
    --zone="$RESTART_NATS_ZONE"
}

section "Plan"
cat <<EOF
project:             $PROJECT_ID
network/subnet:      $NETWORK / $SUBNET
image:               $IMAGE_PROJECT / $IMAGE_FAMILY
mode:                $([ "$APPLY" = "1" ] && echo "APPLY" || echo "DRY-RUN")

create coordinator worker:
  name:              $COORDINATOR_WORKER_NAME
  zone:              $ZONE_A
  machine:           $COORDINATOR_WORKER_MACHINE_TYPE
  boot disk:         $COORDINATOR_WORKER_BOOT_DISK_SIZE $COORDINATOR_WORKER_BOOT_DISK_TYPE
  private IP:        $COORDINATOR_WORKER_PRIVATE_IP
  tags:              $COORDINATOR_WORKER_TAGS
  ssh login user:    $SSH_LOGIN_USER

restart nats:
  enabled:           $RESTART_NATS
  instance:          $RESTART_NATS_NAME
  zone:              $RESTART_NATS_ZONE
EOF

section "Set project"
run gcloud config set project "$PROJECT_ID"

section "Current target VMs"
run gcloud compute instances list \
  --project="$PROJECT_ID" \
  --filter="name=(\"$COORDINATOR_WORKER_NAME\",\"$RESTART_NATS_NAME\")" \
  --format="table(name,zone.basename(),machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)"

section "Check machine type availability"
run gcloud compute machine-types describe "$COORDINATOR_WORKER_MACHINE_TYPE" \
  --project="$PROJECT_ID" \
  --zone="$ZONE_A" \
  --format="value(name)"

section "Create coordinator worker"
create_coordinator_worker_if_missing

section "Restart NATS"
restart_nats_if_requested

section "Result"
run gcloud compute instances list \
  --project="$PROJECT_ID" \
  --filter="name=(\"$COORDINATOR_WORKER_NAME\",\"$RESTART_NATS_NAME\")" \
  --format="table(name,zone.basename(),machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)"

cat <<EOF

Next local deployment config after the VM is reachable:
  COORDINATOR_WORKER_VM_NAME="gcp-coordinator-worker"
  COORDINATOR_WORKER_LAYOUT="0"

Then deploy the online coordinator worker:
  bash deploy/gcp/fresh-staging/14_deploy_workers.sh
EOF
