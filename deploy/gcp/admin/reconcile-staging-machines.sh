#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Reconcile GCP staging machines for the current Parth deployment plan.

Default mode is dry-run. Pass --apply to execute destructive commands.

This script:
  - keeps nostr untouched
  - keeps cp-ce, redis, nats, scylla, postgres untouched
  - deletes old realm-worker-1 and realm-worker-2
  - creates new Ubuntu 24 realm-worker-0 and realm-worker-1
  - recreates prove-proxy as Ubuntu 24 c4d-highcpu-16
  - creates relayer as Ubuntu 24 c4d-standard-16 if missing
  - preserves private IPs expected by deploy/gcp/config.env
  - uses ephemeral public IPs by default

Usage:
  bash deploy/gcp/admin/reconcile-staging-machines.sh
  bash deploy/gcp/admin/reconcile-staging-machines.sh --apply

Override example:
  PROJECT_ID=psy-testnet ZONE_A=asia-southeast1-a ZONE_B=asia-southeast1-b \
    bash deploy/gcp/admin/reconcile-staging-machines.sh --apply
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
ZONE_A="${ZONE_A:-asia-southeast1-a}"
ZONE_B="${ZONE_B:-asia-southeast1-b}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"

IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"

STOP_OLD_NATS="${STOP_OLD_NATS:-0}"
RECREATE_WORKERS="${RECREATE_WORKERS:-1}"
RECREATE_PROVE_PROXY="${RECREATE_PROVE_PROXY:-1}"
CREATE_RELAYER="${CREATE_RELAYER:-1}"

OLD_NATS="${OLD_NATS:-nats}"

OLD_WORKER_1="${OLD_WORKER_1:-realm-worker-1}"
OLD_WORKER_2="${OLD_WORKER_2:-realm-worker-2}"
NEW_WORKER_0="${NEW_WORKER_0:-realm-worker-0}"
NEW_WORKER_1="${NEW_WORKER_1:-realm-worker-1}"
NEW_WORKER_0_PRIVATE_IP="${NEW_WORKER_0_PRIVATE_IP:-10.148.0.27}"
NEW_WORKER_1_PRIVATE_IP="${NEW_WORKER_1_PRIVATE_IP:-10.148.0.28}"
WORKER_MACHINE_TYPE="${WORKER_MACHINE_TYPE:-c4-highcpu-8}"
WORKER_BOOT_DISK_SIZE="${WORKER_BOOT_DISK_SIZE:-50GB}"
WORKER_BOOT_DISK_TYPE="${WORKER_BOOT_DISK_TYPE:-pd-balanced}"

PROVE_PROXY_NAME="${PROVE_PROXY_NAME:-prove-proxy}"
PROVE_PROXY_PRIVATE_IP="${PROVE_PROXY_PRIVATE_IP:-10.148.0.26}"
PROVE_PROXY_MACHINE_TYPE="${PROVE_PROXY_MACHINE_TYPE:-c4d-highcpu-16}"
PROVE_PROXY_BOOT_DISK_SIZE="${PROVE_PROXY_BOOT_DISK_SIZE:-50GB}"
PROVE_PROXY_BOOT_DISK_TYPE="${PROVE_PROXY_BOOT_DISK_TYPE:-pd-balanced}"

RELAYER_NAME="${RELAYER_NAME:-relayer}"
RELAYER_PRIVATE_IP="${RELAYER_PRIVATE_IP:-10.148.0.30}"
RELAYER_MACHINE_TYPE="${RELAYER_MACHINE_TYPE:-c4d-standard-16}"
RELAYER_BOOT_DISK_SIZE="${RELAYER_BOOT_DISK_SIZE:-300GB}"
RELAYER_BOOT_DISK_TYPE="${RELAYER_BOOT_DISK_TYPE:-pd-balanced}"

SSH_KEYS="${SSH_KEYS:-ubuntu:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKm6g1EsF/bkEDZiDxqoPU1iCeFKbNe9xMXdQBL+xCrU tyree@psy.com
ubuntu:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICpdEuNTTwQ5Gm9v/PdOs/iDo/K6Tlw7d/p7UVNzY4ym long@longerM.local}"
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
  printf '%s\n' "$SSH_KEYS" >"$tmp"
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

maybe_stop_instance() {
  local name="$1"
  local zone="$2"
  if [ "$APPLY" = "1" ] && ! instance_exists "$name" "$zone"; then
    echo "skip stop: $name does not exist in $zone"
    return
  fi
  run gcloud compute instances stop "$name" --zone="$zone" --quiet
}

maybe_delete_instance() {
  local name="$1"
  local zone="$2"
  if [ "$APPLY" = "1" ] && ! instance_exists "$name" "$zone"; then
    echo "skip delete: $name does not exist in $zone"
    return
  fi
  run gcloud compute instances delete "$name" --zone="$zone" --quiet
}

maybe_create_worker() {
  local name="$1"
  local ip="$2"
  local ssh_keys_file
  ssh_keys_file="$(ssh_metadata_file)"
  if [ "$APPLY" = "1" ] && instance_exists "$name" "$ZONE_A"; then
    echo "skip create: $name already exists in $ZONE_A"
    return
  fi
  run gcloud compute instances create "$name" \
    --zone="$ZONE_A" \
    --machine-type="$WORKER_MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$WORKER_BOOT_DISK_SIZE" \
    --boot-disk-type="$WORKER_BOOT_DISK_TYPE" \
    --network="$NETWORK" \
    --subnet="$SUBNET" \
    --private-network-ip="$ip" \
    "--metadata-from-file=ssh-keys=$ssh_keys_file"
}

maybe_create_prove_proxy() {
  local ssh_keys_file
  ssh_keys_file="$(ssh_metadata_file)"
  if [ "$APPLY" = "1" ] && instance_exists "$PROVE_PROXY_NAME" "$ZONE_B"; then
    echo "skip create: $PROVE_PROXY_NAME already exists in $ZONE_B"
    return
  fi
  run gcloud compute instances create "$PROVE_PROXY_NAME" \
    --zone="$ZONE_B" \
    --machine-type="$PROVE_PROXY_MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$PROVE_PROXY_BOOT_DISK_SIZE" \
    --boot-disk-type="$PROVE_PROXY_BOOT_DISK_TYPE" \
    --network="$NETWORK" \
    --subnet="$SUBNET" \
    --private-network-ip="$PROVE_PROXY_PRIVATE_IP" \
    "--metadata-from-file=ssh-keys=$ssh_keys_file"
}

maybe_create_relayer() {
  local ssh_keys_file
  ssh_keys_file="$(ssh_metadata_file)"
  if [ "$APPLY" = "1" ] && instance_exists "$RELAYER_NAME" "$ZONE_B"; then
    echo "skip create: $RELAYER_NAME already exists in $ZONE_B"
    return
  fi
  run gcloud compute instances create "$RELAYER_NAME" \
    --zone="$ZONE_B" \
    --machine-type="$RELAYER_MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --boot-disk-size="$RELAYER_BOOT_DISK_SIZE" \
    --boot-disk-type="$RELAYER_BOOT_DISK_TYPE" \
    --network="$NETWORK" \
    --subnet="$SUBNET" \
    --private-network-ip="$RELAYER_PRIVATE_IP" \
    "--metadata-from-file=ssh-keys=$ssh_keys_file"
}

section "Plan"
cat <<EOF
project:                 $PROJECT_ID
region:                  $REGION
zone A:                  $ZONE_A
zone B:                  $ZONE_B
network/subnet:          $NETWORK / $SUBNET
image:                   $IMAGE_PROJECT / $IMAGE_FAMILY
mode:                    $([ "$APPLY" = "1" ] && echo "APPLY" || echo "DRY-RUN")
ssh user:                ubuntu, with tyree and long public keys

untouched:
  nostr                  keep existing Debian VM
  cp-ce                  keep existing c4d-standard-8
  redis                  keep existing dedicated Redis/Valkey VM
  nats                   keep existing dedicated NATS VM
  scylla                 keep existing n2-highmem-4
  postgres               keep existing n2-standard-2, Postgres + Envio

actions:
  stop old nats:         $STOP_OLD_NATS ($OLD_NATS in $ZONE_B)
  recreate workers:      $RECREATE_WORKERS
    delete old:          $OLD_WORKER_1, $OLD_WORKER_2 in $ZONE_A
    create:              $NEW_WORKER_0 $WORKER_MACHINE_TYPE $WORKER_BOOT_DISK_SIZE ip=$NEW_WORKER_0_PRIVATE_IP
    create:              $NEW_WORKER_1 $WORKER_MACHINE_TYPE $WORKER_BOOT_DISK_SIZE ip=$NEW_WORKER_1_PRIVATE_IP
  recreate prove-proxy:  $RECREATE_PROVE_PROXY
    create:              $PROVE_PROXY_NAME $PROVE_PROXY_MACHINE_TYPE $PROVE_PROXY_BOOT_DISK_SIZE ip=$PROVE_PROXY_PRIVATE_IP
  create relayer:        $CREATE_RELAYER
    create:              $RELAYER_NAME $RELAYER_MACHINE_TYPE $RELAYER_BOOT_DISK_SIZE ip=$RELAYER_PRIVATE_IP
EOF

section "Set project"
run gcloud config set project "$PROJECT_ID"

section "Current relevant VMs"
run gcloud compute instances list \
  --filter="name=(\"nostr\",\"cp-ce\",\"redis\",\"scylla\",\"postgres\",\"$OLD_NATS\",\"$OLD_WORKER_1\",\"$OLD_WORKER_2\",\"$NEW_WORKER_0\",\"$NEW_WORKER_1\",\"$PROVE_PROXY_NAME\",\"$RELAYER_NAME\")" \
  --format="table(name,zone.basename(),machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)"

section "Check machine type availability"
run gcloud compute machine-types list \
  --zones="$ZONE_A","$ZONE_B" \
  --filter="name=(\"$WORKER_MACHINE_TYPE\",\"$PROVE_PROXY_MACHINE_TYPE\",\"$RELAYER_MACHINE_TYPE\")" \
  --format="table(name,zone.basename(),guestCpus,memoryMb)"

if [ "$STOP_OLD_NATS" = "1" ]; then
  section "Stop obsolete nats VM"
  maybe_stop_instance "$OLD_NATS" "$ZONE_B"
fi

if [ "$RECREATE_WORKERS" = "1" ]; then
  section "Delete old worker VMs"
  maybe_delete_instance "$OLD_WORKER_1" "$ZONE_A"
  maybe_delete_instance "$OLD_WORKER_2" "$ZONE_A"

  section "Create Ubuntu 24 worker VMs"
  maybe_create_worker "$NEW_WORKER_0" "$NEW_WORKER_0_PRIVATE_IP"
  maybe_create_worker "$NEW_WORKER_1" "$NEW_WORKER_1_PRIVATE_IP"

  section "Set worker hostnames"
  run gcloud compute ssh "$NEW_WORKER_0" \
    --zone="$ZONE_A" \
    --command="sudo hostnamectl set-hostname $NEW_WORKER_0"

  run gcloud compute ssh "$NEW_WORKER_1" \
    --zone="$ZONE_A" \
    --command="sudo hostnamectl set-hostname $NEW_WORKER_1"
fi

if [ "$RECREATE_PROVE_PROXY" = "1" ]; then
  section "Recreate prove-proxy VM"
  maybe_delete_instance "$PROVE_PROXY_NAME" "$ZONE_B"
  maybe_create_prove_proxy

  section "Set prove-proxy hostname"
  run gcloud compute ssh "$PROVE_PROXY_NAME" \
    --zone="$ZONE_B" \
    --command="sudo hostnamectl set-hostname $PROVE_PROXY_NAME"
fi

if [ "$CREATE_RELAYER" = "1" ]; then
  section "Create relayer VM"
  maybe_create_relayer

  section "Set relayer hostname"
  run gcloud compute ssh "$RELAYER_NAME" \
    --zone="$ZONE_B" \
    --command="sudo hostnamectl set-hostname $RELAYER_NAME"
fi

section "Final relevant VM list"
run gcloud compute instances list \
  --filter="name=(\"nostr\",\"cp-ce\",\"redis\",\"scylla\",\"postgres\",\"$OLD_NATS\",\"$NEW_WORKER_0\",\"$NEW_WORKER_1\",\"$PROVE_PROXY_NAME\",\"$RELAYER_NAME\")" \
  --format="table(name,zone.basename(),machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)"

if [ "$APPLY" != "1" ]; then
  cat <<'EOF'

Dry-run complete. Re-run with --apply to execute.
EOF
else
  cat <<'EOF'

Apply complete.

Send the final VM list output back to the deploy operator.
The deploy operator must update local SSH config for new ephemeral public IPs.
Expected deploy config changes:
  REALM_WORKER_1_VM_NAME="gcp-realm-worker-0"
  REALM_WORKER_2_VM_NAME="realm-worker-1"
  PROVE_PROXY_VM_NAME="gcp-prove-proxy"
  DEPLOY_RELAYER="1"
  RELAYER_VM_NAME="gcp-relayer"
EOF
fi
