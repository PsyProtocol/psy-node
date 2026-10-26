#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Recreate staging realm worker VMs on GCP.

Default mode is dry-run. Pass --apply to execute destructive commands.

This script:
  - stops the obsolete nats VM
  - deletes old realm-worker-1 and realm-worker-2
  - creates new Ubuntu 24 realm-worker-0 and realm-worker-1
  - keeps the worker private IPs 10.148.0.27 and 10.148.0.28
  - lets GCP assign new ephemeral public IPs

Usage:
  bash deploy/gcp/admin/recreate-realm-workers.sh
  bash deploy/gcp/admin/recreate-realm-workers.sh --apply

Override example:
  PROJECT_ID=psy-testnet ZONE_A=asia-southeast1-a ZONE_B=asia-southeast1-b \
    bash deploy/gcp/admin/recreate-realm-workers.sh --apply
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

WORKER_MACHINE_TYPE="${WORKER_MACHINE_TYPE:-c4-highcpu-8}"
WORKER_BOOT_DISK_SIZE="${WORKER_BOOT_DISK_SIZE:-50GB}"
WORKER_BOOT_DISK_TYPE="${WORKER_BOOT_DISK_TYPE:-pd-balanced}"
IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"

OLD_WORKER_1="${OLD_WORKER_1:-realm-worker-1}"
OLD_WORKER_2="${OLD_WORKER_2:-realm-worker-2}"
OLD_NATS="${OLD_NATS:-nats}"

NEW_WORKER_0="${NEW_WORKER_0:-realm-worker-0}"
NEW_WORKER_1="${NEW_WORKER_1:-realm-worker-1}"
NEW_WORKER_0_PRIVATE_IP="${NEW_WORKER_0_PRIVATE_IP:-10.148.0.27}"
NEW_WORKER_1_PRIVATE_IP="${NEW_WORKER_1_PRIVATE_IP:-10.148.0.28}"

run() {
  echo "+ $*"
  if [ "$APPLY" = "1" ]; then
    "$@"
  fi
}

section() {
  printf '\n== %s ==\n' "$1"
}

section "Plan"
cat <<EOF
project:              $PROJECT_ID
region:               $REGION
worker zone:          $ZONE_A
nats zone:            $ZONE_B
network/subnet:       $NETWORK / $SUBNET
image:                $IMAGE_PROJECT / $IMAGE_FAMILY
worker machine type:  $WORKER_MACHINE_TYPE
worker boot disk:     $WORKER_BOOT_DISK_SIZE $WORKER_BOOT_DISK_TYPE

will stop:            $OLD_NATS ($ZONE_B)
will delete:          $OLD_WORKER_1 ($ZONE_A)
will delete:          $OLD_WORKER_2 ($ZONE_A)
will create:          $NEW_WORKER_0 private_ip=$NEW_WORKER_0_PRIVATE_IP
will create:          $NEW_WORKER_1 private_ip=$NEW_WORKER_1_PRIVATE_IP

mode:                 $([ "$APPLY" = "1" ] && echo "APPLY" || echo "DRY-RUN")
EOF

section "Set project"
run gcloud config set project "$PROJECT_ID"

section "Current target VMs"
run gcloud compute instances list \
  --filter="name=(\"$OLD_NATS\",\"$OLD_WORKER_1\",\"$OLD_WORKER_2\",\"$NEW_WORKER_0\",\"$NEW_WORKER_1\")" \
  --format="table(name,zone.basename(),machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)"

section "Check machine type availability"
run gcloud compute machine-types list \
  --zones="$ZONE_A" \
  --filter="name=(\"$WORKER_MACHINE_TYPE\")" \
  --format="table(name,zone.basename(),guestCpus,memoryMb)"

section "Stop obsolete nats VM"
run gcloud compute instances stop "$OLD_NATS" \
  --zone="$ZONE_B" \
  --quiet

section "Delete old worker VMs"
run gcloud compute instances delete "$OLD_WORKER_1" \
  --zone="$ZONE_A" \
  --quiet

run gcloud compute instances delete "$OLD_WORKER_2" \
  --zone="$ZONE_A" \
  --quiet

section "Create new worker VMs"
run gcloud compute instances create "$NEW_WORKER_0" \
  --zone="$ZONE_A" \
  --machine-type="$WORKER_MACHINE_TYPE" \
  --image-family="$IMAGE_FAMILY" \
  --image-project="$IMAGE_PROJECT" \
  --boot-disk-size="$WORKER_BOOT_DISK_SIZE" \
  --boot-disk-type="$WORKER_BOOT_DISK_TYPE" \
  --network="$NETWORK" \
  --subnet="$SUBNET" \
  --private-network-ip="$NEW_WORKER_0_PRIVATE_IP"

run gcloud compute instances create "$NEW_WORKER_1" \
  --zone="$ZONE_A" \
  --machine-type="$WORKER_MACHINE_TYPE" \
  --image-family="$IMAGE_FAMILY" \
  --image-project="$IMAGE_PROJECT" \
  --boot-disk-size="$WORKER_BOOT_DISK_SIZE" \
  --boot-disk-type="$WORKER_BOOT_DISK_TYPE" \
  --network="$NETWORK" \
  --subnet="$SUBNET" \
  --private-network-ip="$NEW_WORKER_1_PRIVATE_IP"

section "Set guest hostnames"
run gcloud compute ssh "$NEW_WORKER_0" \
  --zone="$ZONE_A" \
  --command="sudo hostnamectl set-hostname $NEW_WORKER_0"

run gcloud compute ssh "$NEW_WORKER_1" \
  --zone="$ZONE_A" \
  --command="sudo hostnamectl set-hostname $NEW_WORKER_1"

section "Final VM list"
run gcloud compute instances list \
  --filter="name=(\"$OLD_NATS\",\"$NEW_WORKER_0\",\"$NEW_WORKER_1\")" \
  --format="table(name,zone.basename(),machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)"

if [ "$APPLY" != "1" ]; then
  cat <<'EOF'

Dry-run complete. Re-run with --apply to execute.
EOF
else
  cat <<'EOF'

Apply complete.

Next steps:
  1. Send the final VM list output back to the deploy operator.
  2. Update local ~/.ssh/config with the new ephemeral public IPs.
  3. Update deploy/gcp/config.env if using instance names directly:
       REALM_WORKER_1_VM_NAME="gcp-realm-worker-0"
       REALM_WORKER_2_VM_NAME="realm-worker-1"
  4. Redeploy realm workers from the application deploy machine.
EOF
fi
