#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Create the dedicated Faucet Server VM.

Default mode is dry-run. Pass --apply to execute gcloud mutations.

Defaults:
  instance:     faucet
  zone:         asia-southeast1-b
  machine:      e2-standard-2
  boot disk:    30GB pd-balanced
  private IP:   10.148.0.33
  external IP:  ephemeral, for SSH only

No public Faucet port or firewall rule is created. Caddy reaches port 9998
through the VPC private IP.

Usage:
  bash deploy/gcp/admin/create-faucet-vm.sh
  bash deploy/gcp/admin/create-faucet-vm.sh --apply

Optional:
  SSH_METADATA_FILE=/path/to/ssh-keys \
    bash deploy/gcp/admin/create-faucet-vm.sh --apply

  FAUCET_EXTERNAL_IP=0 \
    bash deploy/gcp/admin/create-faucet-vm.sh --apply

FAUCET_EXTERNAL_IP=0 requires a bastion/IAP path for SSH and Cloud NAT for
outbound package downloads and Sepolia RPC access.
USAGE
}

APPLY=0
case "${1:-}" in
  --apply) APPLY=1 ;;
  -h|--help)
    usage
    exit 0
    ;;
  "")
    ;;
  *)
    echo "unknown argument: $1" >&2
    usage >&2
    exit 2
    ;;
esac

PROJECT_ID="${PROJECT_ID:-psy-testnet}"
ZONE="${ZONE:-asia-southeast1-b}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"
IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}"
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"

FAUCET_INSTANCE_NAME="${FAUCET_INSTANCE_NAME:-faucet}"
FAUCET_MACHINE_TYPE="${FAUCET_MACHINE_TYPE:-e2-standard-2}"
FAUCET_PRIVATE_IP="${FAUCET_PRIVATE_IP:-10.148.0.33}"
FAUCET_BOOT_DISK_SIZE="${FAUCET_BOOT_DISK_SIZE:-30GB}"
FAUCET_BOOT_DISK_TYPE="${FAUCET_BOOT_DISK_TYPE:-pd-balanced}"
FAUCET_EXTERNAL_IP="${FAUCET_EXTERNAL_IP:-1}"
FAUCET_NETWORK_TAGS="${FAUCET_NETWORK_TAGS:-parth-faucet}"
SSH_METADATA_FILE="${SSH_METADATA_FILE:-}"

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [ "$APPLY" = "1" ]; then
    "$@"
  fi
}

instance_exists() {
  gcloud compute instances describe "$FAUCET_INSTANCE_NAME" \
    --project="$PROJECT_ID" \
    --zone="$ZONE" \
    --format='value(name)' >/dev/null 2>&1
}

private_ip_owner() {
  gcloud compute instances list \
    --project="$PROJECT_ID" \
    --filter="networkInterfaces.networkIP=$FAUCET_PRIVATE_IP" \
    --format='value(name)' 2>/dev/null
}

cat <<EOF
Faucet VM plan
  mode:         $([ "$APPLY" = "1" ] && echo APPLY || echo DRY-RUN)
  project:      $PROJECT_ID
  zone:         $ZONE
  instance:     $FAUCET_INSTANCE_NAME
  machine:      $FAUCET_MACHINE_TYPE
  disk:         $FAUCET_BOOT_DISK_SIZE $FAUCET_BOOT_DISK_TYPE
  network:      $NETWORK / $SUBNET
  private IP:   $FAUCET_PRIVATE_IP
  external IP:  $FAUCET_EXTERNAL_IP
EOF

if [ "$APPLY" = "1" ]; then
  if instance_exists; then
    echo "skip create: $FAUCET_INSTANCE_NAME already exists in $ZONE"
    gcloud compute instances describe "$FAUCET_INSTANCE_NAME" \
      --project="$PROJECT_ID" \
      --zone="$ZONE" \
      --format='table(name,machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)'
    exit 0
  fi

  owner="$(private_ip_owner)"
  if [ -n "$owner" ]; then
    echo "private IP $FAUCET_PRIVATE_IP is already used by: $owner" >&2
    exit 1
  fi
fi

create_args=(
  gcloud compute instances create "$FAUCET_INSTANCE_NAME"
  "--project=$PROJECT_ID"
  "--zone=$ZONE"
  "--machine-type=$FAUCET_MACHINE_TYPE"
  "--image-family=$IMAGE_FAMILY"
  "--image-project=$IMAGE_PROJECT"
  "--boot-disk-size=$FAUCET_BOOT_DISK_SIZE"
  "--boot-disk-type=$FAUCET_BOOT_DISK_TYPE"
  --boot-disk-auto-delete
  "--network=$NETWORK"
  "--subnet=$SUBNET"
  "--private-network-ip=$FAUCET_PRIVATE_IP"
  "--tags=$FAUCET_NETWORK_TAGS"
  --maintenance-policy=MIGRATE
  "--labels=service=faucet,environment=staging"
)

if [ "$FAUCET_EXTERNAL_IP" = "0" ]; then
  create_args+=(--no-address)
fi
if [ -n "$SSH_METADATA_FILE" ]; then
  [ -f "$SSH_METADATA_FILE" ] || {
    echo "SSH metadata file does not exist: $SSH_METADATA_FILE" >&2
    exit 1
  }
  create_args+=("--metadata-from-file=ssh-keys=$SSH_METADATA_FILE")
fi

run "${create_args[@]}"

if [ "$APPLY" = "1" ]; then
  gcloud compute instances describe "$FAUCET_INSTANCE_NAME" \
    --project="$PROJECT_ID" \
    --zone="$ZONE" \
    --format='table(name,machineType.basename(),networkInterfaces[0].networkIP,networkInterfaces[0].accessConfigs[0].natIP,status)'
else
  cat <<'EOF'

Dry-run complete. Re-run with --apply to create the VM.
EOF
fi
