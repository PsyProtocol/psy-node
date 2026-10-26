#!/usr/bin/env bash
set -euo pipefail

PROJECT="${PROJECT:-psy-testnet}"
REGION="${REGION:-asia-southeast1}"
ZONE="${ZONE:-asia-southeast1-b}"
NETWORK="${NETWORK:-default}"
VM_NAME="${VM_NAME:-gcp-wireguard-gateway}"
ADDRESS_NAME="${ADDRESS_NAME:-gcp-wireguard-gateway-ip}"
NETWORK_TAG="${NETWORK_TAG:-parth-wireguard-gateway}"
FIREWALL_RULE="${FIREWALL_RULE:-allow-parth-wireguard}"

if ! gcloud compute addresses describe "$ADDRESS_NAME" \
  --project="$PROJECT" --region="$REGION" >/dev/null 2>&1; then
  gcloud compute addresses create "$ADDRESS_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --network-tier=STANDARD \
    --ip-version=IPV4
fi

PUBLIC_IP="$(gcloud compute addresses describe "$ADDRESS_NAME" \
  --project="$PROJECT" \
  --region="$REGION" \
  --format='value(address)')"

gcloud compute instances create "$VM_NAME" \
  --project="$PROJECT" \
  --zone="$ZONE" \
  --machine-type=e2-small \
  --provisioning-model=STANDARD \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --boot-disk-size=20GB \
  --boot-disk-type=pd-standard \
  --boot-disk-auto-delete \
  --network="$NETWORK" \
  --address="$PUBLIC_IP" \
  --network-tier=STANDARD \
  --tags="$NETWORK_TAG" \
  --labels=service=wireguard-gateway,environment=staging \
  --can-ip-forward \
  --no-service-account \
  --no-scopes \
  --shielded-secure-boot \
  --shielded-vtpm \
  --shielded-integrity-monitoring

if ! gcloud compute firewall-rules describe "$FIREWALL_RULE" \
  --project="$PROJECT" >/dev/null 2>&1; then
  gcloud compute firewall-rules create "$FIREWALL_RULE" \
    --project="$PROJECT" \
    --network="$NETWORK" \
    --direction=INGRESS \
    --priority=1000 \
    --action=ALLOW \
    --rules=udp:51820 \
    --source-ranges=0.0.0.0/0 \
    --target-tags="$NETWORK_TAG" \
    --description="Allow authenticated WireGuard traffic to staging gateway"
fi

gcloud compute instances describe "$VM_NAME" \
  --project="$PROJECT" \
  --zone="$ZONE" \
  --format='yaml(name,status,machineType,canIpForward,networkInterfaces[].networkIP,networkInterfaces[].accessConfigs[].natIP,networkInterfaces[].accessConfigs[].networkTier,tags.items)'

gcloud compute firewall-rules describe "$FIREWALL_RULE" \
  --project="$PROJECT" \
  --format='yaml(name,direction,sourceRanges,allowed,targetTags,disabled)'
