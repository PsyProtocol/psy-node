#!/usr/bin/env bash
set -euo pipefail

STAGED_ROOT="${STAGED_ROOT:-$HOME/parth-prove-proxy}"
STAGED_RELEASE="${STAGED_RELEASE:-$STAGED_ROOT/staged-release}"
STAGED_SETUP="${STAGED_SETUP:-$STAGED_ROOT/staged-setup}"
RELEASE_ID="${RELEASE_ID:-$(date -u +%Y%m%d%H%M%S)-offsite-prove}"
RELEASE_DIR="/opt/parth/releases/$RELEASE_ID"
OPS_READ_USER="${OPS_READ_USER:-psy}"
WG_ADDRESS="${WG_ADDRESS:-10.250.0.12}"
WG_GATEWAY_IP="${WG_GATEWAY_IP:-10.250.0.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SOURCE="$SCRIPT_DIR/parth-offsite-prove-proxy.service"
CONFIG_SOURCE="$STAGED_RELEASE/client_prover/config.json"

[[ "$RELEASE_ID" =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "invalid RELEASE_ID: $RELEASE_ID" >&2
  exit 1
}

required_files=(
  "$STAGED_RELEASE/target/release/psy_user_cli"
  "$STAGED_RELEASE/deploy/bin/run-parth-service"
  "$CONFIG_SOURCE"
  "$STAGED_RELEASE/BUILD-MANIFEST.env"
  "$UNIT_SOURCE"
)
for kind in bridge deposit_batch_append withdrawal_claim; do
  for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    required_files+=("$STAGED_SETUP/$kind/$file")
  done
done
for path in "${required_files[@]}"; do
  if [ ! -s "$path" ]; then
    echo "missing or empty staged deployment file: $path" >&2
    exit 1
  fi
done

id -u parth >/dev/null 2>&1 ||
  sudo useradd --system --home /var/lib/parth --shell /usr/bin/nologin parth

current_release="$(readlink -f /opt/parth/current 2>/dev/null || true)"
if [ "$current_release" = "$RELEASE_DIR" ] &&
  sudo systemctl is-active --quiet parth-offsite-prove-proxy.service; then
  echo "Stopping the active copy before replacing release $RELEASE_ID"
  sudo systemctl stop parth-offsite-prove-proxy.service
fi
if sudo test -e "$RELEASE_DIR"; then
  sudo rm -rf "$RELEASE_DIR"
fi

sudo install -d -o root -g root -m 0755 /opt/parth /opt/parth/releases
sudo install -d -o root -g root -m 0755 "$RELEASE_DIR"
sudo cp -a "$STAGED_RELEASE/." "$RELEASE_DIR/"
sudo chown -R root:root "$RELEASE_DIR"
sudo chmod 0755 \
  "$RELEASE_DIR" \
  "$RELEASE_DIR/target" \
  "$RELEASE_DIR/target/release" \
  "$RELEASE_DIR/deploy" \
  "$RELEASE_DIR/deploy/bin"
sudo chmod 0755 \
  "$RELEASE_DIR/target/release/psy_user_cli" \
  "$RELEASE_DIR/deploy/bin/run-parth-service"
sudo -u parth test -x "$RELEASE_DIR"
sudo -u parth test -x "$RELEASE_DIR/deploy/bin/run-parth-service"

tmp_config="$(mktemp)"
trap 'rm -f "$tmp_config"' EXIT
jq \
  --arg coordinator "http://$WG_GATEWAY_IP:11337" \
  --arg realm0 "http://$WG_GATEWAY_IP:11338" \
  --arg realm1 "http://$WG_GATEWAY_IP:11339" \
  --arg prove_proxy "http://$WG_ADDRESS:9999" \
  --arg services "http://$WG_GATEWAY_IP:11300" \
  '
    .defaultNetwork as $network
    | if (.networks[$network] | type) != "object" then
        error("default network is missing from config.json")
      else . end
    | .networks[$network].coordinator_configs = [
        {id: 0, rpc_url: [$coordinator]}
      ]
    | .networks[$network].realm_configs = [
        {id: 0, rpc_url: [$realm0]},
        {id: 1, rpc_url: [$realm1]}
      ]
    | .networks[$network].prove_proxy_url = [$prove_proxy]
    | .networks[$network].api_services_url = [$services]
  ' "$CONFIG_SOURCE" >"$tmp_config"
sudo install -o root -g root -m 0644 \
  "$tmp_config" "$RELEASE_DIR/client_prover/config.json"

sudo install -d -o parth -g parth -m 0750 \
  /var/lib/parth \
  /var/lib/parth/.psy \
  /var/lib/parth/.psy/keystore \
  /var/lib/parth/.psy/keystore/deposit_append \
  /var/lib/parth/.psy/keystore/withdrawal_claim \
  /var/lib/parth/prove-captures

install_setup_kind() {
  local source_kind="$1"
  local target_dir="$2"
  local file

  for file in circuit_groth16.bin pk_groth16.bin vk_groth16.bin; do
    sudo install -o parth -g parth -m 0600 \
      "$STAGED_SETUP/$source_kind/$file" "$target_dir/$file"
  done
}
install_setup_kind bridge /var/lib/parth/.psy/keystore
install_setup_kind deposit_batch_append /var/lib/parth/.psy/keystore/deposit_append
install_setup_kind withdrawal_claim /var/lib/parth/.psy/keystore/withdrawal_claim

sudo ln -sfn "$RELEASE_DIR" /opt/parth/current
sudo install -d -o root -g root -m 0755 /etc/parth

tmp_env="$(mktemp)"
trap 'rm -f "$tmp_config" "$tmp_env"' EXIT
cat >"$tmp_env" <<EOF
PARTH_HOME=/opt/parth/current
NETWORK=local-devnet
PROVING_BACKEND=plonky2-poseidon-goldilocks
PROVE_PROXY_LISTEN_ADDR=$WG_ADDRESS:9999
RPC_CONFIG=/opt/parth/current/client_prover/config.json
RUST_LOG=info
PSY_CAPTURE_INPUTS_DIR=/var/lib/parth/prove-captures
PSY_CAPTURE_METHODS=prove_ups_start,prove_ups_start_register_user,prove_contract_call,prove_ups_cfc_standard_tx,prove_ups_cfc_deferred_tx,prove_zk_sign_inner,prove_zk_sign_minifier,prove_secp_sign,prove_withdrawal_batch_claim_groth16,prove_deposit_batch_append_groth16
PSY_CAPTURE_LIMIT_PER_METHOD=20
PSY_CAPTURE_INCLUDE_OUTPUTS=1
EOF
sudo install -o root -g root -m 0600 \
  "$tmp_env" /etc/parth/offsite-prove-proxy.env
sudo install -o root -g root -m 0644 \
  "$UNIT_SOURCE" /etc/systemd/system/parth-offsite-prove-proxy.service
sudo systemctl daemon-reload

if id -u "$OPS_READ_USER" >/dev/null 2>&1; then
  sudo chgrp "$OPS_READ_USER" /var/lib/parth/prove-captures
  sudo chmod 2750 /var/lib/parth/prove-captures
fi

echo "Installed release: $RELEASE_DIR"
echo "Installed service: parth-offsite-prove-proxy.service"
echo "The service has not been started by this installer."
