#!/usr/bin/env bash
set -euo pipefail

: "${ANVIL_DOCKER_IMAGE:=ghcr.io/foundry-rs/foundry:stable}"
: "${ANVIL_HOST_BIND:=0.0.0.0}"
: "${ANVIL_PORT:=8545}"
: "${ANVIL_CHAIN_ID:=31337}"
: "${ANVIL_EXTRA_ARGS:=--steps-tracing -vvvv}"
: "${ANVIL_PERSIST_STATE:=1}"
: "${ANVIL_STATE_INTERVAL_SECONDS:=5}"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl jq docker.io
systemctl enable --now docker

bash /tmp/mount-data-disk.sh

install -d -m 0755 /var/lib/parth/anvil

state_args=""
if [ "$ANVIL_PERSIST_STATE" = "1" ] || [ "$ANVIL_PERSIST_STATE" = "true" ]; then
  state_args="--state /data/state.json --state-interval ${ANVIL_STATE_INTERVAL_SECONDS}"
fi

cat >/etc/systemd/system/parth-anvil.service <<EOF
[Unit]
Description=Parth staging Anvil L1 RPC
Wants=network-online.target docker.service
After=network-online.target docker.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/docker rm -f parth-anvil
ExecStart=/usr/bin/docker run --rm --name parth-anvil \\
  --publish ${ANVIL_HOST_BIND}:${ANVIL_PORT}:8545 \\
  --volume /var/lib/parth/anvil:/data \\
  --entrypoint anvil \\
  ${ANVIL_DOCKER_IMAGE} \\
  --host 0.0.0.0 \\
  --port 8545 \\
  --chain-id ${ANVIL_CHAIN_ID} \\
  ${state_args} \\
  ${ANVIL_EXTRA_ARGS}
ExecStop=/usr/bin/docker stop parth-anvil
Restart=always
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=1048576
SyslogIdentifier=parth-anvil

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now parth-anvil.service
systemctl --no-pager --full status parth-anvil.service || true
