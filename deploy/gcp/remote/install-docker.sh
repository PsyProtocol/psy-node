#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io
systemctl enable --now docker

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  for compose_pkg in docker-compose-v2 docker-compose-plugin docker-compose; do
    if apt-cache show "$compose_pkg" >/dev/null 2>&1; then
      apt-get install -y "$compose_pkg"
      break
    fi
  done
fi

if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  echo "Docker Compose is not available from configured apt repositories" >&2
  exit 1
fi
