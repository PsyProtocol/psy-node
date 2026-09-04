#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/_common.sh"

if deploys_cloud_prove_proxy; then
  run_gcp_script deploy-prove-proxy.sh
else
  [ -n "${CLIENT_PROVE_PROXY_URL:-}" ] || {
    echo "DEPLOY_CLOUD_PROVE_PROXY is disabled but CLIENT_PROVE_PROXY_URL is empty" >&2
    exit 1
  }
  [ -n "${PUBLIC_PROVE_PROXY_UPSTREAM:-}" ] || {
    echo "DEPLOY_CLOUD_PROVE_PROXY is disabled but PUBLIC_PROVE_PROXY_UPSTREAM is empty" >&2
    exit 1
  }
  case "${DEPLOY_OFFSITE_PROVE_PROXY:-0}" in
    1|true|TRUE|yes|YES|on|ON)
      log_step "cloud prove-proxy disabled; deploying arc99x2 through ${PUBLIC_PROVE_PROXY_UPSTREAM}"
      OFFSITE_PROVE_PROXY_HOST="${OFFSITE_PROVE_PROXY_HOST:-arc99x2}" \
      OFFSITE_PROVE_PROXY_APPLY_STAGED="${OFFSITE_PROVE_PROXY_APPLY_STAGED:-1}" \
        bash "$REPO_ROOT/deploy/offsite-prove-proxy/deploy-arc99x2-release.sh"
      ;;
    *)
      cat >&2 <<EOF
DEPLOY_CLOUD_PROVE_PROXY is disabled, but DEPLOY_OFFSITE_PROVE_PROXY is not
enabled. A fresh deployment must install its new bundle on arc99x2 before
workers, relayer, and public checks start.
EOF
      exit 1
      ;;
  esac
fi

case "${PSY_FAUCET_SERVER_MODE:-1}" in
  1|true|TRUE|yes|YES|on|ON)
    if ! deploys_cloud_prove_proxy && [ -z "${FAUCET_VM_NAME:-}" ]; then
      echo "FAUCET_VM_NAME is required when the cloud prove-proxy is disabled" >&2
      exit 1
    fi
    log_step "deploying standalone faucet-server to ${FAUCET_VM_NAME:-${PROVE_PROXY_VM_NAME:-gcp-prove-proxy}}"
    run_gcp_script deploy-faucet-server.sh
    ;;
  *)
    log_step "PSY_FAUCET_SERVER_MODE is disabled; skipping standalone faucet-server"
    ;;
esac
