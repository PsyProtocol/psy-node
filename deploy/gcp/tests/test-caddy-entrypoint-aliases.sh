#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GCP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/bin" "$TMP_DIR/nostr"
cat >"$TMP_DIR/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  inspect) exit 1 ;;
  compose) exit 0 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$TMP_DIR/bin/docker"

PATH="$TMP_DIR/bin:$PATH" \
NOSTR_HOME="$TMP_DIR/nostr" \
NOSTR_DOMAIN="nostr-stg.example.test" \
NOSTR_ALIAS_DOMAINS="nostr.example.test" \
PUBLIC_COORDINATOR_DOMAIN="coordinator-stg.example.test" \
PUBLIC_COORDINATOR_ALIAS_DOMAINS="coordinator.example.test" \
PUBLIC_COORDINATOR_UPSTREAM="10.0.0.1:1337" \
PUBLIC_REALM_DOMAIN="realm0-stg.example.test" \
PUBLIC_REALM_ALIAS_DOMAINS="realm0.example.test" \
PUBLIC_REALM_UPSTREAM="10.0.0.1:1338" \
PUBLIC_REALM1_DOMAIN="realm1-stg.example.test" \
PUBLIC_REALM1_ALIAS_DOMAINS="realm1.example.test" \
PUBLIC_REALM1_UPSTREAM="10.0.0.1:1339" \
PUBLIC_PROVE_PROXY_DOMAIN="prove-stg.example.test" \
PUBLIC_PROVE_PROXY_ALIAS_DOMAINS="prove.example.test" \
PUBLIC_PROVE_PROXY_UPSTREAM="10.0.0.2:9999" \
PUBLIC_FAUCET_DOMAIN="faucet-stg.example.test" \
PUBLIC_FAUCET_ALIAS_DOMAINS="faucet.example.test" \
PUBLIC_FAUCET_UPSTREAM="10.0.0.4:9998" \
PUBLIC_L1_RPC_DOMAIN="rpc-stg.example.test" \
PUBLIC_L1_RPC_ALIAS_DOMAINS="rpc.example.test" \
PUBLIC_L1_RPC_UPSTREAM="10.0.0.1:8545" \
PUBLIC_PSY_SERVICES_DOMAIN="services-stg.example.test" \
PUBLIC_PSY_SERVICES_ALIAS_DOMAINS="services.example.test" \
PUBLIC_PSY_SERVICES_UPSTREAM="10.0.0.1:3000" \
PUBLIC_INDEXER_DOMAIN="indexer-stg.example.test" \
PUBLIC_INDEXER_ALIAS_DOMAINS="indexer.example.test" \
PUBLIC_INDEXER_UPSTREAM="10.0.0.3:18080" \
  bash "$GCP_DIR/remote/update-caddy-entrypoints.sh" >/dev/null

caddyfile="$TMP_DIR/nostr/Caddyfile"
for domain in \
  nostr-stg.example.test nostr.example.test \
  coordinator-stg.example.test coordinator.example.test \
  realm0-stg.example.test realm0.example.test \
  realm1-stg.example.test realm1.example.test \
  prove-stg.example.test prove.example.test \
  faucet-stg.example.test faucet.example.test \
  rpc-stg.example.test rpc.example.test \
  services-stg.example.test services.example.test \
  indexer-stg.example.test indexer.example.test
do
  count="$(grep -Fxc "${domain} {" "$caddyfile")"
  [ "$count" = "1" ] || {
    echo "expected one Caddy site for $domain, got $count" >&2
    exit 1
  }
done

prove_upstream_count="$(grep -Fxc '    reverse_proxy 10.0.0.2:9999 {' "$caddyfile")"
[ "$prove_upstream_count" = "2" ] || {
  echo "expected two prove-proxy upstreams, got $prove_upstream_count" >&2
  exit 1
}
faucet_upstream_count="$(grep -Fxc '    reverse_proxy 10.0.0.4:9998 {' "$caddyfile")"
[ "$faucet_upstream_count" = "2" ] || {
  echo "expected two independent Faucet upstreams, got $faucet_upstream_count" >&2
  exit 1
}
if grep -Fq 'reverse_proxy 10.0.0.2:9998' "$caddyfile"; then
  echo "Faucet must not inherit the prove-proxy host" >&2
  exit 1
fi

if PATH="$TMP_DIR/bin:$PATH" \
  NOSTR_HOME="$TMP_DIR/nostr" \
  NOSTR_DOMAIN="nostr-stg.example.test" \
  NOSTR_ALIAS_DOMAINS="nostr-stg.example.test" \
  bash "$GCP_DIR/remote/update-caddy-entrypoints.sh" >/dev/null 2>&1; then
  echo "duplicate Caddy domains should be rejected" >&2
  exit 1
fi

echo "[ok] canonical and alias Caddy sites render exactly once"
