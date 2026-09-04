#!/usr/bin/env bash
set -euo pipefail

: "${NOSTR_HOME:=/opt/nostr-relay}"
: "${NOSTR_DOMAIN:?NOSTR_DOMAIN is required}"
: "${NOSTR_ALIAS_DOMAINS:=}"
: "${NOSTR_INTERNAL_PORT:=8080}"
: "${PUBLIC_COORDINATOR_DOMAIN:=}"
: "${PUBLIC_COORDINATOR_ALIAS_DOMAINS:=}"
: "${PUBLIC_COORDINATOR_UPSTREAM:=}"
: "${PUBLIC_REALM_DOMAIN:=}"
: "${PUBLIC_REALM_ALIAS_DOMAINS:=}"
: "${PUBLIC_REALM_UPSTREAM:=}"
: "${PUBLIC_REALM1_DOMAIN:=}"
: "${PUBLIC_REALM1_ALIAS_DOMAINS:=}"
: "${PUBLIC_REALM1_UPSTREAM:=}"
: "${PUBLIC_PROVE_PROXY_DOMAIN:=}"
: "${PUBLIC_PROVE_PROXY_ALIAS_DOMAINS:=}"
: "${PUBLIC_PROVE_PROXY_UPSTREAM:=}"
: "${PUBLIC_FAUCET_DOMAIN:=}"
: "${PUBLIC_FAUCET_ALIAS_DOMAINS:=}"
: "${PUBLIC_FAUCET_UPSTREAM:=}"
: "${PUBLIC_L1_RPC_DOMAIN:=}"
: "${PUBLIC_L1_RPC_ALIAS_DOMAINS:=}"
: "${PUBLIC_L1_RPC_UPSTREAM:=}"
: "${PUBLIC_L1_RPC_ROUTES_JSON:=}"
: "${PUBLIC_PSY_SERVICES_DOMAIN:=}"
: "${PUBLIC_PSY_SERVICES_ALIAS_DOMAINS:=}"
: "${PUBLIC_PSY_SERVICES_UPSTREAM:=}"
: "${PUBLIC_INDEXER_DOMAIN:=}"
: "${PUBLIC_INDEXER_ALIAS_DOMAINS:=}"
: "${PUBLIC_INDEXER_UPSTREAM:=}"
: "${PUBLIC_TRUST_SETUP_PATH:=/trust-setup}"
: "${PUBLIC_TRUST_SETUP_ROOT:=$NOSTR_HOME/public/trust-setup}"
: "${PUBLIC_TRUST_SETUP_CONTAINER_ROOT:=/srv/trust-setup}"

[ -d "$NOSTR_HOME" ] || {
  echo "missing NOSTR_HOME: $NOSTR_HOME" >&2
  exit 1
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "Docker Compose is not available; cannot manage nostr-caddy" >&2
    exit 1
  fi
}

install -d -m 0755 "$PUBLIC_TRUST_SETUP_ROOT"

next="$NOSTR_HOME/Caddyfile.next"
backup="$NOSTR_HOME/Caddyfile.backup.$(date +%Y%m%d%H%M%S)"

: >"$next"

declare -A seen_domains=()

register_domains() {
  local label="$1"
  local domains="$2"
  local domain

  for domain in $domains; do
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || {
      echo "invalid domain in $label: $domain" >&2
      exit 1
    }
    if [ -n "${seen_domains[$domain]:-}" ]; then
      echo "duplicate Caddy domain $domain in $label and ${seen_domains[$domain]}" >&2
      exit 1
    fi
    seen_domains[$domain]="$label"
  done
}

register_domains NOSTR "$NOSTR_DOMAIN $NOSTR_ALIAS_DOMAINS"
register_domains coordinator "$PUBLIC_COORDINATOR_DOMAIN $PUBLIC_COORDINATOR_ALIAS_DOMAINS"
register_domains realm0 "$PUBLIC_REALM_DOMAIN $PUBLIC_REALM_ALIAS_DOMAINS"
register_domains realm1 "$PUBLIC_REALM1_DOMAIN $PUBLIC_REALM1_ALIAS_DOMAINS"
register_domains prove-proxy "$PUBLIC_PROVE_PROXY_DOMAIN $PUBLIC_PROVE_PROXY_ALIAS_DOMAINS"
register_domains faucet "$PUBLIC_FAUCET_DOMAIN $PUBLIC_FAUCET_ALIAS_DOMAINS"
register_domains l1-rpc "$PUBLIC_L1_RPC_DOMAIN $PUBLIC_L1_RPC_ALIAS_DOMAINS"
if [ -n "$PUBLIC_L1_RPC_ROUTES_JSON" ]; then
  command -v jq >/dev/null 2>&1 || {
    echo "jq is required for PUBLIC_L1_RPC_ROUTES_JSON" >&2
    exit 1
  }
  jq -e '
    type == "array" and length >= 2
    and all(.[ ];
      (.domain | type == "string" and length > 0)
      and (.upstream | type == "string" and test("^https?://"))
      and (.chain_id | type == "number" and . > 0)
    )
    and ([.[].domain] | length == (unique | length))
  ' <<<"$PUBLIC_L1_RPC_ROUTES_JSON" >/dev/null || {
    echo "invalid PUBLIC_L1_RPC_ROUTES_JSON" >&2
    exit 1
  }
  while IFS= read -r domain; do
    register_domains "multichain-l1-rpc" "$domain"
  done < <(jq -r '.[].domain' <<<"$PUBLIC_L1_RPC_ROUTES_JSON")
fi
register_domains psy-services "$PUBLIC_PSY_SERVICES_DOMAIN $PUBLIC_PSY_SERVICES_ALIAS_DOMAINS"
register_domains indexer "$PUBLIC_INDEXER_DOMAIN $PUBLIC_INDEXER_ALIAS_DOMAINS"

append_nostr_site() {
  local domain="$1"

  cat >>"$next" <<EOF
${domain} {
    encode zstd gzip

    handle_path ${PUBLIC_TRUST_SETUP_PATH%/}/* {
        root * ${PUBLIC_TRUST_SETUP_CONTAINER_ROOT}
        header {
            Access-Control-Allow-Origin *
            Cache-Control "public, max-age=3600"
        }
        file_server
    }

    reverse_proxy nostr-relay:${NOSTR_INTERNAL_PORT}
}
EOF
}

append_nostr_site "$NOSTR_DOMAIN"
for domain in $NOSTR_ALIAS_DOMAINS; do
  append_nostr_site "$domain"
done

append_public_proxy() {
  local domain="$1"
  local upstream="$2"
  local target="$2"
  local rewrite_path=""

  [ -n "$domain" ] || return 0
  [ -n "$upstream" ] || {
    echo "missing upstream for public domain: $domain" >&2
    exit 1
  }

  if [[ "$upstream" =~ ^https?://[^/]+/.+ ]]; then
    if [[ "$upstream" == https://* ]]; then
      local host_path="${upstream#https://}"
      target="https://${host_path%%/*}"
      rewrite_path="/${host_path#*/}"
    else
      local host_path="${upstream#http://}"
      target="http://${host_path%%/*}"
      rewrite_path="/${host_path#*/}"
    fi
  fi

  cat >>"$next" <<EOF

${domain} {
    encode zstd gzip

    @options method OPTIONS
    respond @options 204

    header {
        Access-Control-Allow-Origin *
        Access-Control-Allow-Methods "GET, POST, OPTIONS"
        Access-Control-Allow-Headers "Content-Type, Authorization"
    }

EOF

  if [ -n "$rewrite_path" ] && [ "$rewrite_path" != "/" ]; then
    cat >>"$next" <<EOF
    rewrite * ${rewrite_path}

EOF
  fi

  cat >>"$next" <<EOF
    reverse_proxy ${target} {
        header_up Host {upstream_hostport}
        header_down -Access-Control-Allow-Origin
        header_down -Access-Control-Allow-Methods
        header_down -Access-Control-Allow-Headers
        header_down -Access-Control-Allow-Credentials
        header_down -Access-Control-Expose-Headers
    }
}
EOF
}

append_public_proxy "$PUBLIC_COORDINATOR_DOMAIN" "$PUBLIC_COORDINATOR_UPSTREAM"
for domain in $PUBLIC_COORDINATOR_ALIAS_DOMAINS; do append_public_proxy "$domain" "$PUBLIC_COORDINATOR_UPSTREAM"; done
append_public_proxy "$PUBLIC_REALM_DOMAIN" "$PUBLIC_REALM_UPSTREAM"
for domain in $PUBLIC_REALM_ALIAS_DOMAINS; do append_public_proxy "$domain" "$PUBLIC_REALM_UPSTREAM"; done
append_public_proxy "$PUBLIC_REALM1_DOMAIN" "$PUBLIC_REALM1_UPSTREAM"
for domain in $PUBLIC_REALM1_ALIAS_DOMAINS; do append_public_proxy "$domain" "$PUBLIC_REALM1_UPSTREAM"; done
append_public_proxy "$PUBLIC_PROVE_PROXY_DOMAIN" "$PUBLIC_PROVE_PROXY_UPSTREAM"
for domain in $PUBLIC_PROVE_PROXY_ALIAS_DOMAINS; do append_public_proxy "$domain" "$PUBLIC_PROVE_PROXY_UPSTREAM"; done
append_public_proxy "$PUBLIC_FAUCET_DOMAIN" "$PUBLIC_FAUCET_UPSTREAM"
for domain in $PUBLIC_FAUCET_ALIAS_DOMAINS; do append_public_proxy "$domain" "$PUBLIC_FAUCET_UPSTREAM"; done
append_public_proxy "$PUBLIC_L1_RPC_DOMAIN" "$PUBLIC_L1_RPC_UPSTREAM"
for domain in $PUBLIC_L1_RPC_ALIAS_DOMAINS; do append_public_proxy "$domain" "$PUBLIC_L1_RPC_UPSTREAM"; done
if [ -n "$PUBLIC_L1_RPC_ROUTES_JSON" ]; then
  while IFS=$'\t' read -r domain upstream; do
    append_public_proxy "$domain" "$upstream"
  done < <(jq -r '.[] | [.domain, .upstream] | @tsv' <<<"$PUBLIC_L1_RPC_ROUTES_JSON")
fi
append_public_proxy "$PUBLIC_PSY_SERVICES_DOMAIN" "$PUBLIC_PSY_SERVICES_UPSTREAM"
for domain in $PUBLIC_PSY_SERVICES_ALIAS_DOMAINS; do append_public_proxy "$domain" "$PUBLIC_PSY_SERVICES_UPSTREAM"; done
append_public_proxy "$PUBLIC_INDEXER_DOMAIN" "$PUBLIC_INDEXER_UPSTREAM"
for domain in $PUBLIC_INDEXER_ALIAS_DOMAINS; do append_public_proxy "$domain" "$PUBLIC_INDEXER_UPSTREAM"; done

if [ -f "$NOSTR_HOME/docker-compose.yml" ] && ! grep -Fq "${PUBLIC_TRUST_SETUP_CONTAINER_ROOT}:ro" "$NOSTR_HOME/docker-compose.yml"; then
  tmp_compose="$(mktemp)"
  awk -v host_root="$PUBLIC_TRUST_SETUP_ROOT" -v container_root="$PUBLIC_TRUST_SETUP_CONTAINER_ROOT" '
    {
      print
      if ($0 ~ /^[[:space:]]+- \.\/caddy_config:\/config$/) {
        print "      - " host_root ":" container_root ":ro"
      }
    }
  ' "$NOSTR_HOME/docker-compose.yml" > "$tmp_compose"
  cat "$tmp_compose" > "$NOSTR_HOME/docker-compose.yml"
  rm -f "$tmp_compose"
fi

if docker inspect nostr-caddy >/dev/null 2>&1; then
  docker cp "$next" nostr-caddy:/tmp/Caddyfile.next
  docker exec nostr-caddy caddy validate --config /tmp/Caddyfile.next
fi

[ ! -f "$NOSTR_HOME/Caddyfile" ] || cp "$NOSTR_HOME/Caddyfile" "$backup"
if [ -f "$NOSTR_HOME/Caddyfile" ]; then
  # Preserve the existing inode. Docker single-file bind mounts keep pointing at
  # the old inode if the file is replaced with mv, leaving Caddy on stale config.
  cat "$next" > "$NOSTR_HOME/Caddyfile"
  rm -f "$next"
else
  mv "$next" "$NOSTR_HOME/Caddyfile"
fi

if docker inspect -f '{{.State.Running}}' nostr-caddy 2>/dev/null | grep -qx true; then
  if docker exec nostr-caddy sh -lc "[ -d '$PUBLIC_TRUST_SETUP_CONTAINER_ROOT' ]" \
    && docker exec nostr-caddy sh -lc 'cmp -s /etc/caddy/Caddyfile /tmp/Caddyfile.next'; then
    docker exec nostr-caddy caddy reload --config /etc/caddy/Caddyfile
  else
    echo "nostr-caddy bind mount or trust setup mount is stale; recreating caddy container"
    cd "$NOSTR_HOME"
    compose up -d --force-recreate caddy
  fi
else
  cd "$NOSTR_HOME"
  compose up -d caddy
fi

echo "installed Caddy sites:"
grep -E '^[A-Za-z0-9][A-Za-z0-9.-]* \{$' "$NOSTR_HOME/Caddyfile"
