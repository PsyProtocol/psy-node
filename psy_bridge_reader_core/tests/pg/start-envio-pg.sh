#!/usr/bin/env bash
# Throwaway PostgreSQL with Envio's own DDL, for the ignored PgSource tests.
#
#   start-envio-pg.sh [start]   start postgres:16.13 in docker on a free
#                               127.0.0.1 port, run Envio's migrations into
#                               database "envio", and print its URL on stdout
#   start-envio-pg.sh stop [URL]
#                               remove the container serving URL (default
#                               $PSY_BRIDGE_READER_TEST_PG); only containers
#                               this script started are ever matched
#
# Usage:
#   export PSY_BRIDGE_READER_TEST_PG=$(tests/pg/start-envio-pg.sh)
#   cargo test --release -p psy_bridge_reader_core --test pg_source -- --ignored
#   tests/pg/start-envio-pg.sh stop
#
# The Envio schema is $PSY_BRIDGE_READER_TEST_PG_SCHEMA (default "public",
# Envio's own default); the tests read the same variable with the same default.
#
# The migrations run exactly as envio_initialize in
# psy_cli/psy_relayer_cli/indexer/envio/tests/plan/run_plan_test.py does, so the
# Envio directory needs `pnpm install` and `pnpm codegen` first (codegen needs
# a config.yaml made from config.template.yaml). Envio 2.32.10 needs Node 22:
# put it first on PATH or set ENVIO_NODE to its binary.
set -euo pipefail

IMAGE=postgres:16.13
LABEL=psy-bridge-reader-test-pg
PASSWORD=reader-test
DATABASE=envio
SCHEMA=${PSY_BRIDGE_READER_TEST_PG_SCHEMA:-public}
NODE=${ENVIO_NODE:-node}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ENVIO_DIR=$(cd "$SCRIPT_DIR/../../../psy_cli/psy_relayer_cli/indexer/envio" && pwd)

die() { echo "start-envio-pg.sh: $*" >&2; exit 1; }

free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

start() {
    local migrations="$ENVIO_DIR/generated/src/db/Migrations.res.js"
    [[ -f $migrations ]] || die "generated/ is missing: run \`pnpm codegen\` in $ENVIO_DIR first"
    command -v docker >/dev/null || die "docker is required"
    local suffix port name
    suffix=$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')
    name="$LABEL-$suffix"
    port=$(free_port)
    docker run -d --name "$name" --label "$LABEL=1" \
        -e POSTGRES_PASSWORD="$PASSWORD" -e POSTGRES_DB="$DATABASE" \
        -p "127.0.0.1:$port:5432" "$IMAGE" >/dev/null
    echo "started container $name on 127.0.0.1:$port" >&2
    # The image's init server listens on the socket only, so a TCP check
    # inside the container passes only once the final server is up.
    local deadline=$((SECONDS + 60))
    until docker exec "$name" pg_isready -q -h 127.0.0.1 -U postgres -d "$DATABASE"; do
        if ((SECONDS > deadline)); then
            docker rm -f -v "$name" >/dev/null
            die "postgres did not become ready in 60 s"
        fi
        sleep 1
    done
    if ! (cd "$ENVIO_DIR" && ENVIO_PG_HOST=127.0.0.1 ENVIO_PG_PORT="$port" ENVIO_PG_USER=postgres \
        ENVIO_PG_PASSWORD="$PASSWORD" ENVIO_PG_DATABASE="$DATABASE" \
        ENVIO_PG_PUBLIC_SCHEMA="$SCHEMA" ENVIO_HASURA=false LOG_LEVEL=warn \
        ENVIO_MIGRATIONS="$migrations" \
        "$NODE" -e 'require(process.env.ENVIO_MIGRATIONS).runUpMigrations(true, true)' >&2); then
        docker rm -f -v "$name" >/dev/null
        die "Envio migrations failed"
    fi
    echo "postgresql://postgres:$PASSWORD@127.0.0.1:$port/$DATABASE"
}

stop() {
    local url=${1:-${PSY_BRIDGE_READER_TEST_PG:-}}
    [[ -n $url ]] || die "stop needs a URL (or PSY_BRIDGE_READER_TEST_PG)"
    local port
    port=$(printf '%s' "$url" | sed -nE 's#^postgres(ql)?://[^@/]*@[^:/]+:([0-9]+)/.*#\2#p')
    [[ -n $port ]] || die "no port in $url"
    local found=0 name
    for name in $(docker ps -a --filter "label=$LABEL" --format '{{.Names}}'); do
        if docker port "$name" 5432/tcp 2>/dev/null | grep -qx "127.0.0.1:$port"; then
            docker rm -f -v "$name" >/dev/null
            echo "removed container $name" >&2
            found=1
        fi
    done
    ((found)) || die "no container of this script serves port $port"
}

case ${1:-start} in
    start) start ;;
    stop) stop "${2:-}" ;;
    *) die "usage: start-envio-pg.sh [start | stop [URL]]" ;;
esac
