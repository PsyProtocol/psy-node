# Local Staging Stack

This directory runs a staging-shaped local Psy stack from this checkout.

It is intentionally separate from `deploy/gcp`: it does not create cloud
machines, does not deploy Cloudflare Pages, and does not regenerate
`genesis.json`.

## One Command

```bash
cd "$WORKSPACE_HOME/pr-255-local-deploy"
bash deploy/local-testnet/stack/up.sh
```

The script starts:

- Docker dependencies: Valkey, NATS JetStream, Scylla, PostgreSQL
- nginx for local static frontends
- coordinator processor and edge
- realm 0 and realm 1 processors and edges
- coordinator and realm workers
- stateless prove-proxy
- standalone Psy faucet server
- psy-services
- coordinator and realm psy-indexers
- built app, explorer, and IDE frontends published into nginx

Status:

```bash
bash deploy/local-testnet/stack/status.sh
```

Verify the prove-proxy/faucet process, RPC, config, and secret boundaries:

```bash
bash deploy/local-testnet/stack/test-faucet-split.sh
```

To rebuild or restart only prove-proxy and the standalone faucet server without
touching nodes, indexers, relayers, or psy-services:

```bash
LOCAL_STAGING_BUILD=1 bash deploy/local-testnet/stack/up-faucet-split.sh
```

Stop:

```bash
bash deploy/local-testnet/stack/down.sh
```

Stop and remove local Docker volumes:

```bash
bash deploy/local-testnet/stack/down.sh --volumes
```

If startup failed while creating Scylla keyspaces, clear local volumes before
retrying so the partial keyspace state is removed:

```bash
bash deploy/local-testnet/stack/down.sh --volumes
docker compose -p parth-local-staging -f deploy/local-testnet/stack/docker-compose.yml pull scylla
bash deploy/local-testnet/stack/up.sh
```

## Endpoints

Default endpoints:

```text
coordinator   http://127.0.0.1:1337
realm 0       http://127.0.0.1:13380
realm 1       http://127.0.0.1:13390
prove-proxy   http://127.0.0.1:9999
faucet        http://127.0.0.1:9998
psy-services  http://127.0.0.1:3000
app           http://127.0.0.1:8088
explorer      http://127.0.0.1:8089
ide           http://127.0.0.1:8090
```

You can use `.localhost` names in browsers if that is easier to reason about:

```text
http://coordinator.localhost:1337
http://realm0.localhost:13380
http://realm1.localhost:13390
http://prove.localhost:9999
http://faucet.localhost:9998
http://services.localhost:3000
```

The checked-in `psy-genesis/config.json` already points the `localhost`
network at these default ports.

## Local Overrides

Copy the example env file and edit it:

```bash
cp deploy/local-testnet/stack/local.env.example deploy/local-testnet/stack/local.env
```

Common options:

```bash
LOCAL_STAGING_BUILD=1 bash deploy/local-testnet/stack/up.sh
LOCAL_STAGING_RESET=1 bash deploy/local-testnet/stack/up.sh
LOCAL_STAGING_REALMS="0 1" bash deploy/local-testnet/stack/up.sh
LOCAL_STAGING_START_WORKERS=0 bash deploy/local-testnet/stack/up.sh
LOCAL_STAGING_START_PROVE_PROXY=0 bash deploy/local-testnet/stack/up.sh
LOCAL_STAGING_START_FAUCET_SERVER=0 bash deploy/local-testnet/stack/up.sh
LOCAL_STAGING_BUILD_FRONTENDS=0 bash deploy/local-testnet/stack/up.sh
```

The local Postgres container binds to `127.0.0.1:15432` by default to avoid
conflicting with a developer machine's system PostgreSQL on `5432`. Override
`LOCAL_POSTGRES_PORT` in `local.env` if needed.

The full default mode starts proof workers and prove-proxy, so the first run can
consume substantial memory while circuits are built. Disable workers or
prove-proxy when you only need to test RPC/service wiring.

## Frontends And Wallet

`up.sh` builds and publishes the three frontends by default:

```text
psy-dapp/apps/bridge   -> http://127.0.0.1:8088
psy-dapp/apps/explorer -> http://127.0.0.1:8089
psy-dapp/apps/ide      -> http://127.0.0.1:8090
```

If dependencies are not installed, let the script install the pinned pnpm
workspace once:

```bash
LOCAL_STAGING_NPM_INSTALL=1 bash deploy/local-testnet/stack/up.sh
```

The Psy Wallet is a browser extension, so nginx does not "run" it as a website.
Local staging hosts wallet zip files under:

```text
http://127.0.0.1:8088/downloads/
```

By default it copies the zip already staged in
`psy-dapp/apps/bridge/public/downloads`. To rebuild the wallet zip
from `$WORKSPACE_HOME/psy-wallet` before publishing:

```bash
LOCAL_STAGING_BUILD_WALLET=1 bash deploy/local-testnet/stack/publish-frontends.sh
```

## Scope

This is the local core chain and indexing stack. L1 Anvil, Envio, Nostr, bridge
relayer, and frontends are deliberately left as follow-up layers because they
need extra contract deployment and frontend runtime config. The existing
`deploy/local-testnet/relayer` and `deploy/local-testnet/cloudflare-tunnel` directories still
cover local bridge and shared browser testing.
