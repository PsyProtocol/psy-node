# Local Multichain Deployment

This deployment profile runs the `psy-node` `multi_chain` development stack
and exposes it through the existing `psy-local-staging` Cloudflare named
tunnel. It intentionally lives entirely under `deploy/`, so the deployment
branch can keep following `origin/multi_chain` without mixing deployment code
into product branches.

The native `dev/locSetupV4.ts` remains the owner of the Psy runtime. It starts:

- coordinator, two realms, workers, prove-proxy and faucet;
- psy-services, Psy indexers, Nostr and multichain Envio;
- local Ethereum (`31337` / `8545`), BSC (`31338` / `9545`) and Base
  (`31339` / `10545`) Anvil chains;
- one L1 contract deployment per local chain and the unified multichain
  relayer;
- Bridge, Explorer and IDE development frontends.

This profile adds process supervision around that launcher, three local-gas
faucets, a generated multichain Psy Config page, public frontend endpoint
injection, Cloudflare ingress, DNS routing, and local/public health checks. It points locSetup at private, deployment-owned
cohort checkouts under `deploy/local-multichain/.runtime/projects`; this avoids
building or changing dirty sibling repositories elsewhere in the workspace.
The services checkout follows `PsyProtocol/psy-services` branch `multi_chain`;
the launcher verifies its HEAD against `origin/multi_chain` before every start.

## Configuration

Copy the example only when overriding defaults:

```bash
cp deploy/local-multichain/local.env.example deploy/local-multichain/local.env
```

The default hostnames reuse the existing `psy-protocol.xyz` local test zone.
`local.env` is ignored and may contain machine-specific values. Cloudflare
credentials remain in the normal cloudflared credentials store and must never
be committed. Envio binds to host port `9080` by default because this machine's
Signal daemon owns `127.0.0.1:8080`; override `LOCAL_DEPLOY_ENVIO_PORT` when
needed.

## Start or restart

Build release binaries, restart without deleting chain/database state, start
the named tunnel, and verify everything:

```bash
bash deploy/local-multichain/start.sh
```

Reuse existing release binaries:

```bash
bash deploy/local-multichain/start.sh --no-build
```

`--fresh` is intentionally explicit because it removes local checkpoints,
generated local L1 deployments and devnet Docker volumes.

```bash
bash deploy/local-multichain/start.sh --fresh
```

## DNS and status

Route all configured public names to the named tunnel (one-time or after a
hostname change):

```bash
bash deploy/local-multichain/route-dns.sh
```

Check local endpoints and the public HTTPS routes:

```bash
bash deploy/local-multichain/status.sh
```

Run the complete bridge E2E matrix. Each L1 is an independent test case that
must pass deposit, Psy claim, withdrawal and settlement assertions:

```bash
bash deploy/local-multichain/e2e.sh
```

Run or validate one chain while diagnosing a failure:

```bash
bash deploy/local-multichain/e2e.sh --chain bsc
bash deploy/local-multichain/e2e.sh --chain base --preflight-only
```

The cases map Ethereum, BSC and Base to Psy chain indexes `0`, `1` and `2`.
Results and generated deposit proofs are written below the ignored
`deploy/local-multichain/.runtime/e2e/` directory. E2E changes local chain and
Psy state; `status.sh` and `e2e.sh --preflight-only` are read-only.

Stop while preserving state:

```bash
bash deploy/local-multichain/stop.sh
```

## Source-update workflow

Stop the deployment, merge or rebase the latest `origin/multi_chain` into the
deployment branch, review that only `deploy/` is deployment-owned, then start
again. The launcher temporarily patches the nested DApp checkout so a browser
outside this host uses the public BSC and Base RPC names. It also applies
deployment-owned compatibility patches to the native launcher and private
compiler checkout. Root/submodule files can therefore appear modified while
the stack is running; `stop.sh` restores the tracked source files. These are
runtime overlays, not product changes.

Share these entry points with testers:

- `https://app-local.psy-protocol.xyz`
- `https://config-local.psy-protocol.xyz`
- `https://explorer-local.psy-protocol.xyz`
- `https://ide-local.psy-protocol.xyz`
- `https://eth-faucet-local.psy-protocol.xyz`
- `https://bnb-faucet-local.psy-protocol.xyz`
- `https://base-faucet-local.psy-protocol.xyz`

Integration endpoints:

- Psy RPC: `https://coordinator-local.psy-protocol.xyz`,
  `https://realm0-local.psy-protocol.xyz`, and
  `https://realm1-local.psy-protocol.xyz`
- L1 RPC: `https://rpc-local.psy-protocol.xyz`,
  `https://rpc-bsc-local.psy-protocol.xyz`, and
  `https://rpc-base-local.psy-protocol.xyz`
- APIs: `https://services-local.psy-protocol.xyz`,
  `https://indexer-local.psy-protocol.xyz`,
  `https://prove-local.psy-protocol.xyz`, and
  `https://faucet-local.psy-protocol.xyz`
- Nostr: `https://nostr-local.psy-protocol.xyz`
