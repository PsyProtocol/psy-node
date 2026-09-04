# Deployment Branch

The `deploy-unified` branch follows
`mainnet-beta` for all product code. Deployment-only changes
live under this directory. Maintain both GCP and local-testnet deployment
automation on this branch; do not copy deployment scripts back into the
runtime branch.

## Branch Policy

- Treat `deploy-unified` as the long-lived operational branch for deployment
  automation. Push reviewed deployment commits directly to this branch; do not
  open a pull request from it into `mainnet-beta`.
- Synchronize product code from `mainnet-beta` before a deployment and verify
  that the resulting tree has no product-code drift outside `deploy/`.
- Keep reusable deployment scripts, service units, environment examples,
  runbooks, and deployment-specific tests under `deploy/`.
- Never commit environment-specific secrets or generated `config.env` files.

## Layout

- `ethereum-sepolia/`: canonical Sepolia configuration, source pins,
  preflight, and deployment entrypoint.
- `bsc-testnet/`: canonical BSC Testnet configuration plus the isolated local
  BSC validation stack.
- `multi-chain/gcp/`: one Psy L2 connected to Sepolia, BSC Testnet, and Base
  Sepolia using a generated runtime manifest shared by all backend services.
- `gcp/`: remote GCP staging deployment and operational scripts.
- `local-multichain/`: local three-L1 integration environment.
- `local-testnet/`: the complete local Psy testnet, Cloudflare Tunnel, and
  local relayer tooling.
- `temporary/`: one-off diagnostics and migration helpers. Formal deployment
  entrypoints must not depend on this directory.

Shared helpers used by the GCP stack remain in `bin/`, `cloudflare-pages/`,
`local-coordinator-workers/`, `local-prove-proxy/`, `local-relayer/`,
`offsite-worker/`, and `scripts/`. They are kept at their established paths
so existing remote deployment automation remains compatible.

## Network Profiles

Each profile owns its network configuration and source-version manifest while
reusing the shared implementation under `deploy/gcp/`. The deployment branch's
superproject and Gitlinks continue to follow `mainnet-beta`; each profile's
entrypoint checks out its pinned `psy-genesis`, `psy-contracts`, and `psy-dapp`
working trees before preflight.

Ethereum Sepolia:

```bash
cp deploy/ethereum-sepolia/gcp/config.example.env \
  deploy/ethereum-sepolia/gcp/config.env
DRY_RUN=1 bash deploy/ethereum-sepolia/gcp/deploy_all.sh
```

BSC Testnet:

```bash
cp deploy/bsc-testnet/gcp/config.example.env \
  deploy/bsc-testnet/gcp/config.env
DRY_RUN=1 bash deploy/bsc-testnet/gcp/deploy_all.sh
```

Sepolia + BSC Testnet + Base Sepolia:

```bash
cp deploy/multi-chain/gcp/config.example.env \
  deploy/multi-chain/gcp/config.env
DRY_RUN=1 bash deploy/multi-chain/gcp/deploy_all.sh
```

Do not copy L1 RPC URLs, contract addresses, Envio cursors, or wallet settings
between profiles. The historical `deploy/gcp/config.example.env`,
`deploy/source-versions.env`, and `deploy/gcp/bsc-testnet/` paths remain only as
compatibility loaders.

Initialize the pinned source submodules after cloning this branch. The
temporary override is required because upstream intentionally marks
`psy-dapp` with `update = none`:

```bash
git -c submodule.psy-dapp.update=checkout submodule update --init --recursive \
  psy-genesis psy-contracts psy-dapp
```

The canonical contract artifact, ABI files, and client network config come
from the pinned `psy-genesis` submodule. Browser frontends come from the pinned
`psy-dapp` submodule. Deployment does not rebuild contract bytecode with a
separate compiler checkout.

See `deploy/ethereum-sepolia/README.md`, `deploy/bsc-testnet/gcp/README.md`,
`deploy/multi-chain/gcp/README.md`, and `deploy/gcp/fresh-staging/README.md`
before running a state-changing deployment.

## Local Testnet

```bash
cp deploy/local-testnet/stack/local.env.example \
  deploy/local-testnet/stack/local.env
cp deploy/local-testnet/cloudflare-tunnel/local.env.example \
  deploy/local-testnet/cloudflare-tunnel/local.env

LOCAL_STAGING_BUILD=1 LOCAL_STAGING_RESET=1 \
  bash deploy/local-testnet/cloudflare-tunnel/up.sh
```

Status:

```bash
bash deploy/local-testnet/stack/status.sh
bash deploy/local-testnet/cloudflare-tunnel/status.sh
```

## BSC Local Validation

The BSC Testnet deployment is intentionally staged behind local validation.
Do not point the existing Sepolia environment at BSC or reuse its durable
state. Follow [`bsc-testnet/PLAN.md`](bsc-testnet/PLAN.md) from phase 0. The
local harness is documented in [`bsc-testnet/README.md`](bsc-testnet/README.md),
while the cloud profile lives under `bsc-testnet/gcp/`.

## Temporary Scripts

Scripts under `temporary/` are manually invoked, non-authoritative helpers.
Move a script into the appropriate formal deployment directory before making
another deployment script depend on it.
