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

- `gcp/`: remote GCP staging deployment and operational scripts.
- `local-testnet/`: the complete local Psy testnet, Cloudflare Tunnel, and
  local relayer tooling.
- `temporary/`: one-off diagnostics and migration helpers. Formal deployment
  entrypoints must not depend on this directory.

Shared helpers used by the GCP stack remain in `bin/`, `cloudflare-pages/`,
`local-coordinator-workers/`, `local-prove-proxy/`, `local-relayer/`,
`offsite-worker/`, and `scripts/`. They are kept at their established paths
so existing remote deployment automation remains compatible.

## GCP

Start with:

```bash
cp deploy/gcp/config.example.env deploy/gcp/config.env
bash deploy/gcp/fresh-staging/preflight.sh
CONFIRM_FULL_FRESH_DEPLOY=1 bash deploy/gcp/fresh-staging/deploy_all.sh
```

For the current full deployment, review `deploy/source-versions.env`. It is the
single authoritative list of repository origins, commits, and reproducible
Genesis contract checksum. `deploy/gcp/config.env` contains environment-specific
topology, credentials, and tuning only. Preflight rejects dirty source trees,
wrong repositories, unexpected commits, and any product-code drift outside
`deploy/` by default.

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

See `deploy/gcp/README.md` and `deploy/gcp/fresh-staging/README.md` before
running a state-changing deployment.

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

## BSC Testnet

The BSC Testnet deployment is intentionally staged behind local validation.
Do not point the existing Sepolia environment at BSC or reuse its durable
state. Follow [`bsc-testnet/PLAN.md`](bsc-testnet/PLAN.md) from phase 0; public
BSC contracts and cloud services are blocked until the isolated local Chain ID
97 E2E passes. The phase-2 local contract harness is documented in
[`bsc-testnet/README.md`](bsc-testnet/README.md).

## Temporary Scripts

Scripts under `temporary/` are manually invoked, non-authoritative helpers.
Move a script into the appropriate formal deployment directory before making
another deployment script depend on it.
