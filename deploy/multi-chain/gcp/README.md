# Public multichain GCP deployment

This profile deploys one Psy L2 connected to three EVM testnets:

| Protocol index | Deployment network | EVM chain ID | Public RPC hostname |
| --- | --- | ---: | --- |
| 0 | `sepolia` | 11155111 | `rpc-eth-stg.psy-protocol.xyz` |
| 1 | `bscTestnet` | 97 | `rpc-bsc-stg.psy-protocol.xyz` |
| 2 | `baseSepolia` | 84532 | `rpc-base-stg.psy-protocol.xyz` |

It reuses the current GCP machine topology, offsite workers on `arc99x4`, and
offsite prove-proxy on `arc99x3`. It replaces the current staging L2 and
database state; it does not create a parallel environment.

## Safety model

- The Sepolia and BSC single-chain profiles remain unchanged.
- `config.env` and the runtime deployment manifest are ignored by Git.
- Raw authenticated L1 RPC URLs are used only by deployment/backend services.
- Browsers use one Caddy hostname per chain. The frontend build temporarily
  overlays these public RPC defaults and refuses to publish if a private
  upstream URL is found in the static bundle.
- A real run needs `CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1` and
  `CONFIRM_FULL_FRESH_DEPLOY=1`.
- Preflight checks all three RPC chain IDs, the shared signer address and
  balance, source pins, chain indexes, SSH aliases, and public DNS.
- The node runtime must match the selected source commit. Deployment tools
  live under `deploy/`; only pinned submodule references, the private-key
  ignore rule, and deletion of the obsolete frontend workflow are exempt
  metadata. Arbitrary Rust or root Cargo changes are rejected.
- Wallet releases and DApp workflow pushes are separate from this runner.
  Never substitute an unpublished candidate SHA in `source-versions.env`.

## Prerequisites

1. Point the three public RPC DNS records above to the existing `gcp-nostr`
   public IP. Keep the same proxy mode used by the other backend records.
2. Fund `L1_DEPLOYER_ADDRESS` on Sepolia, BSC Testnet, and Base Sepolia. The
   same keystore is used to deploy contracts and finalize relayer batches.
3. Create `config.env` and set private RPC URLs, keystore password, Postgres,
   Hasura, JWT, Envio HyperSync, Cloudflare, and WireGuard prove endpoint data.
4. Keep `$WORKSPACE_HOME/psy-services-merge-multi-chain` clean at the commit
   pinned in `source-versions.env`.

```bash
# Run from your dedicated deployment checkout.
cp deploy/multi-chain/gcp/config.example.env deploy/multi-chain/gcp/config.env
chmod 600 deploy/multi-chain/gcp/config.env
```

## Validation

First inspect the offline plan. It does not prepare sources, contact nodes,
send transactions, or run deployment steps:

```bash
bash deploy/multi-chain/gcp/deploy_all.sh --plan
```

Then prepare exact source revisions and run checks without changing GCP.
Source preparation can fetch and detach clean local child repositories:

```bash
export WORKSPACE_HOME="$(cd .. && pwd)"

GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  bash deploy/multi-chain/gcp/prepare-sources.sh

GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  bash deploy/multi-chain/gcp/preflight.sh

GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  DRY_RUN=1 \
  bash deploy/multi-chain/gcp/deploy_all.sh
```

`MULTICHAIN_PREFLIGHT_SKIP_RPC=1` and
`MULTICHAIN_PREFLIGHT_SKIP_DNS=1` are only for script development. Do not use
them for the final production-like preflight.

## Deployment order

The entrypoint executes the shared step scripts in `steps.tsv` order. The
plan displays every step ID, description, and script path:

1. Stop services and clear L2/database state.
2. Build and distribute the pinned Psy node/genesis bundle.
3. Deploy L1 contracts in index order: Sepolia, BSC Testnet, Base Sepolia.
4. Write ignored `runtime/l1-deployments.json` only after all three networks
   complete. A `.pending` marker blocks downstream consumers until then.
5. Start one Envio indexer configured with all three network sections.
6. Start Psy nodes, cloud baseline workers, faucet, and prove-proxy routing.
7. Start one relayer with three `[[chains]]` entries and all deployment JSONs.
8. Install Caddy routes and verify each public RPC's exact `eth_chainId`.
9. Publish config/App/Explorer/IDE frontends and run the smoke check.
10. Add offsite workers only after the cloud baseline is healthy.

The Envio YAML renderer and Caddy path handling are covered by
`deploy/gcp/tests/test-multichain-profile.sh`. Authenticated RPC URLs with a
path such as `/v2/<key>` are split into a Caddy origin and request rewrite;
they are never emitted as an invalid `reverse_proxy` upstream.

Run the destructive deployment only after the dry run is reviewed:

```bash
GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  CONFIRM_MULTICHAIN_REPLACES_CURRENT_STAGING=1 \
  CONFIRM_FULL_FRESH_DEPLOY=1 \
  bash deploy/multi-chain/gcp/deploy_all.sh
```

After deployment, run the staging node audit and a transaction E2E for each
source/destination chain. A single primary-chain smoke test is not sufficient
evidence for a multichain release.

## Failure and resume

Each invocation saves private `runtime/runs/<run-id>/<step>.log` files and a
`status.tsv`. The first failed step stops execution; no step is retried
automatically. These logs may include credentials from downstream tools and
must not be committed or posted publicly.

Review a resume plan before executing it, using execution order, not numeric
order (for example, step 29 precedes step 18):

```bash
bash deploy/multi-chain/gcp/deploy_all.sh --plan --from 16 --until 18
bash deploy/multi-chain/gcp/deploy_all.sh --plan --only 30
```

Real resume invocations need both confirmations above. They retain existing
local sources/artifacts instead of automatically switching checkouts. Full
runs prepare sources first. Neither plan output nor skipped RPC/DNS checks
constitutes a successful release preflight.

If step 10 fails, inspect `runtime/l1-deployments.json.pending`, each chain's
receipts, and deployment artifacts before deciding how to recover. The
marker deliberately prevents blind redeployment and use of a stale manifest.
Do not delete it simply to bypass the guard: partial L1 transactions may
already exist. Clearing L2 state without step 10 in the selected plan is
rejected because the existing L1 roots would no longer match.

## Offline script checks

These fixture tests never contact production or submit transactions:

```bash
bash deploy/gcp/tests/test-multichain-deploy-runner.sh
bash deploy/gcp/tests/test-multichain-l1-deployment.sh
bash deploy/gcp/tests/test-multichain-profile.sh
bash deploy/gcp/tests/test-runtime-source.sh
bash deploy/gcp/tests/test-multichain-source-preparation.sh
bash deploy/gcp/tests/test-frontend-workflow-safety.sh
cargo test --locked --release --manifest-path deploy/e2e/cli-full-e2e/Cargo.toml
```

CLI E2E now has a standalone Cargo workspace under `deploy/e2e/`; it does not
alter the node runtime workspace. See [the E2E guide](../../e2e/staging/README.md).

## Psy-services-only update

Do not use the fresh-deployment runner or
`deploy_services_keep_state.sh` for a psy-services application update. The
profile has a narrow entrypoint that builds only `psy-services` and
`psy-indexer`, installs them under `/opt/parth/psy-services/releases`, and
restarts only psy-services plus the coordinator/realm indexers. It never
changes `/opt/parth/current`, genesis, node processes, workers, prove-proxy,
faucet, relayer, Caddy, or frontends.

Review the exact actions first:

```bash
GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  DRY_RUN=1 \
  bash deploy/multi-chain/gcp/deploy-psy-services-update.sh
```

Deploy the commit pinned in `source-versions.env`:

```bash
GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  CONFIRM_PSY_SERVICES_UPDATE=1 \
  bash deploy/multi-chain/gcp/deploy-psy-services-update.sh
```

The entrypoint verifies the GitHub organization/repository, branch ancestry,
exact commit, clean checkout, archive checksum, remote manifest, process
executable paths, public health endpoint, and Explorer bridge activity route.
It stops the three indexers before restarting psy-services, then brings the
indexers back one at a time. Database state is preserved and migrations run
before the new service becomes healthy.

Binary rollback is available if the new process cannot run:

```bash
GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.env" \
  CONFIRM_PSY_SERVICES_ROLLBACK=1 \
  bash deploy/multi-chain/gcp/rollback-psy-services-update.sh
```

Rollback switches the service binaries only. It does not reverse PostgreSQL
migrations, so migration compatibility must be reviewed before using it. The
update from `46f8463` to `9122e5d` contains no migration changes.
