# Public multichain GCP deployment

This profile deploys one Psy L2 connected to three EVM testnets:

| Protocol index | Deployment network | EVM chain ID | Public RPC hostname |
| --- | --- | ---: | --- |
| 0 | `sepolia` | 11155111 | `rpc-eth-stg.psy-protocol.xyz` |
| 1 | `bscTestnet` | 97 | `rpc-bsc-stg.psy-protocol.xyz` |
| 2 | `baseSepolia` | 84532 | `rpc-base-stg.psy-protocol.xyz` |

It reuses the current GCP machine topology, offsite workers on `arc99x4`, and
offsite prove-proxy on `arc99x2`. It replaces the current staging L2 and
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
cd "$WORKSPACE_HOME/psy-node-multi-chain-gcp-deploy"
cp deploy/multi-chain/gcp/config.example.env deploy/multi-chain/gcp/config.env
```

## Validation

First prepare exact source revisions and run checks without changing GCP:

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

The shared fresh-deployment runner performs these relevant phases:

1. Stop services and clear L2/database state.
2. Build and distribute the pinned Psy node/genesis bundle.
3. Deploy L1 contracts in index order: Sepolia, BSC Testnet, Base Sepolia.
4. Write ignored `runtime/l1-deployments.json` with verified addresses and
   start blocks from all three networks.
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
