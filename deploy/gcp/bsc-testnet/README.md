# BSC Testnet GCP Deployment

This profile reuses the existing public staging machine topology and deploys
the Psy L1 bridge contracts to BSC Testnet (`chainId=97`, bridge chain index
`1`). It does not create, resize, or delete GCP VMs.

## Topology

| Role | Host |
| --- | --- |
| Coordinator, realms, psy-services | `gcp-cp-ce` |
| Coordinator workers | `gcp-coordinator-worker` |
| Cloud realm fallback workers | `gcp-realm-worker-0`, `realm-worker-1` |
| Offsite workers | `arc99x4` |
| Offsite prove-proxy | `arc99x2` |
| Faucet and relayer | `gcp-faucet` |
| Scylla | `gcp-scylla` |
| NATS | `gcp-nats` |
| Redis/Valkey | `gcp-redis` |
| Postgres and Envio | `gcp-postgres` |
| Nostr and Caddy public ingress | `gcp-nostr` |

The machine count and sizing are inherited from the current GCP deployment.
The scripts connect to existing SSH aliases; they do not provision machines.

## Important Replacement Boundary

This is not a second side-by-side L2 on the same machines. The fresh deployment
reuses `/var/lib/parth`, Scylla keyspaces, NATS, Redis, Postgres, and systemd
unit names. A real run therefore replaces the current Sepolia-connected Psy
testnet state. BSC uses separate public domains and Cloudflare Pages projects,
so the frontend namespace cannot overwrite staging by accident.

## Preparation

```bash
: "${WORKSPACE_HOME:?set WORKSPACE_HOME to the shared workspace directory}"
cd "$WORKSPACE_HOME/psy-node-deploy-unified"

cp deploy/gcp/bsc-testnet/config.example.env \
  deploy/gcp/bsc-testnet/config.env
```

Edit the ignored `config.env` and set at least:

- `BSC_TESTNET_RPC_URL`: a stable BSC Testnet RPC endpoint.
- `ENVIO_API_TOKEN`: an Envio HyperSync token.
- The inherited deployer/relayer keystore password and expected address.

Alchemy supports BSC Testnet at:

```text
https://bnb-testnet.g.alchemy.com/v2/<API_KEY>
```

An existing Alchemy key can be reused after `BNB_TESTNET` is enabled for its
Alchemy App. A key that has not enabled the network returns HTTP 403; preflight
prints the provider error without printing the key.

The deployer address must hold enough tBNB for contract deployment and relayer
transactions. Preflight defaults to a minimum balance of 0.1 tBNB through
`BSC_MIN_DEPLOYER_BALANCE_WEI`; fund the account with the full 0.3 tBNB faucet
grant when possible. Verify all commits in `source-versions.env` are available
from their remotes before deployment.

Build and dry-run the isolated BSC wallet publication before uploading it:

```bash
R2_SKIP_UPLOAD=1 \
  bash deploy/gcp/bsc-testnet/publish-wallet-r2.sh
```

The command requires the clean wallet checkout pinned by
`source-versions.env`, builds against published `@psy-protocol/psy-sdk@2.0.5`,
and writes BSC metadata under `bsc-testnet/` in the existing wallet R2 bucket.
To publish, load the existing Cloudflare credentials and run without
`R2_SKIP_UPLOAD`:

```bash
CF_ENV_FILE="$WORKSPACE_HOME/cf_env" \
  bash deploy/gcp/bsc-testnet/publish-wallet-r2.sh
```

After the public metadata and zip have been verified, set
`BSC_REQUIRE_PUBLISHED_WALLET=1` in the ignored `config.env`. This turns the
metadata commit check into a deployment gate for the App frontend.

Create DNS records for these BSC-only hosts, pointing at the same ingress used
by staging:

```text
app-bsc-testnet.psy-protocol.xyz
explorer-bsc-testnet.psy-protocol.xyz
ide-bsc-testnet.psy-protocol.xyz
config-bsc-testnet.psy-protocol.xyz
coordinator-bsc-testnet.psy-protocol.xyz
realm0-bsc-testnet.psy-protocol.xyz
realm1-bsc-testnet.psy-protocol.xyz
prove-bsc-testnet.psy-protocol.xyz
faucet-bsc-testnet.psy-protocol.xyz
rpc-bsc-testnet.psy-protocol.xyz
services-bsc-testnet.psy-protocol.xyz
indexer-bsc-testnet.psy-protocol.xyz
nostr-bsc-testnet.psy-protocol.xyz
```

## Validation

Static profile validation without contacting BSC:

```bash
BSC_PREFLIGHT_SKIP_RPC=1 \
  bash deploy/gcp/bsc-testnet/preflight.sh
```

Read-only RPC validation and deployment dry-run:

```bash
DRY_RUN=1 bash deploy/gcp/bsc-testnet/deploy_all.sh
```

The dry-run executes all preflight checks but performs no remote deployment.

## Real Deployment

Only after reviewing the dry-run and accepting replacement of the existing L2:

```bash
CONFIRM_BSC_REPLACES_SEPOLIA=1 \
CONFIRM_FULL_FRESH_DEPLOY=1 \
  bash deploy/gcp/bsc-testnet/deploy_all.sh
```

Step 10 verifies that the RPC reports chain ID 97 before sending a transaction,
deploys new BSC contracts, records the pre-deployment block for Envio, and syncs
the generated addresses back into the ignored BSC config. Anvil is skipped.

## Remaining External Gates

The code paths for node, contracts, genesis, dapp, wallet, R2 publication, local
BSC bridge E2E, and GCP deployment are prepared. Before a real run, enable
`BNB_TESTNET` for the Alchemy App, fund the deployer/relayer with tBNB, publish
the pinned wallet, create the listed DNS/Pages projects, and rerun preflight
without `BSC_PREFLIGHT_SKIP_RPC`.
