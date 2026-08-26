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

The deployer address must hold enough tBNB for contract deployment and relayer
transactions. Verify all commits in `source-versions.env` are available from
their remotes before deployment.

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

## Remaining Release Gate

The node, contracts, genesis, dapp, local BSC bridge E2E, and GCP profile are
prepared. The wallet's BSC network profile and its R2 publication flow still
need explicit verification before advertising the wallet as BSC-ready. This
does not block backend-only deployment, but it blocks a complete public wallet
release.
