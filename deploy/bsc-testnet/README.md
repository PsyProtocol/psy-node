# Local BSC Testnet Preparation

This directory starts an isolated local EVM with BSC Testnet's chain ID and
deploys the complete Psy L1 contract set to it. It is phase 2 of
[`PLAN.md`](PLAN.md), not a public BSC deployment.

The defaults use `127.0.0.1:18545` and `.local-bsc-testnet/`, so they do not
touch the regular local testnet on port `8545` or any GCP staging service.

## Contract-only validation

```bash
cp deploy/bsc-testnet/local.env.example deploy/bsc-testnet/local.env

# Optional while the product changes are still in a separate worktree:
# export PSY_CONTRACTS_DIR=/path/to/psy-contracts-bsc-testnet

AUTHORIZED_BSC_LOCAL_TRANSACTIONS=1 BSC_LOCAL_RESET=1 \
  bash deploy/bsc-testnet/up-local-l1.sh

AUTHORIZED_BSC_LOCAL_TRANSACTIONS=1 \
  bash deploy/bsc-testnet/deploy-local-l1.sh

bash deploy/bsc-testnet/status-local-l1.sh
bash deploy/bsc-testnet/check-local-l1.sh
bash deploy/bsc-testnet/down-local-l1.sh
```

`deploy-local-l1.sh` uses Anvil's documented development key by default. That
key is valid only for this isolated local chain. Public BSC Testnet deployment
will require a separate keystore-backed signer and a dedicated RPC profile.

Generated deployment evidence is copied to
`.local-bsc-testnet/evidence/`. The authoritative generated contract manifest
for the selected contracts worktree is
`deployments/bsc-testnet/deployed-contracts.json`.

## Complete local backend

The complete backend reuses the proven local-testnet process orchestration but
keeps BSC state, ports, Docker projects, Envio storage, and relayer cursors
separate. It uses the BSC product worktrees until those commits are merged into
the normal product branch.

```bash
cp deploy/bsc-testnet/full-stack.env.example deploy/bsc-testnet/full-stack.env

# Static validation can run while another local testnet is active. Host and
# port checks remain disabled for this command only.
bash deploy/bsc-testnet/static-check.sh

# Runtime deployment is deliberately phased. Do not advance until the status
# checks for the current phase pass.
AUTHORIZED_BSC_LOCAL_TRANSACTIONS=1 BSC_LOCAL_RESET=1 \
  bash deploy/bsc-testnet/up-local-stack.sh l1
bash deploy/bsc-testnet/check-local-stack.sh l1

AUTHORIZED_BSC_LOCAL_TRANSACTIONS=1 \
  bash deploy/bsc-testnet/up-local-stack.sh core
bash deploy/bsc-testnet/check-local-stack.sh core

AUTHORIZED_BSC_LOCAL_TRANSACTIONS=1 \
  bash deploy/bsc-testnet/up-local-stack.sh bridge
bash deploy/bsc-testnet/check-local-stack.sh bridge

# `all` remains available for a clean, dedicated test host.
AUTHORIZED_BSC_LOCAL_TRANSACTIONS=1 BSC_LOCAL_RESET=1 \
  bash deploy/bsc-testnet/up-local-stack.sh all

bash deploy/bsc-testnet/status-local-stack.sh

# Retain database volumes and Anvil state.
bash deploy/bsc-testnet/down-local-stack.sh

# Remove isolated Docker volumes on the next reset.
BSC_LOCAL_REMOVE_VOLUMES=1 bash deploy/bsc-testnet/down-local-stack.sh
```

The first full-stack gate is CLI-only. Cloudflare Tunnel and frontend
publication stay disabled so backend behavior can be validated before adding
wallet distribution or public BSC domains.

The BSC profile keeps Groth16 setup files under
`.local-bsc-testnet/home/.psy/keystore`. It does not reuse the regular
`~/.psy/keystore`. Missing setup files are generated before L1 deployment, and
an existing setup whose circuit fingerprint is stale causes a hard failure
until L1 is deliberately reset and redeployed with the matching verifiers.

Fresh realm indexers resume after checkpoint `0`; genesis has no realm endcap
backup to ingest. Override `BSC_LOCAL_REALM_INDEXER_START_CHECKPOINT` only for
an intentional backfill or recovery run.

The bridge relayer withdraw method ID is derived from the current BSC USDT ABI.
This prevents a stale local-testnet default from silently ignoring BSC
withdrawal events after ABI regeneration.

The pinned Scylla `2026.1.5` image requires the host setting
`fs.aio-max-nr >= 67590`. Preflight reports the current value and fails before
starting containers when it is too low. During an approved test window, set it
explicitly before the `core` phase:

```bash
sudo sysctl -w fs.aio-max-nr=167588
```

Restore the previous value after stopping the isolated stack if this is a
shared test host. The deployment scripts never modify host sysctls.

Default isolated ports:

| Component | Port |
| --- | ---: |
| BSC-mode Anvil | `18545` |
| coordinator | `2337` |
| realm 0 / realm 1 | `23380` / `23390` |
| prove-proxy / faucet | `19999` / `19998` |
| psy-services | `13000` |
| Envio/Hasura | `28080` |
| Redis / NATS / Scylla | `16379` / `14222` / `19042` |
| Nostr / psy-services Postgres | `18081` / `25432` |
