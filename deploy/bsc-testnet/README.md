# BSC Testnet Deployment Profile

This directory owns all BSC Testnet-specific deployment configuration.

- `gcp/`: public GCP configuration, source pins, preflight, wallet publication,
  and full deployment entrypoint.
- The scripts in this directory: isolated local BSC contract and backend
  validation.

For the cloud profile, start with [`gcp/README.md`](gcp/README.md).

## Current ownership and frontend sources

These historical single-chain scripts already belong to the node deployment
branch (`deploy/multi-chain-gcp`); they do not live in the DApp product
worktree. Current three-chain deployments use
[`../multi-chain/gcp/README.md`](../multi-chain/gcp/README.md) for GCP and
[`../local-multichain/README.md`](../local-multichain/README.md) for local
testing. Do not copy old single-chain frontend defaults over those profiles.

The local BSC profile no longer requires a dedicated sibling DApp worktree.
It resolves the frontend source in this order:

1. `BSC_PSY_DAPP_DIR`, including an explicit override in `full-stack.env`.
2. The shared `PSY_DAPP_DIR` override.
3. This deployment checkout's `psy-dapp` submodule (`$PARTH_ROOT/psy-dapp`).

Existing ignored `full-stack.env` files are not rewritten. Before reusing
one, remove its retired frontend path or set `BSC_PSY_DAPP_DIR` to an
available, compatible checkout. Do not regenerate Genesis, replace a gitlink,
or change a deployed network to tidy a source path.

This is a source-path migration, not a claim that the current multichain DApp
supports every legacy `bsc-testnet` config schema. Frontend publication remains
disabled by default in this historical profile. For historical frontend
reproduction, explicitly select a matching DApp revision; use the current
multichain profiles for normal frontend work.

The retired DApp branches remain on `PsyProtocol/psy-dapp`:

- `feat/add-zalalena-bsc-faucet` at
  `745d85920789a43ce1297e22a80df573d3819d35`.
- `feat/bsc-testnet-network-support` at
  `bf09fa7604922c3adf9293d54755443d547497e8`.

The local cleanup archive also preserves their Git histories and worktree
files. No part of the cleanup merges their old frontend code into product.

Run the source-path regression tests without Docker, network requests, or
starting any services:

```bash
node --test deploy/bsc-testnet/test-source-paths.mjs
```

## Local Preparation

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
