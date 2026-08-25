# Local BSC Testnet Preparation

This directory starts an isolated local EVM with BSC Testnet's chain ID and
deploys the complete Psy L1 contract set to it. It is phase 2 of
[`PLAN.md`](PLAN.md), not a public BSC deployment.

The defaults use `127.0.0.1:18545` and `.local-bsc-testnet/`, so they do not
touch the regular local testnet on port `8545` or any GCP staging service.

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
