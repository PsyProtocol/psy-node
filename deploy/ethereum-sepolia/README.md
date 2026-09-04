# Ethereum Sepolia Deployment Profile

This directory is the canonical Ethereum Sepolia deployment profile. It owns
the Sepolia configuration, source-version manifest, preflight, and deployment
entrypoint while reusing the shared implementation under `deploy/gcp/`.

Prepare an isolated configuration:

```bash
cp deploy/ethereum-sepolia/gcp/config.example.env \
  deploy/ethereum-sepolia/gcp/config.env
```

Validate without changing infrastructure:

```bash
bash deploy/ethereum-sepolia/gcp/prepare-sources.sh
DRY_RUN=1 bash deploy/ethereum-sepolia/gcp/deploy_all.sh
```

Run a reviewed fresh deployment:

```bash
CONFIRM_FULL_FRESH_DEPLOY=1 \
  bash deploy/ethereum-sepolia/gcp/deploy_all.sh
```

Never reuse the BSC `config.env` or source-version manifest for this profile.
The two profiles may share machines, but their L1 RPC, chain ID, contracts,
Envio cursor, wallet build, and canonical Genesis inputs are independent.
