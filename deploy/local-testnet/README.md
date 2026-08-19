# Local Testnet Deployment

This directory owns the local Psy testnet deployment.

For the machine-specific deployment layout, current health snapshot, operating
commands, frontend auto-deploy state, and handoff rules, read
[`HANDOFF.md`](HANDOFF.md) first.

- `stack/`: local Docker dependencies, coordinator, realms, workers,
  psy-services, indexers, prove-proxy, faucet, nginx, and frontend publishing.
- `cloudflare-tunnel/`: local Anvil, L1 contracts, Envio, bridge relayer,
  public Cloudflare routes, wallet R2 publishing, and atomic frontend releases.
- `relayer/`: standalone local relayer and Groth16 setup helpers.

## One-Command Deployment

For a non-sibling repository layout, copy `local.env.example` to `local.env`
and set the four repository paths. This machine-specific file, along with the
stack and Cloudflare `local.env` files, is ignored by Git.

For the complete externally reachable environment, use the top-level
orchestrator:

```bash
bash deploy/local-testnet/deploy-all.sh
```

It performs preflight checks, rebuilds the code, starts the complete stack,
Anvil and L1 contracts, Envio, bridge relayer, frontends and Cloudflare Tunnel,
enables the two-minute frontend auto-deploy timer, runs final local and public
health checks, and then exits. Long-running services remain in the background.
Preflight enforces the repository commits in `deploy/source-versions.env` and
verifies `genesis_contracts.json`, `genesis.json`, and `private_keys.json`
against their pinned SHA-256 values. The latter two are the exact ignored
artifacts used by the GCP testnet, so local deployment cannot silently create a
network with different genesis identities.

On a clean machine, keep the GCP genesis and matching private keys outside Git
and configure their private seed paths:

```bash
LOCAL_STAGING_GENESIS_DATA_SEED="/secure/path/genesis.json"
LOCAL_STAGING_PRIVATE_KEYS_SEED="/secure/path/private_keys.json"
```

The orchestrator copies a missing artifact atomically only after its hash
matches `deploy/source-versions.env`.

The default preserves the existing chain and database state. For a destructive
clean deployment:

```bash
bash deploy/local-testnet/deploy-all.sh --fresh
```

For a fast restart using existing binaries and frontend artifacts:

```bash
bash deploy/local-testnet/deploy-all.sh --no-build
```

Stop the complete environment while preserving state:

```bash
bash deploy/local-testnet/stop-all.sh
```

Pass `--volumes` to `stop-all.sh` only when the local chain and database state
must be deleted.

Do not run the stack and Cloudflare entrypoints from different Parth checkouts.
Their PID files, generated configs, and frontend release paths are checkout
local.
