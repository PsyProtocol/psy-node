# Local Testnet Deployment

This directory owns the local Psy testnet deployment.

For the machine-specific deployment layout, current health snapshot, operating
commands, frontend auto-deploy state, and handoff rules, read
[`HANDOFF.md`](HANDOFF.md) first.

For the canonical two-part CLI transaction and Playwright browser acceptance
flow, including copy-paste commands and the agent handoff contract, read
[`TESTING.md`](TESTING.md).

- `stack/`: local Docker dependencies, coordinator, realms, workers,
  psy-services, indexers, prove-proxy, faucet, nginx, and frontend publishing.
- `cloudflare-tunnel/`: local Anvil, L1 contracts, Envio, bridge relayer,
  public Cloudflare routes, wallet R2 publishing, and atomic frontend releases.
- `relayer/`: standalone local relayer and Groth16 setup helpers.

For the complete externally reachable environment, use:

```bash
LOCAL_STAGING_BUILD=1 LOCAL_STAGING_RESET=1 \
  bash deploy/local-testnet/cloudflare-tunnel/up.sh
```

Do not run the stack and Cloudflare entrypoints from different Parth checkouts.
Their PID files, generated configs, and frontend release paths are checkout
local.

## Prove-proxy roles (user / system pools)

`psy_user_cli prove-proxy --role user|system|all` decides which proof family a
process registers: `user` serves wallets (UPS session chain, contract calls,
signatures, minifiers), `system` serves the bridge relayer (the three Groth16
methods), `all` serves both. Methods outside the role are not registered and
answer JSON-RPC `-32601`. Every role answers `psy_get_prove_proxy_role`.

The relayer reads `system_prove_proxy_url` from its rendered config and refuses
to start when the key is missing or the pool behind it does not serve system
proofs. `cloudflare-tunnel/up.sh` writes that key for the relayer; the public
`prove-local` host stays the wallet-facing pool.

Defaults keep the old single-process layout: `LOCAL_STAGING_PROVE_PROXY_ROLE="all"`.
To exercise the split locally, run the wallet pool as `user` and add a second
process as `system`:

```bash
LOCAL_STAGING_PROVE_PROXY_ROLE=user \
LOCAL_STAGING_START_SYSTEM_PROVE_PROXY=1 \
LOCAL_STAGING_SYSTEM_PROVE_PROXY_ADDR=127.0.0.1:9997 \
bash deploy/local-testnet/cloudflare-tunnel/up.sh
```

`stack/status.sh` then reports both processes with their roles and checks that
each pool rejects the other family. Budget ~3.5 minutes and ~22 GiB RSS for the
system process (coordinator circuit library plus three Groth16 keystores); the
user process is ready in under half a minute at ~5 GiB.

To test a runtime checkout other than this tree (for example the
`feat/prove-proxy-role-split` worktree), point the tunnel layer at it and build:

```bash
LOCAL_CF_SOURCE_PARTH_DIR=/path/to/psy-node-prove-proxy-role \
LOCAL_STAGING_BUILD=1 \
LOCAL_STAGING_GENESIS_PATH=/path/to/genesis.json \
LOCAL_STAGING_PRIVATE_KEYS_PATH=/path/to/private_keys.json \
bash deploy/local-testnet/cloudflare-tunnel/up.sh
```

`genesis.json` and `private_keys.json` are untracked generated files; a fresh
worktree does not have them, hence the two overrides.
