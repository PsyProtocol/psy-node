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
