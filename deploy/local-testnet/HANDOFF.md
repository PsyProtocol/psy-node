# Local Testnet Handoff

Read this document first when starting a new session on the local Psy testnet.
It records the deployment layout, operating rules, and a dated status snapshot.
The snapshot can become stale, so run the checks in [Verify Current State](#verify-current-state)
before claiming that the environment is healthy.

## Current Status Snapshot

Last checked: **2026-07-23 08:36 +08**

Overall status: **healthy after a clean full deployment and transaction E2E**.

- All 20 managed local processes were alive.
- Coordinator, realm 0, and realm 1 were synchronized and advanced from
  checkpoint `3896` to `3897` during the E2E preflight.
- The relayer was ready at finalized checkpoint `3889`, with latest checkpoint
  `3896` and confirmed backlog `6`.
- All local HTTP endpoints and all Cloudflare routes passed, including the
  dedicated faucet endpoint and Nostr relay.
- Frontend auto deploy is active on a `120` second timer. It built and published
  the latest ABI-compatible frontend source without touching backend services.

The deployed source revisions are:

```text
Parth backend source: 9e31953ada68520ceb49d4faf8936a0e1f117fc8
Parth deploy merge:   138ed2ab604f2cb9f208cfac41deffe16b4c625e
Parth frontend source: a9db930cbe48e74c8895e94885d82c34d6211195
Psy services:         5e3848d002e41eb13cd4d8e71e2bf1e7f4a96e11
Psy Wallet:           66c54b7de8586ba1df41f8c4bbb91e5b7b3242aa
Psy SDK:              8a3f770c55313123daf6ac1a9708cd21ce018a88
Psy compiler:         e6354ca55f08aced300245b9f8a0dca20fb6ba8b
L1 deployment hash:   041b88668ea7ba0c3089c48ab44b223c0cc875e797bd9418e9cf8df503b9ac47
Frontend release:     pa9db930cbe48-w66c54b7de858-s8a3f770c5531-d041b88668ea7
```

The immutable backend ABI snapshot is:

```text
.local-staging/backend-abi/releases/138ed2ab604f-20260722T171924Z
```

The wallet package is version `0.4.21`, with SHA-256
`8cdfad443fdf8cd4feedba72aaf0c4fdf8cb75f699643a6be47d14911b213e44`.
Its immutable R2 metadata is available at:

```text
https://wallet-assets-stg.psy-protocol.xyz/local-devnet/releases/138ed2ab604f-041b88668ea7/wallet-release.json
```

The full E2E run produced the following evidence:

```text
Fresh faucet user:       1638400
Faucet tx:               70d49d162eea962cfac9bf21225be2fdd1712e749b1c2848e3ddbfe26a3095d1
Faucet claimable:        1000000000000
Bridge test user:        327680
Deposit L1 tx:           0xfa9bb43d5eb53f932461bb89d803f8fee708cf9efdab5f88191646928c203fa1
Deposit index/counts:    0, pending=1, proved=1
Deposit claim event:     8:3950:0:1
Withdrawal nonce:        0xaea948c47f28b7d438313b4da4e9b639d3d7b54f5f16ca790cba62245b026802
Withdrawal event:        9:3954:0:2
Withdrawal batch L1 tx:  0x34ccb98664968605584da54826619345343158b5b0f31d56a930f60220c2dc76
L1 USDT balance change:  999999999000000 -> 999999999250000
```

## Canonical Paths And Branches

The live deployment root on this machine is:

```text
${WORKSPACE_HOME}/psy-node-deploy-unified
```

Its deployment branch is:

```text
deploy-unified
```

Related repositories are siblings of the live Parth checkout:

```text
../psy-services
../psy-wallet
../psy-sdk
```

These manual/backend worktrees can contain intentional local changes. Inspect
`git status` before editing and never reset, clean, or discard them as part of a
status check.

Frontend automation does not build from those manual worktrees. It owns clean,
dedicated source checkouts here:

```text
${WORKSPACE_HOME}/frontend-autodeploy/psy-node
${WORKSPACE_HOME}/frontend-autodeploy/psy-wallet
${WORKSPACE_HOME}/frontend-autodeploy/psy-sdk
```

The psy-node checkout tracks `mainnet-beta`; wallet and SDK retain their
configured release branches. Do not use these checkouts for manual development
or commits.

## Deployment Ownership

- `deploy/local-testnet/stack/` owns Docker dependencies, coordinator, realms,
  workers, psy-services, indexers, prove-proxy, faucet-server, nginx, and basic
  frontend publication.
- `deploy/local-testnet/cloudflare-tunnel/` owns local Anvil, localhost L1
  contracts, Envio, bridge relayer, Cloudflare routes, wallet R2 publication,
  atomic frontend releases, and frontend-only auto deploy.
- `deploy/local-testnet/relayer/` contains standalone relayer and Groth16 setup
  helpers. The complete shared environment should normally use the Cloudflare
  entrypoint instead.

Do not run stack and Cloudflare entrypoints from different Parth checkouts.
PID files, generated configs, chain state, and frontend releases are checkout
local.

## Service Map

| Component | Local endpoint | Shared endpoint |
| --- | --- | --- |
| App | `http://127.0.0.1:8088` | `https://app-local.psy-protocol.xyz` |
| Explorer | `http://127.0.0.1:8089` | `https://explorer-local.psy-protocol.xyz` |
| IDE | `http://127.0.0.1:8090` | `https://ide-local.psy-protocol.xyz` |
| Coordinator | `http://127.0.0.1:1337` | `https://coordinator-local.psy-protocol.xyz` |
| Realm 0 | `http://127.0.0.1:13380` | `https://realm0-local.psy-protocol.xyz` |
| Realm 1 | `http://127.0.0.1:13390` | `https://realm1-local.psy-protocol.xyz` |
| Prove proxy | `http://127.0.0.1:9999` | `https://prove-local.psy-protocol.xyz` |
| Faucet server | `http://127.0.0.1:9998` | `https://faucet-local.psy-protocol.xyz` |
| Psy services | `http://127.0.0.1:3000` | `https://services-local.psy-protocol.xyz` |
| Envio/indexer | `http://127.0.0.1:18080` | `https://indexer-local.psy-protocol.xyz` |
| Anvil RPC | `http://127.0.0.1:8545` | `https://rpc-local.psy-protocol.xyz` |
| ETH faucet | `http://127.0.0.1:8555` | `https://app-local.psy-protocol.xyz/eth-faucet` |
| Nostr relay | `ws://127.0.0.1:18081` | `wss://nostr-local.psy-protocol.xyz/` |

The local L1 chain ID is `31338`.

## Start, Stop, And Restart

Run commands from the live deployment root.

Start or reconcile the complete externally reachable environment without a
state reset:

```bash
bash deploy/local-testnet/cloudflare-tunnel/up.sh
```

Build backend binaries explicitly only when a manual backend update is intended:

```bash
LOCAL_STAGING_BUILD=1 bash deploy/local-testnet/cloudflare-tunnel/up.sh
```

A full reset destroys the current local-chain identity and invalidates existing
wallet registrations and pending bridge receipts. Use it only when explicitly
requested:

```bash
LOCAL_STAGING_BUILD=1 LOCAL_STAGING_RESET=1 \
  bash deploy/local-testnet/cloudflare-tunnel/up.sh
```

Stop all managed processes and Docker services while retaining volumes:

```bash
bash deploy/local-testnet/stack/down.sh
```

Remove volumes only for an explicitly requested clean deployment:

```bash
bash deploy/local-testnet/stack/down.sh --volumes
```

## Verify Current State

Use the `parth-local-testnet-status` skill in quick mode, passing this deployment
root explicitly:

```text
${WORKSPACE_HOME}/psy-node-deploy-unified
```

Use the same skill in E2E mode only when state-changing faucet, deposit, and
withdrawal verification is requested.

Useful focused checks:

```bash
bash deploy/local-testnet/stack/status.sh
bash deploy/local-testnet/cloudflare-tunnel/status.sh
bash deploy/local-testnet/cloudflare-tunnel/status-frontend-autodeploy.sh
```

Do not report faucet/deposit/withdraw as passing based only on the quick health
check. The quick check proves process, endpoint, checkpoint, relayer, and tunnel
health, not transaction execution.

For a complete acceptance run, execute both the CLI transaction E2E and the
Playwright frontend E2E described in [`TESTING.md`](TESTING.md). The reusable
copy-paste prompt for another agent is
[`e2e/local-testnet/AGENT_PROMPT.md`](../../e2e/local-testnet/AGENT_PROMPT.md).

## Frontend-Only Auto Deploy

The user-level systemd timer is:

```text
parth-local-frontend-autodeploy.timer
```

It polls Parth, Psy Wallet, and Psy SDK every `120` seconds. A source tuple is the
three source commits plus the live `deployed-contracts.json` and backend ABI
hashes. Git LFS filters are disabled in the polling checkouts. It builds only
SDK WASM, Wallet, app, explorer, and IDE. It must not build or restart coordinator,
realms, workers, psy-services, prove-proxy, faucet-server, relayer, Anvil, Envio,
Nostr, or Docker dependencies.

The first poll is observe-only. Later updates must be fast-forward. Failed source
tuples retain the current release and cool down for `1800` seconds before retry.
Static files switch through one `current` symlink. Wallet zip and immutable
metadata are staged in R2 before the fixed metadata key and local release are
promoted. Smoke failure rolls both back.

An ABI mismatch is not retried as a failed frontend build. It is recorded in
`last-blocked.json` and reported as `waiting backend-update`; the current release
remains active until a manual backend deployment brings the live ABI in sync.
Groth16 setup files remain outside Git and are sourced from
`https://psy-protocol-devnet.s3.ap-southeast-1.amazonaws.com/assets/keystore`.

Install or reconcile the timer:

```bash
bash deploy/local-testnet/cloudflare-tunnel/install-frontend-autodeploy-user-service.sh
```

Inspect it:

```bash
bash deploy/local-testnet/cloudflare-tunnel/status-frontend-autodeploy.sh
```

Run one intentional retry of the current tuple:

```bash
LOCAL_CF_AUTODEPLOY_ONCE=1 LOCAL_CF_AUTODEPLOY_FORCE=1 \
  bash deploy/local-testnet/cloudflare-tunnel/autodeploy-frontends.sh
```

Do not use frontend automation to update backend services.

## State, Logs, And Configuration

Runtime state and logs:

```text
.local-staging/
.local-staging/logs/
.local-staging/pids/
.local-staging/bridge-relayer/
.local-staging-cf-tunnel/
.local-staging-cf-tunnel/autodeploy/
```

Important generated or local-only files:

```text
psy-contracts/deployments/localhost/deployed-contracts.json
deploy/local-testnet/stack/local.env
deploy/local-testnet/cloudflare-tunnel/local.env
${WORKSPACE_HOME}/cf_env
```

The two `local.env` files and `cf_env` are local configuration/credential inputs.
Never commit or print their secret values. The active deployed-contracts file had
SHA-256 `041b88668ea7ba0c3089c48ab44b223c0cc875e797bd9418e9cf8df503b9ac47`
at the snapshot time.

Common logs:

```bash
tail -f .local-staging/logs/*.log
journalctl --user -u parth-local-frontend-autodeploy.service -n 200 --no-pager
tail -100 .local-staging-cf-tunnel/autodeploy/last-error.log
```

## After A Machine Reboot

1. Run the quick health check first.
2. If the stack is down, run `cloudflare-tunnel/up.sh` without reset.
3. Re-run the quick health check and confirm checkpoints advance.
4. Confirm `parth-local-frontend-autodeploy.timer` is active.
5. Run full E2E only when requested or after backend, ABI, prover, relayer, or L1
   contract changes.
6. Update the dated snapshot in this document after a material deployment change.

## Handoff Rules

- Read this file and current `git status` before changing anything.
- Preserve unrelated local modifications in every repository.
- Prefer deployment scripts over ad hoc `tmux` commands or manual database edits.
- Do not backfill, reset databases, reset Anvil, or redeploy contracts to hide a
  failed test.
- Keep deployment-only changes on the deployment branch and runtime fixes on a
  branch targeting `mainnet-beta`.
- Record exact transaction hashes, user IDs, checkpoints, and source SHAs when
  diagnosing faucet or bridge failures.
