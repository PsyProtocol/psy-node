# Local Staging Cloudflare Tunnel

This directory exposes `deploy/local-testnet/stack` through a Cloudflare named tunnel
so other people can test a local Parth/Psy stack from their browsers.

It does not replace `deploy/local-testnet/stack`. It only:

- renders a `cloudflared` ingress config,
- starts local Anvil, deploys localhost L1 contracts, and starts the bridge relayer,
- renders a tunnel-specific `client_prover/config.json`,
- temporarily applies that config while building frontends,
- restores the repo config immediately after the build.

The scripts load `deploy/local-testnet/stack/local.env` first, then
`deploy/local-testnet/cloudflare-tunnel/local.env`, so tunnel-specific settings can
override local staging defaults.

## One-Time Setup

```bash
cd /path/to/psy-node-deploy-unified
cp deploy/local-testnet/cloudflare-tunnel/local.env.example deploy/local-testnet/cloudflare-tunnel/local.env
```

Edit `deploy/local-testnet/cloudflare-tunnel/local.env` and set hostnames under a
Cloudflare zone you control.

Create and route the named tunnel:

```bash
cloudflared tunnel login
cloudflared tunnel create psy-local-staging
bash deploy/local-testnet/cloudflare-tunnel/route-dns.sh
```

If `cloudflared` is not on `PATH`, the scripts download the Linux binary into
`.local-staging/bin/cloudflared` before using it.

If your `cloudflared` requires an explicit credentials file, set
`LOCAL_CF_TUNNEL_ID` and `LOCAL_CF_TUNNEL_CREDENTIALS_FILE` in `local.env`.

## Start Local Staging For Shared Testing

```bash
cd /path/to/psy-node-deploy-unified
bash deploy/local-testnet/cloudflare-tunnel/up.sh
```

Share the app URL printed by the script, for example:

```text
https://app-local.psy-protocol.xyz
```

The app will call the other tunnel hosts instead of `127.0.0.1`, so coworkers'
browsers can reach the coordinator, realms, stateless prove-proxy, standalone
Psy faucet, and psy-services. The split endpoints are:

```text
https://prove-local.psy-protocol.xyz   proof RPC only
https://faucet-local.psy-protocol.xyz  Psy faucet RPC only
```

The prove endpoint must return JSON-RPC `-32601` for faucet methods. Faucet
operator and Turnstile secrets are only passed to the standalone faucet process.
The stack also runs an isolated Nostr relay for private-transfer delivery and
deposit recovery; shared browsers reach it through the same named tunnel.
The script also starts the local bridge relayer, so ETH -> Psy deposits can
move past L1 confirmations into the Psy deposit tree.
It waits until the relayer leaves catchup mode. To resume only that readiness
check without rebuilding or restarting anything, run:

```bash
bash deploy/local-testnet/cloudflare-tunnel/wait-relayer-ready.sh
```

By default, `up.sh` also starts `cloudflared` in the background and records its
PID under `.local-staging/pids/cloudflared.pid`. Set `LOCAL_CF_START_TUNNEL=0`
only if you intentionally want to run `run-tunnel.sh` yourself.
After changing only tunnel ingress, reload cloudflared without evaluating or
restarting local chain and backend services:

```bash
bash deploy/local-testnet/cloudflare-tunnel/reload-tunnel.sh
```

Before deploying localhost L1 contracts, it exports the Groth16 Solidity
verifier sources from the same local setup used by the relayer. The bridge,
deposit, and withdrawal setups use `~/.psy/keystore`,
`~/.psy/keystore/deposit_append`, and
`~/.psy/keystore/withdrawal_claim` by default. A reset regenerates all three
with `psy_relayer_cli regenerate-groth16-keystore` when the relevant circuit
source hash changed or no matching setup stamp exists.
This keeps Anvil's
`ZKVerifier`, `DepositBatchVerifier`, and
`WithdrawalClaimVerifier` aligned with runtime proving; otherwise relayer
proofs can be generated successfully but rejected on L1 with `InvalidProof()`.
When only the withdrawal circuit fingerprint changes, the deploy script keeps
the existing Bridge and StateManager state, deploys the new verifier, and
rotates it through `Bridge.setWithdrawalClaimVerifier`. Bridge or deposit
verifier changes still require a full local L1 redeploy.
For Localhost gas, send coworkers the ETH faucet URL:

```text
https://app-local.psy-protocol.xyz/eth-faucet
```

They can paste their MetaMask account there to top it up with local Anvil ETH.
`https://eth-faucet-local.psy-protocol.xyz` is also supported when its DNS has
propagated, but the `/eth-faucet` path on `app-local` is the preferred shared
URL because it reuses the existing app hostname.

## Check Tunnel Health

```bash
bash deploy/local-testnet/cloudflare-tunnel/status.sh
```

## Frontend-Only Auto Deploy

The auto deploy runner keeps deployment tools in the live deployment checkout
and creates separate clean source checkouts for Parth, Psy Wallet, and Psy SDK.
It only updates static frontends and wallet assets. It does not rebuild or
restart coordinator, realms, psy-services, prove-proxy, relayer, Anvil, Envio,
or any other backend process.

The loop polls the configured product source branches every two minutes by default. If
multiple commits land between polls, only the latest fetched commit is built.
Branch movement must be fast-forward; if the remote branch is force-pushed or
reset, the script stops and keeps the currently published frontend release.
Git LFS filters are disabled for these source checkouts. The frontend build
does not consume `genesis_contracts.json`; Groth16 keystore assets are managed
separately through the S3 keystore manifest.

Before a build starts, the runner compares the tracked branch's canonical
genesis ABI set with the immutable ABI snapshot promoted after the last
successful backend deployment. An ABI
change is treated as a backend update, so the runner records
`waiting backend-update` and keeps the current frontend until the backend is
updated manually. This avoids publishing a frontend that cannot call the
currently deployed contracts.

Install the two-minute user timer:

```bash
bash deploy/local-testnet/cloudflare-tunnel/install-frontend-autodeploy-user-service.sh
```

Inspect the timer, source commits, last attempt, last success, and active
release:

```bash
bash deploy/local-testnet/cloudflare-tunnel/status-frontend-autodeploy.sh
```

Useful configuration in `deploy/local-testnet/cloudflare-tunnel/local.env`:

```bash
LOCAL_CF_AUTODEPLOY_REMOTE="origin"
LOCAL_CF_AUTODEPLOY_BRANCH="mainnet-beta"
LOCAL_CF_AUTODEPLOY_WALLET_BRANCH="feat/improve-bridge-relayer"
LOCAL_CF_AUTODEPLOY_SDK_BRANCH="feat/improve-bridge-relayer"
LOCAL_CF_AUTODEPLOY_INTERVAL_SECONDS="120"
LOCAL_CF_AUTODEPLOY_ALLOW_DIRTY="0"
LOCAL_CF_AUTODEPLOY_BOOTSTRAP_OBSERVE_ONLY="1"
LOCAL_CF_AUTODEPLOY_REQUIRE_ABI_MATCH="1"
LOCAL_CF_SDK_BUILD_ATTEMPTS="2"
LOCAL_CF_FRONTEND_RELEASE_KEEP="5"
```

The source checkouts must stay clean. The first successful poll records the
current remote source tuple without replacing the already-tested frontend.
Only a later branch movement triggers an automatic build. This prevents
enabling the timer from accidentally downgrading an existing local release.
`LOCAL_CF_AUTODEPLOY_ALLOW_DIRTY=1` exists only for isolated smoke tests.

For one-shot testing without the polling loop:

```bash
LOCAL_CF_AUTODEPLOY_ONCE=1 bash deploy/local-testnet/cloudflare-tunnel/autodeploy-frontends.sh
```

Set `LOCAL_CF_AUTODEPLOY_FORCE=1` with one-shot mode only when intentionally
rebuilding the same source tuple. A failed tuple is retried after 30 minutes by
default, rather than consuming build resources every two minutes.

Each build writes a release under:

```text
.local-staging/nginx/html/.releases/frontends/<source-tuple-id>/
```

After validation, one `current` symlink switches app, explorer, IDE, and
downloads together. If endpoint smoke checks fail, the previous release and
wallet metadata are restored:

```text
.local-staging/nginx/html/.releases/frontends/current
```

Wallet packages are built from `PSY_WALLET_DIR` and published to R2 before the
frontend release is switched. The app reads a fixed metadata URL:

```text
https://wallet-assets-stg.psy-protocol.xyz/local-devnet/wallet-release.json
```

Typical wallet/R2 config:

```bash
PSY_WALLET_DIR="$WORKSPACE_HOME/psy-wallet"
CF_ENV_FILE="$WORKSPACE_HOME/cf_env"
LOCAL_CF_WALLET_RELEASE_URL="https://wallet-assets-stg.psy-protocol.xyz/local-devnet/wallet-release.json"
LOCAL_CF_WALLET_R2_METADATA_KEY="local-devnet/wallet-release.json"
LOCAL_CF_WALLET_PACKAGE_MODE="dev"
LOCAL_CF_WALLET_BUILD_COMMAND="pnpm build:dev"
```

If you need to test the static frontend release flow without uploading wallet
assets, set:

```bash
LOCAL_CF_AUTODEPLOY_BUILD_WALLET=0
```

## Default Host Mapping

```text
app-local.psy-protocol.xyz         -> 127.0.0.1:8088
explorer-local.psy-protocol.xyz    -> 127.0.0.1:8089
ide-local.psy-protocol.xyz         -> 127.0.0.1:8090
coordinator-local.psy-protocol.xyz -> 127.0.0.1:1337
realm0-local.psy-protocol.xyz      -> 127.0.0.1:13380
realm1-local.psy-protocol.xyz      -> 127.0.0.1:13390
prove-local.psy-protocol.xyz       -> 127.0.0.1:9999
services-local.psy-protocol.xyz    -> 127.0.0.1:3000
indexer-local.psy-protocol.xyz     -> 127.0.0.1:8080
rpc-local.psy-protocol.xyz         -> 127.0.0.1:8545
eth-faucet-local.psy-protocol.xyz  -> 127.0.0.1:8555
nostr-local.psy-protocol.xyz       -> 127.0.0.1:8081 (WebSocket)
```

The tunnel build rewrites the frontend's localhost Nostr relay to
`LOCAL_CF_NOSTR_RELAY_URL` (default `wss://nostr-local.psy-protocol.xyz/`).
`psy-services` subscribes to the same local relay through
`ws://127.0.0.1:8081` so kind-1059 private notes are indexed locally.

Use a private Cloudflare zone or a temporary subdomain. These endpoints expose a
developer testnet and should not be treated as production infrastructure.
