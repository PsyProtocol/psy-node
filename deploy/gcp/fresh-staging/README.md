# Fresh GCP Staging Deployment

This directory is the shared deployment engine. Use one of the network-owned
entrypoints instead of invoking it directly:

- `deploy/ethereum-sepolia/gcp/deploy_all.sh`
- `deploy/bsc-testnet/gcp/deploy_all.sh`

Each entrypoint loads an independent configuration and source manifest, then
prepares the three network-sensitive submodules before calling this engine.
The compatibility defaults below resolve to Ethereum Sepolia only.

To run the full fresh deployment through Cloudflare Pages:

```sh
cd "$WORKSPACE_HOME/psy-node-deploy-unified"
CONFIRM_FULL_FRESH_DEPLOY=1 bash deploy/gcp/fresh-staging/deploy_all.sh
```

`WORKSPACE_HOME` defaults to the parent directory of the deployment checkout
and can be overridden in `deploy/gcp/config.env`.

Before the destructive run, review the selected profile's
`gcp/source-versions.env`. It is the authoritative list of repositories,
commits, and the verified Genesis contract artifact checksum for that network.
`deploy/gcp/config.env` contains only environment topology, credentials, and
runtime tuning. Genesis contracts, ABI files, and the client config come from
the pinned `psy-genesis` submodule.

Step `04` rejects dirty source trees, repository/commit/submodule mismatches,
and an unexpected canonical artifact checksum.
It records all backend source commits plus Genesis hashes in
`BUILD-MANIFEST.env` inside the node bundle. Frontend steps also reject
unexpected or dirty wallet/SDK checkouts. Use `PSY_SERVICES_DIR`,
`PSY_WALLET_DIR`, and `PSY_SDK_DIR` for dedicated clean checkouts;
`ALLOW_DIRTY_DEPLOY_SOURCES=1` is for deliberate debugging only.
Initialize `psy-genesis`, `psy-contracts`, and `psy-dapp` recursively before a
build. Upstream configures `psy-dapp` with `update = none`, so use:

```sh
git -c submodule.psy-dapp.update=checkout submodule update --init --recursive \
  psy-genesis psy-contracts psy-dapp
```

Contract bytecode is never regenerated during deployment.

Validate the full ordered plan without changing local or remote state:

```sh
DRY_RUN=1 bash deploy/gcp/fresh-staging/deploy_all.sh
```

This still runs preflight, so source, credential, domain, and configuration
errors are found before the real deployment.

The runner stops on the first failed step. Steps `01` to `03` are destructive,
so the runner requires `CONFIRM_FULL_FRESH_DEPLOY=1` before clearing staging
state. Step `15` uploads the local bridge Groth16 trust setup before relayer
startup. The deploy-all entrypoint publishes the public trust setup archive as
`29`, runs frontend/config pages together as `21`, `26`, `28`, and `27`, then
runs step `23` as the optional simple-mint smoke test. Step `23` is disabled by
default to preserve L1/L2 supply parity; set `SMOKE_SIMPLE_MINT_ENABLED=1` to
mint `100` PSY to the relayer genesis user and verify the result.

## Post-deploy TODO: staged fresh deployment

Do not change the step order during the current fresh deployment. After this
deployment is complete, split future fresh deployments into two explicit
phases so compilation and distribution do not extend the service outage.

Phase A must run while the existing staging network is still online:

1. Resolve and verify every pinned source checkout.
2. Validate canonical Genesis contracts and ABI files, then generate Genesis
   state, private keys, frontend configuration, and Groth16 setup artifacts.
3. Build every Rust binary and frontend bundle required by the deployment.
4. Package immutable, checksummed release archives and a build manifest.
5. Upload the artifacts to versioned staging directories on every destination
   host without changing the active release.
6. Run remote preflight checks for disk space, permissions, checksums,
   configuration, executable compatibility, and required secrets.

Phase B is the measured maintenance window:

1. Acquire a deployment lock and record the outage start time.
2. Stop affected services and capture the final state needed for diagnosis.
3. Clear or initialize state required by a full fresh network.
4. Atomically activate the pre-staged releases; do not compile or perform large
   uploads after services have stopped.
5. Initialize databases and L1 contracts, then start services in dependency
   order.
6. Run health checks and transaction smoke tests before recording the outage
   end time.

Acceptance criteria:

- All CPU-heavy compilation, frontend builds, artifact generation, and large
  transfers finish before the maintenance window.
- Every staged artifact is immutable and verified against the build manifest.
- The previous software release remains available until the new services pass
  health checks.
- Deployment logs report preparation duration separately from actual outage.
- Activation failures can restore the previous software release where state is
  compatible. A full fresh deployment still replaces L2/database/L1 state, so
  software rollback alone cannot restore the previous chain.

```sh
CONFIRM_FULL_FRESH_DEPLOY=1 bash deploy/gcp/fresh-staging/deploy_all.sh
```

To redeploy all node runtimes while keeping the existing Sepolia L1 contracts
and durable L2/Postgres state, use the runtime reset path. This clears transient
Redis/NATS queues and node runtime files, preserves checkpoint backup files, and
then redeploys services through the public entrypoint checks:

```sh
CONFIRM_REDEPLOY_NODES_KEEP_L1=1 \
PARTH_BUNDLE=dist/parth-node-bundle.tar.gz \
  bash deploy/gcp/fresh-staging/deploy_nodes_keep_l1_reset_runtime.sh
```

This path is useful for staging recovery when a transient pending queue item is
bad, but the existing L1 bridge roots/cursors must be preserved.

For a full fresh deploy after circuit or verifier changes, use the sequential
runner and regenerate every public Groth16 setup kind in the same run:

```sh
CONFIRM_FULL_FRESH_DEPLOY=1 \
GROTH16_REGENERATE_SETUP=1 \
GROTH16_REGENERATE_OPTIONAL=1 \
GROTH16_FORCE_REGENERATE=1 \
PUBLISH_PUBLIC_TRUST_SETUP=1 \
PARTH_BUNDLE=dist/parth-node-bundle.tar.gz \
  bash deploy/gcp/fresh-staging/deploy_all.sh
```

Use `GCP_DEPLOY_CONFIG=/path/to/config.env` when deploying from a named config
profile instead of the default `deploy/gcp/config.env`.

The full deployment entrypoint is `deploy_all.sh`; it includes backend,
Cloudflare Pages, public checks, and smoke tests in the required order. The
legacy numeric runner supports backend steps `01` through `23` only. To run a
partial backend range:

```sh
bash deploy/gcp/fresh-staging/run_all.sh 12 17
bash deploy/gcp/fresh-staging/run_all.sh 21 23
```

To preview the commands without executing them:

```sh
DRY_RUN=1 bash deploy/gcp/fresh-staging/run_all.sh
```

Run frontend steps `26`, `27`, and `28` directly when doing a partial frontend
deployment. Do not use the numeric runner as a substitute for a full deploy.

You can still run the scripts from the repository root one by one. For the
deploy-all entrypoint, `23_smoke_test_simple_mint.sh` runs after the
frontend/config deploys even though its file number is lower:

```sh
cd "$WORKSPACE_HOME/psy-node-deploy-unified"
bash deploy/gcp/fresh-staging/01_stop_parth_services.sh
bash deploy/gcp/fresh-staging/02_clear_parth_state.sh
bash deploy/gcp/fresh-staging/03_clear_database_state.sh
bash deploy/gcp/fresh-staging/04_prepare_local_bundle.sh
bash deploy/gcp/fresh-staging/05_deploy_scylla.sh
bash deploy/gcp/fresh-staging/06_deploy_redis.sh
bash deploy/gcp/fresh-staging/07_deploy_nats.sh
bash deploy/gcp/fresh-staging/08_deploy_postgres.sh
bash deploy/gcp/fresh-staging/09_deploy_anvil.sh
bash deploy/gcp/fresh-staging/10_deploy_l1_contracts.sh
bash deploy/gcp/fresh-staging/11_deploy_envio.sh
bash deploy/gcp/fresh-staging/12_deploy_cp_ce_stack.sh
bash deploy/gcp/fresh-staging/13_deploy_prove_proxy.sh
bash deploy/gcp/fresh-staging/14_deploy_workers.sh
bash deploy/gcp/fresh-staging/15_upload_bridge_trust_setup.sh
bash deploy/gcp/fresh-staging/16_deploy_relayer.sh
bash deploy/gcp/fresh-staging/17_deploy_caddy_entrypoints.sh
bash deploy/gcp/fresh-staging/29_publish_public_trust_setup.sh
bash deploy/gcp/fresh-staging/18_check_public_entrypoints.sh
bash deploy/gcp/fresh-staging/21_deploy_cf_privacy_bridge_demo.sh
bash deploy/gcp/fresh-staging/26_deploy_cf_psy_explorer.sh
bash deploy/gcp/fresh-staging/28_deploy_cf_psy_ide.sh
bash deploy/gcp/fresh-staging/27_deploy_cf_staging_config.sh
bash deploy/gcp/fresh-staging/23_smoke_test_simple_mint.sh
```

Optional local coordinator workers for cj/Tyree workstations:

```sh
bash deploy/gcp/fresh-staging/25_deploy_local_coordinator_workers.sh
bash deploy/local-coordinator-workers/start-systemd-user-services.sh
```

Or include the optional local step at the end of a fresh deploy:

```sh
DEPLOY_LOCAL_COORDINATOR_WORKERS=1 START_LOCAL_COORDINATOR_WORKERS=1 \
  CONFIRM_FULL_FRESH_DEPLOY=1 bash deploy/gcp/fresh-staging/deploy_all.sh
```

These local workers are not part of the cloud fresh deploy. They open local SSH
tunnels through `gcp-cp-ce` for Scylla, NATS, and Redis, then run two local
`psy_worker_cli worker` processes against the staging coordinator edge.

`14_deploy_workers.sh` deploys and verifies the cloud worker baseline on
`COORDINATOR_WORKER_VM_NAME` (`gcp-coordinator-worker` by default): one
coordinator worker plus one realm0 and one realm1 worker. The lightweight
relayer/proposer runs on `RELAYER_VM_NAME` (`gcp-faucet` by default), sharing
the VM with the standalone Faucet Server configured by `FAUCET_VM_NAME`.
When `DEPLOY_CLOUD_PROVE_PROXY=1`, step `13` deploys the cloud prove-proxy
before deploying Faucet Server. When it is `0`, step `13` requires explicit
`CLIENT_PROVE_PROXY_URL` and `PUBLIC_PROVE_PROXY_UPSTREAM` values, skips the
retired cloud prove VM, stages the new bundle and Groth16 setup on `arc99x2`,
and applies it before workers or relayer are started. Applying the release uses
an interactive SSH terminal because `arc99x2` may request its sudo password.
The deployment stops rather than continuing with the old Genesis if that
installation fails. It then deploys Faucet Server. To update only Faucet
Server, run:

```sh
bash deploy/gcp/deploy-faucet-server.sh
```

When `DEPLOY_OFFSITE_WORKERS=1`, step `31` runs only after step `23` smoke
testing succeeds. It adds the three `arc99x4` workers as incremental capacity
and leaves every cloud worker active. `OFFSITE_WORKER_REQUIRED=0` keeps an
offsite installation failure from invalidating an otherwise healthy cloud
deployment.

`15_upload_bridge_trust_setup.sh` uploads local setups to the cloud
prove-proxy when `DEPLOY_CLOUD_PROVE_PROXY=1`. With cloud proving disabled, it
stages them on `GROTH16_SETUP_HOST` (`gcp-cp-ce` in staging); the offsite
release flow then copies the same local setup to `arc99x2`. The setup sources
are under
`dist/groth16-keystore/bridge` and
`dist/groth16-keystore/deposit_batch_append`. Before uploading or exporting L1
verifier contracts, the scripts reject setup files older than the relevant
circuit sources. After a bridge/circuit-library change, regenerate the affected
setup before the fresh run with:

```sh
GROTH16_FORCE_REGENERATE=1 bash deploy/gcp/generate-upload-groth16-setup.sh --kind bridge --no-upload
bash deploy/gcp/generate-upload-groth16-setup.sh --kind deposit_batch_append --no-upload
```

To regenerate and upload in one staging step, use:

```sh
GROTH16_REGENERATE_KINDS="bridge" GROTH16_FORCE_REGENERATE=1 \
  bash deploy/gcp/fresh-staging/15_upload_bridge_trust_setup.sh
```

If the latest wrapped proof directory is not the right one, pin it explicitly:

```sh
GROTH16_REGENERATE_KINDS="bridge" GROTH16_FORCE_REGENERATE=1 \
GROTH16_REMOTE_WRAPPED_DIR_BRIDGE="/tmp/plonky2_proof/<hash>" \
  bash deploy/gcp/fresh-staging/15_upload_bridge_trust_setup.sh
```

If the optional withdrawal setup is present, script `15` uploads it too:
`dist/groth16-keystore/withdrawal_claim`.
During a full sequential `deploy_all.sh`, step `10` runs step `15` immediately
before exporting and deploying the L1 verifier contracts, then the later
standalone step `15` is skipped. This keeps the relayer keystore and the L1
verifier pinned to the same Groth16 generation. The fresh staging deployment
uses the sequential path only, so Groth16 setup generation, L1 verifier export,
remote keystore upload, and public trust setup publishing happen in one
auditable order.
With the default staging config, these large setup files are staged once on
`GROTH16_SETUP_CACHE_HOST` (`gcp-cp-ce`). The target host, including relayer and
an enabled cloud prove-proxy, installs or fetches them from that cache over the
private VPC instead of receiving repeated uploads from the local workstation.

`29_publish_public_trust_setup.sh` packages the user-facing setup files from the
current `dist/groth16-keystore` output by first staging them into the public
`$HOME/.psy`-compatible layout. It then uploads
`dist/trust-setup/psy-groth16-trust-setup.tar.gz` and writes the matching
`.sha256` file. With `TRUST_SETUP_DISTRIBUTION_MODE=cache-host`, the archive is
staged once on `TRUST_SETUP_CACHE_HOST` (`gcp-cp-ce`) and the public host pulls
it over the private VPC. It runs after
`17_deploy_caddy_entrypoints.sh` and before `27_deploy_cf_staging_config.sh` so
the public config page includes the current archive URL and checksum.

Fresh staging uses `PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE=1` by default, so a
stale `TRUST_SETUP_SOURCE_PSY_ROOT=$HOME/.psy` in an older local config will not
override the current deploy artifact. Set `PUBLIC_TRUST_SETUP_USE_CURRENT_KEYSTORE=0`
and `TRUST_SETUP_SOURCE_PSY_ROOT=/path/to/source` only when you intentionally
want to publish an explicit prebuilt source directory. Set
`PUBLISH_PUBLIC_TRUST_SETUP=0` only if you intentionally want to skip publishing
the public package.

`04_prepare_local_bundle.sh` uses the canonical
`psy-genesis/genesis_contracts.json`, `psy-genesis/genesis_abi/`, and
`psy-genesis/config.json`. A full fresh deploy verifies the pinned contract
checksum, then regenerates matching `genesis.json` and `private_keys.json`.
Local Rust compilation automatically uses the
smaller of the available logical CPU count and one job per 3 GiB of available
memory. `LOCAL_RUST_BUILD_JOBS` overrides all local Rust stages;
`GENESIS_BUILD_JOBS` and `BOOKWORM_BUILD_JOBS` override individual stages. To
run this step directly:

```sh
REGENERATE_GENESIS=1 bash deploy/gcp/fresh-staging/04_prepare_local_bundle.sh
```

The Caddy deployment keeps both staging backend names (`*-stg`) and release
aliases (`coordinator.psy-protocol.xyz`, `realm0`, `realm1`, `prove`,
`services`, `indexer`, and `nostr`) on the same upstreams. Step `18` checks both
sets. This does not publish a second frontend; frontend Pages projects remain
separate from backend aliases.

The generated genesis wallet layout is:

- key indexes `0`, `1`, and `3`: reserved ZK wallets with `0 PSY`
- key index `2`: bridge relayer L2 wallet with `1,000,000 PSY`
- key indexes `4` through `12`: SDK-key faucet operators with
  `100,000,000 PSY` each
- key index `13`: final SDK-key faucet operator with `99,000,000 PSY`

This makes L2 genesis issue exactly `1,000,000,000 PSY`, matching the L1 PSY
token supply. Step `23` is disabled by default so it does not mint extra PSY;
set `SMOKE_SIMPLE_MINT_ENABLED=1` only when intentionally testing mint
behavior.

Nostr relay data is intentionally not cleared by these scripts.

To use a custom L1 owner/admin/proposer key, export this before script `09`/`10`
and keep it exported until `16_deploy_relayer.sh`, or write it into
`deploy/gcp/config.env`:

```sh
export L1_DEPLOYER_PRIVATE_KEY="<64-hex-private-key>"
```

Script `10` derives the address, funds it on Anvil, patches the remote contract
deploy config, and syncs
`L1_DEPLOYER_ADDRESS` plus contract addresses back into `deploy/gcp/config.env`.

Scripts `21`, `26`, `28`, and `27` are Cloudflare Pages Direct Upload deploys. They read
credentials from `deploy/gcp/config.env`, or from exported environment
variables:

```sh
export CLOUDFLARE_ACCOUNT_ID="..."
export CLOUDFLARE_API_TOKEN="..."
```

They read public endpoints and fresh L1 contract addresses from
`deploy/gcp/config.env`. `21_deploy_cf_privacy_bridge_demo.sh` also packages
`psy-wallet` and serves it from the app `/wallet` route. The Psy faucet defaults
to server-side operator signing on the dedicated `FAUCET_VM_NAME`: set
`PSY_FAUCET_TURNSTILE_SECRET` for Faucet Server and
`PSY_FAUCET_TURNSTILE_SITE_KEY` for the Cloudflare Pages bundle when
`PSY_FAUCET_REQUIRE_TURNSTILE=1`.
`21`, `26`, and `28` build the pinned `psy-dapp` apps at `apps/bridge`,
`apps/explorer`, and `apps/ide`. Set
`PSY_EXPLORER_DIR` only if you intentionally build a different checkout.
`28_deploy_cf_psy_ide.sh` deploys the in-repo Psy IDE frontend.
`27_deploy_cf_staging_config.sh` generates a public config page and
`/config.json` from the same staging config.

Script `23` is disabled by default. When `SMOKE_SIMPLE_MINT_ENABLED=1`, it
mints `100` PSY through the public staging endpoints for the relayer genesis
key in `private_keys.json`, waits for checkpoints to advance, and then verifies
contract `0` state slot `0` via the same merkle-proof value query used by
`client_prover/Makefile`'s `get-slot-value` target.
