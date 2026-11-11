# Fresh Testnet: 192-Word Preparation

This is the next source/config preparation profile, not an activation package.
The published runtime candidate is
`15d6316d1bd28bb535698a4797e3c6261e6c9597`. Deployment scripts stay on
`deploy/testnet`; the same runtime source is published on `testnet-dev` and
`prepare/testnet-dev-runtime-20261031` without deployment history.
Neither a successful preflight nor a Git push authorizes reset or activation.

The runtime inputs are now frozen for the offline version-2 build only: source
`15d6316d`, the retained-membership epoch-32 config, and public contracts from
Genesis `8346116` / Compiler `e9cc57fe`. `runtime_inputs_frozen: true` permits
that build; it is not runtime approval or permission to reset/install/start.
The build spec separately pins the exact bundle, provenance and profile bytes.
Actual-key Genesis and production-builder replay are complete; the public
[artifact receipt](artifacts.json) records their hashes without private data.
Installer migration and all remaining acceptance gates below are still required.
The receipt is not an activation package and is not consumed by old installers.

`release.json` is the preparation role inventory. Historical `fresh-topology/`
and `live/components.json` describe older cohorts, not this deployment's inputs.
For this cohort: Relayer stays on `gcp-coordinator-worker`, Faucet on `arc99x2`,
SYSTEM on `arc99x1`, USER on `arc99x3`. Do not rewrite old observations as live
measurements. `topology.json` here is the core-only version-2 planning input.

```sh
python3 -B deploy/multi-chain/gcp/core-only/plan.py \
  --release-lock deploy/multi-chain/gcp/fresh-192-20261030/release-lock.json \
  --release-lock-sha256 "$RELEASE_LOCK_SHA256"
```

This read-only preview returns 2 until acceptance is complete. It reads
`topology.json` and `release.json` from the lock's directory and renders 16 core
units only when the caller supplies the reviewed lock SHA-256 and the lock agrees
with those files. Obtain that hash from the accepted preparation record, not an
untrusted replacement lock. When `--config`, `--genesis` or `--whitelist` is
supplied, its exact bytes must match the lock's pins. It renders
units in seven fresh namespaces from `namespace_prefix`; it does not install
them. The historical host, Services and Faucet installers still require their
own artifact/namespace migration and must not be used with these new inputs.
All core Edges must use the same private Redis database for cross-Edge fetch
replay protection. Per-role namespaces do not partition the replay keys.
The version-2 plan sets `NATS_WORKER_ACK_WAIT_MS` on all 16 units from one
release value (initially the unchanged 30000 ms default). Before activation,
check actual JetStream consumer `ack_wait` against it and measured proof p99;
adjust the release value consistently if necessary, never only the Edge.
Check the shared Redis instance uses `maxmemory-policy noeviction`: eviction of
a live replay key would reopen that signature. The offline planner cannot
certify either live Redis policy or existing JetStream consumer configuration.

## Preparation Parameters

`release.json` records testnet magic `0x1337CF514544CF69`, Plonky2, epoch 32,
192 calldata words, 64 introspectable transactions, 100 Faucet operators,
two Realms with three validators each, and the three existing Guardians.
Bridge Reader is excluded. Only PSY (L2 contract 0) and pUSDT (contract 4)
may be admitted; native deposits and initial public deposits stay disabled.
Host roles are preparation inputs, not fresh SSH or resource measurements.

See [the measured circuit alignment](FINGERPRINT-AUDIT.md). Inclusion, EndCap,
ZK and both secp fingerprints match; Faucet SD-key identity changes. These
measurements do not replace the downstream rebuild and Genesis gates below.
See [the latest preparation status](PREPARATION-STATUS.md) for local consumer
commits, actual config evidence and remaining release work.

The Relayer candidate already supports L2 withdrawal-tree append packs of
1, 2 and 5. Five withdrawals use one `batch_append_withdrawals_5` call with
176 Felt inputs, fitting 192. Use that existing packing rather than porting
the old 128-word `2 + 2 + 1` workaround into this cohort. This is not five
parallel L1 sends, nor a change to L1 deposit aggregation. Keep smaller-pack
regressions and require real five-entry Guardian/SD-key/EndCap acceptance
against the new Genesis before rollout.

## Read-Only Preflight

```sh
python3 -B deploy/multi-chain/gcp/fresh-192-20261030/preflight.py \
  --source "$RUNTIME_SOURCE" --config "$CANONICAL_RUNTIME_CONFIG"
```

This only reads public files and local Git identity/status. It never contacts
nodes, reads private keys, runs Cargo, writes configuration, broadcasts, or
starts/stops services. Missing or inconsistent inputs return 2. Input contents
are not logged. The selected runtime config must already select testnet,
use epoch 32, enable the owned worker whitelist, and carry the retained public
Guardian commitments and six-validator membership. Format checks do not prove
curve-point validity, key possession, provenance or native Genesis acceptance.
Those remain separate runtime checks. A zero exit means these limited input
checks passed, never that `deployment_ready` or `activation_authorized` is true.
The source checkout is operator-trusted: repository-configured Git filters may
execute during status checks. Inherited Git directory/worktree overrides are
removed. All six validator identities must be structurally complete and unique;
this does not establish retained-key provenance or curve-point validity.

The historical `core-only` version-1 planner default and installers still pin
R3 source, epoch 10, old account identities, artifact hashes and namespaces.
The new version-2 preview above is not an updated installer. Do not call old installers with
renamed inputs or replace only their version strings. Likewise, the historical
`source-versions.env` and published SDK 2.1.0 are not this release lock.

## Preparation And Remaining Gates

1. Source publication and all three downstream Node Cargo pins are complete
   at `15d6316d`; retain that immutable source during final artifact integration.
2. Rebuild Compiler and full contract artifacts, measuring affected fingerprints
   and checking token0/token4 layouts, methods and privacy bindings. Public
   contract regeneration completed at Genesis `8346116`, including canonical
   ABI layouts missing from the predecessor; final native
   actual-key network acceptance is still required.
3. Prepare a fresh Genesis and 100 Faucet public identities. Retain Guardian,
   P2P, worker and operator private-key material; the changed Faucet fingerprint
   does not preserve old public identity. Use the reviewed explicit transition
   below; never rewrite the old baseline or disable its identity check.
4. Rebuild the SDK/WASM and clients from the accepted cohort. No npm publication
   is included here. Measure the full 64-slot SD-key resource envelope.
5. Build the five CLIs with the pinned offline Bookworm procedure in
   [BUILD_RUNTIME.md](../core-only/BUILD_RUNTIME.md). Bind the actual config,
   bundle/stamp, source and image, retaining build manifests and hashes. A cache
   build against previous bundle inputs is preliminary, not the final package.
6. Adapt packages/activation scripts and isolated namespaces, journals and
   indexer cursors. Do not transplant old chain state. Resolve baseline holds
   from [REVIEW-NOTES.md](../fresh-sdk210-20261030/REVIEW-NOTES.md).
7. Prepare matching L1 setup/verifiers and paused fresh contracts for all three
   chains. The shared L1 runner now checks the compiled Router ABI before
   broadcasting and checks dual mappings/native rejection at one block before
   writing success readbacks. It does not automatically recover or redeploy
   after a partial deployment or failed readback.
8. Complete real illegal-then-legal deposit, claim and withdrawal E2E for each
   chain before opening public deposits. Mocked readbacks are not this gate.

The PostgreSQL installer now fixes 2 GiB Docker shared memory and compressed
`100m`/100-file logs, checking actual container policy before readiness. It is
a fresh installer that replaces a container, not a live database maintenance
command. Hasura's existing bounded logging remains unchanged.

## Fresh Faucet And Relayer Generation

Before network Genesis assembly, regenerate the compiler-owned public contracts
from the clean published Compiler with the same published Node Cargo revision.
Use the pinned Bookworm build environment and its accepted public config. The
original Make recipe supports an external Cargo target directory through this
explicit command override:

```sh
PSY_NETWORK=testnet PSY_CONFIG_PATH="$PINNED_CANONICAL_CONFIG" \
  make gen-deploy-json PSY_NETWORK=testnet PSY_GENESIS="$PREPARED_GENESIS_REPO" \
  DARGO="RUST_LOG=dargo=info $CARGO_TARGET_DIR/release/dargo"
```

Do not use the default repository-local `target/release/dargo` when Cargo writes
to an external target. Require the recipe's final provenance marker and a zero
exit; compilation alone is not success. The image must include Node and expose
the clean Compiler's Git metadata read-only for the original provenance step.
Inspect generated diffs, hashes and ABIs before publishing the Genesis child.
This builds `genesis_contracts.json`, not the membership-populated network
`genesis.json` or any private keys. Actual network assembly follows below.

The native generator now accepts `--fresh-faucet-identities` only alongside
hash-pinned imported keys and prior public Genesis. It permits a common old
Faucet fingerprint to change to a common new nonzero fingerprint for every
operator. In `fresh-faucet` mode, every public-key parameter and all Validator/Relayer fingerprints and
the six Validator role mappings remain checked. The normal import mode still
rejects all fingerprint changes. This is not a live account migration.

Use the existing `core-only/prepare_genesis.py` entrypoint, not manual JSON
rewrites. Its version-2 public spec adds these exact fields to the version-1
input set documented in [GENESIS.md](../core-only/GENESIS.md):

```json
{
  "schema_version": 2,
  "checkpoints_per_epoch": 32,
  "account_identity_mode": "fresh-faucet-and-relayer"
}
```

The block time, eight pinned public inputs, six complete compiler artifacts and
separately hash-pinned private-key array are still required. The snippet is not
a complete generation spec. Run `plan` first, then `generate` with the same
spec, keys and new protected output path. Both record the selected identity
mode and epoch; combined generation passes each native opt-in flag exactly once.
Version 1 remains strict import with epoch 10. Nothing silently upgrades it.

The retained R3 Genesis also has an older registration-2 multisig fingerprint.
The combined mode adds the separately guarded `--fresh-relayer-fingerprint`:
only that registration may change to the compiled multisig fingerprint, and
its public-key parameter/Guardian policy must stay equal to the prior Genesis.
The original `fresh-faucet` mode never permits this additional transition.
Do not reuse old-chain Guardian/Relayer journals with the new identity.

The generator transition passed 57 release tests (1 existing ignored test).
Deployment adapter tests passed 22 tests, and the network-assembly regressions
passed 37. Adapter children are mocked: these results do not establish that
the final actual-key Genesis or matching Compiler/SDK artifacts exist.

## Retained Public Configuration

`prepare_config.py` creates a new protected candidate directory from two
hash-pinned JSON inputs: the canonical config at the selected Node/Genesis
revision and the retained approved testnet config. It keeps canonical
consensus parameters and selects testnet, retaining only Guardian commitments,
the approved ordered Guardian endpoints, internal Coordinator endpoints, Realm membership and the Worker
whitelist from the prior config. Nested identity objects have exact field
allowlists; credential-bearing RPC URLs reject. Nonempty Guardian governance
history rejects and no history is copied. The two input hashes must match
`release.json`, not merely caller-supplied hashes. The script opens only these
config files and the release profile, never keystores or private-key files;
it does not modify inputs or contact hosts. Inputs remain operator-trusted.

### Worker labels

A whitelist policy may name its workers with an optional `labels` object
alongside `enabled` and `secp256k1`:

```json
"whitelist": {"enabled": true, "secp256k1": ["02..."],
              "labels": {"02...": "c4d-coordinator"}}
```

Each label key must be a whitelisted key, each name 1-64 characters of
`[A-Za-z0-9._-]`, and names must be unique. `core-only/worker_labels.py` holds
the rules for every validator here; Edges with labels support refuse a policy
that breaks them, so check before installing. Labels never change admission.
Edges from before labels support ignore the field. Edges with it add a
`worker_label` field to worker reputation logs and reread the config every 30
seconds, so a label change needs no restart. Labels are operational names:
keep personal names and private addresses out of them.

A live whitelist change makes the installed config differ from the lock's
`runtime_config`. Do not re-pin the lock to follow it: the Guardian and Relayer
build records pin the same hash, and their install checks would refuse. Record
the change outside the lock instead. Before a redeploy that should keep the
new keys, bake them into `worker-whitelist.json` and the runtime config of the
next release. Until then, step 66 refuses the changed Edge configs.

```sh
python3 -B deploy/multi-chain/gcp/fresh-192-20261030/prepare_config.py \
  --canonical "$CANONICAL_CONFIG" --canonical-sha256 "$CANONICAL_SHA256" \
  --retained "$RETAINED_CONFIG" --retained-sha256 "$RETAINED_SHA256" \
  --output "$NEW_CONFIG_DIRECTORY"
```

Outputs are mode-0600 `config.json` and `manifest.json` in a new mode-0700
directory. Existing output paths reject rather than overwrite. Preserve any
partial output for inspection. This establishes only local format/identity
continuity: verify actual private-key possession, host addresses, native config
acceptance and Guardian quorum before rollout. Keep generated configs outside
Git and public client artifacts. Build final caches/artifacts with this exact
accepted config; the earlier template-based checks are not that final build.

## L1 Deployment, Guardians And Relayer (steps 69, 71, 74)

Both `check_hosts` and `deploy_l1` run `fresh_l1.py` on the signer host with the protected route and read
two root-owned files there: `/etc/parth/relayer.env` (the wallet entry) and
`/etc/parth/l1-rpc-fallback.env` with exactly one entry each for `SEPOLIA_RPC_FALLBACK_URL`,
`BSC_TESTNET_RPC_FALLBACK_URL` and `BASE_SEPOLIA_RPC_FALLBACK_URL` (mode 0600 or 0640). The second file is
created by the operator and is not part of any package; the steps check names and modes only and never read a value.
Node 18+ must exist at `/opt/psy-l1-bundles/node-v22.23.4`.

The gas budgets are release inputs: `fresh_l1_gas_budget.<network>.json` next to the lock, hash-pinned with
`release_lock.py update-budgets`. They never come from Hardhat figures: Sepolia reprices state creation
(Bridge creation about 36.6M gas against 5.1M in Hardhat), so `check` also runs a live `eth_estimateGas` of every
creation bytecode per chain and refuses when the estimate plus 20% exceeds `maxGasPerTransaction`.

On the signer host each attempt is `<l1.output_root>/attempt-<n>`. Step 69 never rebroadcasts: a chain with a
`completed-<network>.json` and its evidence is verified and skipped; any other trace of work in the latest attempt stops
the step and prints the `fresh_l1.py prepare` command that creates `attempt-<n+1>`. After reviewing the stage journal and
receipts, run that command and `deploy_all --from 69`. The recorded documents for step 70 are
`<private dir>/state/deploy_l1.json` and `<private dir>/state/l1/attempt-<n>/<chain>/`.

## Local Inputs For The Preparation Steps

The release lock pins hashes, not machine paths. The preparation steps read the
local paths from `local-inputs.json` in the operator-only directory (mode 0600,
never committed). Every file named there is hash-checked against the lock or
`artifacts.json` when used; the file itself is not pinned.

| Section | Names | Meaning |
| --- | --- | --- |
| `build` | `source`, `builder_image`, `caches` (`cargo`, `target`, `go`, `go_build`), `output_root`, `jobs` | Inputs of the pinned Node build. All paths absolute. |
| `files` | `config`, `canonical_config`, `genesis`, `genesis_contracts`, `compiler_stamp`, `groth16_setup_manifest`, `gnark_groth16_verifier`, `deposit_batch_verifier`, `withdrawal_claim_verifier`, `psy_services`, `psy_indexer`, `l1_bundle_manifest`, `l1_policy` | Frozen release inputs. `l1_bundle_manifest` is the `manifest.json` at the root of the L1 bundle directory. |
| `databases` | `postgres_password_file` | Absolute path of a file whose single line is the PostgreSQL superuser password for the rebuilt database host (step `rebuild_databases`). The controller sends it on stdin; the installer exports it and `docker` takes it from the environment, so it is in no command line. |
| `notifier` | `checkout` | Local checkout of the Psy Notifier repository used by step 85 (absolute path). Step 55 checks it; once `sources.notifier` in the lock is set (Task C1, together with `EXPECTED_PSY_NOTIFIER_COMMIT` in `source-versions.env`) it must be at that commit and clean. |
| `packages.core` | `registration_keys`, `faucet_operators`, `p2p_keys`, `output` | Inputs of the core host packages; `output` must not exist before the first run. All absolute. |
| `packages.proxy` | `rpc_endpoints`, `setup_dir`, `verifier_dir`, `output` | Inputs of the SYSTEM and USER Proxy packages; `output` must not exist before the first run and receives `system/` and `user/`. `setup_dir` is the `keystore` directory of the Groth16 setup and `verifier_dir` holds the four exported verifiers (system role only). All absolute. |

`packages.proxy.rpc_endpoints` is a JSON file the operator writes and approves; it is not generated. It holds
`coordinator` (id `"0"`) and `realms` (ids `"0"`, `"1"`) with three RPC URLs each, taken from the Edge and
Realm endpoints of `topology.json`; `prove_proxy_url` and `system_prove_proxy_url` as URL arrays; and
`placement` with, for `system` and `user`, the `host` (the machine's own hostname, used as a unit
`ConditionHost`) and `listen_addr` (IP:port). The listen IP of each role must equal the lock address of its
host, `arc99x1` for system and `arc99x3` for user; step 68 checks that. The hosts are operator hosts without
passwordless sudo, so step 68 stages the package and prints a command for the operator.

`artifacts.json` needs one more pin before step 53 can run, filled at B14 with the runtime values:
`proxy_packages.rpc_endpoints_sha256`, the sha256 of the approved `rpc_endpoints` file. The lock also
needs `groth16.setup_manifest_sha256` (the hash of the setup manifest) and `binaries.psy_user_cli` of the
final runtime build, because the package binary is checked against both. The setup manifest must name
`psy_user_cli` as consumer and `psy_relayer_cli` as generator. The proxy tool is given a narrow build
document (five fields) written to `<private>/state/proxy-build-input.json`, not the full build record.
Default memory caps are 56/60 GiB for system and 40/48 GiB for user, the live effective limits.

Steps 61-64 read the private `retired-state.json` (`stop`, `containers`, `retain`, `clear`, and the optional `clear_allow`).
`stop` may name services, timers and sockets (timers and sockets are stopped first, and every listed unit is disabled and
stopped). `clear_allow` names exact paths strictly below a clear entry (never the entry itself) whose key-like file names
are known harmless: a file, or a directory whose whole subtree is exempt, such as `node_modules`. The clearing tool walks
every clear target and refuses the whole host on any other key-like name, on nested clear entries, on glob characters, on
a symlink that reaches a retained path, and on a mount point. `retained-paths.json` kind `secret` paths are hashed before
and after each clear (files by content, directories by names, sizes and mtimes to depth 3); kind `infrastructure` paths
are only checked for existence, which is why `/opt/nostr-relay/caddy_data` (Caddy rewrites it while running) is listed as
infrastructure. The first hashes seen before a delete are kept in `state/retained_baseline.json`, bound to the lock hash.
Operator hosts (x1, x2, x3) are stopped and cleared by one printed command (step `stop_operator_hosts`) whose files and
result live in a mode 0700 directory under the operator's home; step `clear_node_state` only verifies their results.
The release check (`check_hosts`, step 55) and `stop_services` both run the whole clearing request of every host without
`--apply` (unprivileged on operator hosts) and fail on any refusal.
| `packages.worker` | `output` | Output directory of the Worker package (must not exist before the first run). Absolute. |

Bridge package steps (54, 70, 72, 73) read three more sections. All paths are absolute and no value is a secret.

| Section | Names | Meaning |
| --- | --- | --- |
| `packages.bridge` | `output_root`, `guardian_placement`, `guardian_rpc_config`, `relayer_spec`, `relayer_rpc_config`, `relayer_daemon_config` | `output_root` receives `pending` (replaced on each step 54 run) and `final-<12 hex of the L1 documents>` (create-only); keep it outside Git. `guardian_placement` is `{"version": 1, "guardians": [...]}` with, per Guardian, exactly `guardian_id`, `hostname`, `address`, `guardian_history`, `proof_origins`, `service_user`, `memory_high_gib`, `memory_max_gib`, `custody_keystore_sha256`. `relayer_spec` holds exactly `hostname`, `address`, `guardian_history`, `service_user`, `memory_high_gib`, `memory_max_gib`, `keystore_owner`, `l1_keystore`, `password_credential` (the last two are `{path, sha256}` of host-local files). The RPC configs and the daemon TOML are the approved operator files. Each package is planned locally with its installer before it is written. |
| `packages.services` | `services_source`, `indexer_source`, `genesis_source`, `mirror_host_keys` | Git checkouts at `sources.services`, `sources.indexer` and `sources.genesis` of the lock; `mirror_host_keys` maps the address of each backup source (Coordinator host and the validator 2 and 3 processor hosts) to its Ed25519 SSH host key blob. |
| `packages.envio` | `patches_dir`, `dependency_lock`, `build_script` | The five pinned patch files, the reviewed pnpm v9 lock and an executable that builds Envio. Step 70 runs `build_script <source package dir> <output dir>`; the output must be a finished build whose `build.json` carries the verified flags, the lock's Node hash and the exact file inventory (`install_envio.inventory`). `core-only/build_envio.py` is that executable: it needs `PSY_ENVIO_NODE` (the pinned Node), `PSY_ENVIO_PNPM_STORE` (a populated pnpm store) and `PSY_ENVIO_WORKSPACE_LOCK` (the reviewed lock that includes the generated workspace) in the environment, and runs offline. |
| `databases` | `postgres_password_file` | The file the database host is rebuilt from. Step 72 uses the same value as the login of the Envio and Services roles, so it must hold 24 to 256 of letters, digits, underscore, plus, slash, equals and hyphen. |

Step 72 and 73 write the generated Hasura admin value and the indexer JWT value once to `<state>/service-credentials.json` (mode 0600) and reuse them on reruns.

Build attempts live in `<output_root>/<release id>-<first 12 of the runtime commit>-build-<n>`.
A completed attempt of the same commit is verified and reused; a failed attempt
is kept and the next number is used. A build of another commit never blocks a
new one.

Cache paths may need to match the pinned build. Cargo records `CARGO_HOME`
(the `cargo` cache) in compiled-in paths, so a binary built with a different
cache path can differ from the hash in `artifacts.json`. Use the cache paths of
the build that produced those hashes, or expect to re-pin.

Step `check_hosts` takes the signer host from `l1.signer_host` in the lock and
requires the retained paths to agree: that host must keep both `/etc/parth` and
`/var/lib/parth/.psy/keystore`, plus the keystore file
`/var/lib/parth/.psy/keystore/bridge-relayer-dev`. It reads the L1 balance and
nonces with the pinned `fresh_l1.py status`, sent on stdin to that host and run
with `--rpc-preference protected-env-backup`, the route the deployment uses.

## L1 RPC Routing (step 56)

Guardian, Services, Envio and the Relayer reach L1 through the gateway's private proxy on ports 18545, 18645 and 18945.
Step 56 installs `core-only/l1_rpc_local_first.py` over the retained proxy wrappers and adds drop-in
`91-local-first-20261102.conf`. Both paths sit inside the retained proxy directories, so a wipe keeps them. The step
is idempotent and restarts the proxy only when the wrapper differs. It refuses to run if the retained wrapper hash
differs from the one pinned in the source, and it passes only when all three local nodes report fresh.

| Request | Order | Falls back when |
|---|---|---|
| Read | Local node, then both Alchemy keys | Local is stale or without peers, the call fails, or it answers a non-revert error or a null receipt, transaction or block |
| Nonce read | Alchemy keys, then local | Always, while sends stay on Alchemy: a lagging node hands out a used nonce |
| Read after a receipt | Alchemy keys, then local | Alchemy reported a receipt in a block the local node has not reached: until it does, a caller would check state from before its own transaction |
| Send | First Alchemy key, once | `SEND_VIA_LOCAL` is off until a real transaction has been seen to propagate from each local node |

The null rule is required. Past its pruning window a node errors on logs but answers null for old receipts,
transactions and BSC blocks, which a caller reads as "does not exist".

Rollback: delete the drop-in, run `systemctl daemon-reload` and restart `psy-private-alchemy-20261027.service`.

## Public Release And Acceptance Steps (77-87)

The table finishes the release end to end. Step 77 uploads the nine public Groth16 files (circuit, pk and vk of
bridge, deposit_append and withdrawal_claim, checked against the setup manifest; nothing else of the keystore) to the
Nostr host and verifies the public digest. Step 78 generates `config.json` and the trust-setup installer from the
recorded L1 documents and `public.json` (the public sites, routes and Pages project of this release), refuses any
address that differs from the documents, deploys the page, and verifies the live hashes. Step 79 applies the live
config to the dapp deploy files, pushes `deploy/testnet` fast-forward only and checks that CI is green for the pushed
commit and that the served bundles hold the new PSY addresses and none of the previous release (the account site
carries dead data from a vendored wallet preset and is only checked for the new address). It also compares the
committed config with the live one, because CI builds from the live config without checking the committed file.
Steps 80-84 and 87 refuse to run while the frontends are not current (step 79) or any chain is left unpaused. Step 86
opens deposits and is last on purpose (87 sits before it in the table).

Private inputs, in `local-inputs.json` next to the others:

| Section | Names | Meaning |
| --- | --- | --- |
| `public` | `cloudflare_env` (a file of `export CLOUDFLARE_ACCOUNT_ID=` and `export CLOUDFLARE_API_TOKEN=` lines, mode 0600), `dapp_checkout` (psy-dapp worktree with the release commit; origin must be the GitHub repository), `allow_frontend_push` (`true` lets step 79 push and publish; absent, step 79 raises PENDING with the exact commands), optional `wallet_checkout`, `wallet_sdk_label`, `wallet_skip_build`, `wallet_ref` | Steps 77-79. Absolute paths. |
| `acceptance` | `user_rpc_config` (the public client config, for example the dapp `public-client-r3.json`), `work_dir` (keys of the acceptance users are created here, mode 0600), `wallet_key_file` (EVM test wallet, mode 0600), `wallet_address` | Steps 82-84, 87. |

Step 86 needs `CONFIRM_OPEN_DEPOSITS=1` in the process environment; without it the step is PENDING and opens nothing.
The pause tool `core-only/admin_pause.py` is hash-pinned in the lock like every remote tool. Windows open one chain at a
time, check the illegal deposit while paused first, and restore and read back the pause on any exit; a window that did
not finish is never repeated blindly (read the pending deposit count first). Reads and sends go through the private
gateway ports (an ssh tunnel to the signer host), because the public route can lag one block behind an administrator
transaction. Gas is measured live. The drivers are in `../e2e/three-chain/` and take everything from the environment.
MetaMask flows are skipped by name and the reward claim is recorded as unverified.

After a tool-only change of the lock, recorded state can move to the new lock without hand edits:
`python3 core-only/rebind_lock_state.py --release-dir <dir> --private-dir <private> --previous-lock <old release-lock.json>`
(dry run; add `--apply`). It refuses when the two locks differ in anything but `tool_sha256`. Lock-bound packages of step
53 are removed and rebuilt by the step itself when the lock or an installer changed. A Caddyfile that holds a
maintenance block of another tag inside a listed site is refused by name; the indexer upstream follows
`envio.hasura_port` in `fence`.

## Live Deployment Versus This Lock (2026-11-09)

The lock pins runtime `be1a4817` (all five CLIs from that pinned build; only `psy_relayer_cli` differs from the `badc109c` build). The live SD192 network differs from it in
known, reviewed ways; a redeploy from this lock changes these units:

| Component | Lock | Live |
|---|---|---|
| `psy_node_cli` on the six Realm processors and the coordinator processor | `64a74b01` | `64a74b01` (same) |
| `psy_node_cli` on the Edges | `64a74b01` | `ea150cc9` (build `fbbc0738`, 2026-11-11: user tree proofs only for committed checkpoints) |
| `psy_worker_cli` | `a5024735` | `a5024735` (same) |
| `psy_relayer_cli` on the three Guardians | `03184ab0` | `7abf495c` (build `7c72df70`; the lock adds only relayer-daemon changes, pending-recovery proof wait and claim proof `scan_limit`, which Guardians do not run) |
| `psy_relayer_cli` on the relayer | `03184ab0` | `03184ab0` (same) |
| `psy_dev_cli`, `psy_user_cli` | `f36e9436`, `f2f4762d` | not installed by this release |
| Runtime config `coordinator_configs` | three edges (pinned `04d3056c`) | same file on the core hosts |
| Coordinator clients | `release.json`/topology: ingress `10.148.0.25:15369` | relayer, guardian `rpc.json`, Worker config, Realm processor units, coordinator indexer and Services use the ingress; the x3 user prove-proxy reaches it through the additive gateway forwarder `psy-coordinator-ingress-forward` (`10.250.0.1:15369`); Realm indexers (hash-guarded Services package) still dial the edges, and the gateway edge forwarders `15370`-`15372` remain installed but idle |

The six Edges run the `fbbc0738` build since 2026-11-11 04:52-04:58 UTC: `get_user_tree_merkle_proof` answers
"User tree proof not found" until the Realm checkpoint marker reaches the requested checkpoint, because the Realm
commit writes the top spine before the subtree nodes (Guardians saw "Finalizer composed user proof is invalid").
The previous Edge binary is kept as `psy_node_cli.bak-27d2059f30f2` on both Edge hosts. The gateway forwarder
`psy-coordinator-ingress-forward` is not generated by `prepare_bridge_forwarders.py` yet, so a gateway reinstall drops it. Steps 50
and 53 refuse this lock until the runtime config is regenerated with the ingress URL, which belongs to the next fresh
deploy. Live host changes made outside the installer keep a `.bak-pre-ingress` copy; the coordinator ingress itself is
the step 57 site.
