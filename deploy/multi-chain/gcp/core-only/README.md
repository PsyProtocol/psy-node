# Core-only deployment

The assembler and planner remain offline tools, not release approval. The separate
host package builder and installer below prepare and install an authorized fresh
core release. Installation never starts services or clears databases. No old
deployment, Caddy configuration, Guardian custody, or P2P identity is replaced.

## Frozen inputs

- Tooling base: `deploy/staging` `6246dc871eebc3f8e80d4994360b45fc36a73040`.
- Deployment tooling HEAD before this update: `286500236d3a13d25a0cc3db6032843da71f0459`.
- Published node runtime commit: `dcc1146514ef3eca2336640f6d95e5a1c04feff9`, pinned
  by `runtime_commit` in `topology.json` and both validators. Null, missing,
  abbreviated or different commits are rejected. The superseded
  `runtime_source_base` and `runtime_patch_sha256` fields are no longer accepted
  or emitted. Source publication does not approve binaries or installation.
- Retained Guardian commitments still require key-generation `node_source`
  `de539f565ec1a92f91bb4e9686e1442e89ba8639`. This is custody provenance, not the
  runtime pin; do not relabel it or regenerate identities for this update.
- Requested environment: `PSY_NETWORK=testnet`.
- CLI: `--network psy-public-testnet --proving-backend plonky2-poseidon-goldilocks`.
- Two Realms, three ordered validators each, one distinct Edge per validator.
- Coordinator Processor and three Edges on `.25`, HTTP ports 15370/15371/15372.
- Processor positions 1/2/3 on `.37/.42/.43`, each host runs both Realms.
- Realm 0 Edges on `.36`, HTTP 15380/15381/15382; Realm 1 on `.35`, 15383/15384/15385.
- P2P processor ports 41001..41003 and 41021..41023; Edge ports 41101..41103
  and 41121..41123. These are planned ports, not remotely verified free ports.

### Temporary Realm 1 placement (2026-10-26)

The baseline `topology.json` above remains the target after memory expansion.
The operator authorized a temporary placement: Realm 0 positions 1/2/3 stay on
their original hosts, while all three Realm 1 Processors run on the Coordinator
host. This is a functional test layout, not host-fault-tolerant Realm 1 capacity.
The Coordinator host was measured at 8 CPUs and approximately 30 GiB usable RAM,
with 21 GiB available before adding Realm 1. Individual Realm Processors consumed
approximately 4 GiB after startup; two do not fit safely on the original 8 GB VMs.

`place_realm1_on_coordinator.py` prepares a small private package from the retained
original packages. Only Realm 1 `processor_addresses` change to the Coordinator's
private IP; identities, ports, namespaces, Genesis and consensus parameters do not
change. The three new Processor units and the three Realm 1 Edge drop-ins select
`realm1-cp-ce-config.json`. Other processes retain the original config. The three
temporary Processors share `psy-realm1.slice` with `MemoryHigh=16G` and
`MemoryMax=18G`; this bounds their aggregate memory, but does not guarantee
availability if that limit is reached. Start them sequentially and inspect logs,
memory, P2P connections and checkpoint synchronization before each next start.

```sh
python3 -B deploy/multi-chain/gcp/core-only/place_realm1_on_coordinator.py prepare \
  --packages /absolute/private/original-host-packages \
  --output /absolute/private/new-placement-packages
```

Copy only each host's package to that host, with the script and its imported
`install_host.py`, `prepare_host_packages.py`, `plan.py` modules alongside it.
Run `apply --package PATH --check-only`, then `apply --package PATH` as root.
Neither command starts services. Keep the original Realm 1 units stopped and
disabled. During this rollout each old unit also has a
`90-temporary-placement-hold.conf` drop-in with a `ConditionPathExists` pointing
to the absent `/var/lib/psy-core/core-testnet-20261026/realm1-return-authorized`.
Do not create that file or remove the guard while its replacement is running.
Before copying state, verify no old Realm 1 instance is active; the first temporary
placement checked that no old `realm_1_N` checkpoint directory existed.

Return after expansion is a state-preserving migration, not a second fresh start:
quiesce Realm 1 admission, wait for pending work to drain, stop all three temporary
Processors, then transfer each validator's complete `realm_1_N` checkpoint and
proposal-backup directory to its original host with ownership preserved. Keep the
same remote database namespaces and keys. Stop the Realm 1 Edges while restoring
their original routing configuration. The script's `rollback --package PATH`
removes only matching temporary config, units, drop-ins and slice files; it keeps
keys and state and neither starts nor stops services. It is not a state-transfer
command. Remove only the exact old-host hold drop-ins after replacement processes
are confirmed stopped and state transfer is verified. Reload systemd and resume
the original instances, then verify all three peer connections and checkpoints
before reopening admission. Never run both copies of one validator identity.

| Realm | Position | Registration | User ID |
| --- | --- | --- | --- |
| 0 | 1 | 0 | 0 |
| 0 | 2 | 4 | 262144 |
| 0 | 3 | 6 | 786432 |
| 1 | 1 | 1 | 1048576 |
| 1 | 2 | 3 | 1572864 |
| 1 | 3 | 5 | 1310720 |

Positions are derived from ordered public membership by the runtime. They are
not configurable database sub-IDs. No `--realm-sub-id` is passed to Realm nodes.
Genesis membership uses its existing flat `validators` array with `realm_id`,
`validator_user_id`, `node_id`, `bls_public_key`, not a new backup/config schema.

## Faucet account pool: 100 operators

This fresh deployment explicitly pins `faucet_operator_count: 100` in
`topology.json`. The Rust generator's global default remains 10; do not rely on
it. `plan.py` emits `genesis_account_plan.required_generator_account_args`,
including `--faucet-operator-count 100`, all six validator slots, and relayer
registration 2. These are account arguments, not a complete generation command.
The reviewed testnet generator, contract artifacts, secure random-key mode and
explicit private output paths remain required generation gates.

Expected Genesis: 6 validator accounts + 1 relayer account + 100 faucet accounts
= 107 users. Faucet registrations are 7..106; these are NOT their Strategy5 user
IDs. Both the planner and Genesis assembler reject the old 17-user artifact.
Do not use the historical helper that starts Faucet registrations at index 4.

Before Faucet startup, verify the private operator artifact contains exactly
100 distinct operator user IDs matching these Genesis registrations, with the
matching signing keys and SD-key restrictions. Retain the operator keys and
private artifact securely for reuse; never log or commit them. User-count checks
alone do not prove key ownership or validate the private operator inventory.
The plan explicitly reports that inventory verification as pending.

This change prepares the account pool; it does not generate Genesis, regenerate
Guardian/Validator identities, start Faucet, or increase proof concurrency to 100.
Keep concurrency bounded separately according to proving capacity.

## Network selection

The only accepted deployment combination is `PSY_NETWORK=testnet`, CLI network
`psy-public-testnet`, and backend `plonky2-poseidon-goldilocks`. Node/Worker
compilation must also use `PSY_NETWORK=testnet`. The topology and assembler reject
`localhost`, `local-devnet`, mixed combinations, and JTMB. They do not rewrite a
bad selector silently. `defaultNetwork` and public P2P/rotation/whitelist selection
are `testnet`. Membership and Guardian policy are never mirrored into localhost.

All Node/Worker processes must set `PSY_CONFIG_PATH` to the same deployed absolute
public config path. Every Edge's `--worker-whitelist-config` points to that same
`config.json`, not a second default or a working-directory-relative file. The
dedicated `worker-whitelist.json` is an assembly/validation input: its enabled,
nonempty policy is injected into `networks.testnet.whitelist`.

Do not replace L1 selectors such as `sepolia`, `baseSepolia` or `bscTestnet` with
`testnet`; those describe external chains, not the Psy L2 network. Do not bulk
rewrite historical manifests, localhost connection addresses, or old hotfix
scripts. Older launchers with a local-devnet default are not an entrypoint for
this new core deployment. Peripheral services must adopt this same L2 selection
explicitly when their new-cohort launchers are prepared.

This planner always reports `deployment_ready=false`, `release_approved=false`
and exits 2. With supplied, matching inputs it can report
`input_consistency_passed=true`; that is only an offline consistency result.
There is no bypass flag. Binary/build provenance against the published runtime,
three-validator circuit cache acceptance, Genesis authentication and runtime
acceptance remain gates; consistent parameters do not make those checks pass.
Validation is offline: it does not contact a remote to verify publication or
install the pinned source. Genesis generation is a separate operation.

## Run locally

From the deployment worktree root:

```sh
python3 -B deploy/multi-chain/gcp/core-only/plan.py
python3 -B deploy/multi-chain/gcp/core-only/plan.py \
  --config /absolute/path/to/public-config.json \
  --genesis /absolute/path/to/genesis.json \
  --whitelist /absolute/path/to/worker-whitelist.json
python3 -B -m unittest discover -s deploy/multi-chain/gcp/core-only -p test_plan.py -v
python3 -B -m unittest discover -s deploy/multi-chain/gcp/core-only -p test_prepare_network.py -v
```

Assemble a new public config without generating keys or Genesis:

```sh
python3 -B deploy/multi-chain/gcp/core-only/prepare_network.py \
  --canonical-config /absolute/path/to/psy-genesis/config.json \
  --p2p-config /absolute/path/to/preserved-p2p/config.json \
  --guardian-commitments /absolute/path/to/preserved-guardian/public-commitments.json \
  --topology deploy/multi-chain/gcp/core-only/topology.json \
  --whitelist deploy/multi-chain/gcp/core-only/worker-whitelist.json \
  --config-out /absolute/path/outside-git/new-testnet-config.json
```

The output parent must exist and the output must not already exist. The source
P2P config must select testnet and contain the preserved six identities. The
Guardian commitments retain their original key-generation source provenance;
changing the runtime selector is not permission to regenerate signing keys.
The supplied worker public keys are the two identities already approved in
`psy-memory/governance/fresh-testnet-20261022/owned-worker-whitelist.json`;
only their network selection changes, not their membership.

The JSON output includes argv arrays, environment, host/unit placement and systemd
**previews**, plus hashes of the exact local input bytes. Previews have no Install
section. They are not authorization to copy units or start processes. No SSH,
subprocess, RPC, generation, filesystem write, reset, build or service operation
is performed. `--apply` is not supported. Malformed inputs produce no services.

Public config must have `defaultNetwork=testnet`; the `testnet` entry owns
consensus, membership, routes, fees and Guardian commitments. Unselected canonical
network sections are preserved, not used as a fallback or mirrored runtime.
Consensus is pinned to magic `0x1337CF514544CF69`, user heights 32/20, group height 1,
1048576 users per Realm, and 10 checkpoints per epoch. Membership/routes must match
the topology exactly; P2P multiaddrs must carry the NodeId's corresponding PeerId.
The dedicated whitelist uses `networks.testnet.whitelist`, `enabled=true` and
nonempty distinct compressed secp256k1 public keys. The selected public config
must match it. Private keys are never inputs to the planner.

## Storage and key ownership

Scylla, Redis and NATS endpoints can be shared, but each Validator Processor and
its own Edge share exactly one unique `fresh20261026_rR_vV` namespace. Coordinator
has its own `fresh20261026_coordinator`. Namespace characters are restricted to
avoid normalization collisions. NATS uses `N_stream`, `N_kv`, and `N.>` subjects;
this is logical isolation, not a promise of tenant ACL isolation.

New persistent backup root: `/var/lib/psy-core/core-testnet-20261026/checkpoints`.
Runtime appends `realm_R_V/` or `coordinator_0_0/`; it does not append a sub-ID to
the supplied DB namespace. Do not reuse old data paths or delete old namespaces.
Release root: `/opt/psy-core/releases/core-testnet-20261026`; public configuration
root: `/etc/psy-core/core-testnet-20261026`. Target key paths under `keys/realm-R-vV/`
are references only. Deliver a Processor only its Ed25519/BLS/ZK keys, and an Edge
only its Ed25519 key. Do not distribute the entire key inventory to every host.

The planner validates public encodings and consistency, not cryptographic point
validity, secret possession, the full Rust Genesis schema, or Guardian policy
state embedded in Genesis. Test fixtures are synthetic structural examples, not
deployable identities. Those checks, release binary/circuit provenance, file
permissions, worker reward mapping, host capacity/ports, and actual P2P restart
and rotation acceptance remain required. Guardian commitments must already be
frozen in Genesis even when Guardian/Relayer services are deployed later.

Reuse the pinned runtime's `init-realm-p2p-keys` for separately approved key
provisioning, with `--validators-per-realm 3` and the six ordered user IDs above.
It is not invoked here. Existing fresh-topology/Guardian planners are reference
models, not imported installers. Worker services, Guardian/Relayer, Services,
indexers, proof proxies, L1 deployment, Caddy and frontends are outside this plan.

## Host packages and installation

`prepare_host_packages.py` requires the validated public config and new Genesis,
the pinned release node binary, the retained private P2P inventory, and private
Genesis/operator outputs. Run `--help` for the explicit path arguments. Its new
output directory is private and contains one package per topology host. Never
commit these packages: Processor packages contain only that host's Ed25519,
BLS and ZK secrets; Edge packages contain only that host's Edge identities.
The complete private registration/operator inventories are not distributed.

The builder checks binary/config hashes, 107 registration slots and 100 distinct
Faucet operator mappings. It renders systemd units with the existing planner's
argv, private DB endpoints, bounded restart retries and a writable checkpoint
directory. Generated configuration does not expose a public gateway.

Transfer each package over SSH to its corresponding host, retaining mode 0700
on the directory and 0600 on private files. Transfer the reviewed installer
separately, outside the package (the package rejects unlisted files):

```sh
sudo python3 install_host.py --package /absolute/private/host-package --check-only
sudo python3 install_host.py --package /absolute/private/host-package
```

The installer checks the package manifest, private host address, unit/key scope,
existing destination conflicts and that core units are stopped. It creates the
dedicated `psy-core` account, installs immutable artifacts and unit files, then
runs `systemctl daemon-reload`. It never enables/starts units, initializes a DB,
downloads dependencies, generates keys, or changes `parth-*` services. Exact
retry is supported; conflicting bytes, modes or ownership stop installation.

After all host packages are verified and installed, start Coordinator Processor,
then its three Edges; wait for authenticated Genesis/checkpoint reads before
starting Realm Processors and their Edges. Start matching Workers only against
these fresh endpoints. Confirm real proof pickup/submission and increasing
checkpoints before enabling the new units for reboot. Verify all three validator
positions connect and synchronize; P2P rotation/transaction acceptance is a
separate result, not implied by active systemd units.

Wallet/SDK artifact work is deferred by the operator for this core rollout.
Keep wallet, Faucet, Services/indexers and Bridge exposure disabled until their
matching artifacts are ready. The subsequent L1/Bridge rollout is a **fresh
deployment**: old contract addresses and old Groth16 setup are not inputs to it.
Guardian signing keys remain reusable and are not regenerated for that rollout.
