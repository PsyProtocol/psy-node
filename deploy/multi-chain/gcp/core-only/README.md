# Core-only offline deployment plan

Status: preparation, not an installer or release approval. This directory owns
the core network assembler, planner, topology and public worker policy. No old deployment
script, Caddy configuration, live service, key, Genesis, or database is changed.
Applicability: local tooling only; no generated artifacts or downstream pins.

## Frozen inputs

- Tooling base: `deploy/staging` `6246dc871eebc3f8e80d4994360b45fc36a73040`.
- Node source base: `de539f565ec1a92f91bb4e9686e1442e89ba8639` plus the staged
  testnet runtime patch recorded in `topology.json`. `runtime_commit=null`
  explicitly means the candidate has not been committed/published yet; the base
  alone is NOT the new runtime. Final binary/source provenance remains pending.
- Requested environment: `PSY_NETWORK=testnet`.
- CLI: `--network psy-public-testnet --proving-backend plonky2-poseidon-goldilocks`.
- Two Realms, three ordered validators each, one distinct Edge per validator.
- Coordinator Processor and three Edges on `.25`, HTTP ports 15370/15371/15372.
- Processor positions 1/2/3 on `.37/.42/.43`, each host runs both Realms.
- Realm 0 Edges on `.36`, HTTP 15380/15381/15382; Realm 1 on `.35`, 15383/15384/15385.
- P2P processor ports 41001..41003 and 41021..41023; Edge ports 41101..41103
  and 41121..41123. These are planned ports, not remotely verified free ports.

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
There is no bypass flag. Unpublished runtime provenance, three-validator circuit
cache acceptance, Genesis authentication and runtime acceptance remain gates;
consistent parameters do not make those checks pass.

## Run locally

From the deployment worktree root:

```sh
python3 -B deploy/multi-chain/gcp/core-only/plan.py
python3 -B deploy/multi-chain/gcp/core-only/plan.py \
  --config /absolute/path/to/public-config.json \
  --genesis /absolute/path/to/genesis.json \
  --whitelist /absolute/path/to/worker-whitelist.json
python3 -B -m unittest discover -s deploy/multi-chain/gcp/core-only -p test_plan.py -v
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
