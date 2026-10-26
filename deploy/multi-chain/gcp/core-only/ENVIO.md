# Independent Envio Preparation

`prepare_envio.py` prepares inputs locally from Node
`da6391549e44d49c07e856eaeb5d0b8d7902ef17`. It reads Git objects, not the
working tree, replacement refs, old deployment artifacts or live release.
Inherited `GIT_*` overrides are removed. It never runs APT,
pnpm, patch scripts, SSH, Docker, SQL, systemctl or the old Envio installer.
It does not produce an installed/built release or grant activation approval.
Only new paths are published, using a private sibling directory and
`RENAME_NOREPLACE`. Directories are 0700; files are 0600. Existing output,
symlinks and output inside Git are rejected.

## Inputs

Python 3 with PyYAML and Git are required. The operator spec is private JSON,
mode 0600, owned by the invoking user. Pin its SHA-256 separately. Each
artifact descriptor is exactly `{ "path": "<absolute-path>", "sha256": "<hash>" }`.
The spec has these exact top-level fields:

- `version`: `1`.
- `patches`: descriptors for `history.py`, `polling.py`, `ordered.py`,
  `reorg.py`, `deposit-indexes.py`. The five hashes are enforced independently
  of the spec in `prepare_envio.py:PATCHES`. These are the existing history,
  rebuild-safe polling, ordered failover, fresh-parent reorg and Deposit query
  index tools. Their bytes are copied unchanged; none is executed.
- `dependency_lock`: descriptor for a reviewed pnpm v9 source-only lock, or
  `null` while pending. Its root dependency specifiers must match the pinned
  package. Hash equality/importer matching does not replace dependency review,
  integrity verification or a successful frozen build. Do not take an old
  generated workspace lock without comparison.
- `placement`: `null` while pending, otherwise exactly `postgres_host`,
  `postgres_port`, `postgres_user`, `hasura_bind`, `hasura_port`, `indexer_port`.
  Hosts must be RFC1918 IPv4 literals supplied privately. Require a dedicated
  non-superuser role, distinct ports and unused listeners; old Hasura/Envio
  ports are rejected. Availability is a later read-only host gate, not a
  conclusion from local validation.
- `rpc_routes`: `{}` while pending, otherwise exactly `sepolia`, `bscTestnet`,
  `baseSepolia`. Each has `urls` (1-3 ordered, private, credential-free HTTP(S)
  URLs) and `confirmed_block_threshold`. Minimum windows are 8/200/64
  respectively. First RPC is `sync`; subsequent RPCs are `fallback`.
  Preserve the existing private gateway transport policy; no direct API keys
  or implicit HyperSync source are introduced.
- `l1_documents`: `{}` while pending, otherwise exactly those three networks,
  each with `summary`, `bridge_receipt`, `state_manager_receipt` descriptors.
  Use real deployment summaries and mined successful proxy receipts. Network
  IDs/indexes must be 11155111/0, 97/1, 84532/2. Core, contracts and proxy
  addresses must match the receipt's created contract; creation transaction
  hashes must agree, and Bridge's block must equal exported `deploymentBlock`.
  Use `Bridge_Proxy.json` and `StateManager_Proxy.json`, not upgrade receipts.
  Start block is the earlier creation block. Do not supply proposed addresses.
  These checks bind the supplied bytes; on-chain readback remains a gate.

No DB password or Hasura secret belongs in this spec. Later credential wiring
must provide `ENVIO_PG_PASSWORD`, its percent-encoded equivalent
`ENVIO_POSTGRES_PASSWORD_ENCODED`, and `HASURA_GRAPHQL_ADMIN_SECRET` privately.
They must not fall back to upstream development passwords or enter argv/logs.

## Prepare

```sh
python3 -B deploy/multi-chain/gcp/core-only/prepare_envio.py \
  --source-repo '<pinned-node-repository>' \
  --spec '<private-spec.json>' --spec-sha256 '<spec-sha256>' \
  --output '<new-private-directory-outside-git>'

python3 -B -m unittest discover \
  -s deploy/multi-chain/gcp/core-only -p test_prepare_envio.py
```

The output includes the seven pinned source files, five unchanged tools and
`manifest.json`. A supplied lock is copied as `pnpm-lock.yaml`. Complete
placement adds `compose.hasura.json` and non-secret `runtime-env.json`.
Complete L1 documents plus RPC routes add `config.yaml` and pinned document
copies. Missing L1 documents never produce a runnable config. Handler, schema
and event declarations stay together: in particular do not rename the
template's `WithdrawalClaimed` field from `nullifier` independently of its
handler. Do not copy old timestamp handlers or timestamp migrations.

The only database name is `envio_bridge_fresh_20261026`, schema `envio`.
Compose project is `psy-envio-fresh-20261026`; it contains Hasura only, no PG
service, no PG volume and no auto-restart. Both Hasura data and metadata URLs
are constructed with that new database name, not an overridable database URL.
The candidate release is `/opt/psy-envio/releases/core-testnet-20261026` and
candidate unit is `psy-envio-fresh-20261026.service`; neither is installed.
No old `current` symlink is changed. Hasura v2.43.0 keeps bounded logs
(`100m`, `100`, compression) and nofile 65536/524288.

## Remaining Gates

Before installation, review the dependency lock and freeze compatible
Node/pnpm versions, then build only in a new local release directory. Run
frozen dependency installation, codegen with the real config, and ReScript
build. Generated workspace dependency resolution must also be frozen and
recorded. Dependencies must resolve inside this release; do not reuse old
mutable node_modules, generated files or pnpm hardlinks for in-place patches.
Node 22+ may need the existing yargs 17 CommonJS compatibility fix; validate
the selected Node runtime instead of silently assuming the old cache works.

After dependency compilation, the existing patch invocations are:

```sh
python3 patches/history.py --home "$ENVIO_HOME"
ENVIO_RPC_POLLING_INTERVAL_MILLIS=12000 python3 patches/polling.py --home "$ENVIO_HOME"
python3 patches/ordered.py "$ENVIO_HOME"
python3 patches/reorg.py "$ENVIO_HOME"
```

Only apply ordered failover when the supplied route list has a fallback.
Rebuild ReScript after patching, then repeat each applicable command with
`--check`; checks must pass on both source and emitted JS. Record the final
dependency/generated file hashes in a separate build manifest; the prepare
manifest remains an input inventory, not build approval. The runtime settings
include 12000ms polling, fresh-parent reorg checks and conditional ordered
failover. Do not run `envio dev`: it owns Docker/schema lifecycle.

Before any remote installation/activation, separately verify unused database,
role, release, project, container, unit and ports; exact existing PG identity;
private routing; and Hasura image provenance. Fresh bridge deployment already
authorizes creation/install/start of the new isolated database and services;
the main thread performs remote operations, not this local preparation branch.
Do not restart/recreate existing PG: its runtime
shared memory is currently 2 GiB while its Docker configuration is 64 MiB.
Do not run the old `install-envio.sh`, its bundle installer or its cleanup.

Credential wiring must keep Hasura and Envio on the same new database and
metadata endpoint; Services must use that Hasura's `/v1/graphql`. Envio's
`ENVIO_INDEXER_PORT` does not establish a private bind in 2.32.10; verify host
firewall/private reachability separately before startup. No unit is generated
until the built runtime and its protected writable paths are reviewed.

After the new schema exists, use the retained Deposit index tool in
plan/apply/verify modes against **only the new database**, after checking
`current_database()`. Before enabling consumers verify all three indexes,
all three `envio_chains.max_reorg_depth` values, metadata permissions, all
three indexed heads and chain-specific reads. No BridgeReader is involved.
Until these gates pass, `deployment_ready` and `release_approved` remain false.
