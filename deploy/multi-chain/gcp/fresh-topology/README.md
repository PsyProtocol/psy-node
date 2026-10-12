# Same-fleet fresh deployment preparation (2026-10-12)

## Decision and scope

The next deployment reuses the existing machines, but replaces the current testnet
state with a fresh cohort. This is NOT a state-preserving upgrade. Preparation is
authorized; stopping, clearing, contract deployment and publication have NOT been
performed by this change. Do not run old reset scripts against the expanded fleet.

Keep scripts in `deploy/` on `deploy/multi-chain-gcp`. Do not make another permanent
deployment branch. Integration of these scripts does not authorize deployment.
Frontend workflows remain owned by psy-dapp;
wallet extension publication remains owned by psy-wallet.

## Observed placement / next baseline

`topology.json` captures the Oct 12 read-only audit and the same-fleet baseline.
It is not an artifact lock or a declaration that the new release is ready.
Evidence is in workspace `tmp/topology-audit-20261012/*.json`; current hashes and
source gaps remain in `../live/components.json`. Offsite executable hashes could
not be independently read without operator sudo in this audit.

| Host | Roles to preserve in the next baseline |
| --- | --- |
| gcp-cp-ce | Coordinator Processor, 3 Coordinator Edges, Realm1 Processor, Realm0/1 Edges, Coordinator/Realm1 indexers |
| gcp-edge-1, gcp-edge-2 | Each has one Realm0 Edge and one Realm1 Edge |
| gcp-realm-processor | Realm0 Processor and Realm0 indexer; Realm1 has NOT migrated here |
| gcp-psy-service | Services API, independent of the three indexers |
| gcp-c4d-1 | 1 Coordinator Worker, 2 Realm0 Workers, 2 Realm1 Workers |
| gcp-coordinator-worker | Faucet, despite the historical SSH alias |
| gcp-faucet | Relayer; old Faucet listener is a compatibility forwarder |
| gcp-postgres | PostgreSQL, Envio, Hasura |
| gcp-scylla / gcp-redis / gcp-nats | Scylla / Valkey / NATS |
| gcp-nostr / gcp-gateway | Caddy + Nostr / WireGuard + forwarders |
| arc99x1 | User Proxy and user Nginx ingress, 75% of user requests |
| arc99x4 | User Proxy, 25% of user requests |
| arc99x2 | Installed User Proxy, not in the active upstream pool |
| arc99x3 | System Proxy; no active user role |

Public routing: Caddy -> 3 Coordinator Edges; Caddy -> 3 Edges per Realm;
Services -> `.38:3000`; Faucet -> `.33:9998`; Hasura -> `.24:18080`.
User proofs: Caddy -> gateway `.32:19999` -> x1 `10.250.0.13:9999` -> x1/x4.
System proofs: gateway -> x3 `10.250.0.12:9998`.
These are request weights, not proof-time or CPU-share guarantees.

All DB and queue access must use the VPC; offsite access goes via WireGuard.
Host IPs may be null only if that host is an SSH deployment destination, not an
endpoint rendered by these steps. Never substitute an external address to fill it.
Secrets, wallets and authenticated RPC URLs do not belong in topology.json.

## Sequential entrypoints

No SSH or private config sourcing occurs in this plan:

```bash
bash deploy/multi-chain/gcp/fresh-topology/run-step.sh plan
bash deploy/multi-chain/gcp/fresh-topology/run-step.sh 12-realm0-edges
bash deploy/multi-chain/gcp/fresh-topology/run-step.sh 12-realm0-processor
bash deploy/multi-chain/gcp/fresh-topology/run-step.sh readiness
```

`readiness` deliberately exits 2 while release blockers remain. This is expected.
Each named step invokes existing component installers, using a protected temporary
config overlay. The overlay is applied after the private config every time it is
sourced. Merely exporting NODE_VM_NAME is insufficient: legacy installers source
the config again and can silently undo the target override.

| Step | Installs | Required completion evidence |
| --- | --- | --- |
| 12-coordinator-edges | Three replicas with distinct ports/units, same logical 0/0 | RPC works on each; identical sealed checkpoint/root |
| 12-realm0-edges / 12-realm1-edges | Three per Realm | Correct realm identity; same checkpoint/root within each pool |
| 12-coordinator-processor | One CP, same host for now | Progress after workers start; no duplicate processor |
| 12-realm0-processor | Realm0 on the new host | RPC progress and accepted GUTA |
| 12-realm1-processor | Realm1 still on cp-ce | Same checks; do not silently migrate |
| 12-services | API on the dedicated host | Health, Genesis users, claimable response and configured private endpoints |
| 12-indexers | Three indexers on their recorded hosts | Watermarks advance; events reach the new Services, not old local port 3000 |
| 13-faucet | On former cloud-worker host | Faucet config RPC; one authorized grant completes |
| 14-workers | Five workers on c4d | Each role has real pickup/prove/submit evidence |
| 16-relayer | Existing relayer host; explicit Services address | Three L1 cursors and settlement advance; correct System endpoint and fee policy |
| 17-caddy | Recreate Nostr after reset, then render multi-upstream public routes | Each backend ready before reload; public RPC and API checks |

The old step 12 dispatches to `12-nodes` when DEPLOY_TOPOLOGY_FILE is set;
steps 14, 16, 17 similarly use the inventory. Individual substeps remain callable.
For a combined dry plan only:

```bash
GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.split.example.env" \
  bash deploy/multi-chain/gcp/deploy_all.sh --plan

# Same numbered entrypoint, now select a single distributed component:
GCP_DEPLOY_CONFIG="$PWD/deploy/multi-chain/gcp/config.split.example.env" \
  bash deploy/multi-chain/gcp/deploy_all.sh --plan --only 43
```

The split profile selects `fresh-topology/steps.tsv`, leaving the historical
single-chain and old multi-chain plans unchanged. Step IDs denote resumable
operations, not numeric sort order: 04 builds first, 40/41 install Realm Edges,
42/43/44 install processors, 45 Services, 46 indexers and 47 Faucet. Step 32 is
last. `--from`, `--until` and `--only` retain their existing selection semantics.

After ALL blockers are actually resolved, a reviewed private config and new source
lock are required for `run-step.sh <step> --apply --config <absolute-path>
--versions <absolute-path>`, plus CONFIRM_FULL_FRESH_DEPLOY=1. The current checked-in
inventory refuses activation. Removing blocker text is not a substitute for the
implementation and acceptance work below. Legacy per-component checks prove startup,
not the whole completion column; transaction validation must be recorded separately.

Worker unit names in the generic fresh installer are `parth-worker@...`, whereas
the current machine uses `parth-c4d-worker@...`. The stop/retirement inventory must
disable the old units before starting new ones, including their boot enablement.
Do not use this adapter for a live worker replacement or enable both sets.
`workers.key_indexes` must explicitly map every instance to a reviewed Genesis
key index before the Worker step can apply. Sharing a reward identity remains
allowed when deliberately configured; silent installer defaults are not accepted.
The checked-in map is null pending the next Genesis/identity review.

Every step labelled BLOCKED in the step list also has a hard execution refusal,
independent of the JSON release blocker list. Both the missing implementation and
its acceptance evidence are required before removing those markers.

## Script reconciliation / remaining release gates

| Existing script or record | Problem | Required resolution |
| --- | --- | --- |
| fresh-staging/01_stop_parth_services.sh, _common.sh | Old fixed host enumeration, wildcard stops, ignored failures | Explicit unit inventory for all 18 hosts, all old and new writer roles; prove no writers remain before reset |
| 02_clear_parth_state.sh / 03_clear_database_state.sh | Old paths/DB scope; later hotfix releases and drop-ins survive | Reviewed positive path/keyspace/database allowlist and archive, no broad parth-* deletion |
| 04_prepare_local_bundle.sh | Historically executed after destructive cleanup | Freeze/build/hash artifacts BEFORE downtime; upload and preflight before clearing |
| 12_deploy_cp_ce_stack.sh | Monolithic host and localhost assumptions | Split adapter implemented here; distributed DB credentials / final config still need release validation |
| 13_deploy_prove_proxy.sh | One offsite host, old all-role installer | Replace with explicit x1/x2/x4 user and x3 system installers, CPU/GPU targets and operator sudo gates |
| 14_deploy_workers.sh | Old 3-worker host/layout | Five-worker adapter implemented; retire old c4d units during reset |
| 16_deploy_relayer.sh | Stale artifact record, endpoint/fee-policy risk | Use new cohort artifact; preserve tested fee/failover behavior, batch 64; verify generated TOML and system URL |
| 17_deploy_caddy_entrypoints.sh | Single default upstream | Pools and dedicated API/Faucet hosts rendered from topology; no ambiguous POST retries |
| deploy-monitoring.sh / live/collect.py | Static old host and role lists | Derive monitored expected units from the expanded inventory; monitoring last; no stale missing-worker alerts |
| source-versions.env | Historical full release, not current hotfix set | Freeze next full-cohort exact SHAs and build metadata, separately from the observed-live component map |
| live/components.json | Mixed-age record, some local-only edits | Reconcile after each successful activation; do not pretend one SHA identifies every old binary |

Current example DB endpoints use explicit RFC1918 addresses. The adapter also
checks the effective config before each component installer: database/queue URL
overrides must use literal private IPs, including PSY_SERVICES_DATABASE_URL and
ENVIO_DATABASE_URL. Public addresses and DNS names fail closed without printing
credentials. This check does not replace firewall/ACL tests or inspecting the
generated runtime files (which remain a release gate).

## Full fresh-deploy order (not yet executable end to end)

1. Approve exact source cohort and protocol identity. The previously approved magic
   is `0x1337CF514544CF69`; renaming a stage must not silently change it. Build one
   coherent Node/Genesis/compiler/Services/SDK/wallet/contracts cohort. Native GPU,
   AVX-512 and generic outputs need compatible fingerprints and separate hashes.
2. Build before interruption. Verify disk, CPU ISA, ports, private DB reachability,
   all deployment and relayer wallet balances, backups and restore procedure.
3. Announce maintenance, gate public transaction entrypoints and auto-publish jobs.
   Stop all writers using the reviewed inventory: relayer, Faucet, proxies, workers,
   Edges/Processors, Services/subscribers, three indexers and Envio. Include retired
   units/drop-ins and manually launched test processes. A failed stop blocks reset.
4. Back up chain data/config/receipts and record rollback boundary; then clear only
   approved testnet namespaces, checkpoint/proof/queue state, indexer and Envio data.
   Decide the Nostr retention boundary explicitly: retained old-chain notes must
   not be re-ingested into the fresh database. Do not wipe unrelated services.
5. Start database infrastructure; deploy fresh pUSDT/bridge contracts on ALL three
   L1s, generate a single deployment registry and setup, then Envio. Existing L1
   contracts cannot be erased; old addresses/receipts are retired, not overwritten.
6. Deploy Edges, processors, workers and the role-specific proxies. Verify real
   checkpoint progress and fingerprints, then Services and all three indexers.
   Before exposing any route, verify its complete internal dependency chain.
7. Deploy Faucet and relayer, verify balances/liquidity, limits, RPC failover and
   batch 64. Verify effective Envio 12000 ms polling, timestamp/history patches
   where still required by the selected Envio version; restart alone is not proof.
8. Switch Caddy and publish the config cohort; DApp and wallet pipelines publish
   matching frontend/SDK artifacts. Include Bridge, Explorer, Wallet site, IDE and
   Config; a Node script must not silently publish old frontend snapshots.
9. Run protocol E2E plus deposit/claim/withdraw on Sepolia/BSC/Base using fixed test
   wallets. Reconcile L1 receipts and L2 state; observe memory and indexer lag.
10. Install/enable the correct collectors and probes LAST, remove maintenance,
    record deployed per-component executable SHA/config hash and final acceptance.

Preserve funded wallet/private keys and encrypted keystores, WireGuard keys/peers,
SSH, TLS/ACME and provider credentials. Preserve local Reth/BSC node data, unrelated
databases and monitoring history. Proving setup is NOT a wallet key: archive old
setup and install the new cohort's verified setup without mixing files.
Once new L1 contracts or fresh L2 state are used, rollback is not just changing a
binary symlink. It requires a coherent old cohort + old contracts/config + approved
data restore, and must account for new transactions. No automatic destructive retry.

## Later architecture changes

Coordinator Edge hosts are independent inventory entries, not inferred from the
Processor host. Moving one changes its deployment, Caddy pool, Worker URLs, Realm
Processor URLs, Services RPC and indexer RPC together. It does not provision or
resize a VM. Update ACLs, monitoring and generated Genesis/runtime client endpoints
at the same time; scripts using direct old port 1337 need separate audit.

Keep CP's current size for this baseline. A future 4 vCPU / 8 GiB target is a
candidate for the PROCESSOR, not a sizing approval for the current cp-ce stack:
that host still has three Coordinator Edges, Realm1 Processor, two Realm Edges and
two indexers. First move the intended roles, then measure CP peak RSS/CPU and
checkpoint throughput under load before resizing. Do not shrink it now.

## Local verification

```bash
python3 -m unittest discover -s deploy/multi-chain/gcp/fresh-topology -p 'test_*.py'
bash deploy/gcp/tests/test-multichain-deploy-runner.sh
```

Offline tests are not a release build, a destructive deployment rehearsal, a live
health check, or approval to clear this testnet.

Preparation validation on Oct 12: the Python regression suite passed; the historical
multichain runner regression and multichain profile/Caddy fixtures also passed.
This includes plan-only isolation, early reset blocking, private endpoint checks,
split placement, config re-sourcing, round-robin pool rendering and step selection.
No online service was modified, no data was cleared, and no new-cohort binary was
built by this preparation task. Git history records script publication separately
from online deployment.
