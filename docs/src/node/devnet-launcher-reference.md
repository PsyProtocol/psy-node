# Devnet Launcher Reference

> Status: Approved. Date: 2026-09-02. Audience: developers and devnet operators.

## Abstract

`dev/locSetupV4.ts` is the source of truth for launcher internals: startup flags, environment interpretation,
process construction, readiness, supervision, control commands, ports, persistent Anvil recovery, and teardown.
Use the Make targets for the repository-supported operating lifecycle, and use direct launcher commands only when
selecting a documented component set or diagnosing launcher behavior. The lifecycle procedure remains owned by
`docs/src/node/devnet_lifecycle.md`; this reference explains how the launcher implements that procedure
(`docs/src/node/devnet_lifecycle.md:5-7`; `Makefile:60-79`; `dev/locSetupV4.ts:5289-5648`).

## Motivation

The launcher combines repository setup, resource allocation, persistent infrastructure, application startup,
readiness gates, process supervision, local Layer 1 persistence, and destructive cleanup in one entry point
(`dev/locSetupV4.ts:2579-2621`; `dev/locSetupV4.ts:3788-4689`; `dev/locSetupV4.ts:5072-5080`). Operators therefore
need one source-grounded map that distinguishes supported Make commands from direct launcher mechanics, especially
because a bare launcher invocation and `make run-all` select different counts, and because the embedded help contains
current-source defects that must not be copied into commands (`Makefile:60-66`; `dev/locSetupV4.ts:5297-5303`;
`dev/locSetupV4.ts:5419-5424`; `dev/locSetupV4.ts:5440-5462`).

## Table of Contents

- [Abstract](#abstract)
- [Motivation](#motivation)
- [Table of Contents](#table-of-contents)
- [Terminology and Abbreviations](#terminology-and-abbreviations)
- [1. Source-of-Truth Boundary](#1-source-of-truth-boundary)
- [2. Startup Sequence](#2-startup-sequence)
- [3. Authoritative Process DAG](#3-authoritative-process-dag)
- [4. Startup Mode Selection](#4-startup-mode-selection)
  - [4.1 Bare Launcher Defaults](#41-bare-launcher-defaults)
  - [4.2 Make run-all](#42-make-run-all)
  - [4.3 Component Selection](#43-component-selection)
- [5. Complete CLI Option Reference](#5-complete-cli-option-reference)
- [6. Environment Variable Reference](#6-environment-variable-reference)
  - [6.1 Network and Anvil](#61-network-and-anvil)
  - [6.2 Repository Setup and Build](#62-repository-setup-and-build)
  - [6.3 Keystore and Credentials](#63-keystore-and-credentials)
  - [6.4 Resources, Logging, and Supervision](#64-resources-logging-and-supervision)
  - [6.5 Faucet and Service Forwarding](#65-faucet-and-service-forwarding)
- [7. Foreground Process Inventory and Readiness](#7-foreground-process-inventory-and-readiness)
- [8. Ports and P2P Formulas](#8-ports-and-p2p-formulas)
- [9. CPU Partition and Rayon Derivation](#9-cpu-partition-and-rayon-derivation)
- [10. Anvil Persistence and Restart Recovery](#10-anvil-persistence-and-restart-recovery)
- [11. Control Socket and Application Lifecycle](#11-control-socket-and-application-lifecycle)
- [12. Auto-Restart](#12-auto-restart)
- [13. Teardown and Purge](#13-teardown-and-purge)
- [14. Daemonized Path Differences](#14-daemonized-path-differences)
- [15. Source-Accurate Command Recipes](#15-source-accurate-command-recipes)
  - [Supported Make lifecycle](#supported-make-lifecycle)
  - [Bare foreground full mode](#bare-foreground-full-mode)
  - [Self-contained two-Realm core without Layer 1, bridge, or UIs](#self-contained-two-realm-core-without-layer-1-bridge-or-uis)
  - [Realm P2P core](#realm-p2p-core)
  - [Proxy-only component](#proxy-only-component)
  - [Dummy provers against an existing core](#dummy-provers-against-an-existing-core)
  - [Direct non-purge and purge teardown](#direct-non-purge-and-purge-teardown)
- [16. Failure Diagnosis](#16-failure-diagnosis)
- [17. Current-Source Limitations](#17-current-source-limitations)
- [18. Core Data Structures](#18-core-data-structures)
  - [`ProcessOptions`](#processoptions)
  - [`RuntimeResourceSettings`](#runtimeresourcesettings)
  - [`LocalAnvilStatePlan`](#localanvilstateplan)
  - [`DevnetControlResponse`](#devnetcontrolresponse)
- [19. Core Functions and Call Trace](#19-core-functions-and-call-trace)
  - [`runMain()`](#runmain)
  - [`DevNetProcessManager.setupProcesses()`](#devnetprocessmanagersetupprocesses)
  - [`resolveRuntimeResourceSettings()`](#resolveruntimeresourcesettings)
  - [`resolveLocalAnvilStatePlan()`](#resolvelocalanvilstateplan)
  - [`stopApplications()`, `startApplications()`, and `restartApplications()`](#stopapplications-startapplications-and-restartapplications)
- [20. Core Loops](#20-core-loops)
  - [Foreground Realm startup loop](#foreground-realm-startup-loop)
  - [Supervisor restart loop](#supervisor-restart-loop)
  - [Control command queue](#control-command-queue)
- [21. Rationale](#21-rationale)
- [22. Security Considerations](#22-security-considerations)

## Terminology and Abbreviations

| Term | Meaning in this reference | Evidence |
|---|---|---|
| CLI | Command-line interface parsed by `runMain()`. | `dev/locSetupV4.ts:5289-5329` |
| CPU | Central processing unit; the launcher partitions complete physical-core sibling groups on Linux. | `dev/locSetupV4.ts:161-195`; `dev/locSetupPolicy.ts:82-180` |
| DAG | Directed acyclic graph; the ordered startup dependencies in section 3. | `dev/locSetupV4.ts:3866-4689` |
| HTTP | Hypertext Transfer Protocol, used for coordinator, Realm, Layer 1, Envio, and service readiness. | `dev/locSetupV4.ts:4254-4302`; `dev/locSetupV4.ts:4306-4425` |
| JSON | JavaScript Object Notation, used by genesis, deployment summaries, control replies, and faucet configuration. | `dev/locSetupV4.ts:1008-1041`; `dev/locSetupV4.ts:5202-5212` |
| L1 | Layer 1: local Anvil, a forked Anvil, Sepolia, or Ethereum. | `dev/locSetupV4.ts:246-257`; `dev/locSetupV4.ts:4254-4302` |
| L2 | Layer 2: Coordinator and Realm processors, edges, workers, checkpoints, services, and indexers. | `dev/locSetupV4.ts:3902-4480` |
| LWT | Lightweight transaction; the launcher configures Scylla contention and write timeouts. | `dev/locSetupV4.ts:4737-4753`; `dev/start_db.sh:123-171` |
| NATS | The NATS JetStream messaging service in persistent infrastructure. | `dev/start_db.sh:109-120` |
| Nostr | The local Nostr relay in persistent infrastructure. | `dev/start_db.sh:184-227` |
| P2P | Peer-to-peer Realm transport enabled by `--realm-p2p`. | `dev/locSetupV4.ts:958-1138`; `dev/locSetupV4.ts:5304` |
| RPC | Remote procedure call endpoint exposed by Layer 1, Coordinator edges, and Realm edges. | `dev/locSetupV4.ts:3937-3957`; `dev/locSetupV4.ts:4063-4084` |
| SMP | Symmetric multiprocessing shard count supplied to Scylla. | `dev/locSetupV4.ts:203-221`; `dev/start_db.sh:132-171` |
| TCP | Transmission Control Protocol, used by launcher port readiness gates. | `dev/locSetupV4.ts:3866-3886`; `dev/locSetupV4.ts:4234-4246` |
| UI | User interface: Privacy Bridge, IDE, Explorer, or Mode A Web Wallet Bridge. | `dev/locSetupV4.ts:4556-4689` |

## 1. Source-of-Truth Boundary

This document owns `dev/locSetupV4.ts` internals: parser behavior, startup selection, environment flow, process DAG,
ports, Anvil persistence, supervision, control commands, daemonized behavior, and current-source limitations
(`dev/locSetupV4.ts:123-225`; `dev/locSetupV4.ts:3337-3753`; `dev/locSetupV4.ts:3788-5285`).

`docs/src/node/devnet_lifecycle.md` remains the authority for fresh-start, restart, rollback, and verification
procedure; it explicitly names the supported Make entry points and defines their required operating order
(`docs/src/node/devnet_lifecycle.md:5-7`; `docs/src/node/devnet_lifecycle.md:44-59`;
`docs/src/node/devnet_lifecycle.md:93-146`). When this reference describes a direct launcher command, it describes
source behavior, not a replacement lifecycle procedure.

Persistent infrastructure means **Anvil, Scylla, Redis/Valkey, NATS, Nostr, and Envio backing services**. Applications
means **processors, edges, workers, proxy, faucet, services, indexers, relayer, and UIs**. The control classifier keeps
tracked processes named `db` and `l1_anvil`; the `db` process supervises Scylla, Redis/Valkey, NATS, and Nostr, while
Envio Postgres and Hasura are Docker backing services outside the tracked process list
(`dev/locSetupV4.ts:3339-3346`; `dev/start_db.sh:83-227`; `dev/locSetupV4.ts:3010-3208`). The tracked Envio `pnpm start`
indexer is an application even though its Docker backing services are persistent infrastructure
(`dev/locSetupV4.ts:3195-3208`; `dev/locSetupV4.ts:3339-3346`).

## 2. Startup Sequence

```mermaid
sequenceDiagram
    participant Operator
    participant Launcher
    participant Infra as Persistent infrastructure
    participant Core as Processors and edges
    participant Apps as Applications
    participant Control as Control socket

    Operator->>Launcher: 1. Make target or direct CLI
    Launcher->>Launcher: 2. Parse flags, environment, and acquire lock
    Launcher->>Launcher: 3. Auto-setup repositories, artifacts, and tools
    Launcher->>Infra: 4. Start DB group and wait for TCP readiness
    Launcher->>Core: 5. Start processors, edges, and workers in dependency order
    Launcher->>Infra: 6. Start or connect to L1; deploy or reuse contracts
    Launcher->>Apps: 7. Start Envio, services, indexers, relayer, faucet, and UIs
    Launcher->>Control: 8. Open repository-keyed Unix socket
    Control-->>Operator: 9. Supervisor ready
```

Steps 1-3 are implemented by CLI parsing, lock acquisition, and `ensureDevEnvironment()`
(`dev/locSetupV4.ts:5289-5378`; `dev/locSetupV4.ts:5498-5558`). Steps 4-7 are the foreground
`setupProcesses()` phases (`dev/locSetupV4.ts:3866-4689`). The control socket opens only after
`setupProcesses()` resolves, so startup-time failures cannot be repaired through `make restart`
(`dev/locSetupV4.ts:5613-5628`).

## 3. Authoritative Process DAG

The following ASCII graph is authoritative for the foreground path; conditional nodes run only when selected by the
mode logic in section 4 (`dev/locSetupV4.ts:3788-3805`).

```text
resource derivation + logs + release-binary gate
  |
  v
DB group: Redis/Valkey + NATS + Scylla + Nostr
  |  readiness: group marker, then TCP 6379, 4222, 9042
  v
optional Realm P2P key generation + genesis validator injection
  |
  v
Coordinator processor
  |
  v
Coordinator edges (parallel)
  |
  v
Realm processors in batches of at most four
  |  processors sequential inside a batch
  v
Realm edges for that batch (parallel), then two-second spacing
  |
  v
Coordinator workers (after the complete Realm processor/edge phase)
  |
  v
Realm workers (parallel) -> dummy provers (parallel)
  |
  v
Prove proxy processes; TCP warm-up continues concurrently
  |
  v
Anvil or external L1 -> contract deploy/reuse
  |
  v
Envio Postgres + Hasura -> Envio indexer API
  |
  v
psy-services -> Coordinator indexer -> Realm indexers
  |
  +--------------------+
  |                    |
  v                    v
faucet              relayer
  |                    |
  +----------+---------+
             |
             v
Nostr readiness -> Privacy Bridge -> IDE -> Explorer -> Mode A UI
             |
             v
control socket + steady-state supervisor
```

The DB phase starts `dev/start_db.sh --persist` and then probes ports 6379, 4222, and 9042
(`dev/locSetupV4.ts:3866-3886`). Coordinator startup precedes Realm batching
(`dev/locSetupV4.ts:3902-4098`). Coordinator workers explicitly await the full Realm phase, not only the Coordinator
phase (`dev/locSetupV4.ts:3993-4004`; `dev/locSetupV4.ts:4098`). Workers, dummy provers, proxy, Layer 1, bridge
services, faucet, relayer, and UIs follow in source order (`dev/locSetupV4.ts:4100-4689`).

## 4. Startup Mode Selection

### 4.1 Bare Launcher Defaults

```bash
bun run dev/locSetupV4.ts
```

A bare invocation has no component selector, so `startAll` is true. Its defaults are one Realm beginning at Realm 0,
one Coordinator edge, one Realm edge, one Coordinator worker, two Realm workers, one implicit prove proxy, and the
full foreground infrastructure/application set (`dev/locSetupV4.ts:5297-5303`; `dev/locSetupV4.ts:5333-5342`;
`dev/locSetupV4.ts:3788-3805`; `dev/locSetupV4.ts:4212-4219`).

### 4.2 Make run-all

```bash
make run-all
```

`make run-all` does **not** rely on bare defaults. It expands an explicit component list with two Realms, two
Coordinator workers, one Realm worker, one prove proxy, the database group, Coordinator/Realm nodes, faucet, Layer 1,
relayer stack, and all four UI flags (`Makefile:60-66`). It also defaults `PSY_SKIP_BRANCH_CHECK`,
`PSY_SKIP_KEYSTORE`, and `PSY_SKIP_BUILD` to `1`, whereas a direct launcher invocation has no intrinsic
`PSY_SKIP_BUILD=1` default (`Makefile:13-15`; `Makefile:66`; `dev/locSetupV4.ts:1765-1800`).

| Setting | Bare launcher | `make run-all` | Evidence |
|---|---:|---:|---|
| Realm count | 1 | 2 | `dev/locSetupV4.ts:5302-5342`; `Makefile:60` |
| Coordinator workers | 1 | 2 | `dev/locSetupV4.ts:5340`; `Makefile:60` |
| Realm workers | 2 | 1 | `dev/locSetupV4.ts:5333-5337`; `Makefile:60` |
| Prove proxy | Implicit 1 | Explicit 1 | `dev/locSetupV4.ts:4212-4219`; `Makefile:60` |
| Build policy | Build when required unless environment disables it | Existing artifacts required by default | `dev/locSetupV4.ts:1765-1800`; `Makefile:15,66` |

### 4.3 Component Selection

The component selectors are `--db`, `--coordinator`, `--prove-proxy`, `--faucet-server`, `--dummy-provers`, `--l1`,
`--relayer`, `--bridge-proposer-daemon`, `--psy-privacy-bridge`, `--ide`, `--explorer`, and
`--mode-a-web-wallet-bridge` (`dev/locSetupV4.ts:5333`). Any selector disables top-level full-mode worker defaults;
explicit worker counts then control worker startup (`dev/locSetupV4.ts:5333-5340`). Modifiers such as
`--realm-workers`, `--realm-p2p`, `--realms-count`, `--host`, `--env`, and `--daemonlize` are not selectors, so using
one alone modifies a full launch (`dev/locSetupV4.ts:5297-5326`; `dev/locSetupV4.ts:5333`). Selectors do not pull all
runtime dependencies: for example, `--coordinator` does not select `--db`, `--relayer` does not select Layer 1 or the
core, and `--psy-privacy-bridge` does not select Nostr (`dev/locSetupV4.ts:3788-3805`;
`dev/locSetupV4.ts:4304-4554`; `dev/locSetupV4.ts:4556-4568`).

## 5. Complete CLI Option Reference

Numeric string options are converted with `parseInt(..., 10)` without positive-integer validation at the parser
boundary (`dev/locSetupV4.ts:5338-5350`; `dev/locSetupV4.ts:5373`).

| Option | Type and effective default | Source-accurate effect | Evidence |
|---|---|---|---|
| `--jtmb` | Boolean, false | Chooses `jtmb-poseidon-goldilocks` only when `--proving-backend` is absent. | `dev/locSetupV4.ts:5294-5295`; `dev/locSetupV4.ts:3840` |
| `--proving-backend VALUE` | String, Plonky2 fallback | Supplies processor, worker, dummy-prover, and daemonized backend arguments. | `dev/locSetupV4.ts:3461-3475`; `dev/locSetupV4.ts:3840-4204` |
| `--disable-worker-edge-logs` | Boolean, false | Omits launcher log files for workers and edges in foreground mode. | `dev/locSetupV4.ts:3829-3837` |
| `--realm-workers COUNT` | 2 full / 0 component | Starts shared Realm workers; a positive value also counts toward Rayon sizing. | `dev/locSetupPolicy.ts:303-315`; `dev/locSetupV4.ts:3802-3811`; `dev/locSetupV4.ts:4100-4191` |
| `--realm-edge-nodes COUNT` | String, `1` | Sets edge count per Realm/sub-ID and changes HTTP port stride. | `dev/locSetupV4.ts:5298,5338`; `dev/locSetupV4.ts:1041-1044` |
| `--coordinator-edge-nodes COUNT` | String, `1` | Starts Coordinator edges on `1337 + index`. | `dev/locSetupV4.ts:5299,5339`; `dev/locSetupV4.ts:3937-3957` |
| `--coordinator-workers COUNT` | 1 full / 0 component | Starts Coordinator workers after Realm readiness. | `dev/locSetupV4.ts:5340`; `dev/locSetupV4.ts:3963-4004` |
| `--start-realm-id ID` | String, `0` | Sets the inclusive first Realm ID. | `dev/locSetupV4.ts:5301,5341`; `dev/locSetupV4.ts:3799-3801` |
| `--realms-count COUNT` | String, `1` | Sets the number of consecutive Realm IDs. | `dev/locSetupV4.ts:5302,5342`; `dev/locSetupV4.ts:3799-3801` |
| `--host HOST` | String, `127.0.0.1` | Builds core DB, NATS, Redis, Coordinator, worker, and P2P addresses; it is not the Anvil host setting. | `dev/locSetupV4.ts:5303,5343`; `dev/locSetupV4.ts:3461-3472`; `dev/locSetupV4.ts:490-493` |
| `--realm-p2p` | Boolean, false | Uses sub-IDs 1 and 2, generates/reuses validator keys, injects genesis validators, and adds P2P arguments. | `dev/locSetupV4.ts:5304,5363`; `dev/locSetupV4.ts:958-1138`; `dev/locSetupV4.ts:3888-3900` |
| `--genesis-data-path PATH` | String, `genesis.json` | Supplies processor genesis and is rewritten with P2P validators or an empty validator list. | `dev/locSetupV4.ts:5306,5344`; `dev/locSetupV4.ts:1008-1041` |
| `--coordinator` | Boolean selector | Starts Coordinator processor/edges and Realm processors/edges; it does not select DB. | `dev/locSetupV4.ts:3788-3801`; `dev/locSetupV4.ts:3902-4098` |
| `--db` | Boolean selector | Starts `dev/start_db.sh --persist`: Redis/Valkey, NATS, Scylla, and Nostr. | `dev/locSetupV4.ts:3866-3886`; `dev/start_db.sh:83-227` |
| `--dummy-provers COUNT` | String, `0` | Starts dummy prover scripts for the selected Realm range; daemon mode emits none. | `dev/locSetupV4.ts:4193-4210`; `dev/locSetupV4.ts:4693-5069` |
| `--prove-proxy COUNT` | String, `0`; full foreground implies 1 | Starts proxy listeners on `9999 + index`. | `dev/locSetupV4.ts:4212-4246` |
| `--faucet-server` | Boolean selector | Starts faucet on 9998 after same-launch proxy readiness, when proxies exist. | `dev/locSetupV4.ts:4483-4512` |
| `--l1` | Boolean selector | Starts local/forked Anvil or probes external Layer 1, then deploys/reuses contracts. | `dev/locSetupV4.ts:4254-4302` |
| `--relayer` | Boolean selector | Starts Envio backing services/indexer, psy-services, indexers, and relayer; external core/Layer 1 dependencies must exist in component mode. | `dev/locSetupV4.ts:4304-4554` |
| `--relayer-config PATH` | String, local TOML path | Supplies Envio/dependency configuration; the launcher generates a separate relayer daemon config. | `dev/locSetupV4.ts:4304-4323`; `dev/locSetupV4.ts:4517-4549` |
| `--bridge-proposer-daemon` | Boolean selector | Enables relayer application selection but has a current duplicated-mode defect described in section 17. | `dev/locSetupV4.ts:5333,5353`; `dev/locSetupV4.ts:3788-3792` |
| `--psy-privacy-bridge` | Boolean selector | Waits for Nostr and starts the bridge UI on 5177. | `dev/locSetupV4.ts:4556-4589` |
| `--ide` | Boolean selector | Starts the IDE on 5176. | `dev/locSetupV4.ts:4592-4611` |
| `--explorer` | Boolean selector | Starts Explorer on 5178. | `dev/locSetupV4.ts:4614-4638` |
| `--mode-a-web-wallet-bridge` | Boolean selector | Starts the Mode A UI on 5179 only when every `link:` package resolves. | `dev/locSetupV4.ts:4640-4689` |
| `--daemonlize` | Boolean modifier | Generates root `docker-compose.yml`, starts its limited service set, releases the lock, and exits. | `dev/locSetupV4.ts:4693-5069`; `dev/locSetupV4.ts:5609-5612` |
| `--clean-state` | Boolean, deprecated | Sets startup `cleanState`; it is not a purge teardown flag. | `dev/locSetupV4.ts:5321,5362`; `dev/locSetupV4.ts:3866-3871` |
| `--teardown` | Boolean | Skips auto-setup and startup lock, stops known processes/containers/ports, and exits. | `dev/locSetupV4.ts:5498-5507`; `dev/locSetupV4.ts:5550-5577` |
| `--purge` | Boolean | Adds destructive deletion only to teardown; it also sets startup `cleanState`. | `dev/locSetupV4.ts:5360-5362`; `dev/locSetupV4.ts:3282-3300` |
| `--control COMMAND` | String | Sends exactly `restart`, `rollback-stop`, or `rollback-resume` to a live foreground supervisor. | `dev/locSetupV4.ts:5171-5189`; `dev/locSetupV4.ts:5368-5372` |
| `--env ASSIGNMENTS` | String | Parses nonempty shell-style `KEY=VALUE` assignments; CLI values override inherited values for foreground children. | `dev/locSetupPolicy.ts:42-56`; `dev/locSetupV4.ts:3755-3767` |
| `--help`, `-h` | Boolean | Prints embedded help after network and environment resolution, then exits. | `dev/locSetupV4.ts:5373-5396`; `dev/locSetupV4.ts:5396-5495` |

## 6. Environment Variable Reference

Foreground managed children receive inherited launcher environment, then `--env` overrides, then normalized resource
values, then service-specific overrides (`dev/locSetupV4.ts:3755-3767`; `dev/locSetupV4.ts:3806-3811`;
`dev/locSetupV4.ts:4400-4416`). Daemonized containers receive only the filtered set described in section 14
(`dev/locSetupV4.ts:4758-4765`).

### 6.1 Network and Anvil

| Variable | Default and validation | Effect | Evidence |
|---|---|---|---|
| `VITE_NETWORK` | `localhost`; accepts `localhost`, `sepolia`, `ethereum` | Selects network metadata, deployment namespace, external RPC, and UI network. | `dev/locSetupV4.ts:482-487`; `dev/locSetupV4.ts:3780-3786` |
| `VITE_FORK` | False; truthy: `1`, `true`, `yes`, `on` | Requires non-local network and starts local Anvil from the selected external RPC. | `dev/locSetupV4.ts:118-121`; `dev/locSetupV4.ts:246-257`; `dev/locSetupV4.ts:4267-4275` |
| `VITE_FORK_BLOCK_NUMBER` | Unset | Adds Anvil `--fork-block-number`; launcher only trims, not numerically validates, it. | `dev/locSetupV4.ts:4273-4274` |
| `SEPOLIA_RPC_URL` | Required by configured Sepolia entry | Supplies direct Sepolia RPC or fork source. | `psy-genesis/config.json:125-128`; `dev/locSetupV4.ts:495-505` |
| `ETH_RPC_URL` | Required by configured Ethereum entry | Supplies direct Ethereum RPC or fork source. | `psy-genesis/config.json:193-196`; `dev/locSetupV4.ts:495-505` |
| `L1_RPC_HOST` | `127.0.0.1` | Changes the URL used to reach local Anvil; Anvil still binds `0.0.0.0`. | `dev/locSetupV4.ts:490-493`; `dev/locSetupV4.ts:4263-4265` |
| `REDEPLOY_L1` | Redeploy unless `0`, `false`, `no`, or `off` | Controls external deployment reuse; persisted localhost reuse is governed by the state/deployment pair. | `dev/locSetupV4.ts:506-511`; `dev/locSetupV4.ts:2813-2841` |
| `DEV_PSY_SOURCE_ADDRESS` | Deployment constructor source, then deployer | Selects the impersonated PSY funding source for local/fork accounts. | `dev/locSetupV4.ts:443-447` |
| `DEV_FUND_EXTRA_ADDRESSES` | Empty comma-separated list | Adds addresses to local/fork development funding. | `dev/locSetupV4.ts:451-477` |

### 6.2 Repository Setup and Build

| Variable | Default | Effect | Evidence |
|---|---|---|---|
| `PSY_PROJECTS_DIR` | Parent of repository root | Locates sibling `psy-services`, `psy-wallet`, `psy-sdk`, and `psy-compiler` repositories. | `dev/locSetupV4.ts:1494-1518` |
| `PSY_SKIP_BRANCH_CHECK` | Direct source treats every value except exact `0` as skip; Make default `1` | Exact `0` fetches expected branches, stashes dirty/untracked changes, and checks out remote refs detached. | `dev/locSetupPolicy.ts:300-303`; `dev/locSetupV4.ts:1559-1584`; `Makefile:13` |
| `PSY_SKIP_BUILD` | Direct default off; Make default `1` | Exact `1` requires existing release binaries and current generated artifacts instead of building. | `dev/locSetupV4.ts:1765-1800`; `Makefile:15` |
| `PSY_CONFIG_PATH` | Repository Genesis config | Supplies build configuration to Make and fallback Cargo builds. | `Makefile:3,22-34`; `dev/locSetupV4.ts:2633-2656` |

### 6.3 Keystore and Credentials

| Variable | Default | Effect | Evidence |
|---|---|---|---|
| `HOME` | Required | Locates trust setup and default relayer keystore. | `dev/locSetupV4.ts:2308-2313`; `dev/locSetupV4.ts:2800-2805` |
| `KEYSTORE_PATH` | `${HOME}/.psy/keystore/bridge-relayer` | Overrides only the bridge-relayer wallet path. | `dev/locSetupV4.ts:263-269`; `dev/locSetupV4.ts:2861-2866` |
| `WALLET_PASSWORD` | Prompt/policy; generated development keystore can use development default | Decrypts/generates the relayer wallet and is forwarded to deployment/relayer processes. | `dev/locSetupPolicy.ts:500-540`; `dev/locSetupV4.ts:275-315`; `dev/locSetupV4.ts:2861-2866` |
| `PSY_SKIP_KEYSTORE` | Direct default off; Make default `1` | Exact `1` skips remote trust-setup refresh/hash verification but still requires mandatory local files. | `dev/locSetupV4.ts:2319-2353`; `Makefile:14` |
| `PSY_KEYSTORE_S3_BASE_URL` | Published development asset prefix | Overrides trust-setup manifest and proving-key download base. | `dev/locSetupV4.ts:1489-1492`; `dev/locSetupV4.ts:2117-2127` |

### 6.4 Resources, Logging, and Supervision

| Variable | Default | Effect | Evidence |
|---|---|---|---|
| `PSY_WORKER_BATCH_SIZE` | Positive integer `2` | Supplies worker `--batch-size` and is normalized into child environment. | `dev/locSetupPolicy.ts:1`; `dev/locSetupV4.ts:136-140,208-221` |
| `RAYON_NUM_THREADS` | Derived, maximum `4` | Sets Rayon threads per proving process. | `dev/locSetupPolicy.ts:2,218-220`; `dev/locSetupV4.ts:198-221` |
| `PSY_RUNTIME_CPUSET` | Automatic or unset | Linux-only complete-core runtime partition; wraps foreground children with `taskset`. | `dev/locSetupV4.ts:146-195`; `dev/locSetupV4.ts:656-660` |
| `SCYLLA_CPUSET` | Automatic or unset | Linux-only complete-core Scylla partition. | `dev/locSetupPolicy.ts:128-180`; `dev/start_db.sh:165-171` |
| `SCYLLA_SMP` | Reserved logical-core count, else 1-2 | Sets Scylla shard count. | `dev/locSetupV4.ts:203-221`; `dev/start_db.sh:132-171` |
| `SCYLLA_MEMORY` | `8G` | Sets Scylla memory budget. | `dev/locSetupPolicy.ts:3,14-16`; `dev/start_db.sh:134,171` |
| `SCYLLA_CAS_CONTENTION_TIMEOUT_MS` | Positive integer `10000` | Sets Scylla LWT contention timeout. | `dev/start_db.sh:135-160`; `dev/locSetupV4.ts:4737-4753` |
| `SCYLLA_WRITE_REQUEST_TIMEOUT_MS` | Positive integer `10000` | Sets Scylla write timeout. | `dev/start_db.sh:136-160`; `dev/locSetupV4.ts:4742-4753` |
| `SCYLLA_COMMITLOG_SYNC` | `batch` in foreground DB script | Sets foreground Scylla commitlog mode; daemon generation has no equivalent input. | `dev/start_db.sh:125-163`; `dev/locSetupV4.ts:4747-4756` |
| `SCYLLA_COMMITLOG_BATCH_WINDOW` | `2` milliseconds | Sets foreground batch sync window. | `dev/start_db.sh:129-163` |
| `SCYLLA_COMMITLOG_PERIOD` | `10` milliseconds | Sets foreground periodic sync interval. | `dev/start_db.sh:129-163` |
| `RUST_LOG` | No direct global default | Controls Rust tracing; Make maps `LOG_LEVEL` to `--env RUST_LOG=...`. | `Makefile:9,60`; `dev/locSetupV4.ts:3760-3767` |
| `PSY_NO_AUTO_RESTART` | Restart enabled | Exact `1` disables foreground child auto-restart. | `dev/locSetupV4.ts:3477-3479`; `dev/locSetupV4.ts:5629-5634` |
| `TMPDIR` | `/tmp` | Bases the repository-keyed lock and control socket paths. | `dev/locSetupV4.ts:5092-5095`; `dev/locSetupV4.ts:5182-5184` |

### 6.5 Faucet and Service Forwarding

The supported faucet keys are `PSY_FAUCET_OPERATORS_JSON`, `PSY_FAUCET_OPERATORS_JSON_B64`,
`PSY_FAUCET_TURNSTILE_SECRET`, `PSY_FAUCET_REQUIRE_TURNSTILE`, `PSY_FAUCET_TURNSTILE_ACTION`,
`PSY_FAUCET_TURNSTILE_ALLOWED_HOSTNAMES`, and `PSY_FAUCET_WINDOW_CHECKPOINTS`
(`dev/locSetupPolicy.ts:4-12`). If neither operator representation exists, the launcher best-effort loads the bridge
faucet-operator JSON file before and after auto-setup (`dev/locSetupV4.ts:5380-5392`;
`dev/locSetupV4.ts:5560-5572`). Foreground children inherit these values broadly; daemonized containers receive only
nonempty faucet values plus the fixed runtime allowlist (`dev/locSetupV4.ts:3755-3758`;
`dev/locSetupV4.ts:4758-4765`).

## 7. Foreground Process Inventory and Readiness

| Process | Command/log identity | Readiness and prerequisite | Evidence |
|---|---|---|---|
| DB group | `dev/start_db.sh --persist`, `logs/db_*` | `All services are running.`, then TCP 6379/4222/9042. | `dev/locSetupV4.ts:3866-3886`; `dev/start_db.sh:232-294` |
| Redis/Valkey | Docker `valkey-server` | Group marker plus TCP 6379. | `dev/start_db.sh:83-107`; `dev/locSetupV4.ts:3882-3886` |
| NATS | Docker NATS JetStream | Group marker plus TCP 4222. | `dev/start_db.sh:109-121`; `dev/locSetupV4.ts:3882-3886` |
| Scylla | Docker Scylla | `nodetool status` contains `UN`, then TCP 9042. | `dev/start_db.sh:232-255`; `dev/locSetupV4.ts:3882-3886` |
| Nostr | Docker Nostr relay | Must remain alive for DB group; direct TCP 8081 gate precedes Privacy Bridge. | `dev/start_db.sh:184-245`; `dev/locSetupV4.ts:4556-4564` |
| Coordinator processor | `psy_node_cli start-coordinator-processor` | Exact marker `[COORD_CREATE] processor new done`; 120-second attempt, narrow Scylla retry. | `dev/locSetupV4.ts:3902-3932`; `dev/locSetupPolicy.ts:319-333` |
| Coordinator edges | `start-coordinator-edge` | Edge RPC marker; all edges start in parallel after processor. | `dev/locSetupV4.ts:3937-3961` |
| Realm processors | `start-realm-processor` | Exact marker `[REALM_CREATE] processor new done`; 180-second attempt, narrow Scylla retry. | `dev/locSetupV4.ts:4005-4054`; `dev/locSetupPolicy.ts:319-333` |
| Realm edges | `start-realm-edge` | Edge RPC marker; parallel after every processor in the batch. | `dev/locSetupV4.ts:4054-4094` |
| Coordinator workers | `psy_worker_cli worker` | Worker-start marker; start sequentially after complete Realm readiness. | `dev/locSetupV4.ts:3963-4004`; `dev/locSetupV4.ts:4098` |
| Realm workers | `psy_worker_cli worker` | Worker-start marker; all selected worker promises are awaited. | `dev/locSetupV4.ts:4100-4192` |
| Dummy provers | `dev/dummy_prover.sh` | Dummy-prover marker; start in parallel after Realm workers. | `dev/locSetupV4.ts:4193-4210` |
| Prove proxy | `psy_user_cli prove-proxy` | Log marker starts background warm-up; TCP `9999 + index` has up to 600 one-second attempts. | `dev/locSetupV4.ts:4212-4252` |
| Anvil | `anvil ... --state db/anvil/state.json --state-interval 1` | `Listening on`, then HTTP Layer 1 probe. | `dev/locSetupV4.ts:4254-4289` |
| Envio backing services | Generated Docker Compose | Postgres TCP 5433, SQL `select 1`, Hasura `/healthz`. | `dev/locSetupV4.ts:3170-3196` |
| Envio indexer | `pnpm start` | Outer setup requires TCP 9898. | `dev/locSetupV4.ts:3195-3208`; `dev/locSetupV4.ts:4328-4342` |
| psy-services | `psy-services --disable-auth` | Start marker, then `http://127.0.0.1:3000/health`. | `dev/locSetupV4.ts:4395-4425` |
| psy-indexers | `psy-indexer` Coordinator then Realm | `Starting PSY Indexer`; sequential ordering. | `dev/locSetupV4.ts:4426-4480` |
| Faucet | `psy_user_cli faucet-server` | Waits for same-launch proxies; its TCP 9998 probe is nonblocking after spawn. | `dev/locSetupV4.ts:4483-4512` |
| Relayer | `psy_relayer_cli --config .../daemon.toml` | Relayer marker after same-launch proxy readiness and bridge stack. | `dev/locSetupV4.ts:4513-4554` |
| UIs | Vite/Bun development servers | `ready in`; ports 5177, 5176, 5178, 5179. | `dev/locSetupV4.ts:4556-4689` |

General initialization-hint startup retries after two seconds, with `maxRetries=3` meaning at most four attempts;
without an explicit initialization timeout, a live child that never prints its marker has no helper-level deadline
(`dev/locSetupV4.ts:764-904`). Processor startup is narrower: only recognized transient Scylla schema failures and a
follow-on timeout after such a failure are retried (`dev/locSetupV4.ts:47-96`).

## 8. Ports and P2P Formulas

For Realm ID `R`, sub-ID `S`, edge index `E`, and configured Realm edge count `C`:

```text
Coordinator edge HTTP/RPC = 1337 + edgeIndex
Realm edge HTTP/RPC       = 13380 + 10R + (S - 1)C + E
Realm processor P2P TCP   = 41000 + 20R + S
Realm edge P2P TCP        = 41100 + 20R + S
Validator user ID         = R * 2^20 + S
Coordinator P2P bootnode  = 40999
Prove proxy               = 9999 + proxyIndex
```

The formulas are implemented at `dev/locSetupV4.ts:977-994`, `dev/locSetupV4.ts:1041-1044`, and
`dev/locSetupV4.ts:3937-3954`. P2P addresses are rendered as `/ip4/HOST/tcp/PORT` and bootnodes append
`/p2p/PEER_ID` (`dev/locSetupV4.ts:985-991`).

| Surface | Port | Evidence |
|---|---:|---|
| Redis/Valkey | 6379 | `dev/start_db.sh:91-105` |
| NATS | 4222 | `dev/start_db.sh:109-120` |
| Scylla | 9042 | `dev/start_db.sh:173-181` |
| Nostr | 8081 | `dev/start_db.sh:184-225` |
| Anvil | 8545 in valid current CLI use | `dev/locSetupV4.ts:5373`; `dev/locSetupV4.ts:4258-4266` |
| Envio Postgres | 5433 | `dev/locSetupV4.ts:3170-3179` |
| Hasura | 8080 | `dev/locSetupV4.ts:3181-3188` |
| Envio indexer API | 9898 | `dev/locSetupV4.ts:4328-4342` |
| psy-services | 3000 | `dev/locSetupV4.ts:4400-4425` |
| Faucet | 9998 | `dev/locSetupV4.ts:4483-4512` |
| Privacy Bridge | 5177 | `dev/locSetupV4.ts:4567-4589` |
| IDE | 5176 | `dev/locSetupV4.ts:4592-4611` |
| Explorer | 5178 | `dev/locSetupV4.ts:4614-4638` |
| Mode A UI | 5179 | `dev/locSetupV4.ts:4640-4689` |

## 9. CPU Partition and Rayon Derivation

The proving-process count is Coordinator workers plus Realm workers plus dummy provers plus prove proxies; a full
foreground launch counts one proxy when no explicit proxy count is positive (`dev/locSetupV4.ts:3802-3811`). The
launcher then performs this deterministic derivation (`dev/locSetupV4.ts:131-221`):

```text
1. Validate PSY_WORKER_BATCH_SIZE; use 2 when absent.
2. Determine available physical cores.
3. On macOS, prefer sysctl hw.physicalcpu.
4. On Linux, parse lscpu topology and intersect launcher affinity.
5. When managing Scylla, partition complete sibling groups between Scylla and runtime.
6. Derive Rayon = max(1, min(4, floor(runtime physical cores / max(1, proving processes)))).
7. Derive Scylla SMP from reserved logical cores, else clamp availableParallelism to 1..2.
8. Export normalized resource values to managed children.
```

The exact Rayon formula is `resolveRayonThreadCount()` (`dev/locSetupPolicy.ts:218-220`). With no overrides, Scylla
receives two physical cores when at least eight are available and one otherwise; runtime receives the complement
(`dev/locSetupPolicy.ts:128-180`). Overrides must select available complete sibling groups, be disjoint, cover all
available CPUs, and leave both partitions nonempty (`dev/locSetupPolicy.ts:139-180`). Every foreground child is
wrapped with `taskset --cpu-list` when a runtime set exists; the DB script separately applies the runtime set to
Redis/Valkey, NATS, and Nostr and the Scylla set to Scylla (`dev/locSetupV4.ts:656-660`;
`dev/start_db.sh:77-80`; `dev/start_db.sh:154-180`; `dev/start_db.sh:219-223`).

## 10. Anvil Persistence and Restart Recovery

Anvil state is exactly `db/anvil/state.json`; Anvil receives `--state` with that path and `--state-interval 1`, so it
loads an existing snapshot and writes updates every second (`dev/locSetupV4.ts:2766`; `dev/locSetupV4.ts:4258-4276`).
Do not describe all Anvil-related data as living under `db/`: the required localhost deployment summary is the paired
file `psy-contracts/deployments/localhost/deployed-contracts.json`, outside `db/`
(`dev/locSetupV4.ts:2774-2783`).

The pair invariant is strict:

```text
state absent + deployment absent   -> fresh local chain; reset Envio storage
state present + deployment present -> load Anvil state; reuse deployment; retain Envio storage
only one present                    -> fail and instruct make restart-all
```

This behavior is implemented by `resolveLocalAnvilStatePlan()` and the localhost reuse branch in
`deployPsyContracts()` (`dev/locSetupV4.ts:2774-2824`). Foreground Anvil startup creates the parent directory before
launch, uses the plan's `hasState` result, and passes the plan's reset decision into Envio setup
(`dev/locSetupV4.ts:4254-4302`; `dev/locSetupV4.ts:4304-4325`).

`make restart` sends a control command to the existing supervisor; it stops and recreates applications while the
tracked Anvil and DB processes remain alive (`Makefile:68-69`; `dev/locSetupV4.ts:3339-3346`;
`dev/locSetupV4.ts:3685-3753`; `dev/locSetupV4.ts:5615-5626`). A non-purge shutdown stops Anvil but does not delete
its state or the localhost deployment; a later launch loads the state and reuses the deployment
(`dev/locSetupV4.ts:3282-3300`; `dev/locSetupV4.ts:2774-2824`). Purge deletes both `db/anvil` and the localhost
deployment directory, preserving the pair invariant for the next fresh launch (`dev/locSetupV4.ts:3290-3298`).

## 11. Control Socket and Application Lifecycle

The foreground launcher derives a repository-keyed Unix socket beside its lock under `TMPDIR` or `/tmp`; the server
sets permissions to `0600` (`dev/locSetupV4.ts:5092-5095`; `dev/locSetupV4.ts:5182-5184`;
`dev/locSetupV4.ts:5270-5278`). Clients send one newline-terminated command and receive one JSON response; the client
timeout is 900,000 milliseconds (`dev/locSetupV4.ts:5191-5223`). Server commands are serialized through one promise
queue, so lifecycle mutations do not overlap (`dev/locSetupV4.ts:5249-5267`).

| Command | Supported Make target | Effect | Evidence |
|---|---|---|---|
| `restart` | `make restart` | Stop then start applications; keep DB and Anvil alive. | `Makefile:68-69`; `dev/locSetupV4.ts:3750-3753`; `dev/locSetupV4.ts:5617-5620` |
| `rollback-stop` | `make rollback-stop` | Stop applications, verify ports closed, write rollback sentinel. | `Makefile:71-72`; `dev/locSetupV4.ts:3685-3720` |
| `rollback-resume` | `make rollback-resume` | Start saved application templates and remove sentinel after success. | `Makefile:74-75`; `dev/locSetupV4.ts:3722-3747` |

Application stop sends process groups `SIGTERM`, waits up to 15 seconds, escalates to `SIGKILL`, and verifies derived
application ports are closed (`dev/locSetupV4.ts:3374-3421`; `dev/locSetupV4.ts:3438-3447`;
`dev/locSetupV4.ts:3685-3719`). Resume order is Coordinator processor, Coordinator edges, Realm processors, Realm
edges, workers/dummy provers, proxies, tracked Envio indexer, psy-services, psy-indexers, faucet, relayer, then UIs and
other applications (`dev/locSetupV4.ts:3348-3368`). Controlled resume adds explicit post-start gates for proxy TCP,
Envio 9898, and psy-services health (`dev/locSetupV4.ts:3669-3681`). A failed resume stops the newly started subset and
returns lifecycle state to `stopped` (`dev/locSetupV4.ts:3739-3747`).

## 12. Auto-Restart

All tracked foreground children are wired for restart unless `PSY_NO_AUTO_RESTART=1`; intentional application stop
and full teardown suppress restart (`dev/locSetupV4.ts:3477-3479`; `dev/locSetupV4.ts:3527-3548`;
`dev/locSetupV4.ts:3571-3600`). The delay sequence is 1, 2, 4, 8, 16, then 30 seconds for subsequent exits
(`dev/locSetupV4.ts:3585-3589`). Restarts reuse the saved command, working directory, environment, logs, readiness
detector, and retry settings, and append restart banners rather than truncating logs
(`dev/locSetupV4.ts:3602-3627`; `dev/locSetupV4.ts:3648-3667`). Failed reconstruction retries after twice the prior
delay, capped at 60 seconds (`dev/locSetupV4.ts:3631-3644`).

Recognized fatal processor output terminates the processor for supervised recreation
(`dev/locSetupV4.ts:3551-3568`). When the DB group recovers, running Coordinator and Realm processors are terminated
for supervised restart so they rebuild infrastructure connections (`dev/locSetupV4.ts:3481-3503`;
`dev/locSetupV4.ts:3628-3630`).

## 13. Teardown and Purge

`make shutdown` invokes `--teardown` and adds `--purge` only when `PURGE=1`; `make restart-all` performs purge shutdown
then `make run-all` (`Makefile:77-79`; `Makefile:102-106`). Direct teardown executes this sequence
(`dev/locSetupV4.ts:3234-3300`):

```text
1. Kill known command patterns.
2. Stop/remove known Redis/Valkey, NATS, Scylla, and Nostr containers.
3. Bring generated Envio Compose down; add volume deletion only for purge.
4. Kill listeners on the fixed known port set.
5. For purge only, delete checkpoints, db/anvil, logs, deployment directories,
   Envio volumes, and named Redis/Scylla/NATS volumes.
```

Non-purge teardown preserves `local_checkpoints`, `db/anvil/state.json`, deployment summaries, logs, Envio volumes, and
named infrastructure volumes, although it stops the running processes and containers
(`dev/locSetupV4.ts:3282-3300`). Purge deletes `local_checkpoints`, the complete `db/anvil` directory, logs, localhost,
Sepolia, and Ethereum deployment directories, generated Envio volumes, and named Redis/Scylla/NATS volumes
(`dev/locSetupV4.ts:3226-3231`; `dev/locSetupV4.ts:3290-3298`).

## 14. Daemonized Path Differences

The flag spelling is exactly `--daemonlize`. It generates root `docker-compose.yml`, runs
`docker compose up -d --remove-orphans`, releases the launcher lock, and exits without a control socket
(`dev/locSetupV4.ts:5320`; `dev/locSetupV4.ts:5057-5069`; `dev/locSetupV4.ts:5609-5612`).

The daemonized service map contains Redis/Valkey, NATS, Scylla, Coordinator/Realm processors and edges, workers,
explicit prove proxies, and faucet (`dev/locSetupV4.ts:4767-5014`). It omits Nostr, Anvil/deployment, Envio,
psy-services, psy-indexers, relayer, dummy provers, and UIs (`dev/locSetupV4.ts:4693-5069`). It creates no
`RunningProcess` objects, per-process launcher readiness detectors, launcher log supervision, control socket, or
launcher auto-restart; generated services also have no Compose `restart` field
(`dev/locSetupV4.ts:4831-4844`; `dev/locSetupV4.ts:5016-5069`).

Daemonized containers receive only `RUST_LOG`, forced `RUST_BACKTRACE=1`, `RAYON_NUM_THREADS`,
`PSY_WORKER_BATCH_SIZE`, and nonempty faucet keys; arbitrary `--env` entries are not generally forwarded
(`dev/locSetupV4.ts:4758-4765`). CPU sets become Compose `cpuset` fields, and every daemonized Realm worker connects to
every generated Realm edge instead of using the foreground count-sensitive distribution
(`dev/locSetupV4.ts:4767-4803`; `dev/locSetupV4.ts:4960-4987`).

## 15. Source-Accurate Command Recipes

### Supported Make lifecycle

```bash
make run-all
make restart
make rollback-stop
make rollback-resume
make shutdown
PURGE=1 make shutdown
make restart-all
```

These are the repository-supported lifecycle entry points (`docs/src/node/devnet_lifecycle.md:5-7`;
`Makefile:63-79`; `Makefile:99-106`). `make restart` requires the original foreground supervisor; it is not a new
launcher startup (`Makefile:68-75`; `dev/locSetupV4.ts:5191-5223`).

### Bare foreground full mode

```bash
bun run dev/locSetupV4.ts
```

This uses the bare defaults in section 4.1 and differs from `make run-all` (`dev/locSetupV4.ts:5297-5342`;
`Makefile:60`).

### Self-contained two-Realm core without Layer 1, bridge, or UIs

```bash
bun run dev/locSetupV4.ts \
  --db \
  --coordinator \
  --realms-count 2 \
  --coordinator-workers 2 \
  --realm-workers 1
```

`--db` and `--coordinator` make this component mode, so worker counts are explicit
(`dev/locSetupV4.ts:5333-5340`; `dev/locSetupV4.ts:3866-4192`).

### Realm P2P core

```bash
bun run dev/locSetupV4.ts \
  --db \
  --coordinator \
  --realm-p2p \
  --start-realm-id 0 \
  --realms-count 2 \
  --realm-edge-nodes 2 \
  --coordinator-workers 1 \
  --realm-workers 2
```

This selects sub-IDs 1 and 2, creates four Realm processors and eight Realm edges, and injects generated validators
into the selected genesis file (`dev/locSetupV4.ts:958-1138`; `dev/locSetupV4.ts:3888-3900`;
`dev/locSetupV4.ts:3993-4098`).

### Proxy-only component

```bash
bun run dev/locSetupV4.ts --prove-proxy 2
```

This starts proxy listeners 9999 and 10000 without selecting DB, core, Layer 1, or services
(`dev/locSetupV4.ts:5333`; `dev/locSetupV4.ts:4212-4246`).

### Dummy provers against an existing core

```bash
bun run dev/locSetupV4.ts \
  --dummy-provers 4 \
  --start-realm-id 1 \
  --realms-count 2
```

This starts four dummy-prover processes targeting Realms 1 and 2 and does not select their dependencies
(`dev/locSetupV4.ts:4193-4210`; `dev/locSetupV4.ts:5333`).

### Direct non-purge and purge teardown

```bash
bun run dev/locSetupV4.ts --teardown
bun run dev/locSetupV4.ts --teardown --purge
```

Only the second command deletes persisted state (`dev/locSetupV4.ts:5574-5577`;
`dev/locSetupV4.ts:3282-3300`).

## 16. Failure Diagnosis

| Symptom | Source-grounded diagnosis and action | Evidence |
|---|---|---|
| Another devnet is running | A repository-keyed kernel `flock` is held; use supported teardown or control rather than starting a second foreground launcher. | `dev/locSetupV4.ts:5114-5163` |
| Help or teardown fails before its branch | Network resolution and `--env` parsing occur before help/teardown; correct invalid network, missing external RPC, or invalid assignment. | `dev/locSetupV4.ts:5368-5396`; `dev/locSetupV4.ts:5574-5577` |
| Processor exits before ready | Read its error log; only recognized transient Scylla schema failures receive processor retry. | `dev/locSetupV4.ts:47-96`; `dev/locSetupV4.ts:3902-3932` |
| Anvil state/deployment mismatch | Do not create or delete one side; run `make restart-all`. | `dev/locSetupV4.ts:2774-2783` |
| `make restart` cannot connect | The foreground supervisor/socket is absent; daemon mode and completed teardown have no control server. | `dev/locSetupV4.ts:5215-5217`; `dev/locSetupV4.ts:5609-5628` |
| Rollback stop reports open ports | The manager remains in `stopping`; identify the retained application listener and retry the supported stop after resolving it. | `dev/locSetupV4.ts:3394-3421`; `dev/locSetupV4.ts:3711-3713` |
| Controlled resume fails | Newly started applications are stopped and lifecycle returns to `stopped`; fix the failing application and rerun resume. | `dev/locSetupV4.ts:3739-3747` |
| Prove proxy appears slow | Log readiness can precede TCP readiness; the TCP gate permits up to 600 one-second attempts. | `dev/locSetupV4.ts:4212-4252` |
| Faucet port is not open when setup continues | Its post-spawn TCP wait is detached and warning-only. | `dev/locSetupV4.ts:4499-4512` |
| DB group restarts repeatedly | One Redis/Valkey, NATS, Scylla, or Nostr pipeline exited; the DB script stops the group and exits nonzero for supervisor restart. | `dev/start_db.sh:232-294` |
| `PSY_SKIP_BUILD=1` reports missing/stale artifacts | Rebuild/regenerate required artifacts; skip-build intentionally fails instead of repairing them. | `dev/locSetupV4.ts:1765-1800`; `dev/locSetupV4.ts:2079-2084` |

## 17. Current-Source Limitations

These are limitations of the current source, not supported command examples.

1. `--l1-port` is read and documented but not declared in `parseArgs`; strict parsing therefore makes the intended
   custom port unreachable through a valid current command (`dev/locSetupV4.ts:5293-5327`;
   `dev/locSetupV4.ts:5373`; `dev/locSetupV4.ts:5423-5424`).
2. Embedded help advertises `--workers` and examples use `--realm`, but neither option is declared; do not use those
   examples (`dev/locSetupV4.ts:5293-5327`; `dev/locSetupV4.ts:5419`; `dev/locSetupV4.ts:5461-5462`).
3. Help says bare startup uses Realms 0-127, while the parser default is one Realm; section 4.1 is authoritative
   (`dev/locSetupV4.ts:5302,5342`; `dev/locSetupV4.ts:5440-5441`).
4. `--bridge-proposer-daemon` is counted as a top-level component selector but omitted from the manager's second
   selector expression; alone, it gives component-mode worker defaults while manager `startAll` becomes true
   (`dev/locSetupV4.ts:5333-5340`; `dev/locSetupV4.ts:3788-3792`).
5. Numeric CLI values use `parseInt` without range validation; zero, negative, malformed-suffix, and nonnumeric values
   can produce empty loops, invalid arithmetic, or silent suppression instead of a clear parser error
   (`dev/locSetupV4.ts:5338-5350`; `dev/locSetupV4.ts:4145-4148`).
6. Realm HTTP port sets overlap adjacent Realms when `subIdCount * realmEdgeCount > 10`; P2P processor and edge port
   families also collide between Realm IDs separated by five (`dev/locSetupV4.ts:977-983`;
   `dev/locSetupV4.ts:1041-1044`).
7. Multiple Realm edges for the same Realm/sub-ID receive the same P2P listen port because the P2P formula has no edge
   index (`dev/locSetupV4.ts:981-983`; `dev/locSetupV4.ts:4063-4082`).
8. `--host` is not a complete topology relocation: Layer 1 uses `L1_RPC_HOST`, while bridge services contain literal
   loopback endpoints (`dev/locSetupV4.ts:490-493`; `dev/locSetupV4.ts:4332`;
   `dev/locSetupV4.ts:4400-4416`).
9. Daemonized selectors for Layer 1, relayer, dummy provers, and UIs can suppress daemon full mode without generating
   the requested service because those implementations are absent (`dev/locSetupV4.ts:4702-4710`;
   `dev/locSetupV4.ts:4767-5014`).
10. Daemonized P2P constructs loopback multiaddresses inside separate containers and does not publish P2P port
    families; treat daemonized P2P as a current-source limitation (`dev/locSetupV4.ts:4903-4954`).
11. Teardown uses fixed process patterns and port ranges rather than the actual launch plan; Mode A port 5179 and a
    hypothetical custom Anvil port are absent from the fixed listener list (`dev/locSetupV4.ts:3234-3279`).
12. `--clean-state` is not a supported purge recipe: full/DB startup rejects clean-state startup, and teardown purge
    receives only `--purge` (`dev/locSetupV4.ts:3866-3871`; `dev/locSetupV4.ts:5574-5577`).

## 18. Core Data Structures

### `ProcessOptions`

```ts
interface ProcessOptions {
    cwd?: string;
    jtmb?: boolean;
    l1Port?: number;
    workerRealmCount: number;
    realmEdgeCount: number;
    coordinatorEdgeCount: number;
    coordinatorWorkersCount: number;
    disableWorkerEdgeLogs?: boolean;
    startRealmId?: number;
    realmsCount?: number;
    coordinator?: boolean;
    db?: boolean;
    dummyProvers?: number;
    genesisDataPath?: string;
    proveProxyCount?: number;
    faucetServer?: boolean;
    l1?: boolean;
    relayer?: boolean;
    relayerConfig?: string;
    bridgeProposerDaemon?: boolean;
    bridgeUi?: boolean;
    privacyUi?: boolean;
    psyPrivacyBridge?: boolean;
    ide?: boolean;
    explorer?: boolean;
    modeAWebWalletBridge?: boolean;
    daemonlize?: boolean;
    cleanState?: boolean;
    realmP2p?: boolean;
}
```

`runMain()` creates this object after CLI/network/environment processing, and `DevNetProcessManager` reads it to
construct either foreground processes or Compose services (`dev/locSetupV4.ts:3302-3332`;
`dev/locSetupV4.ts:5579-5614`). Required count fields always receive parsed/default values; optional booleans are false
when omitted (`dev/locSetupV4.ts:5333-5363`). Example: `make run-all` materializes counts `workerRealmCount=1`,
`realmEdgeCount=1`, `coordinatorEdgeCount=1`, `coordinatorWorkersCount=2`, `realmsCount=2`, plus its explicit component
booleans (`Makefile:60`; `dev/locSetupV4.ts:5579-5607`).

### `RuntimeResourceSettings`

```ts
type RuntimeResourceSettings = {
    workerBatchSize: string;
    runtimeCpuSet?: string;
    scyllaCpuSet?: string;
    scyllaSmp: string;
    env: { [key: string]: string };
};
```

`resolveRuntimeResourceSettings()` owns creation; foreground and daemonized setup read it, while callers do not mutate
it (`dev/locSetupV4.ts:123-135`; `dev/locSetupV4.ts:216-221`; `dev/locSetupV4.ts:3806-3811`;
`dev/locSetupV4.ts:4730-4765`). Every integer string is validated positive before construction, and CPU sets are
present only when partitioning succeeds (`dev/locSetupV4.ts:136-214`). A four-core runtime with two proving processes
and no override yields `RAYON_NUM_THREADS=2` by the documented formula (`dev/locSetupPolicy.ts:218-220`).

### `LocalAnvilStatePlan`

```ts
export interface LocalAnvilStatePlan {
    statePath: string;
    hasState: boolean;
    shouldResetEnvio: boolean;
}
```

`resolveLocalAnvilStatePlan()` creates this immutable decision record after validating the state/deployment pair;
foreground Layer 1 and Envio startup consume it (`dev/locSetupV4.ts:2766-2790`;
`dev/locSetupV4.ts:4254-4325`). For a preserved chain, the concrete value is
`{ statePath: "db/anvil/state.json", hasState: true, shouldResetEnvio: false }` relative to the repository
(`dev/locSetupV4.ts:2766-2789`).

### `DevnetControlResponse`

```ts
interface DevnetControlResponse {
    ok: boolean;
    message: string;
}
```

The control server serializes one instance as one JSON line; the client accepts `message` only when `ok` is true
(`dev/locSetupV4.ts:5173-5176`; `dev/locSetupV4.ts:5202-5212`;
`dev/locSetupV4.ts:5258-5267`). Example success messages are returned by the command handler after restart, stop, or
resume (`dev/locSetupV4.ts:5615-5626`).

## 19. Core Functions and Call Trace

### `runMain()`

**Signature:** `async function runMain(): Promise<void>` (`dev/locSetupV4.ts:5289`).

**Internal flow:**

```text
parseArgs(Bun.argv)
  -> derive selector mode, counts, flags, network, RPC, and child environment
  -> control client OR help OR startup/teardown
  -> acquireDevnetLock()
  -> ensureDevEnvironment()
  -> teardownDevnet() OR construct ProcessOptions
  -> setupDaemonized() OR setupProcesses()
  -> startDevnetControlServer()
  -> steady-state interval
```

The exact dispatch and cleanup are at `dev/locSetupV4.ts:5291-5648`. CLI/network/environment/lock errors before the
main `try` do not enter the `Setup failed` cleanup branch, while errors inside auto-setup, teardown, manager setup, or
control-server creation invoke non-purge manager teardown and exit 1 (`dev/locSetupV4.ts:5368-5549`;
`dev/locSetupV4.ts:5637-5646`).

### `DevNetProcessManager.setupProcesses()`

**Signature:** `async setupProcesses(options: ProcessOptions): Promise<void>`
(`dev/locSetupV4.ts:3788`).

**Preconditions:** required tools/artifacts have passed auto-setup, selected external RPC values exist, and the caller
holds the repository startup lock (`dev/locSetupV4.ts:5498-5558`).

**Postcondition:** every selected foreground phase has reached its source-defined readiness point; tracked children
are supervisor-wired (`dev/locSetupV4.ts:3527-3568`; `dev/locSetupV4.ts:3788-4689`).

**Internal flow:** derive selection/resources, prepare logs/binaries, start DB, inject P2P validators, start core,
workers/proxy, Layer 1/deployment, bridge stack, faucet/relayer, then UIs
(`dev/locSetupV4.ts:3788-4689`).

### `resolveRuntimeResourceSettings()`

**Signature:**

```ts
async function resolveRuntimeResourceSettings(
    env: { [key: string]: string },
    provingProcessCount: number,
    shouldPartitionCpus: boolean,
): Promise<RuntimeResourceSettings>
```

The function validates worker size, inspects platform topology, resolves optional CPU partitioning, derives Rayon and
Scylla concurrency, and returns normalized child environment (`dev/locSetupV4.ts:131-221`). It calls
`parseLscpuTopology()`, `resolveCpuPartitionForAffinity()`, `resolveRayonThreadCount()`, and
`resolvePositiveIntegerSetting()` (`dev/locSetupV4.ts:161-206`).

### `resolveLocalAnvilStatePlan()`

**Signature:** `export async function resolveLocalAnvilStatePlan(repoCwd: string): Promise<LocalAnvilStatePlan>`
(`dev/locSetupV4.ts:2774`). It checks both files, throws on mismatch, and returns whether to reuse state and retain
Envio storage (`dev/locSetupV4.ts:2775-2789`).

### `stopApplications()`, `startApplications()`, and `restartApplications()`

**Signatures:**

```ts
async stopApplications(cwd: string = ".", writeRollbackSentinel: boolean = false): Promise<void>
async startApplications(cwd: string = "."): Promise<void>
async restartApplications(cwd: string = "."): Promise<void>
```

Stop separates persistent processes, terminates applications, waits for exits/closed ports, and optionally writes the
sentinel (`dev/locSetupV4.ts:3685-3720`). Start replays sorted templates, applies selected readiness gates, removes the
sentinel only after success, and rolls back a partial start on failure (`dev/locSetupV4.ts:3722-3747`). Restart is
exactly stop without sentinel followed by start (`dev/locSetupV4.ts:3750-3753`).

## 20. Core Loops

### Foreground Realm startup loop

**Entry:** after DB and Coordinator readiness (`dev/locSetupV4.ts:3866-3993`).

```text
for each Realm batch of at most four:
  1. Build the batch's Realm IDs.
  2. For each active sub-ID, start processors sequentially by Realm ID.
  3. Require every processor's exact readiness marker.
  4. Start all batch Realm edges in parallel.
  5. Require every edge initialization detector.
  6. Sleep two seconds.
repeat until every Realm is ready.
```

This loop terminates on completion or the first unhandled process-start failure
(`dev/locSetupV4.ts:3993-4098`). Coordinator workers wait on the entire loop's promise
(`dev/locSetupV4.ts:3993-4004`; `dev/locSetupV4.ts:4098`).

### Supervisor restart loop

**Trigger:** unexpected tracked-child exit (`dev/locSetupV4.ts:3538-3548`).

```text
1. Stop if manager teardown or intentional stop is active.
2. Stop if PSY_NO_AUTO_RESTART=1.
3. Increment restart count and derive capped exponential delay.
4. Wait; recheck stop state.
5. Recreate the child from its saved template and readiness detector.
6. Replace the old tracked entry and append log banners.
7. If DB recovered, request processor reconnection restarts.
8. On reconstruction failure, wait up to 60 seconds and retry.
```

The implementation is `dev/locSetupV4.ts:3571-3645`. State retained between iterations includes command, spawn
options, readiness detector, retry policy, name, and restart count (`dev/locSetupV4.ts:3602-3627`;
`dev/locSetupV4.ts:3648-3667`).

### Control command queue

**Entry:** one newline-terminated socket command (`dev/locSetupV4.ts:5250-5258`).

```text
1. Append handler work to commandQueue.
2. Parse one of restart, rollback-stop, rollback-resume.
3. Await the complete lifecycle mutation.
4. Return one JSON line with ok=true and message.
5. Convert handler failure to ok=false without stopping the supervisor.
```

Commands execute serially and the loop remains available until the server is closed during shutdown
(`dev/locSetupV4.ts:5249-5284`; `dev/locSetupV4.ts:5526-5547`).

## 21. Rationale

- **Make for lifecycle, direct CLI for mechanics:** Make fixes the repository-supported full-stack counts and control
  entry points, while direct CLI exposes lower-level component selection (`Makefile:60-79`;
  `docs/src/node/devnet_lifecycle.md:5-7`).
- **Paired Anvil state and deployment:** restoring chain storage without matching addresses, or addresses without the
  chain, would describe different Layer 1 histories; the launcher therefore fails closed on mismatch
  (`dev/locSetupV4.ts:2774-2783`).
- **Persistent/application split:** restart and offline rollback need application processes to stop without recreating
  Anvil or the DB group (`dev/locSetupV4.ts:3339-3346`; `dev/locSetupV4.ts:3685-3753`).
- **Exact readiness before dependents:** processors require exact completion markers, bridge services require network
  health, and proof consumers wait for proxy TCP to avoid treating process creation as service readiness
  (`dev/locSetupPolicy.ts:319-333`; `dev/locSetupV4.ts:4212-4252`;
  `dev/locSetupV4.ts:4306-4425`).
- **Complete-core CPU partitioning:** assigning sibling threads from one physical core to competing Scylla/runtime
  partitions would violate the partition model, so overrides require complete sibling groups
  (`dev/locSetupPolicy.ts:143-180`).

## 22. Security Considerations

1. Never put `WALLET_PASSWORD` or another secret in `--env`; CLI arguments are visible in shell history and process
   inspection, while the launcher already supports parent-environment transport
   (`dev/locSetupV4.ts:5324-5326`; `dev/locSetupV4.ts:5378`; `dev/locSetupV4.ts:3755-3758`).
2. Treat external RPC URLs as credential-bearing. `make run-all` expands them into a recipe command, and fork mode
   passes the selected URL to Anvil as `--fork-url` (`Makefile:63-66`; `dev/locSetupV4.ts:4267-4274`).
3. Treat `PSY_FAUCET_TURNSTILE_SECRET` and operator configuration as sensitive. Daemon mode writes nonempty faucet
   values into generated Compose environment data (`dev/locSetupPolicy.ts:4-12`;
   `dev/locSetupV4.ts:4758-4765`; `dev/locSetupV4.ts:5057-5061`).
4. Foreground environment inheritance is broad: after resolution, `WALLET_PASSWORD` and other parent values are
   available to managed children, not only the process that semantically consumes them
   (`dev/locSetupV4.ts:275-315`; `dev/locSetupV4.ts:3755-3758`).
5. `PSY_SKIP_KEYSTORE=1` replaces remote manifest/hash refresh with local existence checks, and `PSY_SKIP_BUILD=1`
   trusts current artifacts instead of rebuilding them; use both only under the lifecycle artifact gate
   (`dev/locSetupV4.ts:2319-2353`; `dev/locSetupV4.ts:1765-1800`;
   `docs/src/node/devnet_lifecycle.md:24-42`).
6. The control socket is local and permissioned `0600`, but any process running as the same account can attempt its
   three lifecycle commands (`dev/locSetupV4.ts:5171-5189`; `dev/locSetupV4.ts:5270-5278`).
7. Purge is intentionally destructive across both Layer 1 and Layer 2 state. Review the exact deletion set before
   running `PURGE=1 make shutdown` or `make restart-all` (`Makefile:77-79`; `Makefile:102-106`;
   `dev/locSetupV4.ts:3290-3298`).
8. `--genesis-data-path` is input and output: startup rewrites validators. Use a disposable copy when preserving an
   existing validator list matters (`dev/locSetupV4.ts:1008-1041`; `dev/locSetupV4.ts:3888-3900`).
