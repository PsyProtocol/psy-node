# Devnet Startup, Shutdown, Restart, and Rollback Lifecycle

> Status: Approved. This is the required operating procedure for local Psy devnet work.

## Purpose

Use only the lifecycle below for local devnet startup, shutdown, restart, and offline rollback. It keeps the persisted Anvil chain, Scylla state, checkpoint files, and supervised processes aligned. Supported entry points are `make run-all`, `make restart`, `make rollback-stop`, `make rollback-resume`, `make shutdown`, and `make restart-all`.

## 1. Environment

Use release binaries. These environment variables are valid for fresh startup:

```bash
PSY_SKIP_BRANCH_CHECK=1
PSY_SKIP_KEYSTORE=1
```

Do not set `PSY_NO_AUTO_RESTART=1` when `make restart`, `make rollback-stop`, or `make rollback-resume` will be used. Those targets require the foreground supervisor to remain active. `PSY_SKIP_BUILD=1` is valid only after the release binaries and compiler-generated artifacts have been verified against the current source. `Makefile:13-15` defines the defaults; `dev/locSetupV4.ts` rejects stale Psy SDK compiler artifacts.

Before startup, initialize required submodules at their recorded gitlink SHAs, install frozen dependencies in `./psy-dapp` and the standalone `./psy-dapp/mode-a-web-wallet-bridge` workspace, and build release `psy_node_cli`, `psy_worker_cli`, `psy_dev_cli`, `psy_relayer_cli`, `psy_user_cli`, `psy-services`, and `psy-indexer`. Install `../psy-wallet` dependencies only when the wallet surface is exercised. Use `PSY_SKIP_BUILD=1` only after those binaries are newer than their changed sources.

Never run a formatter. Root `rustfmt.toml` and `client_prover/rustfmt.toml` set `disable_all_formatting = true`.

## 2. Artifact Gate

Before startup, compare the current compiler revision with both artifact stamps:

```bash
COMPILER_REV=$(git -C ../psy-compiler rev-parse HEAD)
test "$(jq -r '.compilerRevision' ../psy-sdk/psy-ts-sdk/packages/psy-sdk/.compiler-artifact.json)" = "$COMPILER_REV"
test "$(jq -r '.compilerRevision' psy-genesis/.genesis_contracts.compiler-artifact.json)" = "$COMPILER_REV"
```

If either comparison fails:

```bash
make -C ../psy-compiler gen-deploy-json
CARGO_NET_GIT_FETCH_WITH_CLI=true pnpm --dir ../psy-sdk/psy-ts-sdk/packages/psy-sdk build
make build
```

Do not weaken the provenance check. Do not add Cargo `[patch]` or `[replace]` overrides for pinned Psy node revisions. `dev/locSetupV4.ts:2294-2337` verifies the Genesis payload and stamp before process startup. Regenerate root `genesis.json` with `make generate-genesis-data` after regenerating compiler/Genesis contract artifacts; the root file embeds the contract circuit definitions consumed by processors and the prove proxy.

## 3. Fresh Start

A fresh test chain requires a full purge because Scylla volumes, checkpoint ring buffer files, the persisted Anvil snapshot, and localhost deployments must start from the same genesis state:

```bash
PURGE=1 make shutdown
make build
PSY_SKIP_KEYSTORE=1 \
PSY_SKIP_BRANCH_CHECK=1 \
PSY_SKIP_BUILD=1 \
make run-all
```

`PURGE=1 make shutdown` removes checkpoints, `db/anvil/state.json`, logs, local deployments, and devnet Docker volumes. `make restart-all` performs this purge followed by `make run-all`. Never delete only Scylla, the Anvil state, deployments, or `local_checkpoints/`; retained components would describe different chains.

`make run-all` stays in the foreground. Run it in a dedicated terminal or tmux pane. Do not background it with `&`.

## 4. Readiness

Startup is ready only after all of these checks pass:

```bash
nc -z 127.0.0.1 9042
nc -z 127.0.0.1 1337
nc -z 127.0.0.1 13380
nc -z 127.0.0.1 13390
curl -fsS http://127.0.0.1:3000/health
curl -fsS http://127.0.0.1:9999/health
```

Required processor markers:

```text
[COORD_CREATE] processor new done
[REALM_CREATE] processor new done
```

The markers are defined in `dev/locSetupPolicy.ts`. A launcher timeout is not proof of startup failure while `make run-all` remains active. Check ports and markers, then read `logs/coordinator_processor_errs.txt` and `logs/realm_*_processor_errs.txt`.

Read checkpoint heads with the `psy_` RPC prefix:

```bash
curl -s -X POST http://127.0.0.1:1337 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}'
```

Realm edge ports are `13380` for Realm 0 and `13390` for Realm 1. Realm processor sub-ID is `1`.

## 5. State-Preserving Restart

Keep the terminal running `make run-all` alive. Restart only its supervised application children:

```bash
make restart
```

`make restart` sends a command to the existing supervisor. It stops and recreates processors, edges, workers, proof services, APIs, indexers, relayer, and UIs from their recorded commands. The original Anvil process, database launcher, Scylla, Redis, NATS, Nostr, Envio containers, checkpoints, and logs remain active. Contract deployment and Envio storage initialization are not rerun.

Anvil continuously saves the local L1 chain to `db/anvil/state.json`. A non-purge `make shutdown` followed by `make run-all` loads that exact L1 state and reuses `psy-contracts/deployments/localhost/deployed-contracts.json`. The state and deployment must exist together; mismatch fails with an instruction to run `make restart-all`.

`make shutdown` is a full process teardown that preserves the paired Anvil state, L2 databases, checkpoints, and deployments. A later `make run-all` restores the same chain. For a complete fresh restart use:

```bash
make restart-all
```

`make restart-all` purges L1 and L2 together before starting a new chain. The equivalent single-command form passes `--purge` to the launcher, which runs the same paired purge (checkpoints, `db/anvil/state.json`, logs, localhost deployments, devnet Docker volumes) before any process starts and then deploys contracts fresh:

```bash
make run-all LOCSETUP_START_ARGS="... --purge"
```

Purge and contract redeployment are paired by design: removing the persisted Anvil state and deployment summary makes the next startup deploy fresh contracts with `--reset`. There is no supported keep-data contract-swap path; a circuit or keystore change always requires a purge restart.

## 6. Offline Rollback Stop and Resume

Rollback generation and execution require processors, services, indexers, relayer, and UIs to stop while Anvil, its `db/anvil/state.json` snapshot, Scylla, Redis, NATS, Nostr, Envio infrastructure, checkpoint files, and logs remain available.

1. Record the L1 block number, deployed contract addresses, L1 finalized checkpoint, and every L2 checkpoint head.
2. Pause applications through the existing supervisor:

```bash
make rollback-stop
```

This command writes `local_checkpoints/rollback-stop.sentinel` with exactly:

```text
rollback offline: all processors and relayer stopped; Scylla Redis NATS and checkpoints retained
```

Pass that path to rollback generation and execution with `--stop-sentinel local_checkpoints/rollback-stop.sentinel`.

3. Confirm processor endpoints are down and retained infrastructure is up:

```bash
for p in 1337 13380 13390 3000 9999; do ! nc -z 127.0.0.1 "$p"; done
for p in 8545 9042 6379 4222 8081 5433 8080; do nc -z 127.0.0.1 "$p"; done
```

4. Generate and execute one rollback plan for the Coordinator and one for every Realm. Rollback validation uses only `plonky2-poseidon-goldilocks`; JTMB is test-only. `--target-contract-state <json>` is optional: generation retains it only when `last_finalized_checkpoint_id` exactly equals the rollback target, and absence or mismatch never blocks local rollback. Generate every RP before executing any RP, then require every phase in every RP to be `completed` before resume. Any L1 force-state action is a separate operator task.
5. Resume the saved application commands without deploying L1 or resetting Envio:

```bash
make rollback-resume
```

The supervisor removes the stop sentinel only after every saved application process reaches its startup condition. Never purge or run `make shutdown` between rollback plan generation, execution, recovery, and resume.

`make rollback-resume` restarts the saved application templates. It can take several minutes because release Plonky2 workers and the prove proxy rebuild circuit state. A long-running command is not stuck while new `CONTROLLED START` markers appear and readiness ports progressively open. The current supervisor starts templates serially; the prove proxy warm-up is usually the critical path.

## 7. Post-Restart and Post-Rollback Verification

1. Require the Anvil block number to be no lower than before the operation, `db/anvil/state.json` to parse as complete JSON, and StateManager, Bridge, and Router addresses to remain byte-identical. If `target_contract_state` was omitted or ignored because its checkpoint differed, record that no matching target contract snapshot was attached to the local RP; verify any separate L1 recovery independently.
2. Require Coordinator and every Realm readiness marker.
3. Require every processor checkpoint head to advance above the rollback target, allow short Realm lag, then require all heads to converge.
4. Verify the target checkpoint remains queryable and target application state was restored.
5. Submit a real state-changing transaction that covers the rolled-back state. Repeating the exact pre-rollback spend is stronger than registering a new user because it proves the consumed balance/state can be used again.
6. Require the transaction to confirm and checkpoint heads to continue advancing.
7. Require checkpoint ring buffers to be contiguous through the current head and new gatherer backups to begin above the retained monotonic pending high-water.
8. If an end cap anchors to a historical checkpoint after rollback, bound the checkpoint-tree proof query by the current logical head; an unbounded per-node max query can mix physical post-rollback residual versions.

The earlier checkpoint-289-to-0 run proved L2 rollback, convergence, and transaction acceptance. It did not prove localhost L1 continuity because the old restart path recreated Anvil. Treat it only as L2 rollback evidence.

## 8. Failure Rules

| Failure | Action |
|---|---|
| `compiler revision changed` | Regenerate compiler/Genesis contract artifacts, regenerate root `genesis.json`, rebuild affected release binaries, then run the artifact checks. |
| Root `genesis.json` contract circuit differs from canonical compiler output | Run `make generate-genesis-data`; stale embedded circuit definitions can fail prove-proxy circuit construction. |
| Cargo cannot authenticate to `git@github.com` | Set `CARGO_NET_GIT_FETCH_WITH_CLI=true`; repair empty cached submodules without deleting the whole Cargo git cache. |
| Submodule fetch reports `early EOF` | Retry the same authenticated command. |
| Scylla `raft operation add_entry timed out` during fresh schema creation | Run `make restart-all`; do not reuse the partial Scylla volume. |
| Anvil state and localhost deployment do not both exist | Run `make restart-all`; do not regenerate or delete only one artifact. |
| `db/anvil/state.json` is truncated or invalid JSON | The L1 snapshot is unusable. Do not repair it manually or claim L1 continuity. Use `make restart-all` for full-stack work; an explicitly authorized L2-only test may omit L1 and must record that limitation. |
| Database proof differs from checkpoint ring buffer proof | Keep the stack stopped and identify whether the DB history or ring buffer is stale; do not delete only one side. |
| `rollback-stop` reports an application port still open | Keep the supervisor in `stopping`, terminate the tracked application process group, and retry `make rollback-stop`. Do not write the sentinel manually. |
| `make restart` cannot reach the control socket | The foreground `make run-all` supervisor is absent. Start `make run-all` only when the preserved Anvil/deployment pair and retained databases are valid. |
| Processor exits before the exact readiness marker | Read that processor's error log; do not treat an open RPC port as processor readiness. |
| Realm resume has no positive pending/proc mapping below the retained counter | Resolve the committed pair from the latest checkpoint mapping at or before the marker; the `(0,0)` sentinel is valid for an unchanged Realm. Never lower or reuse the counter. |
| Rollback CLI says an endpoint is reachable | Run `make rollback-stop`; do not bypass the offline guard. |
| Rollback plan phase fails | Keep applications stopped and rerun the same RP. The phase model is idempotent. |
| `make rollback-resume` fails | Keep the sentinel and retained infrastructure; fix the failing application, then rerun `make rollback-resume`. |

## 9. Forbidden Operations

- Do not use `make shutdown && make run-all` unless `db/anvil/state.json` and the localhost deployment both remain present.
- Do not run `docker compose` or manually restart one devnet service.
- Do not run individual process binaries to substitute for the supervisor control targets.
- Do not use `PSY_NO_AUTO_RESTART=1` when process-only restart or rollback stop/resume is required.
- Do not use non-purge restart after deleting Scylla, Redis, NATS, Anvil state, deployments, or checkpoint files.
- Do not use `PSY_SKIP_BUILD=1` after source, compiler, Genesis, or SDK artifact changes without rebuilding.
- Do not regenerate a rollback plan after destructive phases have started; resume the frozen RP.
- Do not restart processors until all Coordinator and Realm rollback plans and external recovery have completed.
- Do not run formatters.
