# Local Rollback Operations

Status: Review. Updated: 2026-09-16. Internal operator runbook.

## Terminology

- **RP**: one role-local rollback plan, serialized as JSON (JavaScript Object Notation).
- **CLI**: command-line interface.
- **L1 / L2**: Layer 1 / Layer 2.
- **P2P**: peer-to-peer Realm transport.
- **YAML**: YAML Ain't Markup Language, the processor template format.
- **E2E**: end-to-end verification with a real committed state change.
- **JTMB**: the test-only “just trust me bro” proving backend; forbidden here.

## Scope and authority

Use five independent RPs to roll back the default local stack: one Coordinator and four Realm processors. This runbook supplies executable generation, inspection, and execution commands; [devnet lifecycle, sections 6–9](devnet_lifecycle.md#6-offline-rollback-stop-and-resume) owns stopping, retained infrastructure, resuming, and acceptance. [Launcher control lifecycle](devnet-launcher-reference.md#11-control-socket-and-application-lifecycle) explains the supervisor. Do not substitute a new launcher invocation for the saved supervisor commands (`docs/src/dev/devnet_lifecycle.md:164-243`; `Makefile:61-76`).

This procedure requires the default foreground stack on loopback, realms 0 and 1, two validators per Realm, one edge per validator, and one Coordinator edge. It does not cover a custom topology, daemonized stack, or remote network (`Makefile:61`; `dev/locSetupV4.ts:1004-1007,1125-1135,4195-4206,4224-4239,4293-4317`).

**Never follow the current rollback CLI success text that suggests `make run-all`. Use only `make rollback-resume` after every RP and external recovery are complete.** The text is stale relative to the canonical lifecycle (`psy_cli/psy_dev_cli/src/subcommand/rollback.rs:139-156`; `docs/src/dev/devnet_lifecycle.md:190-199`).

## Table of contents

- [1. Flow](#1-flow)
- [2. Preflight and shell variables](#2-preflight-and-shell-variables)
- [3. Processor configs and role matrix](#3-processor-configs-and-role-matrix)
- [4. Stop and generate all five RPs](#4-stop-and-generate-all-five-rps)
- [5. Inspect and validate the frozen RPs](#5-inspect-and-validate-the-frozen-rps)
- [6. Execute and require completion](#6-execute-and-require-completion)
- [7. Failure and resume procedure](#7-failure-and-resume-procedure)
- [8. Resume and post-E2E acceptance](#8-resume-and-post-e2e-acceptance)
- [9. Security](#9-security)

## 1. Flow

```mermaid
sequenceDiagram
    participant Operator
    participant Supervisor
    participant CLI as Release psy_dev_cli
    participant Stores as Retained stores
    Operator->>Supervisor: 1. make rollback-stop
    Supervisor-->>Operator: 2. Applications stopped; sentinel written
    loop Coordinator and four Realm identities
        Operator->>CLI: 3. --generate with unique RP path
        CLI->>Stores: 4. Read target, mappings, backups, high-water
        CLI-->>Operator: 5. Validated RP persisted
    end
    Operator->>Operator: 6. Inspect all five frozen RPs
    loop Coordinator and four Realm identities
        Operator->>CLI: 7. --execute with the same RP
        CLI->>Stores: 8. Apply phases, verify, commit marker last
        CLI-->>Operator: 9. Persist completed phases
    end
    Operator->>Operator: 10. Require all phases completed and external recovery complete
    Operator->>Supervisor: 11. make rollback-resume
    Supervisor-->>Operator: 12. Saved applications ready; sentinel removed
```

Generation reads authoritative stores and backups; execution writes the checkpoint marker last and persists phase progress (`psy_cli/psy_dev_cli/src/subcommand/rollback/generate.rs:301-340`; `psy_node_common/src/rollback/executor.rs:130-203`).

## 2. Preflight and shell variables

1. Complete the existing [startup preflight](devnet_lifecycle.md) before this maintenance window: release binaries and matching Plonky2 artifacts must already exist. Do not rebuild, regenerate Genesis, rotate validator keys, or change configuration during rollback (`AGENTS.md:25-41`).
2. Record the L1 block number, StateManager/Bridge/Router addresses, L1 finalized checkpoint, all five L2 heads, and the target application state before stopping. Choose one target checkpoint present in every processor's retained history; generation rejects a target newer than that processor's head (`docs/src/dev/devnet_lifecycle.md:168,201-210`; `psy_cli/psy_dev_cli/src/subcommand/rollback/generate.rs:355-368`).
3. Keep the original foreground supervisor alive. The following blocks run in **one Bash operator shell from the repository root**, not in the supervisor's terminal. Bash, `jq`, `sed`, `cp`, `mkdir`, `make`, and the already-built release CLI are prerequisites. Shell checks here are operator gates, not a replacement for Rust plan validation.

Set variables once. `REPO_ROOT` identifies the current checkout; `WORKSPACE` is a new operator-selected relative directory outside `local_checkpoints`; `TARGET` is the recorded target checkpoint; `RP_DIR` holds the five RPs. For example, enter `rollback-work-001` for the workspace. The workspace must not already exist, preventing accidental replacement of a frozen RP set.

```bash
set -euo pipefail
umask 077
REPO_ROOT="$PWD"
test -f "$REPO_ROOT/Makefile"
test -f "$REPO_ROOT/psy_cli/psy_dev_cli/src/subcommand/rollback.rs"
read -r -p 'New relative rollback workspace directory: ' WORKSPACE
[[ "$WORKSPACE" =~ ^[A-Za-z0-9_-]+$ ]]
[[ "$WORKSPACE" != local_checkpoints ]]
read -r -p 'Recorded target checkpoint: ' TARGET
[[ "$TARGET" =~ ^(0|[1-9][0-9]*)$ ]]
CLI="$REPO_ROOT/target/release/psy_dev_cli"
RP_DIR="$WORKSPACE/plans"
CONFIG_DIR="$WORKSPACE/config"
STOP_SENTINEL=local_checkpoints/rollback-stop.sentinel
export PSY_CONFIG_PATH=./local_checkpoints/realm_p2p/config.json
export PSY_NETWORK=localhost
test -x "$CLI"
test -r "$PSY_CONFIG_PATH"
test -r genesis.json
command -v jq
mkdir "$WORKSPACE"
mkdir "$RP_DIR" "$CONFIG_DIR"
printf '%s\n' "$TARGET" > "$WORKSPACE/target-checkpoint.txt"
```

`PSY_CONFIG_PATH` must remain the launcher's generated **public runtime config**, not `psy-genesis/config.json` and not a processor config. It supplies the validator identities used to derive each Realm sub-identity. The launcher exports this exact path and selects `localhost`; rollback derives the sub-identity from the existing local identity key (`dev/locSetupV4.ts:1004,1180-1182,4180-4184`; `psy_cli/psy_dev_cli/src/subcommand/rollback.rs:237-257`; `psy_cli/psy_node_cli/src/node/realm_p2p.rs:359-382`).

## 3. Processor configs and role matrix

**There is no launcher-generated `locSetupV4/config` directory.** The current launcher starts processors with arguments, not processor config files. The block below copies the checked-in Coordinator template and derives four operator-owned Realm YAML configs from the two checked-in sub-1 templates. It changes only namespace, key paths, and listener to match the default launcher. It never edits the templates or launcher output (`dev/locSetupV4.ts:4195-4206,4305-4317`; `psy_cli/example_node_configs/coordinator_processor_1.yaml:1-12`; `psy_cli/example_node_configs/realm_0_processor.yaml:1-18`; `psy_cli/example_node_configs/realm_1_processor.yaml:1-18`).

| RP filename under `RP_DIR` | `--role` | Processor config under `CONFIG_DIR` | Identity in config | Required Realm flags | `db_namespace` | RP identity fields |
|---|---|---|---|---|---|---|
| `coordinator.json` | `coordinator` | `coordinator.yaml` | `coordinator_id: 0`, `coordinator_sub_id: 0` | Neither flag | `coordinator` | `realm_id: 0`, `realm_sub_id: 0` |
| `realm0sub1.json` | `realm` | `realm0sub1.yaml` | `realm_id: 0`, sub 1 identity key | `--realm-id 0 --realm-sub-id 1` | `realm_0_1` | `0`, `1` |
| `realm0sub2.json` | `realm` | `realm0sub2.yaml` | `realm_id: 0`, sub 2 identity key | `--realm-id 0 --realm-sub-id 2` | `realm_0_2` | `0`, `2` |
| `realm1sub1.json` | `realm` | `realm1sub1.yaml` | `realm_id: 1`, sub 1 identity key | `--realm-id 1 --realm-sub-id 1` | `realm_1_1` | `1`, `1` |
| `realm1sub2.json` | `realm` | `realm1sub2.yaml` | `realm_id: 1`, sub 2 identity key | `--realm-id 1 --realm-sub-id 2` | `realm_1_2` | `1`, `2` |

A Realm processor config has **no `realm_sub_id` field**: unknown fields are rejected, and rollback derives that value from the key and runtime validator registry. The command-line value must match. Coordinator identity is stored in the RP's `realm_id`/`realm_sub_id` fields but must not be supplied through Realm CLI flags (`psy_node_core/src/config/node_cli_config.rs:34-114,191-254`; `psy_cli/psy_dev_cli/src/subcommand/rollback.rs:173-195,237-270`; `psy_node_common/src/rollback/validate.rs:31-33`).

```bash
cp psy_cli/example_node_configs/coordinator_processor_1.yaml "$CONFIG_DIR/coordinator.yaml"
for realm in 0 1; do
  for sub in 1 2; do
    port=$((41000 + realm * 20 + sub))
    for suffix in processor_identity.key bls.key zk.key; do
      test -r "./local_checkpoints/realm_p2p/realm_${realm}_sub_${sub}_${suffix}"
    done
    sed \
      -e "s/^db_namespace: realm_${realm}_1$/db_namespace: realm_${realm}_${sub}/" \
      -e "s/realm_${realm}_sub_1_/realm_${realm}_sub_${sub}_/g" \
      -e "s|^p2p_listen: .*|p2p_listen: /ip4/127.0.0.1/tcp/${port}|" \
      "psy_cli/example_node_configs/realm_${realm}_processor.yaml" \
      > "$CONFIG_DIR/realm${realm}sub${sub}.yaml"
  done
done
```

The substitutions match the checked-in template lines above; namespaces, ports, and key paths are defined at `dev/locSetupV4.ts:1120-1127,1342-1347`. Connection values match `dev/locSetupV4.ts:3675-3690`. The loader chooses YAML by extension and requires the typed processor fields (`psy_node_core/src/config/node_cli_config.rs:8-16,34-114,191-254`). Section 4's exact `--generate` commands are the config validation gate: before reading rollback stores or writing an RP they load the config, derive identity, enforce local-devnet and matching Realm flags, then verify offline guards (`psy_cli/psy_dev_cli/src/subcommand/rollback.rs:125-138,163-170,198-257`). There is no separate config-only validation option in the rollback clap definition (`psy_cli/psy_dev_cli/src/subcommand/rollback.rs:21-74`).

The backup root remains `./local_checkpoints`, resolving to `coordinator_0_0` and `realm_0_1`, `realm_0_2`, `realm_1_1`, `realm_1_2`. Never point it at the RP workspace. These directories contain checkpoint-tree and gatherer backups, not RPs (`psy_node_core/src/config/node_start_config.rs:37-53,98-127`).

## 4. Stop and generate all five RPs

Follow lifecycle section 6 to stop applications and check retained infrastructure. In this operator shell:

```bash
make rollback-stop
test -f "$STOP_SENTINEL"
```

Do not create the sentinel manually. The supervisor owns its exact content and must confirm application ports are closed (`docs/src/dev/devnet_lifecycle.md:169-188,226`; `docs/src/dev/devnet-launcher-reference.md:546-558`).

Define the common arguments and transparent role functions. Every invocation probes **all five default edge endpoints**, including Coordinator generation. The Coordinator endpoint is always required; Realm endpoints and both identity flags are required for Realm plans. These are reachability guards, not a substitute for stopping processors and the relayer (`psy_cli/psy_dev_cli/src/subcommand/rollback.rs:50-73,173-195,273-322`; default ports: `dev/locSetupV4.ts:1132-1135,4224-4239,4341-4345`).

```bash
COMMON=(
  --target "$TARGET"
  --proving-backend plonky2-poseidon-goldilocks
  --stop-sentinel "$STOP_SENTINEL"
  --coordinator-endpoint http://127.0.0.1:1337
  --realm-endpoint http://127.0.0.1:13380
  --realm-endpoint http://127.0.0.1:13381
  --realm-endpoint http://127.0.0.1:13390
  --realm-endpoint http://127.0.0.1:13391
)
rollback_coordinator() {
  "$CLI" rollback "$@" "${COMMON[@]}" \
    --role coordinator \
    --processor-config "$CONFIG_DIR/coordinator.yaml" \
    --rp-path "$RP_DIR/coordinator.json"
}
rollback_realm() {
  local realm="$1" sub="$2"
  shift 2
  "$CLI" rollback "$@" "${COMMON[@]}" \
    --role realm --realm-id "$realm" --realm-sub-id "$sub" \
    --processor-config "$CONFIG_DIR/realm${realm}sub${sub}.yaml" \
    --rp-path "$RP_DIR/realm${realm}sub${sub}.json"
}

rollback_coordinator --generate --reward-realm-id 0 --reward-realm-id 1
rollback_realm 0 1 --generate
rollback_realm 0 2 --generate
rollback_realm 1 1 --generate
rollback_realm 1 2 --generate
```

**Finish all five generation commands before any execution.** Coordinator generation requires the explicit nonempty reward Realm set; Realm generation uses its own Realm automatically. `--reward-realm-id` belongs only to generation (`psy_cli/psy_dev_cli/src/subcommand/rollback.rs:23-32`; `psy_cli/psy_dev_cli/src/subcommand/rollback/generate.rs:485-518`).

These commands intentionally omit `--target-contract-state`. It is optional, generation-only, and retains a snapshot only when `last_finalized_checkpoint_id` equals `TARGET`. If attaching a separately recorded snapshot, assign its existing JSON path to `TARGET_CONTRACT_STATE` and append `--target-contract-state "$TARGET_CONTRACT_STATE"` to generation commands **before generating the set**. Do not add it to execution. Its fields are defined in `psy_node_common/src/rollback/plan.rs:72-90`; filtering occurs at `psy_node_common/src/rollback/generator.rs:847`. An omitted or mismatched snapshot does not block local rollback; **L1 force-state and relayer recovery are separate operator work**, never performed by this executor (`docs/src/dev/devnet_lifecycle.md:190,203`; `psy_cli/psy_dev_cli/src/subcommand/rollback.rs:148-159`).

## 5. Inspect and validate the frozen RPs

The files are mutable progress journals but their target, identity, snapshots, delete keys, and ordering are frozen. Never edit or reserialize an RP with `jq`: `proc_id` is an unsigned 128-bit integer, and JSON tooling can lose integer precision. Use `jq` read-only for inspection. The Rust reader enforces typed fields; the validator checks exact phase order, APIs, semantic keys, and marker-last ordering (`psy_node_common/src/rollback/plan.rs:63-70,108-131,157-203`; `psy_node_common/src/rollback/validate.rs:18-96`).

```bash
PLAN_NAMES=(coordinator realm0sub1 realm0sub2 realm1sub1 realm1sub2)
check_plan() {
  local name="$1" role="$2" realm="$3" sub="$4" status="$5"
  jq -e --arg role "$role" --arg target "$TARGET" \
    --argjson realm "$realm" --argjson sub "$sub" --arg status "$status" '
    .role == $role and .realm_id == $realm and .realm_sub_id == $sub
    and (.target_checkpoint_id | tostring) == $target
    and (.latest_checkpoint_id >= .target_checkpoint_id)
    and (.latest_pending_id | type == "number")
    and (.ids | type == "array")
    and (.snapshot.target_info | type == "string")
    and (.snapshot.worker_reputation_fields | type == "array")
    and (.phases | type == "array" and length > 1)
    and all(.phases[];
      (.table | type == "string") and (.api | type == "string")
      and (.keys | type == "array") and .status == $status)
    and .phases[-2].table == "all" and .phases[-2].api == "verify"
    and .phases[-1].table == "u64_singleton_table"
    and .phases[-1].api == "set_latest_checkpoint_id"
    and ((has("target_contract_state") | not)
      or .target_contract_state.last_finalized_checkpoint_id == .target_checkpoint_id)
  ' "$RP_DIR/$name.json"
}
check_all_plans() {
  local status="$1"
  check_plan coordinator coordinator 0 0 "$status" || return
  check_plan realm0sub1 realm 0 1 "$status" || return
  check_plan realm0sub2 realm 0 2 "$status" || return
  check_plan realm1sub1 realm 1 1 "$status" || return
  check_plan realm1sub2 realm 1 2 "$status" || return
}
check_all_plans pending
for name in "${PLAN_NAMES[@]}"; do
  printf '\n%s\n' "$name"
  jq '{role, realm_id, realm_sub_id, target_checkpoint_id,
       latest_checkpoint_id, latest_pending_id,
       phase_status: [.phases[] | {table, api, status}]}' "$RP_DIR/$name.json"
done
```

Require five readable files, the matrix identities, one common target, and every initial status `pending`. Compare each `latest_checkpoint_id` with the recorded stopped head, and retain each `latest_pending_id` as its frozen high-water; heads need not have been identical. The checks above cover the operator-visible schema and status, **not the complete Rust semantic validator**. Generation validates before persisting; execution validates again before mutating stores (`psy_cli/psy_dev_cli/src/subcommand/rollback.rs:135-138,150-154`; `psy_node_common/src/rollback/executor.rs:139-151,274-287`).

## 6. Execute and require completion

Run sequentially, stopping at the first error. Do not generate replacement RPs after any execution has started.

```bash
rollback_coordinator --execute
rollback_realm 0 1 --execute
rollback_realm 0 2 --execute
rollback_realm 1 1 --execute
rollback_realm 1 2 --execute
check_all_plans completed
```

A zero exit code for one identity does not complete the other four. Require every phase in every RP to be `completed`, including empty-key phases, verification, and the final marker. The executor checks stored postconditions before the marker and preserves the exact pending high-water (`psy_node_common/src/rollback/plan.rs:107-115`; `psy_node_common/src/rollback/executor.rs:158-203,248-287`; `docs/src/dev/devnet_lifecycle.md:190`).

## 7. Failure and resume procedure

Throughout generation, execution, recovery, and resume: **no purge and no teardown**. This prohibits `make shutdown`, `PURGE=0 make shutdown`, `make restart-all`, launcher `--teardown`/`--purge`, Docker teardown, manual per-service restart, deleting retained files, and substituting `make run-all`. Preserve the original supervisor, Anvil and its snapshot/deployment pair, Scylla, Redis, NATS, checkpoint files, logs, keys, runtime config, sentinel, and RPs (`docs/src/dev/devnet_lifecycle.md:166,197,234-243`).

| Failure | Required action |
|---|---|
| Missing/invalid sentinel or reachable endpoint | Retry `make rollback-stop` through the existing supervisor; resolve the tracked application stop failure. Never forge the sentinel or omit an endpoint (`docs/src/dev/devnet_lifecycle.md:226,230`). |
| Realm identity/config mismatch | Keep applications stopped. Check the matrix, namespace, `PSY_CONFIG_PATH`, and original identity-key path. Do not rotate keys or add `realm_sub_id` to the processor config (`psy_cli/psy_dev_cli/src/subcommand/rollback.rs:237-270`; `psy_node_core/src/config/node_cli_config.rs:34-52`). |
| Generation fails, target unavailable, or backup/history disagreement | Execute nothing until all five valid RPs exist. Diagnose retained state; never delete one side of a database/backup disagreement (`psy_cli/psy_dev_cli/src/subcommand/rollback/generate.rs:301-368`; `docs/src/dev/devnet_lifecycle.md:225`). |
| Execution phase or progress persistence fails | Keep all applications stopped, repair the reported retained-store or filesystem problem without clearing state, and rerun `--execute` against the same RP path. Never mark a phase complete by hand (`psy_node_common/src/rollback/executor.rs:158-198`). |
| Current marker differs from both frozen head and target, or pending counter differs | Stop recovery and investigate unexpected writes or the wrong config/RP. Do not alter markers, lower counters, or regenerate the RP to bypass the guard (`psy_node_common/src/rollback/executor.rs:142-151,274-287`). |
| Marker is already the target after an interrupted execution | Rerun the same RP. Reconciliation verifies postconditions and persists missing completion statuses; it does not authorize ignoring failures (`psy_node_common/src/rollback/executor.rs:153-155,206-245`). |
| Missing/corrupt RP after destructive work | Keep applications stopped; recover the original frozen RP from a trusted preserved copy. Do not regenerate it from partially rolled-back stores (`docs/src/dev/devnet_lifecycle.md:242`). |
| Resume fails | Preserve the sentinel and infrastructure, fix the failing application, then rerun `make rollback-resume`. The supervisor stops the newly started subset on failure (`docs/src/dev/devnet_lifecycle.md:232`; `docs/src/dev/devnet-launcher-reference.md:554-558`). |

For example, if `realm0sub2` failed, retain the existing shell variables/functions and run:

```bash
rollback_realm 0 2 --execute
rollback_realm 1 1 --execute
rollback_realm 1 2 --execute
check_all_plans completed
```

If the operator shell was lost, return to the same repository root, restore `WORKSPACE` to the existing directory, read `TARGET` from `"$WORKSPACE/target-checkpoint.txt"`, and restore the assignments/functions from sections 2, 4, and 5. **Do not rerun workspace creation, config generation, RP generation, or the initial `pending` gate.** Reexecuting already-completed RPs while still offline invokes reconciliation (`psy_node_common/src/rollback/executor.rs:153-155`).

## 8. Resume and post-E2E acceptance

Only after `check_all_plans completed` succeeds and the separately authorized L1/relayer recovery is verified complete:

```bash
make rollback-resume
test ! -e "$STOP_SENTINEL"
```

This restores saved application templates; it does not redeploy L1 or reset Envio. The sentinel is removed after startup conditions succeed. Plonky2 worker/proxy initialization can take minutes; ongoing controlled-start markers and progressively opening readiness ports are progress, not permission to replace the supervisor (`docs/src/dev/devnet_lifecycle.md:191-199`; `dev/locSetupV4.ts:4019-4039`).

Apply the complete [post-rollback acceptance checklist](devnet_lifecycle.md#7-post-restart-and-post-rollback-verification), not just an open port or an accepted submission (`docs/src/dev/devnet_lifecycle.md:201-210`):

- Require preserved L1 continuity, byte-identical deployed addresses, and a valid Anvil snapshot. Record explicitly that these commands attached no target contract snapshot; independently verify external recovery.
- Require the exact Coordinator readiness marker `[COORD_CREATE] processor new done` and each Realm marker `[REALM_CREATE] processor new done`, then all five heads above `TARGET` and converged (`docs/src/dev/devnet-launcher-reference.md:410-413`).
- Require target checkpoint queryability and restored application state. Submit the original pre-rollback state-changing transaction when repeatable, require committed confirmation, and observe continued head advancement.
- Require contiguous checkpoint ring buffers and new gatherer backups above each RP's retained pending high-water. Historical end-cap checkpoint proofs must be bounded by the current logical head.

Keep the five completed RPs and before/after evidence together. A completed local RP is not proof of L1 recovery, and transaction admission alone is not E2E success (`docs/src/dev/devnet_lifecycle.md:203-212`).

## 9. Security

- Treat rollback as destructive privileged maintenance. Restrict workspace access (`umask 077` above), retain original evidence, and do not expose private keys or credentials in tickets, logs, or version control.
- Use key **paths**, never inline key contents. Keep the runtime public validator registry and the original identity keys unchanged; identity matching is a safety check, not an obstacle to bypass (`psy_cli/psy_node_cli/src/node/realm_p2p.rs:359-382`).
- Do not hand-edit delete keys, phases, statuses, snapshots, counters, or markers. Typed decoding and semantic validation are deliberately fail-closed (`psy_node_common/src/rollback/plan.rs:63-131`; `psy_node_common/src/rollback/validate.rs:18-96`).
- Use only `plonky2-poseidon-goldilocks`. JTMB is not rollback evidence and is rejected by this command (`psy_cli/psy_dev_cli/src/subcommand/rollback.rs:173-177`; `AGENTS.md:39-41`).
