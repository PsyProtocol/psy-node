# Genesis Generation

> Updated: 2026-09-03.

## Abstract

"Genesis" names three distinct generated artifacts. They have different producers, different triggers, and different consumers; never substitute one procedure for another. The trigger rules live in `AGENTS.md` (`Genesis Regeneration Boundary`) and `docs/src/node/circuit-and-verifier-operations.md` §6.1. This page is the operational how-to; those sections own when generation is authorized.

| Artifact | Producer | Consumer |
|---|---|---|
| Root `genesis.json` (network bootstrap state) | `make generate-genesis-data` in `psy-node` | Coordinator/Realm processors via `--genesis-data-path` |
| `psy-genesis/` repository artifacts (`config.json`, `genesis_contracts.json`, `genesis_abi/`, token artifacts) | `make gen-deploy-json` in `<workspace>/psy-compiler` | Node builds, SDK, services, contracts, DApp gitlinks |
| `validators` list inside root `genesis.json` | Devnet launcher P2P injection | Coordinator/Realm P2P validator registry |

## Table of Contents

- [1. Root `genesis.json`](#1-root-genesisjson)
  - [1.1 Trigger](#11-trigger)
  - [1.2 Command](#12-command)
  - [1.3 Outputs](#13-outputs)
  - [1.4 Verification](#14-verification)
- [2. `psy-genesis/` Repository Artifacts](#2-psy-genesis-repository-artifacts)
- [3. P2P Validator Injection into `genesis.json`](#3-p2p-validator-injection-into-genesisjson)
- [4. Excluded Generation Tasks](#4-excluded-generation-tasks)
- [5. Failure Handling](#5-failure-handling)

## 1. Root `genesis.json`

### 1.1 Trigger

Run generation only when at least one of these changed (`docs/src/node/circuit-and-verifier-operations.md` §6.1):

1. `psy-genesis/genesis_contracts.json` content;
2. a Genesis setup constant or construction input in `psy_plonky2_circuits/src/node/config/networks/local_devnet.rs`;
3. the serialized `genesis.json` format or serializer;
4. an intentionally adopted `psy-genesis` gitlink whose changed content affects Genesis construction.

EndCap metadata, GUTA, cache, verifier JSON, fingerprint, and ordinary witness changes do not trigger it.

### 1.2 Command

```bash
cd <repo-root>
make generate-genesis-data
```

The target runs the local-devnet Genesis test (`Makefile:110-111`):

```bash
cargo test --release --package psy_plonky2_circuits --lib \
  -- node::config::networks::local_devnet::tests --nocapture
```

### 1.3 Outputs

| Output | Handling |
|---|---|
| Root `genesis.json` | Network bootstrap state containing contract registrations, worker whitelist, validator list, and checkpoint stats. |
| Root `private_keys.json` | Generated private keys. **Secret.** Never package, upload, commit, paste, or publish it (`docs/src/node/circuit-and-verifier-operations.md` §13 and Security Considerations). |
| `psy-dapp/apps/bridge/src/config/faucetOperators.json` | Faucet operator config (`psy_plonky2_circuits/src/node/config/networks/local_devnet.rs:368-460`). |

### 1.4 Verification

1. The test passes; the three output files exist and are nonempty.
2. `genesis.json` is valid JSON and its `validators` list matches the intended set (see §3).
3. Node startup accepts it via `--genesis-data-path`.

## 2. `psy-genesis/` Repository Artifacts

`psy-genesis/config.json`, `genesis_contracts.json`, `genesis_abi/`, and the token artifacts are generated from a clean `psy-compiler` HEAD, not edited by hand:

```bash
cd <workspace>/psy-compiler
make gen-deploy-json
```

Preconditions and the full DAG position are in `AGENTS.md` (`Ordered Release State Machine` §3): the compiler tree must be clean and exactly at the pinned `R_compiler`; the target writes `../psy-genesis/genesis_contracts.json`, refreshes `../psy-genesis/genesis_abi/`, writes the compiler provenance stamp, and copies the token artifact into `psy-node` `client_prover/token.json`.

If `genesis_contracts.json` content changed, the node-side root `genesis.json` (§1) is affected through `genesis_contracts.json` as a construction input — regenerate it and check the `TOKEN_CONTRACT_STATE_TREE_HEIGHT` consequence per `docs/src/node/token-privacy-circuit-fingerprints.md`.

## 3. P2P Validator Injection into `genesis.json`
Devnet startup always rewrites the `validators` list of the file passed as `--genesis-data-path` from the selected public-only runtime network config. Each Realm's ordered validator array is flattened into Genesis with `realm_id`, `validator_user_id`, `node_id`, and `bls_public_key`; sub-id is derived later as the one-based array position. The launcher pins `PSY_NETWORK` to the same config key selected by the node (`localhost` for `local-devnet`) and exports the generated config as `PSY_CONFIG_PATH`.

The key generator assigns validator user IDs from the selected network's `realm_user_tree_height`, and creates one distinct edge identity and public address for every requested edge index. Foreground public addresses use the requested host. Daemon startup writes a separate runtime config whose public addresses use Compose DNS service names; container listeners remain wildcard addresses. All of these addresses use the standard Realm P2P transport.

Genesis construction fails closed when a Realm has more than 255 validators, a NodeId, BLS key, or validator user ID is duplicated, a public identity is invalid, or `validator_user_id` is outside the owning Realm's half-open user range. Processor startup also requires its local Ed25519 NodeId and BLS secret to match the configured public values exactly.

## 4. Excluded Generation Tasks

| Task | Owner |
|---|---|
| Regenerate `cached_circuit_library.rs` / `cached_common_data.rs` | `docs/src/node/circuit-and-verifier-operations.md` §5.1 |
| Regenerate EndCap verifier JSON | `docs/src/node/circuit-and-verifier-operations.md` §4 |
| Regenerate `local_circuits.json` | `make generate-local-circuits` (`Makefile:117-118`) |
| Regenerate token fingerprints in precompiles | `docs/src/node/token-privacy-circuit-fingerprints.md` |
| Regenerate Groth16 keystores | `Makefile:130-134` |

## 5. Failure Handling

| Failure | Response |
|---|---|
| `make generate-genesis-data` test fails | Do not ship the partial `genesis.json`; fix the generator input and rerun |
| `validators` entries stale after a non-P2P start | Expected rewrite behavior; re-inject with a P2P start when needed |
| Provenance mismatch in `psy-genesis` stamp | Rebuild from the committed clean compiler revision; never hand-edit provenance JSON |
| `private_keys.json` leaked | Treat as secret compromise; rotate and remove from every distribution channel |
