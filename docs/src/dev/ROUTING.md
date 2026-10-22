# Dev Docs Routing

> Repository-only routing index for `docs/src/dev`. Not part of the published mdBook (SUMMARY.md).

> Updated: 2026-10-21. Status: Review.

## Abstract

Each task below names the document that owns it and the document to read next. Every filename listed here exists under `docs/src/dev`; `AGENTS.md` is the sole exception and sits at the repository root as repository-root policy. `docs/src/dev/reward-claim-operations.md` is the reward-claim protocol and the operational runbook for the implemented CLI (`client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs:50`; `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:41`).

## Table of Contents

- [Task index](#task-index)
- [Document ownership](#document-ownership)
- [Related Documents](#related-documents)

## Task index

| I want to | Read first | Then |
|---|---|---|
| Create a wallet, register an account, fund PSY, query state, deploy or call a contract | `common-operations.md` | `devnet_lifecycle.md` |
| Deposit, claim a deposit, withdraw, settle through the relayer, or review bridge architecture | `bridge-common-operations.md` | `private-transfer.md` |
| Understand the reward-claim protocol or run the implemented claim-rewards CLI against the deployed contracts (`client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs:50`; `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:41`; `psy-contracts/src/PsyToken.sol:67-104`) | `reward-claim-operations.md` (protocol and runbook) | `common-operations.md` |
| Read reward tree circuit layouts, modes, or offsets | `reward-tree-circuits.md` | `gatherers.md` |
| Understand gatherer job modes or publication | `gatherers.md` | `processors.md` |
| Understand coordinator or realm processor pipelines | `processors.md` | `gatherers.md` |
| Generate or validate EndCap verifier metadata, Plonky2 caches, or the Bridge Groth16 cohorts | `circuit-and-verifier-operations.md` | `AGENTS.md` (repository root; governing release policy, `AGENTS.md:92-102`) |
| Start, stop, restart, or purge the local devnet; look up launcher flags, ports, supervision, or Anvil persistence | `devnet_lifecycle.md` | `rollback-operations.md` |
| Roll back the local stack | `rollback-operations.md` (five independent RPs) | `devnet_lifecycle.md` |
| Review private transfer and private claim architecture | `private-transfer.md` | `common-operations.md` |
| Choose a name for a function, field, or type | `TERMINOLOGY.md` | the role doc that owns the pipeline |
| Check token privacy circuit fingerprints (`private_claim`, `claim_deposit`) | `token-privacy-circuit-fingerprints.md` | `fn-circuit-fingerprint-playbook.md` |
| Debug a function-circuit fingerprint or EndCap mismatch | `fn-circuit-fingerprint-playbook.md` | `circuit-and-verifier-operations.md` |
| Generate genesis artifacts | `genesis-generation.md` | `circuit-and-verifier-operations.md` |
| Understand relayer L1 RPC failover | `relayer-rpc-failover.md` | `bridge-common-operations.md` |
| Create a multi-repo worktree cohort | `worktree-cohort.md` | `devnet_lifecycle.md` |
| Review RealmFinalizeGUTA BLS authentication | `realm-finalize-bls-auth.md` | `processors.md` |
| Review realm P2P validator identity and routing | `realm-p2p-validators.md` | `processors.md` |

## Document ownership

| Document | Owns |
|---|---|
| `common-operations.md` | Wallet, registration, funding, queries, contract deployment, calls |
| `bridge-common-operations.md` | Bridge architecture and deposit, claim, withdrawal, settlement procedures |
| `reward-claim-operations.md` | Reward-claim protocol and the claim-rewards CLI (`client_prover/psy_cli/psy_user_cli/src/subcommand/mod.rs:50`) with deployed-contract operations (`psy-contracts/src/PsyToken.sol:67-104`) |
| `reward-tree-circuits.md` | Reward tree circuit layouts, modes, offsets |
| `gatherers.md` | Gatherer job modes and publication |
| `processors.md` | Coordinator and realm processor pipelines |
| `circuit-and-verifier-operations.md` | Verifier metadata, Plonky2 caches, Groth16 cohorts |
| `devnet_lifecycle.md` | Devnet lifecycle and launcher internals, flags, ports, supervision |
| `rollback-operations.md` | Five-RP local rollback execution |
| `private-transfer.md` | Private transfer and claim architecture |
| `TERMINOLOGY.md` | Shared vocabulary and naming authority |
| `token-privacy-circuit-fingerprints.md` | Token privacy circuit fingerprints |
| `fn-circuit-fingerprint-playbook.md` | Function-circuit fingerprint debugging |
| `genesis-generation.md` | Genesis artifact generation |
| `relayer-rpc-failover.md` | Relayer L1 RPC provider pool |
| `worktree-cohort.md` | Multi-repo workspace script |
| `realm-finalize-bls-auth.md` | RealmFinalizeGUTA BLS authentication design |
| `realm-p2p-validators.md` | Realm P2P validator identity |

## Related Documents

- `AGENTS.md` (repository root) governs release policy at `AGENTS.md:92-102`; `circuit-and-verifier-operations.md` cites it as the governing reference. Its "Guardian And Relayer Storage Boundary" block is the current configuration contract: the selected network carries the stable public `guardian_initial_member_hashes` plus the guardian endpoints (`guardian_configs`, `guardian_history`, optional `l1_config_url`); chain id and bridge come from the deployment documents the deployer writes, selected at guardian and relayer startup through repeatable `--l1-config` paths, which replace `l1_config_url`. The guardian and relayer only read those documents, and no step writes the canonical config; there is no `guardian_authorization`, `l1_endpoints`, policy JSON, digest, or code allowlist (`AGENTS.md:74-84`; `psy_cli/guardian_common/src/runtime.rs:101-229`; `psy_cli/guardian_common/src/protocol.rs:413-432`).
- `docs/src/dev/reward-claim-operations.md` is referenced here.
