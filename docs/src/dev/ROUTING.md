# Dev Docs Routing

> Repository-only routing index for `docs/src/dev`. Not part of the published mdBook (SUMMARY.md).

> Updated: 2026-10-19. Status: Review.

## Abstract

Each task below names the document that owns it and the document to read next. Every filename listed here exists under `docs/src/dev`; `AGENTS.md` is the sole exception and sits at the repository root as repository-root policy. `docs/src/dev/reward-claim-operations.md` is the operational reward-claim runbook for the implemented CLI (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:41-53`).

## Table of Contents

- [Task index](#task-index)
- [Document ownership](#document-ownership)
- [Related Documents](#related-documents)

## Task index

| I want to | Read first | Then |
|---|---|---|
| Create a wallet, register an account, fund PSY, query state, deploy or call a contract | `common-operations.md` | `devnet_lifecycle.md` |
| Deposit, claim a deposit, withdraw, or settle through the relayer | `bridge-common-operations.md` | `deposit-withdrawal.md` |
| Understand the checkpoint reward claim design | `checkpoint-claim-cutover.md` (draft design spec, not a runbook) | `reward-claim-operations.md` |
| Run the implemented claim-rewards CLI against the deployed contracts (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:41-53`; `psy-contracts/src/PsyToken.sol:67-104`) | `reward-claim-operations.md` | `checkpoint-claim-cutover.md` |
| Read reward tree circuit layouts, modes, or offsets | `reward-tree-circuits.md` | `gatherers.md` |
| Understand gatherer job modes or publication | `gatherers.md` | `processors.md` |
| Understand coordinator or realm processor pipelines | `processors.md` | `gatherers.md` |
| Generate or validate EndCap verifier metadata, Plonky2 caches, or the Bridge Groth16 cohorts | `circuit-and-verifier-operations.md` | `AGENTS.md` (repository root; governing release policy, `AGENTS.md:78-101`) |
| Start, stop, restart, or purge the local devnet | `devnet_lifecycle.md` | `devnet-launcher-reference.md` |
| Look up launcher flags, ports, supervision, or Anvil persistence | `devnet-launcher-reference.md` | `devnet_lifecycle.md` |
| Roll back the local stack | `rollback-operations.md` (five independent RPs) | `devnet_lifecycle.md` |
| Review bridge deposit and withdrawal architecture | `deposit-withdrawal.md` | `bridge-common-operations.md` |
| Review private transfer and private claim architecture | `private-transfer.md` | `common-operations.md` |
| Choose a name for a function, field, or type | `TERMINOLOGY.md` | the role doc that owns the pipeline |
| Check token privacy circuit fingerprints (`private_claim`, `claim_deposit`) | `token-privacy-circuit-fingerprints.md` | `fn-circuit-fingerprint-playbook.md` |
| Debug a function-circuit fingerprint or EndCap mismatch | `fn-circuit-fingerprint-playbook.md` | `circuit-and-verifier-operations.md` |
| Generate genesis artifacts | `genesis-generation.md` | `circuit-and-verifier-operations.md` |
| Understand relayer L1 RPC failover | `relayer-rpc-failover.md` | `bridge-common-operations.md` |
| Create a multi-repo worktree cohort | `worktree-cohort.md` | `devnet_lifecycle.md` |
| Review RealmFinalizeGUTA BLS authentication | `realm-finalize-bls-auth.md` | `processors.md` |
| Review realm P2P validator identity and routing | `realm-p2p-validators.md` | `realm-recovery-e2e.md` |
| Run the realm recovery end-to-end validation | `realm-recovery-e2e.md` | `devnet_lifecycle.md` |

## Document ownership

| Document | Owns |
|---|---|
| `common-operations.md` | Wallet, registration, funding, queries, contract deployment, calls |
| `bridge-common-operations.md` | Bridge deposit, claim, withdrawal, settlement procedures |
| `checkpoint-claim-cutover.md` | Checkpoint reward claim design specification (draft; not the operations runbook) |
| `reward-claim-operations.md` | Claim-rewards CLI (`client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:41-53`) and deployed-contract operations (`psy-contracts/src/PsyToken.sol:67-104`) |
| `reward-tree-circuits.md` | Reward tree circuit layouts, modes, offsets |
| `gatherers.md` | Gatherer job modes and publication |
| `processors.md` | Coordinator and realm processor pipelines |
| `circuit-and-verifier-operations.md` | Verifier metadata, Plonky2 caches, Groth16 cohorts |
| `devnet_lifecycle.md` | Devnet start, stop, restart, purge, rollback lifecycle |
| `devnet-launcher-reference.md` | Launcher internals and supervision |
| `rollback-operations.md` | Five-RP local rollback execution |
| `deposit-withdrawal.md` | Bridge architecture |
| `private-transfer.md` | Private transfer and claim architecture |
| `TERMINOLOGY.md` | Shared vocabulary and naming authority |
| `token-privacy-circuit-fingerprints.md` | Token privacy circuit fingerprints |
| `fn-circuit-fingerprint-playbook.md` | Function-circuit fingerprint debugging |
| `genesis-generation.md` | Genesis artifact generation |
| `relayer-rpc-failover.md` | Relayer L1 RPC provider pool |
| `worktree-cohort.md` | Multi-repo workspace script |
| `realm-finalize-bls-auth.md` | RealmFinalizeGUTA BLS authentication design |
| `realm-p2p-validators.md` | Realm P2P validator identity |
| `realm-recovery-e2e.md` | Realm recovery end-to-end runbook |

## Related Documents

- `AGENTS.md` (repository root) governs release policy, repository topology, and when generation is authorized (`AGENTS.md:78-101`); `circuit-and-verifier-operations.md` cites it as the governing reference.
- `docs/src/dev/reward-claim-operations.md` is referenced here.
