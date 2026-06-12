# Unmerged Commits: `origin/feat/shield-poseidon-bridge-2-realms-new`

Base branch: `feat/shield-poseidon-bridge`  
Compared branch: `origin/feat/shield-poseidon-bridge-2-realms-new`  
Generated on: 2026-05-15

## 1) Runtime Stability & Recovery

- `7ab06ce2` feat: soft restart/shutdown, nats persistence, and crash recovery fixes  
  Improves soft restart/shutdown flow, strengthens NATS persistence/crash recovery, and reduces restart state loss.

- `8689849d` fix(realm): robust recovery, coordinator backup format, and DB consistency  
  Hardens realm recovery, updates coordinator backup format, and fixes DB consistency issues.

- `68923752` fix(realm): move processing_realm_end_root assignment after no-jobs guard  
  Fixes state write timing when no jobs exist, preventing incorrect end_root writes.

- `fb585109` fix(realm): eliminate genesis double unique-id rotation in get_results_from_gatherers  
  Prevents duplicate unique-id rotation during genesis and avoids downstream offset errors.

## 2) State Tree / Zero-Hash / Checkpoint Correctness

- `13ec807c` fix(db_loader_sub_root): fix level mutation and zero-hash bugs in sub-tree loader  
  Fixes subtree loader level mutation and zero-hash derivation bugs.

- `6450f950` fix: correct zero hash, max_user_id unit and add root check in global_user_tree loader  
  Fixes zero-hash and max_user_id unit handling, and adds global_user_tree root validation.

- `d6d42101` fix(claim-rewards): fix ClearEntireTree zero_hash, proof index shift, endianness, and realm routing  
  Fixes multiple claim-rewards correctness issues (zero_hash, proof index shift, endianness, realm routing).

- `59864142` feat(coordinator): checkpoint reset + genesis global_user_tree fix  
  Adds checkpoint reset support and fixes genesis global_user_tree initialization/loading.

## 3) SDK Key / Wallet Capability

- `fc57028b` feat(client_prover): add SDK key sign type with allow-method policy  
  Adds SDK key signing type and allow-method policy constraints.

- `bf743a45` feat: expose register_sdk_key_circuit on WalletSession and RPC  
  Exposes register_sdk_key_circuit through WalletSession and RPC surface.

## 4) Config / Dependency / Engineering

- `f8de414a` chore: split tokio signal feature to crates that need it  
  Narrows `tokio signal` feature usage to crates that actually require it.

- `db2f4b83` chore: set guta fee to 1 PSY  
  Updates guta fee parameter to 1 PSY.

- `be17ad92` chore: update genesis contracts and local devnet genesis test  
  Updates genesis contracts and local devnet genesis test baseline.

---

## Raw Commit List (newest first)

- be17ad92
- db2f4b83
- f8de414a
- bf743a45
- fc57028b
- 59864142
- d6d42101
- 8689849d
- 68923752
- fb585109
- 6450f950
- 13ec807c
- 7ab06ce2
