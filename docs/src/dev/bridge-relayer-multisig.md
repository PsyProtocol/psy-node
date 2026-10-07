# Bridge relayer multisig and guardian signing service

> **Status: Review — implementation documentation, 2026-10-05.** Normative protocol version 14 is retained. The implementation facts below describe the current source, including uncommitted changes; they do not extend the approved protocol or approve this documentation revision.
> Verification boundary: this revision is based on static source inspection only. No tests, builds, generators, formatter, service startup or deployment were run. Full three-guardian network, rotation, crash/offline and end-to-end acceptance remain separate gates; source presence is not execution evidence.

## Terminology & Abbreviations

[TERMINOLOGY.md](TERMINOLOGY.md):238-282 defines the existing multisig and guardian vocabulary. Stored fields, derived policy commitment, initial identity, runtime configuration and signing authorization have distinct owners.

| Term | Meaning |
|---|---|
| Guardian signer | One of exactly three Psy-operated services, each holding one different secp256k1 key. Not the L1 pause guardian. |
| L1 / L2 | External settlement chain / Psy network. |
| UPS / EndCap | User proving session / its final proof. |
| CSTATE / UCON | Per-user per-contract state / per-user contract tree. |
| IMT | Indexed Merkle tree. |
| PI | Circuit public input. |
| ABI | Application binary interface. |
| RPC / HTTP / TLS | Remote procedure call / Hypertext Transfer Protocol / Transport Layer Security. |
| JSON / SQL | JavaScript Object Notation / Structured Query Language. |
| SDK / CLI | Software development kit / command-line interface. |
| ECDSA / SEC1 | Elliptic Curve Digital Signature Algorithm / compressed public-key encoding standard. |
| SHA-256 | Secure Hash Algorithm with 256-bit output. |
| GuardianAuthorization | Approved network, contract and initial enrollment identities; never the current-member authority. |
| GuardianSession | Authenticated canonical account session, whether this guardian signed it or learned it. |
| GuardianSigned | This key's own irreversible nonce reservation/signature record. |
| A / B | Companion proof artifacts owned by [bridge-proof-aggregation.md](bridge-proof-aggregation.md), not substitutes for guardian authorization. |

## Abstract

The bridge account uses **exactly three Psy-operated member commitments and two external signatures**, with mutable policy stored by precompile6 and immutable enrollment bound to **user524288**. Guardians independently reconstruct deposit custody, authenticate committed withdrawal records, replay the entire pinned session and durably reserve its nonce before signing the existing UPS message. Current members come from authenticated state, never an operator member list. This document retains normative version14 while distinguishing implemented signing behavior, operational assumptions and planned acceptance. Companion aggregate proof code already exists in the current source; it does not replace guardian authorization or make aggregate no-op transitions valid guardian deposit anchors. No shared master key or secret-wallet fallback is part of the guardian submission path.

## Motivation

The relayer constructs a public multisig wallet and checks the registered key maps exactly to user524288 (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2498-2505`). It rebuilds deposit setter roots from independently verified custody instead of trusting caller roots (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2556-2571`). Signature validity alone does not establish custody: the guardian derives the complete authorized call list before comparing the replayed trace (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:336-363`).

The implemented circuit reads all four policy slots on both sides and verifies exactly two selected member signatures (`client_prover/psy_circuit/psy_ups_circuit/src/signature/multisig.rs:207-269`). The policy precompile stores individual commitments and checks expected prior fields before mutation (`../psy-compiler/psy-precompiles/multisig_policy/src/main.psy:59-82`). These are current implementation facts, not instructions to reintroduce the removed commitment-only design.

## Table of Contents

- [Specification](#specification)
  - [1. Scope, revisions and sequence](#1-scope-revisions-and-sequence)
  - [2. Authorities and flow](#2-authorities-and-flow)
  - [3. Policy precompile and account authentication](#3-policy-precompile-and-account-authentication)
  - [4. Registration and identity propagation](#4-registration-and-identity-propagation)
  - [5. Current custody and burn verification](#5-current-custody-and-burn-verification)
  - [6. Exact message, encoding and replay](#6-exact-message-encoding-and-replay)
  - [7. Catch-up, reservation and halt](#7-catch-up-reservation-and-halt)
  - [8. Operational head authority and protected runtime inputs](#8-operational-head-authority-and-protected-runtime-inputs)
- [Data Structures](#data-structures)
- [Core Functions](#core-functions)
- [Core Loops](#core-loops)
- [Module Changes](#module-changes)
- [File Changes](#file-changes)
- [Rationale](#rationale)
- [Security Considerations](#security-considerations)
- [Future Acceptance](#future-acceptance)
- [Real-network guardian acceptance](#real-network-guardian-acceptance)
- [Aggregate acceptance ownership](#aggregate-acceptance-ownership)
- [External Prerequisites](#external-prerequisites)

## Specification

### 1. Scope, revisions and sequence

**In scope:** real policy precompile; three stored canonical member commitments; fixed two-of-three precompile/circuit enforcement; exact account524288 registration; authenticated policy reads and rotation; guardian service, custody/burn checks, pinned replay, durable decisions and learned history; clean relayer/CLI/provider cutover; required ABI/artifact applicability plan.

**Out of scope:** implementing Spiderman, changing final Groth16 artifact count, rewards migration, changing L1 proposer/pause roles, another signature scheme, shared master key, automatic environment purge, deployment, generation or publication. No secret-wallet fallback or old commitment-only multisig path remains after implementation. Unrelated local work is preserved.

Order: current-protocol multisig design/review/implementation/verification, then reviewed merge, then separately gated companion proof redesign. User authorization for breaking source changes is not permission to delete data, regenerate Genesis, deploy or push. Existing local occupied state is checked, never overwritten automatically.

**Current source boundary:** the ordering above is the approved delivery sequence, not a statement that aggregate code is absent. `psy_cli/psy_relayer_cli/src/bridge/prove_bridge.rs:100-232` implements aggregate construction, and `psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2489-2496,2611-2629` binds a guardian-producing session to retained aggregate capacity. This document specifies their signing boundary only; aggregate protocol ownership remains with [bridge-proof-aggregation.md](bridge-proof-aggregation.md).

| Repository | Starting state | Read revision |
|---|---|---|
| psy-node | mainnet-beta | `0341409b15017b31276620e2df31564e96d4ac27` |
| psy-compiler | mainnet-beta | `8bf63cfe1f0fe8db6d53178c7784d0a5e87281d4` |
| psy-sdk | mainnet-beta | `a34d5fc84580b8ef88d77c7d72fdcc515c467a3a` |
| psy-contracts | detached | `46feb516102e5b19e28aa73b20a149ca480adae3` |

These revisions identify the design's starting source, not a clean current working tree. External specification reconciliation is complete against [the canonical psy-node specification directory](https://github.com/PsyProtocol/psy-memory/tree/f9dff5bb7a1eb495f462eac37fece95c8b5e9fcf/src/repositories/psy-node/specs) at psy-memory revision `f9dff5bb7a1eb495f462eac37fece95c8b5e9fcf`, inspected through authenticated repository access and confirmed by the design reviewer. Existing bridge/aggregation, multichain and access-control designs were checked; no duplicate guardian two-of-three service specification or separate publication/lifecycle requirement was found. No external files were written. `PIPELINE.md:19-38` continues to govern implementation and execution gates.

### 2. Authorities and flow

```mermaid
sequenceDiagram
    participant Relayer
    participant Guardian as Psy guardian x3
    participant Nodes as Verified nodes
    participant Journal
    participant Realm
    Relayer->>Guardian: 1. Mutual-TLS exact session request
    activate Guardian
    Guardian->>Nodes: 2. Policy fields, custody, burn and contract proofs
    Nodes-->>Guardian: 3. Evidence at pinned canonical checkpoints
    Guardian->>Guardian: 4. Catch up history and replay exact session
    Guardian->>Journal: 5. Commit nonce reservation, sign, commit signature
    Journal-->>Guardian: 6. Durable decision
    Guardian-->>Relayer: 7. Existing UPS signature
    deactivate Guardian
    Relayer->>Relayer: 8. Verify two members and prove exact trace
    Relayer->>Realm: 9. Submit EndCap
    Realm-->>Relayer: 10. Admission; observe canonical inclusion separately
    Relayer->>Guardian: 11. Retain canonical session for catch-up
    Guardian->>Nodes: 12. Authenticate inclusion, never trust relayer receipt
```

```text
on-chain policy fields ----+                 one separate Psy key
current L1 custody --------+                         ^
committed burn/code paths -+--> replay --> durable nonce decision --> signature
canonical history --------+                         |
relayer <-- two signatures --> exact EndCap --> canonical inclusion
                            
                             current L1 proof/sender path (separate authority)
```

| Authority | Owner | Not conferred |
|---|---|---|
| Current members/version | User524288 policy precompile CSTATE fields | Configuration cannot replace them. |
| Initial identity | Registered multisig fingerprint plus initial-policy parameter | Not current membership after rotation. |
| Signing keys | Three separate Psy key instances/journals | No common master seed; not three independent institutions. |
| Signing decision | Each guardian key's journal | Relayer cannot release a nonce reservation. |
| Included history | Canonical checkpoints/account transitions | Relayer archive is untrusted availability storage. |
| L1 custody | Finalized configured Bridge receipts/state | Services are discovery only. |
| Proposer/sender/pause | Existing L1 contracts and separately held transaction keys | UPS signatures do not grant these roles. |
| Proof validity | Pinned current verifier set | Guardian approval never bypasses it. |

The implemented ordering is `handle_request` → `observe` → `verify_guardian_session` → `GuardianSigner::sign_verified` (`psy_cli/psy_relayer_cli/src/guardian/service.rs:372-414`). History recovery precedes request replay; the request cannot supply the observation root. Signature bytes are serialized under `GuardianDb::authorize_response`, which requires Active state and an exact signed reservation before committing (`psy_cli/psy_relayer_cli/src/guardian/db.rs:215-225`). Relayer publication is an availability action after independently verified inclusion, not an assertion accepted on trust (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2671-2680`).

`psy-contracts/src/StateManager.sol:94-99,205-210` gates `applyBridgeWindow` with proposer permission; guardian UPS signatures confer no such role. Bridge guardian pause remains a separate contract authority. Realm admission checks starting leaf, historical checkpoint root, public inputs, state consistency and EndCap proof (`psy_node_common/src/realm/edge/handler.rs:737-862`), not L1 custody truth. Admission is not inclusion.

### 3. Policy precompile and account authentication

#### Authoritative registry and storage

The registry contains `multisig_policy` immediately after faucet, with `MultisigPolicyContractRef`, `get_policy`, `set_policy` and declared height4 (`../psy-compiler/psy-precompiles/precompiles.json:89-98`). Registry enumeration emits identifier6 (`../psy-compiler/psy-precompiles/build.rs:226-227`); it is not operator-selectable. Existing identifiers0..5 retain their positions.

`ContractConfig.declared_state_tree_height: Option<u8>` exists at `client_prover/psy_core/psy_config/src/lib.rs:139-140`. Build compares inferred height to declared height and rejects inferred>declared or declared>32 (`../psy-compiler/psy-precompiles/build.rs:83-87`). Policy uses the declared height4 rather than dummy mutable slots. Artifact consumers require artifact and ABI heights to agree.

| Slot | Exact Hash value | Owner/validation |
|---|---|---|
| 0 | `[version,2,3,0]` | u32 version>0 after initialization; threshold/member count are constants checked by precompile and circuit. |
| 1 | member commitment0 | Nonzero canonical four limbs. |
| 2 | member commitment1 | Nonzero and lexicographically greater than slot1. |
| 3 | member commitment2 | Nonzero and lexicographically greater than slot2. |

Only slots0..3 store policy. The initial commitment encodes the header and three members with five zero padding entries; padding is not membership. Selected compressed SEC1 keys are hashed and compared against authenticated current members (`client_prover/psy_circuit/psy_ups_circuit/src/signature/multisig.rs:303-311`). No separately stored whole-policy hash is an authority.

`get_policy() -> (Hash,[Hash;3])` returns header and members; no off-chain authority. Policy mutation is the precompile call `set_policy(expected_header:Hash,expected_members:[Hash;3],next_members:[Hash;3])` (`../psy-compiler/psy-precompiles/multisig_policy/src/main.psy`), not an RPC setter. It compares all four current slots, validates next keys' canonical nonzero strict order, and writes all four slots atomically. Uninitialized all-four-zero state installs header `[1,2,3,0]`. Otherwise require header shape, checked version increment and at least one changed member, then write `[version+1,2,3,0]`. No caller can set threshold1/3, member count2/4, arbitrary version, zero member or duplicate. The local wallet has no policy RPC: `register_multisig_user` and `add_multisig_user` enroll the public account, and `psy_set_multisig_policy` is not a method (`client_prover/psy_prover/src/local/native/mod.rs:50-55,489-490`). Precompile execution alone cannot authorize an account session: the account authentication circuit supplies current-member authorization and strict bootstrap identity below.

#### Circuit/host cutover

Extend existing `MultisigSignatureCircuit`, do not fork an alternate signature scheme. Replace its slot0 commitment readers with authenticated reads of slots0..3 at starting and ending self state, each bound to the same account/user/checkpoint context. `StateReaderGadget::get_self_user_current_contract_state_slot_hash` creates one UCON proof plus one CSTATE slot proof per call (`client_prover/psy_circuit/psy_ups_circuit/src/signature/state_reader.rs:98-137`). The circuit calls it four times on each reader (`multisig.rs:220-222`), so each start/end reader carries exactly **eight membership proofs**, ordered `(UCON,slot0,UCON,slot1,UCON,slot2,UCON,slot3)`, and repeated UCON anchors are connected (`:224-232`). These eight proofs are not signatures. The same circuit adds exactly **two** `Secp256K1Gadget` instances (`:193,247-255`); `prove` rejects any other signature count (`:284`). Host witness construction makes the same four slot reads per side (`client_prover/psy_prover/src/session/session.rs:2916-2948`), and `prove` rejects a side whose `merkel_proofs.len()` is not 8 (`multisig.rs:290-297`). Do not describe the eight proofs as two ECDSA signatures, or the two signatures as eight proofs.

Derive current and ending policy from authenticated fields. Signature witness contains account, start/end state proofs, signature data, sign context, starting user leaf and nonce; current and ending policies are derived, not caller-supplied preimages. The local wallet does not install current policy. Initial policy remains immutable enrollment data for `MultisigAccount.public_key_param`, a distinct identity role. The circuit pins threshold2/count3 and exactly two selected distinct increasing indices for every session, not merely guardian policy. It recomputes current/ending commitment and retains exact message/identity PI semantics (`multisig.rs:57-94,234-243`).

Registered identity is `PoseidonHash::two_to_one(fingerprint, public_key_param)` (`multisig.rs:300-301`; `client_prover/psy_prover/src/wallet/memory_wallet.rs:626-632`). The fingerprint is the host hash of the revised circuit's verifier data (`multisig.rs:350-351`; `client_prover/psy_circuit/psy_common_circuit/src/proof_minifier/pm_core.rs:19-38`). It is not a public input: the circuit registers only `H(sighash, public_key_param)` (`multisig.rs:242-243`). A fingerprint chosen inside the proof could not authenticate the verifier that checks that proof, so the circuit does not embed or recompute it. The host constructs the local circuit, requires the trace fingerprint to equal `circuit.get_fingerprint()`, and requires the saved verifier bytes to equal that circuit (`client_prover/psy_prover/src/session/session.rs:2903-2911`). Guardian verification repeats the approved-fingerprint check (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:290-293`). A caller-supplied fingerprint or verifier is not authority.

Bootstrap is allowed only when all four starting slots are zero **and** authenticated starting account nonce is zero **and** its user-state root is the default/pristine root **and** the registered public key equals `two_to_one(host fingerprint, initial parameter)`. Ending version must be1 and ending members equal immutable initial members; initial two signatures authorize it. An existing nonpristine account with zero policy fields is rejected. Nonbootstrap ending fields are either exactly unchanged, or changed members with version exactly+1; current fields authorize every operation. Restoring earlier members still increments version. Clearing header/members or resetting bootstrap is impossible.

The circuit accepts any policy transition that satisfies those field rules. It does not restrict which contract calls surround that transition. Guardian and daemon code do. For `Bootstrap` or `ReplacePolicy`, the daemon refuses bridge calls and builds exactly one contract6 `set_policy` (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2449-2451,2583-2597`). `verify_guardian_session` does the same: bridge requires an unchanged policy and independently derived deposit/withdrawal calls; bootstrap or replacement requires the single derived `set_policy` (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:301-308,336-357`). A non-bridge request carrying deposit anchors or withdrawal records is `UnsupportedCall` (`protocol.rs:354`). That call grammar is a host authorization boundary, not a circuit constraint.

The circuit fingerprint changes when this layout changes. Regenerate dependent EndCap metadata and circuit artifacts at their authorized stage, and update consumers atomically under `AGENTS.md:55-69`; do not claim current artifacts already validate the new policy layout. No new signature message domain or master-key DPN/Plonky2 software-defined substitute is introduced.

### 4. Registration and identity propagation

`WalletSession::register_bridge_multisig_user(&mut self, account: MultisigAccount, exclusive_registration_intake: bool) -> anyhow::Result<QHashOut<F>>` implements exact enrollment (`client_prover/psy_prover/src/session/session.rs:1831-1866`). It first requires exclusive drained intake and checks both Strategy5 directions, registration2↔user524288. It derives the public account locally; an exact existing key returns only when its resolved identifier list is exactly `[524288]`. An occupied slot, wrong next index or prior registration elsewhere stops before submission.

For an empty slot, the method submits once, waits for checkpoint advancement and rechecks slot2 and the resolved identifier list. Submission errors explicitly report an unknown outcome and forbid automatic resubmission; an observed race returns a conflict without rollback (`client_prover/psy_prover/src/session/session.rs:1847-1863`). This source uses `get_coordinator_latest_block_state` for registration polling, unlike guardian signing's committed-head observation. Exclusive intake is an operator assertion, not enforced network-wide by this client. Source arithmetic is not evidence that registration has executed.

#### Public-only Genesis enrollment source

**Implemented generator:** required `--relayer-multisig-account` and `--multisig-policy-artifact` inputs are declared at `psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:78-84`. The strict public-account decoder accepts only `contract_id` and the full initial policy, then invokes `public_key_param()` for policy validation (`psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:171-197`). The generator checks the approved policy artifact before constructing the actual local circuit, seeds the four policy slots plus fee balance, and exports `None` at registration2 (`psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:207-272,425-438,479-488`). The remaining enrollment requirements below describe the operator and consumer contract; they are not instructions to replace this implemented generator again.

Both generation entry points require two public paths: `PSY_RELAYER_MULTISIG_ACCOUNT` and `PSY_MULTISIG_POLICY_ARTIFACT`. The Makefile forwards quoted explicit arguments and removes the six obsolete secret environment aliases from the generator child only (`Makefile:107-112`). `planGenesisGeneration` validates public account/artifact files, resolves paths and returns argv plus a copied child environment (`dev/locSetupV4.ts:2746-2795`). L1 signing credentials remain a separate operational authority; public Genesis enrollment requires no guardian private keys or live signing service.

The generator derives fingerprint from `MultisigSignatureCircuit::new()` and parameter from the validated public account. `initialized_multisig_user` sets nonce/balance/checkpoint/event index to zero, contract0 fee slot to `[initial_fee_balance,0,0,0]`, and contract6 slots0..3 to `[1,2,3,0]` and the initial members (`psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:207-229,479-488`). Fee balance must be nonzero and canonical. This is an **initialized-policy Genesis account**, not pristine bootstrap: first ordinary nonce1 uses stored initial members. A genuinely empty registered account retains section3 bootstrap semantics.

Private export is dense `Vec<Option<Hash>>`; registration2 is `None`, not omitted or a dummy secret. Validator/faucet indices remain aligned (`psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:425-472`). Faucet export explicitly requires `Some` at its selected slot (`psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:566-570`). Launcher reads `(string|null)[]` (`dev/locSetupV4.ts:1326`); phase1 verification requires real values for indices0/1 (`client_prover/psy_prover/examples/phase1_verify.rs:24-26`). No guardian secret enters this export.

**Planned acceptance, not executed here:** authenticate generated policy/fee slots through actual account/UCON/CSTATE roots and prove initialized-policy nonce1; exercise invalid public account/artifact rejection and child-only secret filtering; retain the same Genesis/deployment/checkpoint during separately authorized no-relayer setup and full startup. Existing lifecycle documentation owns state-preserving operations. This paragraph grants no generation, startup, purge or deployment permission.

#### Uniform approved compiler-artifact authority

Keep existing Genesis transport: `PsyGenesisBlockSetupData.contracts` remains `Vec<PQBCDeployContract<Hash>>` (`psy_data/src/genesis/genesis_block_setup.rs:32-38`); exported named deployment objects retain existing flat fields/name. No new Genesis wrapper, layout metadata, full-private ABI manifest, canonical type-DAG producer or stamp schema is required for multisig. Existing CLV2 leaf fields/domain/FFS and unrelated deploy/layout work remain unchanged. Public-only multisig Genesis, initialized member slots plus fee state, dense null2 export and required caller forwarding above remain mandatory.

One model applies to every contract regardless of layout-root value: authenticate the **entire expected current contract leaf** under the approved Coordinator checkpoint, and interpret execution using an explicitly approved **complete compiler artifact**. Artifact contains state_tree_height, all circuit_definitions and existing ABI2.0.0 bytes; exact bytes/digest are retained in historical approval. Rebuild deployment code_definition/code_root/function_whitelist with existing `gen_contract_deploy_and_circuits_for_functions` and compute function-tree root at existing network height. Require roots/methods/height equal expected leaf and ABI height equal artifact height. This identifies the current approved executable; it does not prove an arbitrary ABI is committed on chain. Operator approval binds ABI interpretation to those definitions. No special verification branch for zero layout root or Genesis; missing artifact fails closed.

The artifact predicate requires one visible `state_map` with exact `Map<Hash,Hash,1048576>` shape, value size4, alignment4, aligned offset and checked felt size (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:167-178`). The offset is the approved absolute compiler offset, not field ordinal or a sum of visible predecessors. It is cross-checked against the compiled withdraw method; private-field descriptions are unnecessary. Policy interpretation uses its approved direct slots0..3.

At approval activation/startup, validate each complete artifact once and cache `ApprovedTokenMap {subslot_base:u64,capacity:u64}` after validating the approved ABI field name is exactly state_map. This is a derived immutable descriptor, not another operator-configured authority. Include all callable definitions in code/function-root reconstruction; approval covers their full semantics, not only withdraw. Verify the withdraw namespace6 command's resolved base/capacity against the visible field, retaining the actual absolute compiler offset despite private predecessors. Cache keyed by artifact digest plus exact expected leaf; invalidate on approval/artifact/leaf change. Per-record checks authenticate current leaf equality and use that verified descriptor, not rebuild/prove every function for every burn. No remote ABI substitution or full-private reconstruction is performed.

`verify_withdraw_map_constants` builds a typed-wire constant map, rejects duplicate identities, permits canonical literal Constant/ConstantU32 and Boolean constants, and requires each relevant map operand definition to precede its command-resolution boundary (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:181-218`). It requires exactly one map write and at least one map read/contains operation, with matching base/capacity. It does not perform arithmetic folding, execute the program or analyze key/value-wire semantics. Namespace6, debit correctness and historical writer safety remain approval assumptions for the complete executable, not properties established by this helper alone.

Namespace6 burn semantics and safe historical token upgrades are explicit Psy operational approval assumptions. Neither current code membership nor layout-root membership proves every historical writer was safe. The approved canonical network must permit only approved safe upgrades; if that assumption cannot be established, signing is unavailable until an approved historical artifact/network disposition exists. Do not add an unrequested chain scanner or claim current membership independently proves lineage.

Keep ABI2.0.0 public state/types unchanged. Build emits complete existing ABI with definitions for guardian-approved contracts; uniform existing-ABI emission for all precompiles is acceptable, but introduces no state_layout/storage_types schema. Required approved artifact output failures remain fatal. Existing provenance format can remain; no new Genesis stamp/wrapper protocol or root-layout-derived metadata is mandated. Compiler/SDK/services retain original Genesis deployment parsing. No new root psy_node_data/parth_core dependency is needed solely for removed layout derivation.

The implemented guardian artifact predicate consumes complete existing ABI bytes and does not derive a new Genesis wrapper or private-layout authority (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:148-219`). Unrelated deployment/layout work is outside this document's write scope. No source deletion, parser migration or collaborator-file reset is authorized by this implementation inventory.

Acceptance (unexecuted): actual approved artifact reproduces current authenticated code/function roots/height; wrong digest, missing definitions/map, mismatched ABI offset or executable constant/capacity reject. Current token artifacts succeed without new Genesis layout roots, using the same checks for any approved layout-field values. Preserve actual initialized policy/fee roots and flat bundle consumers. No arbitrary ABI matching text substitutes artifact approval, and no test claims historical writer safety from current leaf membership.

| Consumer | Clean cutover contract |
|---|---|
| Relayer account submission | Public multisig enrollment checks exactly user524288 and reconstructs contract2 deposit setters before signing (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2498-2505,2556-2571`). |
| Existing bridge proof circuits | Numeric account524288/deposit2/withdrawal3 remain the signing contract; current aggregate construction is separately owned (`psy_cli/psy_relayer_cli/src/bridge/prove_bridge.rs:100-232`). |
| Token and USDT interpretation | Every selected token mapping requires approved complete artifact and historical whole-leaf membership (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:226-244`). |
| Policy precompile/ABI/config | Registry owns id6 and height4; complete approved artifact reproduces Genesis code/function roots and direct four-slot policy storage. No new on-chain layout metadata or Dargo-example deployment fallback. |
| Genesis/registration inputs | One enrollment record derives fingerprint/initial parameter/public key and required registration index2; no independently hand-copied member policy authority. Changed precompile bundle is a Genesis applicability input, not authorization to execute generation. |
| L1 StateManager/Bridge | Current verifier/role/frontier semantics remain; account constants agree with524288. No force-set/recovery mechanism added. |
| SDK, services, DApp, claim CLI, prove proxy and L1 wallet callers | Continue numeric524288 and existing bridge formats; consume revised account/EndCap artifact metadata where applicable, remove old commitment-only multisig witness callers. Browser guardian signing API is unnecessary. |

SDK, services, DApp, claim and proof callers do not become guardian membership authorities. Numeric account identity and artifact applicability remain the contract; this revision makes no claim of downstream release validation. L1 custody evidence is independently established as specified in section5.

### 5. Current custody and burn verification

#### Deposits

Pin one finalized block number/hash per changed chain through each guardian's own configured verified nodes. Check chain id/genesis, Bridge/code/implementation and authorized token mapping. A request cannot define finality. A chain lacking a verified adapter is unavailable, not accepted after arbitrary block counting.

The guardian custody implementation is `psy_cli/psy_relayer_cli/src/guardian/verify_l1.rs:137-175`, not the relayer discovery log helper. It pins the requested block hash with `requireCanonical`, verifies deployment identities and pending count, and reconstructs from genesis or a reauthenticated cached prefix. The cache is keyed by the chain-authorization digest and endpoint URL; a contradictory saved anchor returns `FinalityConflict`. Logs are fetched in inclusive blocks of at most5000, checked against canonical blocks and successful transaction receipts, and their recomputed leaf is compared to pinned `depositLeafHashes` (`psy_cli/psy_relayer_cli/src/guardian/verify_l1.rs:178-222`). Missing indices return unavailable; malformed, duplicated or mismatched evidence returns mismatch.

`DepositAnchor` strictly requires `old_count<new_count` (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:356-357`). The daemon skips equal counts before creating an anchor and independently reconstructs every requested setter root (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2556-2571`). Guardian call equality permits only these deposit `set_chain_root` calls, not raw append methods (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:336-357`). Separately, aggregate `DepositTransition` permits zero count delta only with equal roots (`client_prover/psy_core/psy_data/src/bridge_aggregate.rs:359-366`); `build_deposit_spiderman_inputs` requires an empty prefix for that no-op chain (`psy_cli/psy_relayer_cli/src/bridge/prove_bridge.rs:100-114`). Aggregate identity does not relax guardian custody authorization, and guardian signing itself requires no Spiderman witness.

#### Burns, code and map location

Discovery starts at service offset0 for every selected chain; supplied chain offsets are reduced to chain selection and both checkpoint arguments remain unused (`psy_cli/psy_relayer_cli/src/bridge/propose_withdrawals.rs:421-455`). A service leaf-hash mismatch is logged and skipped, not accepted; selected records are sorted, deduplicated by `(sender,token_contract,nonce[8])`, and conflicting duplicate payloads reject (`psy_cli/psy_relayer_cli/src/bridge/propose_withdrawals.rs:470-523`). Guardian membership verification remains mandatory for every selected record. Missing service records delay discovery; they cannot establish enumeration completeness.

The approved token withdraw debits balance and inserts the namespace6 record (`../psy-compiler/psy-precompiles/token/src/main.psy:245-286`). Guardian `amount_u64` decodes only the low two big-endian words and requires high six words zero plus `0<amount<0xffffffff00000001`; it never reduces an out-of-range amount modulo the field (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:324-328`). Network magic is likewise canonical and nonzero.

The34-field leaf preimage is sender, recipient8, token8, amount8, nonce8 and destination chain; record key derives from nonce, while token contract identifies the authenticated location (`../psy-compiler/psy-precompiles/token/src/main.psy:273-286`; `psy_cli/psy_relayer_cli/src/guardian/verify.rs:116-133`). Full leaf preimage/key/value/next pointers and CSTATE/UCON/user/checkpoint paths are authenticated.

Token and recipient upper96 bits must be zero, recipient nonzero; destination/token/L2-contract must match exactly one approved mapping (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:330-340`; `psy_cli/psy_relayer_cli/src/guardian/verify.rs:226-243`). A zero-address native token is accepted only through that exact mapping. The caller-chosen token address in the token contract is not itself evidence of asset equivalence.

**Program identity and interpretation:** `verify_withdrawal_burn` authenticates the entire expected contract leaf, global-contract path, sender leaf, UCON path and scoped record membership (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:226-244`). `validate_approved_contract` reconstructs deployment roots and derives the visible token-map offset from approved complete artifact bytes (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:148-219`). Operator approval supplies semantic interpretation; current membership does not prove safe historical writers. There is no Genesis/zero-layout bypass.

The contract leaf digest is explicitly `PoseidonHash::hash_no_pad([0x434c5632] || leaf.to_qfelts())`: the domain element followed by all19 fields in `client_prover/psy_core/psy_data/src/qdata/contract.rs:39-61` order, including deployer, function root, code root, state height and layout fields. Compare this20-field hash with the global-contract path value before verifying that path. Do not hash only the19 fields or omit the domain (`contract.rs:84-107`).

Approved token-map offsets must be divisible by4; the actual reader uses `b=subslot_base/4`, not an independently configured location (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:174-178,234-241`). `QIMTMembershipProofRPCRequest` carries checkpoint, user, contract, key, state-slot base and capacity; its checked inclusive range is `[b+1,b+capacity]`, including every nonzero successor and excluding the sentinel (`client_prover/psy_provider/src/request.rs:1213-1227`). The guardian repeats these checks before accepting membership. A root-equal proof outside the approved map is rejected.

#### Ordering and append indices

Because the system is unlaunched and breaking change is authorized, choose a **new deterministic selection order**, not fictional authenticated event order. For each destination chain sort selected new burns by `(sender_user_id,token_contract_id,nonce[0],...,nonce[7])`; concatenate chains ascending. Replay existing withdrawal-tree append/batch chunking in that order. Assign indices `old_count+j` per chain only after reconstructing canonical GuardianSession history to the starting checkpoint and matching old subtree root/count. Previously included ordering is retained as account history; new burns never insert before it. Reject a repeated burn identity or destination-local nonce in selected or included history, including different users/tokens sharing a nonce. Current L1 nonce scope is destination-wide; this signer rule changes no L1 map. Every relayer entry point uses this one selector; no parallel services-offset branch remains.

#### Exhaustive authorized call grammar and fee

The guardian constructs `ContractCallData::new(calls)` and compares the entire parsed call data before replay (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:336-357`). Bridge calls begin with one deposit setter per sorted changed chain; then the existing `build_withdrawal_batch_calls` packs sorted withdrawals into singles, twos and fives (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:608-722`). Setter encoding is chain index, absolute count and eight root words (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2234-2256`). Policy operations contain exactly one derived `set_policy` and no deposit/withdrawal arrays. Empty bridge requests are `UnsupportedCall` (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:354-355`). No caller-provided software-defined call override survives exact call-data equality.

No other requested top-level calls are permitted: in particular no withdrawal `set_chain_root`, raw withdrawal `append_leaf`, arbitrary token call, caller-supplied fee call, extra policy call, deferred invocation or free-standing inline invocation. Internally generated inline/deferred steps are accepted **only** when deterministically generated by replaying this independently derived list through the approved pinned contract definitions; full typed trace equality binds every such step. Replaying arbitrary supplied calls faithfully is not business authorization.

`TraceBuildSession::required_fee` computes `GUTA_FEE + DA_FEE*s` using checked integer multiplication/addition, where `s` is modified slots plus one if token0 slot0 is not yet modified, and rejects fee>=field modulus (`client_prover/psy_prover/src/session/session.rs:856-864`). Guardian rejects fee above `authorization.max_fee` before finalization, then requires exactly one generated `BurnFee` with contract0 and `TOKEN_SIMPLE_BURN_METHOD_ID`/`simple_burn` (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:358-365`). Entire trace equality binds its inputs and resulting state. Caller-supplied fee calls fail independent call-data equality.

### 6. Exact message, encoding and replay

The circuit computes the existing UPS sighash, converts its four limbs to reversed canonical message bytes, and binds both ECDSA gadgets to that message (`client_prover/psy_circuit/psy_ups_circuit/src/signature/multisig.rs:206,244-269`). Host verification requires `Hash256::from(sighash)`, exactly two strictly increasing indices0..2, selected compressed-key commitment and low-S scalars (`client_prover/psy_circuit/psy_ups_circuit/src/signature/multisig.rs:279-312`). Service signs the raw reserved prehash (`psy_cli/psy_relayer_cli/src/guardian/service.rs:456-459`), not JSON, a personal-sign prefix or request-id SHA-256. Immutable identity binds the initial-policy parameter; current policy authorizes the signatures.

Pinned replay calls `begin_trace_build_at_checkpoint` with the independently authenticated checkpoint-tree root, account identity, checkpoint and expected nonce (`client_prover/psy_prover/src/session/session.rs:2189-2229`). Zero authenticated user-tree value selects nonce1; otherwise `next_session_nonce` performs checked addition and requires a canonical field value (`client_prover/psy_prover/src/session/session.rs:2200-2208,2232-2235`). Checkpoint, global roots, account membership and first-session registration membership are checked before returning the builder. Neither request JSON nor a later head can replace this anchor.

Supplied and replayed `TxTrace` values are compared through complete `serde_json::to_value` equality, with no excluded fields (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:411-412`). Envelope decoding checks account/network/nonce, hash strings, `steps.len()` and unsigned proof absence before replay (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:367-379`). The independently derived call data is compared separately. Equal independent traces remain an acceptance requirement, not execution evidence here.

Imported JSON uses recursive duplicate rejection and the source-type round trip `serialize(deserialize(parsed)) == parsed` (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:76-118`). Source-defined optional omissions are accepted only when serialization preserves them; unknown or noncanonical keys fail. Original nested text is retained for request-byte identity, independently of typed replay equality.

Canonical request bytes start ASCII `PSYGS001`, then request fields in table order. Primitive encoding:

| Type | Bytes |
|---|---|
| u8/u16/u32/u64/u256 | unsigned little-endian1/2/4/8/32, overflow rejected |
| enum | one u8, declared discriminant only |
| Hex20/32/33/64 | decoded raw fixed-width bytes, no prefix or length |
| Hash4 | four canonical field u64 little-endian limbs |
| fixed array | elements in order, no count |
| Vec<T> | u64 little-endian element count then elements |
| String/JsonText | u64 UTF-8 byte count then exact bytes, no normalization |
| Option<T> | 0 absent, 1 thenT present |
| struct | declared field order, no names/padding |

`request_id=SHA256(bytes)` is journal identity only. Exact nested JsonText whitespace is intentionally included: semantically equal reformatted retries at a reserved nonce conflict. Replay equality is typed/semantic, journal equality byte-exact. Example Vec<u8>[2,3] is `02 00 00 00 00 00 00 00 02 03`; bridge enum00; u32(1)=`01 00 00 00`.

### 7. Catch-up, reservation and halt

**Separate meanings, not parallel authorities:** `GuardianSigned` records what this key reserved/signed; `GuardianSession` records what canonical chain included. A guardian that did not sign has no fabricated local signature/decision. All accepted append history is derived exclusively from GuardianSession records, never from the local decision log or services offsets.

Relayer retains full request, two signatures, EndCap bytes and observed inclusion before discarding pending work. It serves mutual-TLS `GET /v1/sessions?after_nonce=N&limit=L`, L1..64, records in increasing nonce, each at most64MiB, streamed one record per response page; response `{sessions:[GuardianSessionRecord],next_after_nonce:u64,has_more:bool}`. Limit bounds record count, transport caps each response64MiB and stops before exceeding it; if one record alone exceeds the cap reject its creation before signing. `next_after_nonce` is last returned nonce or N for empty. An empty/omitted page is unavailable evidence, not proof of completeness. Relayer and any guardian can serve their same retained canonical envelopes; endpoints are discovery/availability only. History endpoint addresses live in runtime config, not signing request.

Before reservation, conservatively serialize the complete future envelope/page using exact request and EndCap nonproof input already known from the trace, maximum-width decimal context fields, two maximum-width signature representations, and a hex string sized to the approved verifier's maximum serialized EndCap proof bytes. Measure JSON serialization including nested-string escaping and page wrapper; reject if it exceeds64MiB. The maximum proof size is a required approved artifact-derived bound (`max_endcap_proof_bytes` below), not guessed from request size. After actual proving, enforce both proof byte bound and exact serialized envelope/page bound again before submission. A violating generated proof is an artifact/implementation error: do not submit or alter the reserved request. The history server emits only pages whose actual serialized size is within the cap.

The service authenticates saved anchors before catch-up, then replays retained and fetched next-nonce sessions through `verify_session`; insertion and cursor advancement are atomic (`psy_cli/psy_relayer_cli/src/guardian/service.rs:168-202`; `psy_cli/psy_relayer_cli/src/guardian/db.rs:258-314`). Missing pages or incomplete history return `HistoryUnavailable`. **Observed distinction:** `verify_chain_state` count/root mismatch returns `StateMismatch`, converted to `GuardianAccountError::Unavailable`, rejecting signing without durable halt (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:281-288,560-562`). Durable `AppendHistoryMismatch` instead covers import-time duplicate/index/history failures (`psy_cli/psy_relayer_cli/src/guardian/db.rs:301-305`). Not every rejected state comparison halts the account.

Historical import resolves authorization from the immutable **local Psy approval archive**, independently of own GuardianSigned. Runtime configuration supplies archive directory and a locally approved version/digest index. Each version has exactly one UTF-8 GuardianAuthorization file; SHA-256 of its exact bytes must match its indexed digest and its embedded version. Files/index are provisioned through the existing authenticated Psy operator configuration channel, owner-only writable, immutable once approved, and retained for the entire account history. A replacement guardian receives this archive and index before catch-up. Peer history envelopes can name a version but cannot approve or replace its bytes. Missing approved historical version returns HistoryUnavailable; digest/version conflict refuses startup or import. New signing uses only the active version; exact old retries retain section7 restrictions. Historical import is a distinct read-only verification mode that accepts its locally approved archived version without requiring this key's prior decision or current-policy membership. It uses that version's token mappings, ABI/code pins, fee parameters and proof bound at the original checkpoint, never substitutes active-version policy. Canonical inclusion/threshold signatures remain independently verified.

If C was offline while A+B signed, C imports the same canonical session without own GuardianSigned, then can sign with A while B is offline. Replacement key enrollment uses identical catch-up. A local Reserved row whose exact request is included by the other two remains Reserved/unanswered, linked to GuardianSession; it never gains a fabricated own signature. No further signing at consumed nonce occurs. If a cached local signature does exist, retain it. A different canonically included request consuming a local Reserved/Signed nonce is a permanent conflict. Mere lack of this guardian's signature is not evidence of corruption: two other signers can validly include it. An archive lacking threshold signatures/trace/proof cannot be reconstructed or trusted and yields HistoryUnavailable.

Own decision key `(network_magic,user_id,nonce)` excludes checkpoint/version. Commit Reserved full bytes before key use; deterministic raw signing; commit Signed before release. Timeout/cancellation does not delete or replace a reservation. Full bytes are compared inside one redb write transaction. Exact cached response still runs current observation/history/evidence checks. Storage failure returns no signature. One Psy key instance exclusively owns one redb file plus an external `complete_journal`/`exclusive_key_use` signing authorization; a file lock cannot detect another database clone. Immediate durable commits precede signature release and terminal-halt errors. Missing signing authorization disables startup; revocation halts. No automatic unhalt or nonce release.

`GuardianAccount` Active→Halted is durable. Precise contradiction predicates:

1. For each saved L2 checkpoint `(id,leaf_hash)`, verify current provider Merkle path at that id against locally verified canonical checkpoint-tree root. Hash mismatch under a valid path proves contradiction. Missing path/root is unavailable, not rollback.
2. For each GuardianSession, verify user leaf membership at its included checkpoint/global user root; require exact ending leaf and public key/nonce. Check historical checkpoint, not latest leaf after later valid sessions.
3. For each saved finalized L1 block, verify canonical block hash at its height and ancestry to locally verified finalized head. A verified different canonical hash is conflict; inaccessible node is unavailable.
4. Reconstructed count/root mismatch rejects request verification with `StateMismatch`; import-time append-history contradiction commits `AppendHistoryMismatch`. Behind/incomplete history is not contradiction.
5. Canonical different session consumes local reserved nonce, or the retained signing authorization has readable changed bytes, `revoked=true`, `exclusive_key_use=false`, or `complete_journal=false`: halt. Missing, unreadable, expired, or not-yet-valid approval stays unavailable and does not halt.

Startup authenticates Genesis and database shape; full saved-history observation runs in the observer and before each cached/new response (`psy_cli/psy_relayer_cli/src/guardian/service.rs:269-323,380-402`). Old-version retries require exact existing request bytes. Consumed nonces additionally require an already-saved signature and reconstruct history strictly before that nonce; consumed unsigned reservations are not signed (`psy_cli/psy_relayer_cli/src/guardian/service.rs:381-401`). Unresolved decisions block authorization-version changes (`psy_cli/psy_relayer_cli/src/guardian/db.rs:251-253`). Completed observations do not promise instantaneous reorg awareness.

### 8. Operational head authority and protected runtime inputs

This section defines precisely what earlier references to a locally verified L2 canonical root mean: **an independently queried, explicitly Psy-approved Coordinator/full-node operational authority**, authenticated as below. Merkle checks bind historical state to that authority's committed head; they do not independently prove consensus finality or implement a recursive light client. Compromise of one guardian's authority can cause that guardian to mis-sign. Three keys sharing one compromised upstream are not independent evidence. Each guardian operator must approve its own authority and document upstream isolation. L1 finality requirements remain unchanged.

`load_network` reads one protected strict `NetworkConfigGoldilocks`, checks compiled magic/dimensions/fees, requires empty `prove_proxy_url`, and pins `l2_rpc_url` to the first URL of Coordinator0 (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:205-218`). After exact route/pin coverage it constructs `RpcProvider::new_with_endpoint_clients`; service then calls `WalletSession::new_with_provider` (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:220-250`; `psy_cli/psy_relayer_cli/src/guardian/service.rs:276-278`). These runtime fields and constructor injection are implemented. Requests cannot override them.

Preserve existing Coordinator/Realm route topology and URL order. `L2RpcEndpointPin {role:Coordinator|Realm,config_id:u64,rpc_url:String,tls_certificate_sha256:Option<Hex32>}` uses role discriminants0/1 and the source configuration entry's id. Require exact one-to-one correspondence between protected locally approved pin records and every `(role,config_id,url)` occurrence in coordinator_configs/realm_configs. Reject missing/extra pins, duplicate route tuples, empty groups and duplicate ids within a role. Same-origin different paths are distinct endpoints; approval for one realm is not approval for another. Existing provider role/realm selection dispatches each RPC to its original configured route. No common routing proxy or new protocol is assumed. Validate realm coverage, users_per_realm and tree/group heights against compiled constants, magic against GuardianAuthorization and fees against approved constants. All retry/fallback URLs need matching approval, not only first URLs. Other network URL fields are unused by guardian replay/signing; any path requiring them rejects instead of using an unapproved fallback. Install approved transports for every provider client before network operations.

Approved clients are installed before wallet construction. Marker/root/recheck use the selected URL without mid-observation failover; historical paths retain configured role/realm routes and authenticate to that root (`psy_cli/psy_relayer_cli/src/guardian/service.rs:21-43,149-209`). `PinnedCertificate` checks both normal TLS validation and exact leaf digest; endpoint clients disable proxies/redirects (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:166-202`).

For each HTTPS route require normal certificate-chain/hostname validation and SHA-256 of its exact DER leaf certificate equal that endpoint's tls_certificate_sha256, checked during TLS authentication before application data. No redirects, environment proxies, URL credentials, queries or fragments. Normalize scheme/host/default port with existing URL parser, preserve full path, reject dot-segment/encoded-path aliases. Certificate renewal requires explicit protected configuration change and restart. HTTP is allowed only numeric127.0.0.1 or[::1], with null pin; hostname localhost, other127/8 and nonloopback HTTP reject. Loopback authentication relies on Psy-controlled OS user/network namespace and approved local node process, not TLS. HTTPS requires nonnull pin; HTTP null. Approval binds role/config_id/full URL; TLS authenticates origin certificate, request routing enforces path. Responses cannot select routes.

For L2 only, `GuardianAuthorization.genesis_hash` means the 32 bytes `Hash256::from(checkpoint_zero_leaf.qfhash::<PoseidonHash>())`, rendered Hex32 using the existing reversed canonical-limb conversion. It is not a file checksum, an L1 block hash, or an unspecified network-id RPC value. On startup fetch checkpoint0 leaf and global-root preimage, hash both with existing checkpoint types, and verify checkpoint0 membership under the selected committed head. Require the resulting leaf bytes equal approved genesis_hash. Read explicit checkpoint-tree root at height0 and verify the same leaf/path there; retain that root as derived observation, not a second configurable genesis authority. Require network magic and compiled/configured dimensions independently agree; a claimed network name alone establishes nothing.

`load_guardian_committed_head(provider: &RpcProvider, url: &str) -> Result<GuardianCommittedHead, GuardianSignError>` reads durable identifier C then explicit root(C), validating canonical fields (`psy_cli/psy_relayer_cli/src/guardian/service.rs:38-43`). `verify_genesis` authenticates checkpoint0 under that head and explicit root0 and compares approved genesis bytes (`psy_cli/psy_relayer_cli/src/guardian/service.rs:46-54`). Observation checks saved ancestry, imports to the authenticated account nonce, rereads marker and original root(C), and halts on regression/root contradiction (`psy_cli/psy_relayer_cli/src/guardian/service.rs:149-215`). Persistence stores checkpoint identifier and leaf hash, not a separately persisted root authority. Missing evidence is unavailable.

Signing observation never uses the latest-block singleton or an implicit latest root as committed authority: the implemented reader obtains an identifier first and explicitly requests its root (`psy_cli/psy_relayer_cli/src/guardian/service.rs:38-43`). Merkle verification binds historical paths to that selected root; request/archive data cannot override it. Registration polling's different latest-singleton boundary is explicitly recorded in section4, not silently described as the signing path.

Protected-file grammar: resolve runtime/config-relative paths beneath an operator-approved directory handle using fd-relative `openat` and `O_NOFOLLOW` for **each** component; reject symlinks, traversal (`..`), nonregular final files and ownership/mode violations. Ancestors are owned by root or effective service uid and not group/other writable; secret/config/approval/database files are owned by effective uid with mode0600. Hold the verified file descriptor for each read/use; do not validate a path then reopen it unchecked. Immutable inputs compare descriptor metadata before/after read and fail on modification. Configuration/approval JSON uses the strict duplicate/unknown-key grammar already specified, maximum64MiB; encrypted key maximum1MiB; password1..4096 bytes valid UTF-8 with no NUL, CR or LF, no BOM and no trimming. The mutable database is opened read/write without creation by normal service startup; it has no content digest or connection secret. Empty, missing, unreadable or invalid databases disable startup. No stdin, environment, raw-key or default-keystore fallback.

`load_signing_key` holds the protected key descriptor and passes `/proc/self/fd/<fd>` with a borrowed zeroizing password to `Wallet::load_encrypted_keystore` (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:146-157`). Immutable reads check size, device, inode, mode, owner and timestamps before/after reading (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:56-68`). Buffers erase on return/error; opaque library internals are outside that promise. `SigningAuthorizationFile` retains approval bytes and database device/inode, not a mutable-content digest (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:113-142`).

`SigningAuthorization` is protected local JSON with exactly `network_magic:u64,user_id:u64,public_key:Hex33,db_path:String,not_before_unix:u64,expires_at_unix:u64,exclusive_key_use:bool,complete_journal:bool,revoked:bool`. It is an authenticated operator-file assertion, not a threshold signature or on-chain policy. Require exact canonical network/user/key match to authorization and the database's immutable33-byte key singleton, exact relative `db_path` match to runtime configuration, true exclusive/complete, false revoked, and `not_before<=trusted_OS_unix_time<expires_at` with not_before<expires_at. Capture device/inode from the held database descriptor. Before each signature response and observer iteration, reopen the configured path through protected-file rules and require the same device/inode; a missing or replaced file stops release without switching the live database. Do not hash evolving database contents or compare mutable size/timestamps. No random database identity or incarnation mechanism is introduced: cloned databases/configurations and stale restored state remain external key-use risks despite matching key/path. The removed PostgreSQL connection-secret field and old `exclusive_custody` key are rejected, not aliased.

`SigningAuthorizationFile::check` compares retained bytes, flags, validity interval and process-local clock, then reopens the database path and compares device/inode (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:128-142`). Missing/unreadable/expired approval prevents release without automatically halting. Readable changed bytes or invalid exclusive/complete/revoked flags trigger `SigningAuthorizationInvalid` through the service's durable halt transaction. Renewal requires stopping, replacing approved inputs and restarting; it never clears Halted or proves clone absence. The observer continues attempting history observation when approval is merely unavailable; successful history import still writes canonical rows and cursors, but never signs. A durable Halted account rejects observation immediately. Revocation after the final response check remains an operational race, not instantaneous detection.

Amendment acceptance (unexecuted): explicit durable C/rootC rejects singleton/MAX mixes; advancing marker with unchanged rootC succeeds, historical contradiction halts, missing data is unavailable; wrong DER pin/genesis/magic/config route fails before replay; request URL override is impossible; symlink/mode/traversal/changed-descriptor/password-newline files reject; wrong database path/inode/key, expiry, missing approval, live approval mutation/revocation and terminal-halt restart obey the exact rules above. Normal database writes do not invalidate the signing authorization. English-only documentation and existing policy/business predicates are unchanged.

`psy_relayer_cli guardian-create-db --runtime-config PATH` is the sole database initializer. It validates protected configuration, approvals, key and authenticated Genesis before exclusive `O_CREAT|O_EXCL` creation, commits four typed tables plus signer and initial account atomically, then syncs the parent directory. Parents must already exist. Existing files, including empty files, are never overwritten; a failed initialization retains its partial file for operator investigation. The command does not sign or start a listener. `guardian-service` only reopens existing state, requires its signer and account, and never recreates missing tables or clears Halted. redb engine crash recovery can write engine metadata before application validation; it does not authorize application repair or state reset.

Creation is only for a genuinely new signing key without prior reservations/signatures, including a new replacement key that subsequently authenticates canonical history. Existing PostgreSQL journal evidence remains untouched. No PostgreSQL-to-redb importer is supplied: an already-used key must not receive a fresh redb database, even at chain nonce zero, because uncommitted reservations/signatures are not recoverable from canonical history. Existing-key migration and deployment require separate authorization and an evidence-preserving migration procedure. Stop/drain the exclusive owner before offline inspection or backup; never operate a signing clone or restore stale bytes as ordinary restart. The unrelated Envio/indexer PostgreSQL dependency remains.

## Data Structures

### Policy and approval types

Policy definitions at `client_prover/psy_vm/src/ups/multisig.rs:23-28,69-72,89-116` are `MultisigPolicy {version:u32,threshold:u8,member_count:u8,member_hashes:[Hash4;8]}`, `MultisigAccount {contract_id:u32,initial_policy:MultisigPolicy}`, `MultisigSignatures {member_indices:Vec<u8>,signatures:Vec<PsyCompressedSecp256K1Signature>}`, `StoredMultisigPolicy {header:Hash4,members:[Hash4;3]}` and `MultisigSignatureInput {witness:MultisigSignatureWitness,signatures:MultisigSignatures}`. Witness fields are `account:MultisigAccount`, `start_state/end_state:StateReaderResults<GoldilocksField>`, `sig_data:PsyUserProvingSessionSignatureDataCompact<GoldilocksField>`, `sign_context:SignContext<GoldilocksField>`, `start_session_user_leaf:PsyUserLeaf<GoldilocksField>`, `nonce:GoldilocksField`. Existing serde types own serialization; current/ending policies are derived. Precompile owns storage, wallet builds witnesses, circuit verifies. Header `[1,2,3,0]` and indices `[0,2]` illustrate initialized version1 and two selected members; cryptographic bytes must come from real enrolled keys. Sections3 and6 define validation.

`ApprovedContract` fields are `contract_id:u32`, `contract_leaf_json:JsonText<PsyContractLeaf<GoldilocksField>>`, `compiler_artifact_json:JsonText<CompilerArtifact>`, `compiler_artifact_sha256:Hex32`. `CompilerArtifact` fields are `state_tree_height:u16`, `circuit_definitions:Vec<DPNFunctionCircuitDefinition>`, `abi:serde_json::Value`, not a Rust `Abi` type (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:152-164`). The operator archive owns exact artifact text/digest; verification derives roots and optional `ApprovedTokenMap {subslot_base:u64,capacity:u64}`. Policy example: height4, methods `get_policy`/`set_policy`. Token-map capacity is1048576 with artifact-defined aligned offset. Validation compares schema, methods, roots and executable map constants (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:148-219`); ABI semantics remain approved interpretation, not a new layout commitment.

`GuardianAuthorization` fields in order: `version:u32`, `network_magic:u64`, `genesis_hash:Hex32`, `user_id:u64`, `account_json:JsonText<MultisigAccount>`, `account_public_key:Hash4`, `multisig_fingerprint:Hash4`, `deposit_contract_id:u32`, `withdrawal_contract_id:u32`, `fee_contract_id:u32`, `guta_fee:u64`, `da_fee:u64`, `max_fee:u64`, `max_endcap_proof_bytes:u32`, `approved_contracts:Vec<ApprovedContract>`, `chains:Vec<ChainAuthorization>`. Require version>0, canonical0<magic<p, user524288, policy contract6, deposit2/withdrawal3, fee contract0, guta_fee/da_fee equal pinned network artifact constants, max_endcap_proof_bytes positive and equal the approved verifier serialization bound, exact derived registered key, approved contracts unique sorted id covering policy/deposit/withdrawal/fee and every token mapping. Initial-policy identity is not a current membership cache.

`ChainAuthorization` fields: `chain_index:u8`, `chain_id:u256`, `genesis_hash:Hex32`, `bridge:Hex20`, `state_manager:Hex20`, `bridge_code_hash:Hex32`, `bridge_implementation:Hex20`, `bridge_implementation_code_hash:Hex32`, `state_manager_code_hash:Hex32`, `state_manager_implementation:Hex20`, `state_manager_implementation_code_hash:Hex32`, `deployment_block:u64`, `token_mappings:Vec<TokenMapping>`. Nonzero pinned identities,1..256 sorted unique chains. Nonproxy implementation=contract. `TokenMapping {token:Hex20,l2_contract_id:u32}` sorted unique token,1..65536 entries, each id approved. Unlike event bytes32 input, typed L2 id is u32 and event value must encode that id canonically.

### Runtime and signing wire

`GuardianRuntimeConfig` fields: `authorization_path:String`, `authorization_archive_path:String`, `authorization_index_path:String`, `rpc_config_path:String`, `listen_address:String`, `tls_certificate_path:String`, `tls_private_key_path:String`, `client_ca_path:String`, `allowed_client_certificate_sha256:Vec<Hex32>`, `db_path:String`, `signing_key_secret_path:String`, `signing_key_password_secret_path:String`, `signing_authorization_path:String`, `l2_rpc_url:String`, `l2_rpc_endpoint_pins:Vec<L2RpcEndpointPin>`, `l1_rpc_urls:Vec<ChainEndpoint>`, `history_urls:Vec<String>`. `ChainEndpoint {chain_index:u8,rpc_url:String}` exactly covers chains; history_urls1..4 pinned mutual-TLS origins; caller pins1..16 distinct. Section8 defines L2RpcEndpointPin and exact protected-file/route/network/approval validation. Paths are nonempty config-relative, secrets owner-only, no environment key fallback. Example fixture listen127.0.0.1:9443, db_path guardian.redb, authorization version1/magic90101/user524288; actual role/realm URLs are retained from approved NetworkConfig and individually pinned. Old `custody_attestation_path` is rejected.

The archive directory and index paths are config-relative and locally Psy-approved. `GuardianAuthorizationIndex {active_version:u32,versions:Vec<GuardianAuthorizationVersion>}` contains strictly increasing positive versions, with `GuardianAuthorizationVersion {version:u32,sha256:Hex32}` and active_version present. Filename is decimal version plus `.json`; `authorization_path` names the active archive file, not an independently editable copy. Example active2 retains approved files1 and2 with their actual digests. Archive loading verifies SHA-256 of each file's exact bytes and its embedded version, then retains both parsed authorization and original bytes (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:87-96`; `psy_cli/psy_relayer_cli/src/guardian/protocol.rs:472-476`). During service observation, each `GuardianSigned.authorization_bytes` must equal the retained archive bytes for the request's authorization version before the saved-anchor verifier is called (`psy_cli/psy_relayer_cli/src/guardian/service.rs:100-113`). Separately, `verify_guardian_saved_anchors` parses the saved bytes, selects an approved authorization by the parsed version and compares their serialized JSON values before validating the request and anchors; that helper does not itself compare file digests or exact text (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:539-545`). Neither path permits a saved decision or peer envelope to introduce a new approved version or replace on-chain member authority.

`POST /v1/sign-session`, mutual TLS, maximum64MiB. Strict fields in canonical byte order:

| Field | Type | Validation |
|---|---|---|
| schema_version | u32 | 1 |
| authorization_version | u32 | signing: active or exact archived retry; historical import: locally approved archive version |
| network_magic | u64 | authorized canonical field value |
| genesis_hash | Hex32 | exact configured identity |
| user_id | u64 | 524288 |
| session_nonce | u64 | pinned replay-derived nonce |
| operation | enum u8 | bridge0/bootstrap1/replace_policy2 |
| trace_json | JsonText<GeneratedTxTraceJson> | full unsigned typed equality |
| deposit_anchors | Vec<DepositAnchor> | <=256, sorted changed chains |
| withdrawal_records | Vec<WithdrawalBurnRecord> | <=1024, exact selected per-chain order |

No current/ending policy preimage request fields: replay reads authoritative state and derives ending policy from the precompile call. `DepositAnchor {chain_index:u8,block_number:u64,block_hash:Hex32,old_count:u32,new_count:u32}`; example old7/new9 selects7,8. `WithdrawalBurnRecord {sender_user_id:u32,token_contract_id:u32,destination_chain_index:u8,token:[u32;8],amount:[u32;8],recipient:[u32;8],nonce:[u32;8]}` with big-endian word semantics. Require high amount limbs zero and0<amount<p. Fixture sender1000/token4/chain0/amount100/nonce7; recipient/token are actual fixture addresses. Policy-only requests have empty evidence arrays.

Use the existing typed, process-local `psy_provider::lps::WithdrawalBurnProof` (`client_prover/psy_provider/src/lps.rs:24-39`), with `F=GoldilocksField`: `checkpoint_id:u64`, `checkpoint_leaf:PsyCheckpointLeaf<F>`, `global_roots:PsyCheckpointGlobalStateRoots<F>`, `checkpoint_path:MerkleProofCore<QHashOut<F>>`, `user_leaf:PsyUserLeaf<F>`, `user_path:MerkleProofCore<QHashOut<F>>`, `contract_path:MerkleProofCore<QHashOut<F>>`, `contract_leaf:PsyContractLeaf<F>`, `global_contract_path:MerkleProofCore<QHashOut<F>>`, `record_membership:IMTMembershipProof<F>`. The provider assembles this evidence and the verifier authenticates it to the approved committed checkpoint root and expected whole contract leaf/artifact. UCON contract_path and global_contract_path are distinct; neither substitutes the other. This is not a signing-request field or network evidence envelope. Do not retain a duplicate guardian protocol JSON/JsonText wrapper for it; authority and membership checks are unchanged.

`GuardianSignResponse {request_id:Hex32,network_magic:u64,user_id:u64,session_nonce:u64,policy_commitment:Hash4,member_index:u8,message:Hex32,public_key:Hex33,signature:Hex64}`. Commitment is derived, not stored authority. Verify exact context, selected on-chain member, low-S/raw message. Example nonce8/member1; bytes computed from exact request.

`GuardianSignErrorResponse {request_id:Option<Hex32>,code:GuardianSignError,retry_after_ms:u32}`. Exhaustive codes: MalformedRequest, UnauthorizedCaller, AccountIdentityConflict, AuthorizationMismatch, EvidenceUnavailable, EvidenceMismatch, StateMismatch, UnsupportedCall, PolicyMismatch, NonceConflict, WithdrawalNonceConflict, HistoryUnavailable, JournalUnavailable, KeyUnavailable, AccountHalted. HTTP400 malformed;401 caller;403 identity/policy/call/evidence;409 authorization/state/nonce;503 unavailable/halted. Retry1000ms only unavailable evidence/history/journal/key, zero otherwise. No error releases reservations; null id only before canonical parse.

### Durable rows and history envelope

`GuardianSigned`: `network_magic:u64,user_id:u64,nonce:u64` unique key; `request_bytes:Vec<u8>,authorization_bytes:Vec<u8>,starting_leaf_hash:Hash4,ending_leaf_hash:Hash4,message:[u8;32],signature:Option<[u8;64]>`. A signature marks Signed; its absence marks Reserved. `request_id` is `sha256(request_bytes)`. `public_key` is the signer identity row. `member_index` is recomputed by locating that key's commitment in the exact retained request session's historically reverified starting policy, using retained `request_bytes` and approved `authorization_bytes`; never the later live policy or the session's ending policy. Example nonce8 Reserved remains Reserved if other two include its exact request; no signature is synthesized.

`GuardianSessionRecord`: `request_json:JsonText<GuardianSignRequest>,signatures_json:JsonText<MultisigSignatures>,endcap_input_json:JsonText<SubmitUserEndCapNonProofInput>,endcap_proof_hex:String,included_checkpoint_id:u64,included_checkpoint_hash:Hash4`. Proof hex is lowercase0x even-length raw bytes, bounded by overall64MiB. Exact original request retained. Two signatures satisfy revised current policy; EndCap inputs/proof and checkpoint inclusion are authenticated. Example missed nonce8 signed members0/1 is imported by member2.

`GuardianSession`: `network_magic:u64,user_id:u64,nonce:u64` unique canonical key; `record:GuardianSessionRecord,starting_leaf_hash:Hash4,ending_leaf_hash:Hash4,withdrawal_appends:Vec<WithdrawalAppendRecord>`. `WithdrawalAppendRecord {chain_index:u8,append_index:u32,burn:WithdrawalBurnRecord}`. Deltas are deterministically derived from verified replay, not trusted archive fields. This table alone derives accepted append history; request-bearing envelope is sufficient to recreate delta, stored delta must compare equal on recovery. No mutable parallel history store.

`GuardianAccount {network_magic:u64,user_id:u64,state:Active|Halted,last_checkpoint_id:u64,last_checkpoint_hash:Hash4,imported_nonce:Option<u64>,authorization_version:u32,halt_reason:Option<HaltReason>}`. HaltReason: FinalityConflict, CheckpointConflict, NonceConsumedDifferently, IncludedTransitionMissing, AppendHistoryMismatch, SigningAuthorizationInvalid. The last variant is fixed-integer bincode ordinal 5. Active has no reason; Halted has one. Imported nonce advances only with GuardianSession insertion in the same Immediate redb transaction. Four typed tables retain signer, account, decisions and canonical sessions. Account/session/decision values use complete-struct fixed-integer bincode encoding with trailing-byte rejection and table-key identity checks; fixed widths and existing domain validation remain enforced. Backups are encrypted and restricted. Catch-up inserts never overwrite local decisions.

Process-local types at `psy_cli/psy_relayer_cli/src/guardian/verify.rs:17-46`: `GuardianVerificationContext<'a>` contains `wallet:&'a WalletSession`, `provider:&'a RpcProvider`, `verified_checkpoint_id:u64`, `verified_checkpoint_tree_root:Hash4`, `l1_endpoints:&'a [ChainEndpoint]`, `history:&'a GuardianHistory`. `VerifiedGuardianSession` owns `trace:TxTrace`, `current_policy/ending_policy:MultisigPolicy`, `starting_leaf_hash/ending_leaf_hash:Hash4`, `message:[u8;32]`, `withdrawal_appends:Vec<WithdrawalAppendRecord>`. Neither is serialized request authority. For example, nonce8 verification receives a service-acquired checkpoint root and returns derived message/append records only after full replay; key access remains in `GuardianSigner`.

## Core Functions

These are implemented signatures, not proposed aliases. `F` is `GoldilocksField`; the verification context supplies the independently acquired operational root.

### Pinned builder

```rust
pub async fn begin_trace_build_at_checkpoint(
    &self, public_key: QHashOut<F>, user_id: u64, checkpoint_id: u64,
    expected_nonce: u64, verified_checkpoint_tree_root: QHashOut<F>,
) -> anyhow::Result<TraceBuildSession<'_>>;
```

Owner `client_prover/psy_prover/src/session/session.rs:2189-2229`; callers `psy_cli/psy_relayer_cli/src/guardian/verify.rs:320` and `psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2601`. Flow: range-check location → fetch user membership → derive nonce/event index → compare expected nonce → `PsyLocalProvingSessionStore::new_at` → `build_trace_session` → authenticate checkpoint/global roots/user/registration proofs → return unsigned builder. Any mismatch returns an error before business calls. Caller runs each derived `trace_call`, checks `required_fee`, then invokes `finalize_tx_trace`. No reservation or key use occurs here.

### Evidence and session verification

```rust
pub async fn get_withdrawal_burn_proof(
    context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization,
    checkpoint_id: u64, record: &WithdrawalBurnRecord,
) -> Result<psy_provider::lps::WithdrawalBurnProof, GuardianSignError>;
pub fn verify_withdrawal_burn(
    history: &GuardianHistory, authorization: &GuardianAuthorization,
    record: &WithdrawalBurnRecord, proof: &psy_provider::lps::WithdrawalBurnProof,
    verified_checkpoint_root: Hash4,
) -> Result<(), GuardianSignError>;
pub async fn verify_guardian_session(
    context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization,
    request: &GuardianSignRequest,
) -> Result<VerifiedGuardianSession, GuardianAccountError>;
```

Owners `psy_cli/psy_relayer_cli/src/guardian/verify.rs:226-255,311-372`. Burn retrieval rejects future checkpoints, loads the approved map, calls the scoped provider method, replaces its checkpoint path with one under the selected head, then verifies amount, asset mapping, whole contract leaf and every membership path. Provider composition is at `client_prover/psy_provider/src/lps.rs:73-93`; its contract-leaf reply is unversioned and becomes authoritative only after equality and historical global-contract membership checks. Missing historical metadata after an upgrade cannot be replaced with unrelated current metadata.

`verify_guardian_session` is called by service preparation, historical `verify_session` and daemon preflight. Its complete control flow is:

1. Validate authorization/request/envelope; reject future start checkpoint; authenticate checkpoint membership; construct the pinned builder.
2. Derive current/ending policy using `trace_policy` and `witness.policies()`. Require history nonce+1 and prior ending-leaf continuity. Iterate authorized chains and authenticate deposit/withdrawal counts and roots through `verify_chain_state`.
3. For Bridge, require unchanged policy. Iterate sorted deposit anchors through `verify_deposit_anchor`, authenticate old state, append derived setter. Iterate sorted burns, reject selected/included identity or destination nonce duplicates, verify membership, assign checked append indices, then call `build_withdrawal_batch_calls`. Otherwise derive exactly one `policy_call`.
4. Require whole call-data equality. Execute each `trace_call`, reject noncanonical/excessive fee, finalize, and require complete typed trace equality.
5. `verify_trace_contracts` checks approved code/leaf/function membership. Require one approved generated fee step, derive final policies/message/ending leaf, check future envelope bound, return `VerifiedGuardianSession` without signing.

`GuardianSignError` converts to `GuardianAccountError::Unavailable`; only explicit `Conflict(HaltReason)` causes `save_guardian_account_result` to commit a halt (`psy_cli/psy_relayer_cli/src/guardian/service.rs:220-228`). This distinction includes nonretryable malformed/state errors; the enum name does not make all wrapped errors retryable.

### Historical verification and durable import

```rust
pub async fn verify_session(
    context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization,
    record: GuardianSessionRecord,
) -> Result<GuardianSession, GuardianAccountError>;
pub async fn import_session(&mut self, value: &GuardianSession)
    -> Result<GuardianSession, GuardianSignError>;
```

Owners `psy_cli/psy_relayer_cli/src/guardian/verify.rs:479-499` and `psy_cli/psy_relayer_cli/src/guardian/db.rs:258-314`. Service resolves the local archived authorization before invoking them (`psy_cli/psy_relayer_cli/src/guardian/service.rs:189-200`). Verify replay, two starting-policy signatures, exact EndCap input, bounded canonical proof bytes, public inputs and approved verifier; authenticate ending leaf at included checkpoint. Then import checks row/request identity, derived appends, Active state, next nonce, previous ending leaf and any own reservation. Identical records are idempotent; conflicting retained records or reservation consumption commit halt. Insert and imported cursor advance share one transaction. Import never creates an own signature.

### Durable signing

```rust
async fn sign_verified(
    &mut self, request: &GuardianSignRequest, authorization_bytes: &[u8],
    verified: &VerifiedGuardianSession,
    signing_authorization_file: &mut SigningAuthorizationFile,
    active_authorization: &GuardianAuthorization,
) -> Result<Vec<u8>, GuardianSignError>;
pub async fn reserve_guardian_nonce(&mut self, value: &GuardianSigned)
    -> Result<GuardianSigned, GuardianSignError>;
pub async fn save_guardian_signature(
    &mut self, network: u64, user: u64, nonce: u64,
    request_bytes: &[u8], signature: [u8; 64],
) -> Result<GuardianSigned, GuardianSignError>;
pub async fn authorize_response<T, F>(
    &mut self, network: u64, user: u64, nonce: u64,
    request_bytes: &[u8], serialize: F,
) -> Result<T, GuardianSignError>
where F: FnOnce(&GuardianSigned) -> Result<T, GuardianSignError>;
```

Owners `GuardianSigner` at `psy_cli/psy_relayer_cli/src/guardian/service.rs:434-475`, `GuardianDb` at `psy_cli/psy_relayer_cli/src/guardian/db.rs:173-225`. After request observation/replay, locate this key in the starting policy; construct full reservation bytes; commit reservation. If unsigned, call `sign_prehash_raw` only for its saved message and commit the signature; otherwise reuse the saved signature. Recheck signing authorization; readable invalidation commits halt. `authorize_response` checks signer, Active state and exact signed request under a write transaction, serializes without network activity and withholds bytes until commit. Consumed unsigned reservations fail `NonceConflict`; storage failure fails `JournalUnavailable` without release.

### Relayer collection and proof

```rust
pub async fn collect(
    &self, request_json: &JsonText<GuardianSignRequest>,
    policy: &MultisigPolicy, sighash: QHashOut<GoldilocksField>,
) -> anyhow::Result<MultisigSignatures>;
pub(crate) async fn prove_pending_request(
    wallet: &mut WalletSession, client: &GuardianClient, archive: &RelayerArchive,
    authorization: &GuardianAuthorization, request_json: &JsonText<GuardianSignRequest>,
) -> anyhow::Result<Vec<u8>>;
```

Owner `psy_cli/psy_relayer_cli/src/bridge/guardian_client.rs:100-147,305-351`. Send identical retained text concurrently to three HTTPS origins; bound responses and check identity/policy/message. Ignore failed/invalid responses and validate sorted distinct pairs until two succeed; exhaustion is `EvidenceUnavailable`. Proving first validates future envelope size and saves the immutable request, then loads or collects/saves signatures, validates them and injects them into the public wallet. Return a bounded saved proof or execute UPS-start, every scheduled contract-function job, signature and EndCap jobs for that exact trace; save proof before return. No submission occurs in this function.

Caller `submit_guardian_operation` retries only quorum `EvidenceUnavailable` after one second (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2634-2643`). Before submission and after a submission error, `recover_guardian_inclusion` compares the committed account leaf and calls full `verify_session` before publishing (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2647-2708`). Normal submission waits for inclusion and verifies the same envelope. Admission never clears pending work.

## Core Loops

1. **Startup/request** (`psy_cli/psy_relayer_cli/src/guardian/service.rs:269-340,342-425`): load protected configuration/archive, install approved clients, enroll public identity, load key/approval, open retained database, authenticate Genesis and artifacts, then bind TLS. Full catch-up occurs in `observe` before every signature, not before listener binding. Body reading has30s timeout and64MiB bound. Four permits limit parsed signing tasks, not all HTTP connections. Mutex wait and read-only preparation each have separate120s deadlines. Spawned signing survives requester cancellation. Shutdown stops the observer and drains all permits and the mutex.
2. **Observer** (`psy_cli/psy_relayer_cli/src/guardian/service.rs:83-216,310-326`): one-second interval, missed ticks skipped, stop on watch notification. Lock service, check signing authorization, then call `observe` with30s timeout even if that check failed. Scan saved sessions/decisions one row at a time; reauthenticate and apply retained sessions; fetch exactly next nonce while imported<head nonce. Every successful import advances the cursor. Recheck marker and original root before saving observation. The first error exits the scan without signing.
3. **Observed diagnostics:** the observer retains a process-local `warned: Option<GuardianSignError>` across ticks and passes `Some(error)` for failed signing-authorization checks or `None` for success (`psy_cli/psy_relayer_cli/src/guardian/service.rs:313-323`). `warn_observer_authorization` resets that state without warning on success or `KeyUnavailable`, suppresses a repeated identical error, and otherwise records the error and emits a structured warning with its actual `code`, including `JournalUnavailable` (`psy_cli/psy_relayer_cli/src/guardian/service.rs:479-485`). A different error warns immediately; the same error warns again after success or `KeyUnavailable` resets the state. This diagnostic state neither changes durable halt/signature rules nor persists across restarts. The separate30s timeout and `observe` results are still discarded. These are static source facts, not executed diagnostic-test evidence.
4. **Relayer** (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2484-2682`): hold archive lock, refresh canonical history, recover exact pending request or derive new plan. Policy retries require matching intent/members; aggregate-owned requests require matching producing owner and capacity counts. Empty calls return current checkpoint without signing. Persist producing ownership, retain request through quorum retries, prove, recover inclusion before resubmission, then verify and publish inclusion. Other errors retain pending evidence and return; no replacement-request fallback exists.
5. **Rotation** (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2449-2468,2583-2597`): policy command uses the same lock/history server, reads four starting slots, requires initialized replacement state, builds one `set_policy`, then uses ordinary signing/proving/inclusion. Quiescence and replacement-key provisioning are operator actions, not an automatic distributed orchestrator. Current indices come from authenticated starting policy; quorum loss has no master bypass.

## Module Changes

Policy precompile owns stored members/version; circuit owns authenticated field/signature constraints; session owns pinned execution. Protocol owns canonical wire types, verifier owns evidence predicates and derived history, runtime owns protected inputs/transports, database owns durable decisions/imports, service owns ordering/key release. Relayer owns availability and submission, not history truth. `GuardianHistory` caches are derived from approved artifacts and verified sessions, not additional durable authorities (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:37-100`). Current aggregate code is separately owned and is not re-specified here.

## File Changes

**This revision modifies only `docs/src/dev/bridge-relayer-multisig.md`.** The following is an implementation inventory, not a source patch queue. Existing code must not be recreated from conceptual hunks.

| Implemented source | Current responsibility and inspected location |
|---|---|
| `../psy-compiler/psy-precompiles/multisig_policy/src/main.psy:3-83` | Four slots, ordered canonical members, compare-before-write `set_policy`. |
| `../psy-compiler/psy-precompiles/precompiles.json:89-98` | Seventh registry entry, methods and height4. |
| `../psy-compiler/psy-precompiles/build.rs:83-87,226-227` | Declared-height validation and positional identifiers. |
| `client_prover/psy_core/psy_config/src/lib.rs:139-140` | Optional declared height. |
| `client_prover/psy_vm/src/ups/multisig.rs:23-175` | Policy/account/signature/witness definitions, authenticated field decoding and transitions. |
| `client_prover/psy_circuit/psy_ups_circuit/src/signature/multisig.rs:199-313` | Four reads per side, two signature gadgets, fixed policy and identity checks. |
| `client_prover/psy_prover/src/session/session.rs:1831-1878,2189-2229,2903-2948` | Exact registration, pinned replay, signature injection and saved verifier binding. |
| `client_prover/psy_provider/src/request.rs:1213-1227` | Scoped membership request and checked map range. |
| `client_prover/psy_provider/src/lps.rs:28-93` | Typed burn evidence and scoped proof composition. |
| `psy_cli/psy_relayer_cli/src/guardian/protocol.rs:152-313,349-412` | Wire/approval/durable types, strict request checks, byte identity and typed equality. |
| `psy_cli/psy_relayer_cli/src/guardian/verify.rs:148-255,311-400,479-558` | Artifact interpretation, burn authorization, replay, imported session and saved-anchor verification. |
| `psy_cli/psy_relayer_cli/src/guardian/verify_l1.rs:105-222` | Finalized custody anchors, receipt-backed reconstruction and reauthenticated prefix cache. |
| `psy_cli/psy_relayer_cli/src/guardian/runtime.rs:10-251` | Protected file descriptors, archive, signing authorization, key loading and endpoint clients. |
| `psy_cli/psy_relayer_cli/src/guardian/db.rs:18-27,72-325` | Four redb tables, fixed-integer codec, retained-state open, reservation/signature/import/halt transactions. |
| `psy_cli/psy_relayer_cli/src/guardian/service.rs:239-485` | Separate database creation, service startup, request/observer ordering, deduplicated authorization warnings and final response gate. |
| `psy_cli/psy_relayer_cli/src/bridge/guardian_client.rs:100-351` | Two-signature collection, immutable request/signature/proof/inclusion archive and exact trace proving. |
| `psy_cli/psy_relayer_cli/src/bridge/daemon.rs:2445-2709` | Public account submission, capacity ownership, policy-only construction and inclusion recovery. |
| `psy_cli/psy_relayer_cli/src/bridge/propose_withdrawals.rs:421-523` | Offset0 discovery, deterministic sort and conflicting duplicate rejection. |
| `psy_cli/psy_relayer_cli/src/bridge/prove_bridge.rs:100-232` | Existing companion aggregate construction; equal-count chains require empty append input. |
| `psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:78-84,207-272,425-438,479-488` | Public input/artifact requirements, initialized policy+fee, actual fingerprint and null relayer private export. |
| `Makefile:107-112` | Both public paths forwarded with obsolete child secret variables removed. |
| `dev/locSetupV4.ts:1326,2746-2795` | Nullable private export and validated public account/artifact forwarding. |
| `client_prover/psy_prover/examples/phase1_verify.rs:24-26` | Explicit optional private-key selection for registrations0/1. |
| `docs/src/dev/TERMINOLOGY.md:238-282` | Existing shared multisig/guardian names; unchanged by this revision. |
| `psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:677-678` | Existing ignored real-fixture acceptance entry; not executed here. |

**Planned / not established by this documentation revision:** full real-network acceptance, artifact applicability/promotion and downstream release-cohort validation. Generated identifiers, fingerprints, EndCap metadata and circuit-library/common-data outputs must be treated as one authorized cohort; source presence does not prove the checked-in or deployed artifacts match. No generator, migration, deployment or publication is authorized. The companion aggregation document owns aggregate source changes; this inventory does not redesign them.

There are no proposed source hunks in this documentation-only revision. Source discrepancies are reported separately for owner review rather than represented as implemented fixes or silently changed protocol requirements.

## Rationale

Four member slots/fixed2of3 satisfy policy without hash mirror; initial identity/prehash avoid a new signature scheme. Current authenticated executable plus uniformly approved complete artifact gives the existing visible token-map interpretation, and scoped paths prevent wrong-map acceptance. GuardianSession differs from own decisions and permits offline catch-up. Exact business-call derivation, trace equality and irreversible reservations retain safety. A global Genesis layout transport/full-private ABI producer is unnecessary for these approved visible bridge fields and is excluded rather than bypassed.

## Security Considerations

Two compromised Psy keys can approve false business evidence despite valid account proof; fixed2/3 constraints do not prove custody. Shared Psy administration is not institutional independence. Per-key journals do not provide Byzantine consensus: two conflicting threshold certificates can exist with a malicious intersection member, but canonical account nonce permits only one canonical history. A stale reservation can stall a key; no master reset exists.

Bootstrap requires pristine registered initial identity; initialized policy Genesis uses ordinary nonce1. Approved executable/ABI changes need new historical artifact approval and current-leaf verification. Psy's canonical network/safe-upgrade approval establishes historical writer safety; neither current code nor layout membership independently proves lineage. Amount/network aliases reject before conversion. Missing RPC/archive evidence is unavailable, not canonical completeness. No automatic purge at occupied index2. Current L1 proofs/roles remain mandatory and artifact approval grants no bypass.

## Future Acceptance

Planned acceptance is unexecuted by this documentation revision. The operator procedure is [Real-network guardian acceptance](#real-network-guardian-acceptance). After the required gates, the release command is `cargo test --release -p psy_relayer_cli --test guardian_acceptance -- --ignored --exact guardian_acceptance`. Existing function `guardian_acceptance` is ignored and requires `GUARDIAN_ACCEPTANCE_FIXTURE` (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:1-8,676-681`). Source presence and fixture requirements do not establish a pass. Companion aggregate acceptance is owned outside this runbook; see [Aggregate acceptance ownership](#aggregate-acceptance-ownership).

| Case | Executable scenario and required observation |
|---|---|
| Real precompile | Registry generates id6, ABI methods/height4; bootstrap writes header+three members, no policy-hash mirror; read proofs agree with storage. |
| Fixed policy | Mutate header threshold/count, duplicate/zero/order, version skip/overflow; precompile and revised circuit reject even with valid signatures for another policy shape. |
| Bootstrap/reset | Correct registered pristine initial identity succeeds; all-zero fields on nonpristine account, wrong initial members or cleared/reset ending state fail. |
| Rotation | Current two authorize exactly version+1 and three stored members atomically; old keys fail; mixed bridge operation rejected. |
| Registration524288 | Source strategy maps index2; register exact public-only multisig key at available slot, verify inclusion/key; occupied/different/ raced index aborts with no overwrite, alternate id or purge. |
| Current custody | Real current Bridge deposits and tree reconstruction produce included setter and current L1 proofs; fake/missing/duplicate/nonfinal receipt/equal-count root rewrite fail. |
| Burn semantics | Expected current whole leaf/global-contract path matches complete approved artifact; visible map ABI and executable IMT constants agree, scoped paths prove namespace6 record. Wrong code/digest/incomplete artifact/base/capacity or unsupported safe-upgrade assumption rejects, with no new layout-root requirement or zero-layout branch. |
| Asset substitution | Authentic committed burn from approved token contract A carries another configured L1 asset B; proof/replay remain valid. Guardian rejects destination/token/contract mapping mismatch; high address bits and zero recipient reject; an explicitly authorized zero-address native-token mapping remains valid. |
| Call grammar and fee | Faithfully replay extra token transfer, withdrawal setter/raw append, second policy call, caller fee call, changed batch layout, generated fee above max_fee or overflow. Reject before reservation; exact independently derived list plus one correct generated fee succeeds. |
| Integer boundary | p-1 passes policy amount bound;0,p,p+1/high limbs fail, including an authentic committed p+1 record. Magic>=p rejected; no modular aliases. |
| Selection/history | Reordered discovery pages yield same sorted selected per-chain plan; omitted records delay; duplicate burn/destination nonce fails; all relayer entry points use selector. |
| Independent replay | Two independent service processes build byte-equivalent typed unsigned traces at same checkpoint/nonce; mutate every major field and observe rejection. Canonical omitted proof=None accepted, unknown/duplicate nested keys rejected. |
| Wire identity | Cross-language primitive/full-request vectors agree; raw hex/vector counts/enum widths exact; reformatted nested JSON conflicts after reservation. |
| Offline signer | C misses A+B inclusion, imports retained threshold-signed/proved session without creating C signature, then C+A signs next session with B offline. Replacement key uses same path. |
| Historical approval | C misses version1 session, active approval advances to2, and replacement C has no own version1 decision. Locally provisioned immutable version1 archive permits authenticated import; peer-supplied/unapproved/replaced version bytes fail. Catch-up never applies version2 mappings/ABI to version1. |
| Reserved inclusion | Other two include exact C-reserved request; C imports, retains unsigned own Reserved row and never signs consumed nonce. Different canonical request at same reserved nonce halts. Missing archive signature is unavailable, never synthesized. |
| Ancestry/halt | Valid current checkpoint-tree path contradicts saved leaf, historical user ending leaf differs, or finalized L1 ancestor changes: durable halt. Missing data/behind imported cursor instead stays unavailable and catches up. |
| Crash/retry | Crash after reservation/key use/Signed commit; only reserved message and committed signature returned. Cached/old-config retry rechecks canonical evidence and halt lock. |
| Signing journal | Shared-journal duplicate lock denied; missing signing authorization disables service. No false autonomous isolated-clone detection claim. |
| Role separation | Guardian key without proposer/pause role cannot use those L1 privileges; bad UPS domain/low-S/member index fails. |

The revised authentication circuit needs focused field-proof/initial-identity mutants and dependent artifact validation at QA. Performance, independent trace determinism and current-runtime registration were not executed or claimed successful here.

## Real-network guardian acceptance

This is the G1 runbook. The only entry is the ignored test `guardian_acceptance`. No `psy_relayer_cli` subcommand wraps it. The test builds `psy_relayer_cli` from `psy_cli/psy_relayer_cli/src/main.rs` and discards every child stdout and stderr (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:85,256-259`). A log line from a child is not a pass signal.

Run the command from the `psy-node` workspace root. Do not start or stop the shared devnet. The test does not provision a network, does not purge one, and does not call `guardian-policy --intent bootstrap` or `propose-withdrawals` (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:12-14,44-45,57-59`).

### Network and artifacts already present

Provide a disposable network before constructing the fixture. User 524288 must already have the public-only initialized Genesis policy, account nonce zero, and a positive fee balance. No other process may submit for that account. The network must already contain at least one genuine unconsumed indexed withdrawal, real Plonky2 aggregate artifacts, and L1 custody for the chains in the guardian authorization. This runbook does not generate Genesis, Groth16 keys, or those artifacts.

The guardian RPC file named by each runtime `rpc_config_path` must have an empty `prove_proxy_url`. `load_network` rejects a nonempty list (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:205-218`). That file is not the devnet `psy-genesis/config.json` when that file contains a prove-proxy URL.

### Fixture directory

`GUARDIAN_ACCEPTANCE_FIXTURE` is the absolute path of one directory. The effective uid must own it, its mode must be `0700`, and it must not be a symlink. Every ancestor must be a directory owned by that uid or by root and must not be group-writable or other-writable. `/tmp` fails that ancestor check. The loader rejects a missing variable with `GUARDIAN_ACCEPTANCE_FIXTURE is required` and a relative path with `fixture must be absolute` (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:100-109,186-189`).

`manifest.json` in that directory must be mode `0600`, owned by the same uid, and not a symlink. Its JSON must contain:

| Field | Required value |
|---|---|
| `disposable` | `true` |
| `network_magic` | integer greater than 0 and less than `0xffffffff00000001` |
| `relayer_rpc_config`, `relayer_guardian_config`, `relayer_daemon_config`, `relayer_archive`, `next_members` | one fixture-relative path each |
| `guardians`, `db_files`, `guardian_listen_addresses` | three entries each |
| `relayer_history_listen_address` | one listener |
| `timeouts.service_ready_secs`, `timeouts.session_secs` | optional; each integer from 1 through 7200. Defaults are 120 and 600 |

A present `journal_database_files` key fails with `PostgreSQL journal files are not part of this fixture`. Every manifest path is relative to the fixture root and may contain only normal path components (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:15-38,191-247`).

`relayer_archive` must already exist, be an empty mode-`0700` directory, and stay empty until the test writes it. A nonempty archive fails with `archive must be empty`. Each `db_files` entry must not exist, even as an empty file. Its parent directory must already exist and pass the same directory checks. The test creates each database once with `guardian-create-db`. Creating a database first fails with `database path already exists`.

The four listeners are numeric socket addresses. Each address must be loopback, use a nonzero port, and be distinct. A TCP connect to each address must fail. An occupied port fails with `fixture listener already occupied or unavailable` (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:532-538`).

### Relayer client config

`relayer_guardian_config` is JSON decoded as `GuardianClientConfig` with unknown fields rejected (`psy_cli/psy_relayer_cli/src/bridge/guardian_client.rs:14-31`). Paths inside it are relative to that file's parent (`:41-44`). Required keys:

`authorization_path`, `archive_path`, `endpoints`, `tls_identity_path`, `server_ca_path`, `authorization_archive_path`, `authorization_index_path`, `l1_endpoints`, `listen_address`, `history_tls_certificate_path`, `history_tls_private_key_path`, `history_client_ca_path`, `allowed_client_certificate_sha256`.

`endpoints` has length 3. Each value is an `https` origin with path `/` and no user, password, query, or fragment (`psy_cli/psy_relayer_cli/src/bridge/guardian_client.rs:86-91`). `listen_address` must equal `relayer_history_listen_address`. The parent of the client file joined with `archive_path` must equal the manifest archive (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:219-224`).

### Three guardian runtime configs

`guardians` names three JSON files, one per signing key, decoded as `GuardianRuntimeConfig` with unknown fields rejected (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:201-211`). A `postgres_connection_secret_path` key fails the fixture check. Paths inside each file are relative to that file's parent. The parent joined with `db_path` must equal `db_files` at the same index. `listen_address` must equal `guardian_listen_addresses` at the same index (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:231-238`).

Each runtime file also contains `authorization_path`, `authorization_archive_path`, `authorization_index_path`, `rpc_config_path`, `tls_certificate_path`, `tls_private_key_path`, `client_ca_path`, `allowed_client_certificate_sha256`, `signing_key_secret_path`, `signing_key_password_secret_path`, `signing_authorization_path`, `l2_rpc_url`, `l2_rpc_endpoint_pins`, `l1_rpc_urls`, and `history_urls`. `history_urls` has length 1 through 4 and must include the relayer history origin and the other guardians' origins so a stopped guardian can import retained history (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:501-529`; `psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:31-33`). `tls_private_key_path` and `signing_key_secret_path` must differ. `allowed_client_certificate_sha256` has length 1 through 16, all distinct.

There is no guardian keystore flag. `signing_key_secret_path` is the encrypted key file and `signing_key_password_secret_path` is the password file. Both are mode `0600`. The password file is at most 4096 bytes, UTF-8, without NUL, CR, LF, or a leading BOM. The key file is at most 1 MiB. `load_signing_key` reads those files and does not consult `WALLET_PASSWORD`, `KEYSTORE_PATH`, or stdin (`psy_cli/psy_relayer_cli/src/guardian/runtime.rs:75-79,146-157`). Do not put a guardian password in the environment.

`signing_authorization_path` is JSON with exactly `network_magic`, `user_id` (`524288`), `public_key`, `db_path`, `not_before_unix`, `expires_at_unix`, `exclusive_key_use` (`true`), `complete_journal` (`true`), and `revoked` (`false`) (`psy_cli/psy_relayer_cli/src/guardian/protocol.rs:223-229`). The recorded `db_path` must equal the runtime `db_path`.

`next_members` is canonical JSON for `[Hash4; 3]`, the value `guardian-policy --intent replace` parses (`psy_cli/psy_relayer_cli/src/main.rs:217-223`). At least one member must differ from the Genesis initial members.

### Daemon config

`relayer_daemon_config` is TOML. `rpc_config` and `guardian_config` are paths relative to the fixture root, because the test sets the child current directory to that root (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:225-230,256-271`). Joining either value to the fixture root must produce the matching manifest path.

`BridgeProposeDaemonConfig` also requires `services_url`, `withdraw_method_id`, `aggregate_setup_config`, `aggregate_artifact_dir`, `aggregation_token_file`, and `aggregate_limits` (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:62-89`). `aggregate_limits` requires `max_deposits`, `reserved_withdrawals`, `reserved_rewards`, `max_window_calldata_bytes`, and `chains` (`:92-110`). Set `proof_dir` to a directory inside the fixture. The unset value is `/tmp/psy_bridge_proofs` (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:38,898-919`), which is not fixture-local. The proof directory must not already contain `daemon_state_multichain.toml` from another network. The scan that this daemon will perform must contain one unconsumed withdrawal and no later incoming work.

`[finalize]` and `[[chains]]` may contain `keystore_path` and `password_env`. That keystore is the L1 proposer key decrypted by `password_env`, or by `WALLET_PASSWORD` when `password_env` is absent (`psy_cli/psy_relayer_cli/src/bridge/l1_signer.rs:10-30`). It is not a guardian signing key. Leave it unset unless this disposable network's daemon must sign an L1 transaction. Do not point it at the shared devnet bridge-relayer keystore. The test passes no `--keystore-path`.

### Command

```bash
GUARDIAN_ACCEPTANCE_FIXTURE=/absolute/path/to/the/fixture \
  cargo test --release -p psy_relayer_cli --test guardian_acceptance -- --ignored --exact guardian_acceptance
```

Replace the fixture path. The package and test target are `psy_relayer_cli` and `guardian_acceptance` (`psy_cli/psy_relayer_cli/Cargo.toml:2-8`; `psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs`). The test header omits `--release`; this runbook keeps it because release mode is the required Rust test invocation. `--ignored` is required. Without it, Cargo reports the test ignored and exits 0, which is not a pass. `--exact guardian_acceptance` selects that one function.

The test, not the operator, runs:

| Child | Arguments |
|---|---|
| `psy_relayer_cli guardian-create-db` | `--runtime-config` set to each `guardians` entry |
| `psy_relayer_cli guardian-service` | `--runtime-config` set to each `guardians` entry |
| `psy_relayer_cli` | `--config` set to `relayer_daemon_config`, no subcommand |
| `psy_relayer_cli guardian-policy` | `--rpc-config`, `--guardian-config`, `--intent replace`, `--next-members-json` set to the trimmed `next_members` bytes |

Those flags are declared at `psy_cli/psy_relayer_cli/src/main.rs:28-59`. The default `--config` value `./psy_cli/psy_relayer_cli/config/local.toml` is not used, because the test always passes `--config`.

### Pass

Cargo exits 0 and prints `test guardian_acceptance ... ok`. The same output must not contain `ignored`. The test also panics on a cleanup failure after the scenario, so a pass means the scenario returned and every child the test spawned was reaped (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:676-691`).

A pass leaves the three redb files and the archive, including nonce-1 and nonce-2 receipts. Those files are the retained evidence. Child logs are not available.

### Fail

Any of these is a failure. The panic text is the signal, because child output is discarded.

| Signal | Meaning |
|---|---|
| `test guardian_acceptance ... ignored`, exit 0 | `--ignored` was omitted |
| `GUARDIAN_ACCEPTANCE_FIXTURE is required` or `guardian fixture rejected` | The fixture failed a check in `Fixture::load` before any child started |
| `fixture listener already occupied or unavailable` | A listed port already accepts TCP |
| `database path already exists` | A `db_files` path was created before the test |
| `archive must be empty` | The archive was reused |
| `CLI exited before required condition` or `CLI listener readiness timed out` | `guardian-create-db`, `guardian-service`, or the daemon exited or never accepted its port. The bound is `service_ready_secs` |
| `policy CLI failed` or `policy CLI timed out` | `guardian-policy --intent replace` failed. The bound is `session_secs` |
| `lone guardian durable signature timed out` | One guardian did not produce a nonce-1 decision within `session_secs` |
| `one guardian unexpectedly obtained quorum` | Nonce 1 gained signatures or an inclusion receipt while two guardians were stopped |
| `fixture produced extra work` or `recovery advanced account instead of recovering nonce one` | A nonce-2 request appeared before rotation |
| `crash recovery changed archived request/signatures/proof` or `crash recovery changed durable decision/signature` | Daemon restart did not reproduce the original nonce-1 bytes |
| `offline guardian acquired a signing decision` or `catch-up fabricated an own decision` | Guardian C signed or stored nonce 1 before its own restart |
| `rotation did not change members` or `offline B signed rotation` | Replacement did not change the stored members, or the stopped guardian signed nonce 2 |
| `guardian acceptance overall deadline exceeded` | The scenario exceeded twelve times `session_secs` |
| `could not reap an owned acceptance child` | A child the test spawned did not exit within 15 seconds of being killed |

### Cleanup

The test deletes only `relayer_archive/acceptance-original-pending.json` and kills the children it spawned (`psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:305-311,330-333,682-686`). It does not delete the databases, the archive receipts, or the fixture, on success or failure.

1. Leave the three `db_files` paths and the archive in place. Do not replace them and do not run the test again on this fixture. A second run requires a new fixture whose database paths are absent and whose archive is empty.
2. If Cargo itself is killed before the test reaps its children, stop only `psy_relayer_cli` processes whose arguments contain this fixture's `--runtime-config` or `--config` path. Do not run `make shutdown` or `make run-all`, and do not stop the shared devnet.
3. Do not delete a halted redb file to make a retry pass. `guardian-service` does not clear a halted account, and `guardian-create-db` refuses an existing path (`docs/src/dev/bridge-relayer-multisig.md` section 8).

## Aggregate acceptance ownership

`guardian_acceptance` does not accept an aggregate proof. A G1 pass is not aggregate acceptance.

The acceptance contract is [Bridge Window Finalization](bridge-merkle-settlement.md) §8, [Acceptance and resource bounds](bridge-merkle-settlement.md#8-acceptance-and-resource-bounds). [bridge-proof-aggregation.md](bridge-proof-aggregation.md) names that document as the design authority and holds no separate contract. Section 8 records its QA list as unexecuted. This runbook does not add a procedure for that list.

The settlement CLI surface is two subcommands of `psy_relayer_cli`. Neither is invoked by `guardian_acceptance`.

| Command | Declaration | Dispatch |
|---|---|---|
| `prove-bridge-agg` | `ProveBridgeAgg` at `psy_cli/psy_relayer_cli/src/main.rs:72-85` | `psy_cli/psy_relayer_cli/src/main.rs:256-274` |
| `finalize-bridge-agg` | `FinalizeBridgeAgg` at `psy_cli/psy_relayer_cli/src/main.rs:86-87`; arguments at `psy_cli/psy_relayer_cli/src/bridge/finalize_bridge.rs:63-81` | `psy_cli/psy_relayer_cli/src/main.rs:275` |

`prove-bridge-agg` requires `--from-checkpoint`, `--to-checkpoint`, `--aggregate-config`, and `--out`. `--rpc-config` defaults to `config.json`. `--deployments-network` defaults to `localhost` (`psy_cli/psy_relayer_cli/src/bridge/constants.rs:2`). `finalize-bridge-agg` requires `--window-json`, `--config`, `--chain-index`, and `--aggregate-limits`.

`psy_cli/psy_relayer_cli/tests/` contains only `guardian_acceptance.rs`. There is no aggregate-acceptance test target. Do not treat either subcommand, or the no-subcommand daemon, as a substitute for the section 8 list.

## External Prerequisites

Actual Psy signing keys, signing authorization, TLS, target network canonical magic/genesis, available registration slot2 or exact already-registered key, approved compiler ABI/code/layout outputs, chain/deployment/finality identities and L1 role credentials are operating inputs. The design fixes id524288/precompile6/three members/two signatures; it does not defer those choices. An occupied local slot blocks that registration action until the user authorizes an environment action; it does not create a production migration requirement or permit deletion. L1 deposit custody inputs remain separate.

Normative version14 remains the protocol basis. This implementation-documentation revision is **Review**, not an approval or execution report. Real three-guardian/end-to-end acceptance, artifact compatibility and final delivery gates require independent evidence for the exact candidate. Generation, environment changes, deployment, publication and push retain separate authorization boundaries. Companion aggregation and rewards remain separately owned even where their current code shares relayer entry points.
