# Bridge relayer multisig and guardian signing service

> **Approved design — normative version 14, 2026-09-27.** Author: MultisigDesignWriter. Independent GPT, Grok and design-reviewer approval covers the uniform artifact-authority contract and scoped cleanup. Source implementation remains in progress; the complete user goal is not finished.
> Verification status: scoped implementation QA has run and is recorded under `T-BRIDGE-GUARDIANS` in the existing task evidence ledger. The parent also reports a real-artifact initialized-Genesis nonce1 proof fixture pass; this is not full-chain acceptance. Full three-guardian network, rotation, crash/offline and end-to-end bridge acceptance remain incomplete. This author's work is documentation only; no implementation, generation or runtime action is authorized by this status update.

## Terminology & Abbreviations

[TERMINOLOGY.md](TERMINOLOGY.md):238-255 defines existing multisig vocabulary. Implementation updates its commitment-only description to the field-authenticated policy below.

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
| A / B | Future artifacts owned by [bridge-proof-aggregation.md](bridge-proof-aggregation.md), not first-milestone prerequisites. |

## Abstract

Cleanly replace the current secret-backed bridge relayer with **exactly three Psy-operated keys requiring two signatures**, register the mutable multisig software-defined account as **user 524288**, and store its individual member commitments in a real **multisig_policy precompile**. The system is not launched; there is no compatibility mode or production migration mechanism. Current bridge proof and settlement semantics are retained: multisig first, reviewed merge second, Spiderman/two-Groth16 last. Each guardian independently verifies current L1 custody, committed L2 burn membership, and the complete pinned session before signing the existing UPS message. Current membership is authenticated from on-chain fields, not an opaque policy hash or an operator file. No shared master key is introduced.

## Motivation

Current wallet setup loads a private key (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:292-320`). The planner takes services deposit roots after count checks (`:2719-2733`), then submits a combined session (`:2758-2793`). The current deposit setter accepts a supplied root with nondecreasing count, including an equal-count different root (`../psy-compiler/psy-precompiles/deposit_tree/src/main.psy:212-243`). Signers must establish custody, not just signature validity.

Existing multisig provides external signatures and immutable initial identity, but reads only a policy commitment at slot0 (`client_prover/psy_circuit/psy_ups_circuit/src/signature/multisig.rs:190-212`). The existing Dargo example stores only that commitment (`../psy-compiler/psy-dargo-cli/examples/multisig_policy/src/main.psy:3-18`). Neither satisfies the required on-chain member storage. This design replaces that field authentication and promotes the policy implementation into the authoritative precompile registry.

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
- [External Prerequisites](#external-prerequisites)

## Specification

### 1. Scope, revisions and sequence

**In scope:** real policy precompile; three stored canonical member commitments; fixed two-of-three precompile/circuit enforcement; exact account524288 registration; authenticated policy reads and rotation; guardian service, custody/burn checks, pinned replay, durable decisions and learned history; clean relayer/CLI/provider cutover; required ABI/artifact applicability plan.

**Out of scope:** implementing Spiderman, changing final Groth16 artifact count, rewards migration, changing L1 proposer/pause roles, another signature scheme, shared master key, automatic environment purge, deployment, generation or publication. No secret-wallet fallback or old commitment-only multisig path remains after implementation. Unrelated local work is preserved.

Order: current-protocol multisig design/review/implementation/verification, then reviewed merge, then separately gated companion proof redesign. User authorization for breaking source changes is not permission to delete data, regenerate Genesis, deploy or push. Existing local occupied state is checked, never overwritten automatically.

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

`StateManager.sol:83-87,173-182` enforces proposer permission. `Bridge.sol:350-364` grants additive pause only; clearing/replacing verifiers belongs elsewhere (`:366-389`). Realm admission verifies account start leaf, checkpoint root, PI, consistency and EndCap (`psy_node_common/src/realm/edge/handler.rs:737-862`), not L1 receipt truth. Admission is not inclusion.

### 3. Policy precompile and account authentication

#### Authoritative registry and storage

Append `multisig_policy` after the six existing entries in `../psy-compiler/psy-precompiles/precompiles.json:2-88`, with path `multisig_policy`, contract name `MultisigPolicyContractRef`, methods `get_policy`, `set_policy`. `build.rs:214-215` assigns identifiers by registry position; therefore its generated identifier is **6**, not a guessed configurable deployment id. Existing token/mining/deposit/withdrawal/USDT/faucet identifiers0..5 remain unchanged. Account `contract_id` must equal generated `MULTISIG_POLICY_CONTRACT_ID`, and authorization rejects any other value. Dargo is the package/build mechanism used by precompiles (`build.rs:43-115`), not permission to deploy a separate example contract.

Use positional CSTATE height4, preserving the existing multisig account parameter's height4 domain. Add `declared_state_tree_height:Option<u8>` to `ContractConfig` (`client_prover/psy_core/psy_config/src/lib.rs:134`); policy registry sets it to4. If absent, retain the compiler-inferred height. If present, require inferred storage height<=declared height<=32 and emit the declared height consistently in compiled contract definition and ABI/layout construction; reject any mismatch between those outputs. Thus a smaller inferred minimum is deliberately extended to4 rather than rejected or silently used. No dummy mutable slots are added to force height. All approval/circuit readers pin the resulting height4 artifact.

| Slot | Exact Hash value | Owner/validation |
|---|---|---|
| 0 | `[version,2,3,0]` | u32 version>0 after initialization; threshold/member count are constants checked by precompile and circuit. |
| 1 | member commitment0 | Nonzero canonical four limbs. |
| 2 | member commitment1 | Nonzero and lexicographically greater than slot1. |
| 3 | member commitment2 | Nonzero and lexicographically greater than slot2. |

Unused slots4..15 remain zero. There is **no stored whole-policy hash**. Derive existing policy commitment when needed from header and the three member commitments, with five zero padding entries only for existing eight-slot hash encoding. They are not extra members. Membership commitment is the shipped `hash_no_pad_compressed_public_key` of each compressed SEC1 key; proof checks each supplied public key against the selected stored commitment (`multisig.rs:288-298`). Actual current member keys need not be duplicated in configuration or state beyond these individual commitments.

`get_policy() -> (Hash,[Hash;3])` returns header and members; no off-chain authority. `set_policy(expected_header:Hash,expected_members:[Hash;3],next_members:[Hash;3])` compares all four current slots, validates next keys' canonical nonzero strict order, and writes all four slots atomically. Uninitialized all-four-zero state installs header `[1,2,3,0]`. Otherwise require header shape, checked version increment and at least one changed member, then write `[version+1,2,3,0]`. No caller can set threshold1/3, member count2/4, arbitrary version, zero member or duplicate. Precompile alone cannot authorize an account session: the account authentication circuit supplies current-member authorization and strict bootstrap identity below.

#### Circuit/host cutover

Extend existing `MultisigSignatureCircuit`, do not fork an alternate signature scheme. Replace its slot0 commitment readers with authenticated reads of slots0..3 at starting and ending self state, each bound to the same account/user/checkpoint context. `StateReaderGadget::get_self_user_current_contract_state_slot_hash` creates one UCON plus one slot proof per call (`signature/state_reader.rs:98-132`), so the simple implementation has exactly **eight proofs per start/end reader**, ordered `(UCON,slot0,UCON,slot1,UCON,slot2,UCON,slot3)`. All UCON anchors must match. This is a concrete reuse, not an assumed deduplicated five-proof gadget. Update host proof-shape checks and trace witness construction together; existing two-proof checks at `session.rs:2679-2746` and `multisig.rs:276-283` are obsolete.

Derive current and ending policy from authenticated fields. Signature witness contains account, start/end state proofs, signature data, sign context, starting user leaf and nonce; remove caller-supplied current/ending policy preimages as independent fields. Local setters that install authoritative current policy are removed; consumers load state. Initial policy remains immutable enrollment data for `MultisigAccount.public_key_param`, a distinct identity role. The circuit pins threshold2/count3 and exactly two selected distinct increasing indices for every session, not merely guardian policy. It recomputes current/ending commitment and retains exact message/identity PI semantics.

Bootstrap is allowed only when all four starting slots are zero **and** authenticated starting account nonce is zero **and** its user-state root is the default/pristine root **and** the registered public key equals the circuit fingerprint/initial parameter. Ending version must be1 and ending members equal immutable initial members; initial two signatures authorize it. An existing nonpristine account with zero policy fields is rejected. Nonbootstrap ending fields are either exactly unchanged, or changed members with version exactly+1; current fields authorize every operation. Restoring earlier members still increments version. Clearing header/members or resetting bootstrap is impossible. Policy change sessions contain only the precompile mutation and required fee operation; guardian rejects mixed bridge operations.

The circuit fingerprint changes. Regenerate dependent EndCap metadata and circuit artifacts at their authorized stage, and update consumers atomically under `AGENTS.md:55-69`; do not claim current artifacts already validate the new policy layout. No new signature message domain or master-key DPN/Plonky2 software-defined substitute is introduced.

### 4. Registration and identity propagation

The logical requirement is **register this exact software-defined mutable multisig public key as user524288**. Registration RPC accepts public-key information, not a requested id (`session.rs:1704-1727`). Wallet registration derives fingerprint and initial-policy parameter (`wallet/memory_wallet.rs:625-638`). User ids come from registration position through Strategy5 (`psy_core/src/user_id.rs:321-374,381-410`), not key grinding or a CLI `--user-id` override.

For current coordinator height12, realm height20 and group height1 (`psy_core/src/network_config/local_devnet.rs:33-42`; `psy_mainnet.rs:33-42`), registration index **2** maps to524288: low realm bit0 selects realm0, remaining user index1 reverses over20 bits to2^19. Inverse mapping gives2. The registration gatherer maps registration positions using that same function (`register_user_gatherer.rs:70-82`) and appends keys in position order (`:159-175`). This is static arithmetic, not an executed registration result.

Operator registration procedure: derive revised multisig fingerprint and initial account parameter; query registered key at user524288 and registration index2. If already that exact key, load it without another registration. If occupied by another key, stop with `AccountIdentityConflict`; never overwrite it, substitute another id or automatically purge local state. If empty, register only when authoritative next registration index is2 and registration intake is exclusively controlled for that slot; wait for inclusion and verify mapping+registered key before bootstrap. If the index is earlier/later or races another registration, stop; user approval of logical registration is not permission to create dummy users or rewrite the tree. Authorizing a local initialization that allocates the intended first registrations is a separate action, not a production-migration gate. Nothing assumes a launched network.

#### Public-only Genesis enrollment source

The first-stage cutover replaces `psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:326,335-339`, which currently chooses a relayer secret (including deterministic fallback), exports it and calls ZK `compact_user`. Add required `--relayer-multisig-account <path>` containing exactly existing public `MultisigAccount {contract_id,initial_policy}`. No private key, caller fingerprint or caller public-key parameter. Reject missing input, unknown/duplicate keys, contract_id!=6, initial version!=1, threshold!=2, member_count!=3, invalid sorted members/padding. Remove relayer secret/keystore/password CLI/environment inputs at :76-95 and resolver/fallback. Validator/faucet key generation remains unchanged.

Both real generator entry points must forward the public input. The single operator field is `PSY_RELAYER_MULTISIG_ACCOUNT`, a nonempty path to the public account JSON, supplied to the launcher through its existing environment/`--env` mechanism. Resolve relative paths against repository root, require a readable existing regular file, parse/validate the exact public account before invoking generation, and pass its normalized absolute path as explicit `--relayer-multisig-account` to `psy_dev_cli`. In `dev/locSetupV4.ts:2745-2819`, require this field only when the already-authorized Genesis applicability path actually generates output; preserving an existing verified Genesis does not trigger generation or a new required guardian configuration. When guardian authorization is loaded, its initial account must exactly match this same public account. This public input does not require full guardian TLS/signing authorizations before the no-relayer initialization stage.

Root `Makefile:107-114` must replace its encrypted-relayer-keystore instructions, require nonempty `PSY_RELAYER_MULTISIG_ACCOUNT` for `generate-genesis-data`, fail before invoking the binary if absent, and pass the value as a quoted explicit `--relayer-multisig-account` argument. Direct CLI invocation likewise requires that argument. Neither entry point falls back to a deterministic secret, environment secret, old fingerprint or placeholder public account. Paths with spaces must remain one argument; launcher uses argv rather than a constructed shell command.

For the generator child only, remove inherited `PRIVATE_KEY`, `BRIDGE_RELAYER_L2_PRIVATE_KEY`, `KEYSTORE_PATH`, `PSY_BRIDGE_RELAYER_KEYSTORE_PATH`, `BRIDGE_RELAYER_KEYSTORE_PATH`, and `WALLET_PASSWORD` from its environment; the root Makefile target uses the same explicit child-only removals. Do not mutate parent environment or strip credentials from L1 subprocesses. Retain L1 signer provisioning: `ensureKeystoreFiles` calls at `dev/locSetupV4.ts:2588-2609`, `loadBridgeRelayerSigner` at :373, deployment environment at :3118-3119 and L1 daemon config at :4936/:4946 consume that separate encrypted L1 key. `autoGenerateBridgeRelayerKeystore` at :2440-2457 remains an L1 function, not an L2 enrollment step. Rename the misleading `LOCAL_DEVNET_RELAYER_ZK_PRIVATE_KEY` symbol at :1035 to `LOCAL_DEVNET_L1_SIGNER_PRIVATE_KEY` without changing its existing local L1 fixture value or copying that value into documentation; update its sole constructor reference at :2442. Remove the statement at :2869 that Genesis decrypts this keystore; retain any password setup required by actual L1 consumers. No L1 key or password becomes a guardian or Genesis relayer signing key.

Derive `fingerprint=MultisigSignatureCircuit::new()?.get_fingerprint()` from the actual revised local circuit and `public_key_param=account.public_key_param()?`; derive registered public key through existing Poseidon two-to-one. No old constant, arbitrary input fingerprint, remote proxy or master-key helper. Before output, compare Genesis contract6 deployment code/function roots and height4 with the approved complete local multisig_policy compiler artifact, including get_policy/set_policy and direct four-slot semantics. No new on-chain layout metadata is required. Missing/mismatched artifact stops. Public account input remains the same immutable initial identity used by guardian authorization.

Insert public-key info at dense registration index2, assert Strategy5 maps it to524288. Generated relayer fields: nonce0, balance0, last_checkpoint_id0, event_index0. Contract records contain contract0 slot0 `[initial_fee_balance,0,0,0]` and contract6 slots0..3 `[1,2,3,0]`, initial member0, member1, member2. Require `0<initial_fee_balance<p`. Fee and policy records make the user-state root nondefault: this is an **initialized-policy Genesis account**, not pristine bootstrap. First ordinary UPS nonce1 authenticates already-stored initial members. No `guardian-policy --intent bootstrap` command for this fixture; never weaken pristine-root bootstrap constraints. General genuinely empty registration retains section3 bootstrap semantics. Current compact_user already seeds fee state (`generate_genesis.rs:290-312`); use a public-key-info construction helper for relayer and confine private-key derivation to validator/faucet branches.

Private export remains dense with exact type `Vec<Option<Hash>>`, length=users length. Index2 is None/JSON null; validator/faucet keys are Some at unchanged registration indices. Never omit/shift index2, export zero/dummy relayer secret, or copy guardian secrets. Example shape: `[validator0_secret,validator1_secret,null,validator3_secret,validator4_secret,faucet5_secret]`; actual secrets are not documentation examples. Faucet export at `generate_genesis.rs:457-462` requires Some at its calculated slot or returns a contextual error. Launcher `dev/locSetupV4.ts:1322-1333` reads `(string|null)[]`, retaining exact validator-index/string checks. `client_prover/psy_prover/examples/phase1_verify.rs:24-26` reads `Vec<Option<String>>`, requires Some0/1. `client_prover/Makefile:66-68` removes USER2 secret and stale public aliases; register-users commands :127/:133 using that secret for zk/secp are removed, not replaced by automatic guardian calls. Other users' examples stay;0/1/3/4 references keep indices and require string secrets when selected. No parallel compatibility export.

After separately authorized isolated artifact/Genesis/L1 setup, initialization can use existing supervisor `LOCSETUP_START_ARGS` with `--db --coordinator --realms-count 2 --coordinator-workers 2 --realm-workers 1 --prove-proxy 1 --l1` and existing Plonky2 backend option, **without --relayer**. Override entry is `Makefile:61-67`; no new launcher or placeholder guardian config. Observe actual initialized account/policy and deployment/checkpoint0 identities, then provision real approval/route/signing-authorization files. Canonical state-preserving shutdown uses `PURGE=0` (`Makefile:99-100`), followed by full supervisor startup with relayer and validated guardian files. Preserve paired databases/checkpoints/Anvil/deployments (`docs/src/dev/devnet_lifecycle.md:148-150`). This does not authorize generation, startup, or deployment by itself.

Exact amendment file plan: generator :76-103,290-312,324-380,419-422,457-462 changes required public input, actual fingerprint/artifact validation, initialized policy+fee and nullable export; `psy_cli/psy_dev_cli/Cargo.toml` adds only direct existing workspace circuit/type dependencies; launcher :1322 adopts nullable type; phase1 example :24-26 handles Option; client Makefile :66-68,127,133 removes only obsolete USER2 aliases/calls. Existing Genesis-generation operator docs replace relayer-keystore instructions with public account/null2 contract. The guardian acceptance driver/fixture contract must verify Genesis already contains initial four policy fields and start its first operation as initialized-policy nonce1, not blindly invoke bootstrap. Keep genuine bootstrap circuit coverage; a separate empty-account runtime bootstrap case requires its own authorized fixture. This is a reviewed fixture change, not permission to hide a driver failure or weaken a test.

Additional exact consumer amendments: root `Makefile:107-114` public-input requirement/explicit argv/child-secret stripping; launcher `ensureGenesisFiles:2745-2819` same public-input forwarding and child-only environment filtering; launcher :1034-1035/:2442 correct L1-only fixture naming and :2868-2873 remove only the Genesis decrypt dependency, preserving independent L1 password behavior. `docs/src/dev/genesis-generation.md` existing relayer-keystore input/call examples at :121,:123,:157 and `docs/src/dev/devnet-launcher-reference.md` stale relayer-wallet statements near :334-343 must document public account input and independent L1 custody. `docs/src/dev/circuit-and-verifier-operations.md:281` must no longer instruct registration2 to use a secret keystore. These documentation/source consumers are implementation scope only; this assignment still edits solely this design file.

Amendment acceptance (unexecuted): registration2 exactly matches current-circuit fingerprint/account parameter; contract6 initial members/header and fee slot authenticate; first nonce1 takes initialized policy branch; old secret flags/env, invalid input/artifact reject before output; export length/order/null2 and validator/faucet/phase1 key selection correct; no relayer private key/dummy exists; no-relayer→state-preserving full supervisor retains same genesis/deployment/checkpoint. Generated outputs remain untouched until separately authorized execution.

Forwarding acceptance (unexecuted): direct CLI, root Makefile target and launcher generation path all reject missing/malformed public account before output and forward identical validated account identity; recording child environment shows all six obsolete secret aliases absent while parent/L1 signer environment remains unchanged. An existing verified Genesis reuse does not regenerate because the variable is missing. Build the actual Genesis account/UCON/CSTATE roots from the generated records, authenticate contract6 slots and contract0 fee leaf against those roots, and prove first ordinary nonce1 session with revised multisig; an assertion only inspecting JSON fields is insufficient. The initialized-policy fixture driver must follow that root-proven path and must not issue bootstrap. Existing unrelated user registration examples and L1 signing/funding remain functional under their separate tests.

#### Uniform approved compiler-artifact authority

Keep existing Genesis transport: `PsyGenesisBlockSetupData.contracts` remains `Vec<PQBCDeployContract<Hash>>` (`psy_data/src/genesis/genesis_block_setup.rs:32-38`); exported named deployment objects retain existing flat fields/name. No new Genesis wrapper, layout metadata, full-private ABI manifest, canonical type-DAG producer or stamp schema is required for multisig. Existing CLV2 leaf fields/domain/FFS and unrelated deploy/layout work remain unchanged. Public-only multisig Genesis, initialized member slots plus fee state, dense null2 export and required caller forwarding above remain mandatory.

One model applies to every contract regardless of layout-root value: authenticate the **entire expected current contract leaf** under the approved Coordinator checkpoint, and interpret execution using an explicitly approved **complete compiler artifact**. Artifact contains state_tree_height, all circuit_definitions and existing ABI2.0.0 bytes; exact bytes/digest are retained in historical approval. Rebuild deployment code_definition/code_root/function_whitelist with existing `gen_contract_deploy_and_circuits_for_functions` and compute function-tree root at existing network height. Require roots/methods/height equal expected leaf and ABI height equal artifact height. This identifies the current approved executable; it does not prove an arbitrary ABI is committed on chain. Operator approval binds ABI interpretation to those definitions. No special verification branch for zero layout root or Genesis; missing artifact fails closed.

The needed state_map is already public in current token/USDT (`../psy-compiler/psy-precompiles/token/src/main.psy:101`). Existing ABI carries aligned offset/type/capacity/felt_size (`../psy-compiler/psy-abi/src/abi.rs:25-33,97-115`; extractor.rs:355-396,403-417). Require one visible field named state_map with direct Map<Hash,Hash,1048576>, alignment_felts4, value_felt_size4, aligned offset and checked felt_size=4*capacity. Derive subslot base from actual approved ABI offset, never ordinal or summing filtered visible predecessors. Cross-check base/capacity against the concrete namespace6 IMT access in that artifact's compiled withdraw method: operands must resolve to identical compile-time constants through existing compiled command/constant representation. Reject missing, ambiguous, dynamic or mismatched access. This is an exact approved-method predicate, not a generic bytecode scanner/layout framework. Scoped membership still validates base+1..base+capacity and key/value under authenticated state. Private-field descriptions are unnecessary to locate this approved visible field. Policy uses approved slots0..3 directly.

At approval activation/startup, validate each complete artifact once and cache `ApprovedTokenMap {subslot_base:u64,capacity:u64}` after validating the approved ABI field name is exactly state_map. This is a derived immutable descriptor, not another operator-configured authority. Include all callable definitions in code/function-root reconstruction; approval covers their full semantics, not only withdraw. Verify the withdraw namespace6 command's resolved base/capacity against the visible field, retaining the actual absolute compiler offset despite private predecessors. Cache keyed by artifact digest plus exact expected leaf; invalidate on approval/artifact/leaf change. Per-record checks authenticate current leaf equality and use that verified descriptor, not rebuild/prove every function for every burn. No remote ABI substitution or full-private reconstruction is performed.

Exact operand helper: use `DPNFunctionCircuitDefinition.definitions`, `state_commands` and `state_command_resolution_indices` (`client_prover/psy_vm/src/dpn/vm/def.rs:42-50`). Build one map keyed by `DPNIndexedVarDef::get_combined_data_type_index()` (typed wire identity, not bare numeric index; `dpn/ops/op_types.rs:564-566`). Reject duplicate identities rather than overwrite. Accept direct Constant/ConstantU32 with one canonical literal input, ConstantTrue as1 and ConstantFalse as0, following existing lookup pattern `../psy-compiler/psy-dargo-cli/src/cli/compile_cmd.rs:160-176`; other opcodes have no constant entry. For each approved withdraw map read/contains/write command, look up base_offset and capacity wire ids once and require their definitions precede that command's declared resolution boundary. Reject missing/nonliteral/forward references, malformed canonical literals and any mismatch with the unique approved ABI state_map offset/capacity. Reuse existing command-resolution index semantics; do not compare wire ids themselves with offsets. Perform no arithmetic folding, VM execution or key/value-wire analysis. Main's inspected current token example has base wire index10 resolving to8589934680 and capacity wire index11 resolving to1048576; those are artifact evidence examples, not universal hard-coded identities. Namespace6 construction, balance debit and safety of every callable writer remain explicit approval of the complete executable, not conclusions of this location helper. Preserve public ABI offsets obtained by the original complete storage walk, including private predecessors.

Namespace6 burn semantics and safe historical token upgrades are explicit Psy operational approval assumptions. Neither current code membership nor layout-root membership proves every historical writer was safe. The approved canonical network must permit only approved safe upgrades; if that assumption cannot be established, signing is unavailable until an approved historical artifact/network disposition exists. Do not add an unrequested chain scanner or claim current membership independently proves lineage.

Keep ABI2.0.0 public state/types unchanged. Build emits complete existing ABI with definitions for guardian-approved contracts; uniform existing-ABI emission for all precompiles is acceptable, but introduces no state_layout/storage_types schema. Required approved artifact output failures remain fatal. Existing provenance format can remain; no new Genesis stamp/wrapper protocol or root-layout-derived metadata is mandated. Compiler/SDK/services retain original Genesis deployment parsing. No new root psy_node_data/parth_core dependency is needed solely for removed layout derivation.

Source cleanup only after independent gate: manually remove **task-owned** new Genesis wrapper/metadata/parser branches from `psy_data/src/genesis/genesis_block_setup.rs`, `psy_node_core/src/genesis/genesis_db_data_builder.rs`, generator wrapper parsing, compiler Genesis exporter/replace tool, `client_prover/psy_core/psy_config/build.rs`, services parsers and task-authored wrapper fixtures. Preserve original deployment transport and unrelated CLV2/layout changes. Remove only task-added full-private state_layout/storage_types producer in compiler `psy-abi/src/{abi.rs,extractor.rs}` and task-added shared root JSON/DAG consumer changes/dependencies/fixtures; never revert another task's canonical-layout code. Keep policy precompile, revised authentication, initialized public Genesis, required approved ABI artifact emission, null2 consumers, child-only secret sanitization and L1 custody separation. Guardian protocol/verifier changes to complete artifact authority below; update affected tests. No git restore/reset or broad collaborator-file replacement. Owners inspect exact hunks and obtain static review after cleanup.

Acceptance (unexecuted): actual approved artifact reproduces current authenticated code/function roots/height; wrong digest, missing definitions/map, mismatched ABI offset or executable constant/capacity reject. Current token artifacts succeed without new Genesis layout roots, using the same checks for any approved layout-field values. Preserve actual initialized policy/fee roots and flat bundle consumers. No arbitrary ABI matching text substitutes artifact approval, and no test claims historical writer safety from current leaf membership.

| Consumer | Clean cutover contract |
|---|---|
| Relayer constants and all entry points | Keep524288 and contracts2/3; remove secret-wallet enrollment/submission, use revised multisig/precompile6. `constants.rs:3-4`, `daemon.rs:292-320,2767-2771`, `main.rs:406-407`. |
| Existing bridge proof circuits | Keep bridge user524288/deposit2/withdrawal3 (`bridge_agg_final.rs:59-61,278-291`); update dependent circuit pins only when actual auth/artifact dependency changes. |
| Token and USDT readers | Keep deposit user524288/contract2 (`../psy-compiler/psy-precompiles/{token,usdt_token}/src/main.psy:105-106`). |
| Policy precompile/ABI/config | Registry owns id6 and height4; complete approved artifact reproduces Genesis code/function roots and direct four-slot policy storage. No new on-chain layout metadata or Dargo-example deployment fallback. |
| Genesis/registration inputs | One enrollment record derives fingerprint/initial parameter/public key and required registration index2; no independently hand-copied member policy authority. Changed precompile bundle is a Genesis applicability input, not authorization to execute generation. |
| L1 StateManager/Bridge | Current verifier/role/frontier semantics remain; account constants agree with524288. No force-set/recovery mechanism added. |
| SDK, services, DApp, claim CLI, prove proxy and L1 wallet callers | Continue numeric524288 and existing bridge formats; consume revised account/EndCap artifact metadata where applicable, remove old commitment-only multisig witness callers. Browser guardian signing API is unnecessary. |

Existing claim/prove callers include `client_prover/psy_prover/src/local/native/prove_proxy.rs:105-108`, SDK local-prover request types, and `psy-dapp/apps/bridge/src/services/claimActions.ts:119-123`. All id consumers are intentionally unchanged numerically; no broad migration or configurable alternate bridge id is designed. Actual signing-authorization, TLS, and network values are operator inputs, not coding blockers. L1 deposit custody remains the separate evidence in section 5.

### 5. Current custody and burn verification

#### Deposits

Pin one finalized block number/hash per changed chain through each guardian's own configured verified nodes. Check chain id/genesis, Bridge/code/implementation and authorized token mapping. A request cannot define finality. A chain lacking a verified adapter is unavailable, not accepted after arbitrary block counting.

Reconstruct the current height32 deposit tree from canonical custody events, or a derived cache whose roots/counts and retained canonical anchors verify. Existing event fields/fetch checks are at `deposit_logs.rs:23-35,90-161`; extend fetch output with block/transaction/log provenance and a pinned finalized upper bound. Require each contiguous index `[old_count,new_count)` exactly once, successful receipt, correct address/chain/mapping, recomputed leaf and match to pinned L1 custody leaf storage. Require new count<=pending count; pending count alone does not commit a root. Independently reconstructed old/new roots must match authenticated L2 starting root and requested setter. Equal count requires equal root and no setter call. Missing/duplicate/nonfinal/mismatched evidence rejects the whole session.

Relayer deposit updates use only `set_chain_root` (`daemon.rs:2489-2510,2583-2589,2728-2733`). Reject bridge-account `append_leaf`, `batch_append_deposits_2`, `batch_append_deposits_5`, `append_deposit`, including mixed sessions, because its separate L2 frontier is not maintained by root setters. Preserve these methods for non-bridge state. Current **L1** frontier and append proofs remain active; no Spiderman witness is required here.

#### Burns, code and map location

Services discovery currently orders by `event_id` and uses per-chain cursor as service offset (`propose_withdrawals.rs:461-561`); checkpoint arguments are unused. Cleanly remove that authority assumption. Discover candidate pages from offset0, deduplicate identity `(sender,token_contract,nonce[8])`, reject conflicting duplicates, and authenticate selected records individually. Membership is not enumeration completeness: omissions delay discovery, never justify false appends.

The approved token withdraw subtracts balance then inserts namespace6 record (`../psy-compiler/psy-precompiles/token/src/main.psy:245-286`; USDT same). Before accepting even an authentic record, decode its amount as an integer: high six limbs must be zero and **0<amount<p**, `p=0xffffffff00000001`. No modular conversion. Source computes the low64 amount in Felt arithmetic (`:180-186`), so p+1 would alias1; u64 bounds alone are insufficient. Require network magic likewise `0<magic<p`, unique by field value (`ups_signature.rs:29-37` converts noncanonically).

Leaf preimage is exactly34 fields: sender, recipient8, token8, amount8, nonce8, destination chain index (`token:273-283`). Derive `record_key=Poseidon(nonce[0..8])` (`:197-200`) and `K=Poseidon(6,record_key[0..4])` (`../psy-compiler/psy-std/storage.psy:37-43,354-364`). Authenticate full IMT leaf preimage/key/value/next pointers, its CSTATE proof, UCON, sender leaf and checkpoint paths. Value equals recomputed34-field leaf. Token contract id is authenticated location, not an extra leaf field.

Before accepting a burn, require its destination chain index to select an authorized ChainAuthorization. Decode token and recipient as big-endian256-bit integers and require each upper96 bits zero, then require recipient!=zero. Require exactly one TokenMapping on that destination chain with `mapping.token == decoded token` **and** `mapping.l2_contract_id == record.token_contract_id`. A zero token address is accepted only when that exact mapping explicitly authorizes the native asset; never blanket-reject authorized native-token mapping. Reject unknown/mismatched mapping even when the burn membership and replay are valid: the token precompile accepts caller-chosen token_address (`token/src/main.psy:245-286`) and does not prove this asset relationship. Address/recipient predicates match `psy-contracts/src/Bridge.sol:752-760`; configured asset and integer amount checks remain mandatory on L1 (`:810-816`).

**Program identity and interpretation:** authenticate global contract path (`client_prover/psy_provider/src/lps.rs:742-768`) and exact expected whole PsyContractLeaf, all existing fields included. Reconstruct code/function roots and height from approved complete definitions; compare visible state_map ABI location/type/capacity with matching executable namespace6 IMT constants. Operator-approved artifact bytes supply semantic interpretation; chain proof establishes exact current program identity. No new layout-root proof, private-state inference, or Genesis/zero-layout verification branch. Unversioned provider code replies remain hints.

The contract leaf digest is explicitly `PoseidonHash::hash_no_pad([0x434c5632] || leaf.to_qfelts())`: the domain element followed by all19 fields in `client_prover/psy_core/psy_data/src/qdata/contract.rs:39-61` order, including deployer, function root, code root, state height and layout fields. Compare this20-field hash with the global-contract path value before verifying that path. Do not hash only the19 fields or omit the domain (`contract.rs:84-107`).

Let `b=ceil(subslot_base/4)`. Require IMT leaf index in **[b+1,b+capacity]**, checked arithmetic, and each nonzero next_index in that same range (`psy_vm/src/vm/exec.rs:64-85,105-114`). Namespace key is unchanged by base (`:1258-1265,1305-1321`). Use a scoped provider request carrying checkpoint,user,contract,K,b,capacity; server validates returned index/range and client repeats it. Existing unscoped `handler.rs:1433-1467` is not consumed as authoritative without these checks. A global key lookup resolving the wrong map fails closed; no root-equal out-of-range proof is accepted.

#### Ordering and append indices

Because the system is unlaunched and breaking change is authorized, choose a **new deterministic selection order**, not fictional authenticated event order. For each destination chain sort selected new burns by `(sender_user_id,token_contract_id,nonce[0],...,nonce[7])`; concatenate chains ascending. Replay existing withdrawal-tree append/batch chunking in that order. Assign indices `old_count+j` per chain only after reconstructing canonical GuardianSession history to the starting checkpoint and matching old subtree root/count. Previously included ordering is retained as account history; new burns never insert before it. Reject a repeated burn identity or destination-local nonce in selected or included history, including different users/tokens sharing a nonce. Current L1 nonce scope is destination-wide; this signer rule changes no L1 map. Every relayer entry point uses this one selector; no parallel services-offset branch remains.

#### Exhaustive authorized call grammar and fee

The guardian independently builds the expected top-level call list from verified evidence, then requires parsed `ContractCallData.contract_calls` to equal it exactly before replay. For `bridge`: first exactly one contract2 `set_chain_root(chain_index,new_absolute_count,new_root_u32x8)` per changed deposit anchor, ascending chain index, using independently reconstructed roots and the encoding of `daemon.rs:2489-2510`; then exactly the selected withdrawal calls produced by existing `build_withdrawal_batch_calls` (`daemon.rs:449-516`) over the section5 sorted record list. Its `optimal_batch_sizes` (`:403-433`) chooses counts of1/2/5 minimizing call count, keeping its existing tie resolution and emitting singles, then twos, then fives; no alternative chunker. Single calls are contract3 `append_withdrawal(sender,token_contract,destination,token8,amount8,recipient8,nonce8)`. Batch calls are contract3 `batch_append_withdrawals_2` or `_5`, with real count followed by sender array, token-contract array, destination array, token words, amount words, recipient words, nonce words in that exact builder order. Empty bridge plan is not signed. For `bootstrap` or `replace_policy`, list is exactly one contract6 `set_policy` with section3 expected fields and initial/proposed three members; evidence arrays are empty. Software-defined-call override is the existing empty/default value produced by `ContractCallData::new`, never a caller-selected extra execution.

No other requested top-level calls are permitted: in particular no withdrawal `set_chain_root`, raw withdrawal `append_leaf`, arbitrary token call, caller-supplied fee call, extra policy call, deferred invocation or free-standing inline invocation. Internally generated inline/deferred steps are accepted **only** when deterministically generated by replaying this independently derived list through the approved pinned contract definitions; full typed trace equality binds every such step. Replaying arbitrary supplied calls faithfully is not business authorization.

The session engine appends exactly one generated fee operation after those calls (`client_prover/psy_prover/src/session/session.rs:863-873`): contract0, `TOKEN_SIMPLE_BURN_METHOD_ID=2923993647`, `simple_burn`, one input F. Derive `s=get_total_modified_slots_for_fee()` after business/policy calls and before fee; add1 if token contract0 positional slot0 is not yet modified. Checked integer `F=GUTA_FEE+DA_FEE*s`, require `F<p` and `F<=authorization.max_fee` before conversion or reservation. `fee_contract_id` must equal0. Constants must equal the pinned network artifact's GUTA_FEE and DA_FEE, never request input. Source formula is `client_prover/psy_circuit/psy_ups_circuit/src/session.rs:1911-1928`; identifiers are `client_prover/psy_core/psy_config/src/network_constants.rs:20-21`. Require exactly one BurnFee trace step with that method/input and no extra user fee call; full replay must yield corresponding fee state/statistics. Any integer overflow or excessive fee rejects before key use.

### 6. Exact message, encoding and replay

Signature scheme is unchanged; policy-state constraints change. Compute existing `sig_hash_fields_from_header_poseidon`, `get_sig_action_for_user` and `Hash256::from(sighash)` (`psy_vm/src/ups/signature.rs:17-49`; `ups_signature.rs:20-50,70-84`; `multisig.rs:272-298`). For limbs h0..h3 bytes are `BE64(h3)||BE64(h2)||BE64(h1)||BE64(h0)` (`:213-215`). Sign raw secp256k1 prehash, low-S; signature64-byte r||s, compressed key33-byte, no recovery byte/personal-sign/JSON/SHA prefix. Reuse host verification (`external_secp256k1_user.rs:52-59`). Exactly two distinct increasing indices0..2 bind to stored commitments. Derived policy commitment binds to immutable initial account identity in the revised circuit; no current-policy hash slot exists.

Pinned replay explicitly sets authenticated start checkpoint/account leaf **and derived session nonce** before constructing any call. If authenticated user-tree leaf is zero (first session), nonce is exactly1; otherwise nonce is authenticated starting leaf nonce+1, with checked integer addition and canonical result<p. A pristine policy bootstrap has starting account nonce0 and therefore session nonce1. Request expected_nonce must equal that value before building. The exact source owner is `client_prover/psy_core/psy_data/src/qstore/controllers/proving_session.rs:470-483`; its getter is at :219-224. All reads and approved contract definitions use the pinned checkpoint. Reuse existing builder with that anchor/nonce, not a second interpreter or a latest-head fallback.

Compare supplied and replayed full typed `TxTrace` via `serde_json::to_value`, recursively equal: meta, anchor, ups_start_witness, contract_codes, every ordered step and all finalization fields (`trace/mod.rs:58-86,619-628,682-688`). **No fields excluded.** Unsigned request trace contains no precomputed proofs. Require envelope identifiers/hashes equal nested trace, envelope count equal `steps.len()` (current encoder:88-102), and parsed calls equal replay input; signature transaction count remains distinct and is compared through trace. Independent equal traces are a required positive acceptance, not presumed runtime evidence.

Canonical imported JSON rule is solely `serialize(deserialize(parsed)) == parsed`, plus recursive duplicate-key rejection. This permits source-defined canonical omissions such as `proof=None` omitted by `skip_serializing_if` (`trace/mod.rs:458-471`); reject unknown keys or omitted fields that the source serializer would emit. No blanket explicit-optional-field rule and no source-schema fork.

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

Catch-up runs **before** classifying a behind root as conflict. Starting from last imported canonical session, fetch next nonce, authenticate archived source evidence at its original start checkpoint, replay exact trace and policy transition with approved artifacts, verify the two signatures/EndCap, and authenticate ending leaf at claimed included checkpoint against current locally verified checkpoint-tree root. Connect its starting leaf to prior imported ending leaf (allow checkpoint reference advance without account-leaf change only as existing session semantics permit); enforce exact next account nonce, assigned append indices and uniqueness. Atomically insert GuardianSession and advance imported cursor. Repeated identical record is idempotent; two conflicting records do not overwrite. If archive is unavailable or canonical head is ahead of imported history, return HistoryUnavailable and fetch missing sessions, **not Halted**. If complete verified history reaches a pinned checkpoint but its root/count disagrees, halt.

Historical import resolves authorization from the immutable **local Psy approval archive**, independently of own GuardianSigned. Runtime configuration supplies archive directory and a locally approved version/digest index. Each version has exactly one UTF-8 GuardianAuthorization file; SHA-256 of its exact bytes must match its indexed digest and its embedded version. Files/index are provisioned through the existing authenticated Psy operator configuration channel, owner-only writable, immutable once approved, and retained for the entire account history. A replacement guardian receives this archive and index before catch-up. Peer history envelopes can name a version but cannot approve or replace its bytes. Missing approved historical version returns HistoryUnavailable; digest/version conflict refuses startup or import. New signing uses only the active version; exact old retries retain section7 restrictions. Historical import is a distinct read-only verification mode that accepts its locally approved archived version without requiring this key's prior decision or current-policy membership. It uses that version's token mappings, ABI/code pins, fee parameters and proof bound at the original checkpoint, never substitutes active-version policy. Canonical inclusion/threshold signatures remain independently verified.

If C was offline while A+B signed, C imports the same canonical session without own GuardianSigned, then can sign with A while B is offline. Replacement key enrollment uses identical catch-up. A local Reserved row whose exact request is included by the other two remains Reserved/unanswered, linked to GuardianSession; it never gains a fabricated own signature. No further signing at consumed nonce occurs. If a cached local signature does exist, retain it. A different canonically included request consuming a local Reserved/Signed nonce is a permanent conflict. Mere lack of this guardian's signature is not evidence of corruption: two other signers can validly include it. An archive lacking threshold signatures/trace/proof cannot be reconstructed or trusted and yields HistoryUnavailable.

Own decision key `(network_magic,user_id,nonce)` excludes checkpoint/version. Commit Reserved full bytes before key use; deterministic raw signing; commit Signed before release. Timeout/cancellation does not delete or replace a reservation. Full bytes are compared inside one redb write transaction. Exact cached response still runs current observation/history/evidence checks. Storage failure returns no signature. One Psy key instance exclusively owns one redb file plus an external `complete_journal`/`exclusive_key_use` signing authorization; a file lock cannot detect another database clone. Immediate durable commits precede signature release and terminal-halt errors. Missing signing authorization disables startup; revocation halts. No automatic unhalt or nonce release.

`GuardianAccount` Active→Halted is durable. Precise contradiction predicates:

1. For each saved L2 checkpoint `(id,leaf_hash)`, verify current provider Merkle path at that id against locally verified canonical checkpoint-tree root. Hash mismatch under a valid path proves contradiction. Missing path/root is unavailable, not rollback.
2. For each GuardianSession, verify user leaf membership at its included checkpoint/global user root; require exact ending leaf and public key/nonce. Check historical checkpoint, not latest leaf after later valid sessions.
3. For each saved finalized L1 block, verify canonical block hash at its height and ancestry to locally verified finalized head. A verified different canonical hash is conflict; inaccessible node is unavailable.
4. After authenticated catch-up reaches the pinned account nonce, require complete reconstructed deposit/withdrawal history cursors/roots agree with authenticated state. Behind/incomplete history is not contradiction.
5. Canonical different session consumes local reserved nonce, or the retained signing authorization has readable changed bytes, `revoked=true`, `exclusive_key_use=false`, or `complete_journal=false`: halt. Missing, unreadable, expired, or not-yet-valid approval stays unavailable and does not halt.

Observer covers own Reserved/Signed and every imported GuardianSession plus saved anchors. Startup and each cached/new response perform the same checks; a redb write transaction serializes response authorization against durable halt. Old configuration exact retries use retained approved bytes and reauthenticate evidence; new requests require active version. Configuration changes drain unresolved signed/reserved work, except consumed reservations linked to authenticated included history. Policy rotation is authenticated on chain and does not replace custody endpoints as membership authority. No claim of instantaneous reorg awareness after a completed observation.

### 8. Operational head authority and protected runtime inputs

This section defines precisely what earlier references to a locally verified L2 canonical root mean: **an independently queried, explicitly Psy-approved Coordinator/full-node operational authority**, authenticated as below. Merkle checks bind historical state to that authority's committed head; they do not independently prove consensus finality or implement a recursive light client. Compromise of one guardian's authority can cause that guardian to mis-sign. Three keys sharing one compromised upstream are not independent evidence. Each guardian operator must approve its own authority and document upstream isolation. L1 finality requirements remain unchanged.

Retain `l2_rpc_url` solely as the selected Coordinator committed-head endpoint; it must equal the first URL of the first approved `coordinator_configs` entry, so it is a checked selection from configuration, not a second authority. Required runtime additions are `rpc_config_path:String`, `signing_key_password_secret_path:String`, `signing_authorization_path:String`, and `l2_rpc_endpoint_pins:Vec<L2RpcEndpointPin>`. The protected rpc_config file contains exactly one strict source-serialized `NetworkConfig<GoldilocksField>` JSON (`client_prover/psy_core/psy_config/src/lib.rs:49-75`), not an environment-selected multi-network file. Pass it to `WalletSession::new(&NetworkConfigGoldilocks)` (`client_prover/psy_prover/src/session/session.rs:1509`). No request/relayer override or generated configuration. `custody_attestation_path` is rejected, not aliased.

Preserve existing Coordinator/Realm route topology and URL order. `L2RpcEndpointPin {role:Coordinator|Realm,config_id:u64,rpc_url:String,tls_certificate_sha256:Option<Hex32>}` uses role discriminants0/1 and the source configuration entry's id. Require exact one-to-one correspondence between protected locally approved pin records and every `(role,config_id,url)` occurrence in coordinator_configs/realm_configs. Reject missing/extra pins, duplicate route tuples, empty groups and duplicate ids within a role. Same-origin different paths are distinct endpoints; approval for one realm is not approval for another. Existing provider role/realm selection dispatches each RPC to its original configured route. No common routing proxy or new protocol is assumed. Validate realm coverage, users_per_realm and tree/group heights against compiled constants, magic against GuardianAuthorization and fees against approved constants. All retry/fallback URLs need matching approval, not only first URLs. Other network URL fields are unused by guardian replay/signing; any path requiring them rejects instead of using an unapproved fallback. Install approved transports for every provider client before network operations.

Require prove_proxy_url empty so construction cannot contact unapproved remote provers before transport installation; use local approved circuit artifacts. Constructor wiring must prevent network operations before approved clients are installed; if needed add an injected approved-client constructor instead of transient unpinned access. Within a committed-head observation use selected l2_rpc_url for marker/root/recheck; failure is unavailable, never a mid-observation authority switch. Historical account/contract witnesses retain approved role/realm routes and must verify to that selected Coordinator root.

For each HTTPS route require normal certificate-chain/hostname validation and SHA-256 of its exact DER leaf certificate equal that endpoint's tls_certificate_sha256, checked during TLS authentication before application data. No redirects, environment proxies, URL credentials, queries or fragments. Normalize scheme/host/default port with existing URL parser, preserve full path, reject dot-segment/encoded-path aliases. Certificate renewal requires explicit protected configuration change and restart. HTTP is allowed only numeric127.0.0.1 or[::1], with null pin; hostname localhost, other127/8 and nonloopback HTTP reject. Loopback authentication relies on Psy-controlled OS user/network namespace and approved local node process, not TLS. HTTPS requires nonnull pin; HTTP null. Approval binds role/config_id/full URL; TLS authenticates origin certificate, request routing enforces path. Responses cannot select routes.

For L2 only, `GuardianAuthorization.genesis_hash` means the 32 bytes `Hash256::from(checkpoint_zero_leaf.qfhash::<PoseidonHash>())`, rendered Hex32 using the existing reversed canonical-limb conversion. It is not a file checksum, an L1 block hash, or an unspecified network-id RPC value. On startup fetch checkpoint0 leaf and global-root preimage, hash both with existing checkpoint types, and verify checkpoint0 membership under the selected committed head. Require the resulting leaf bytes equal approved genesis_hash. Read explicit checkpoint-tree root at height0 and verify the same leaf/path there; retain that root as derived observation, not a second configurable genesis authority. Require network magic and compiled/configured dimensions independently agree; a claimed network name alone establishes nothing.

Service-only `GuardianCommittedHead {checkpoint_id:u64,checkpoint_tree_root:Hash4}` is obtained by `load_guardian_committed_head() -> Result<GuardianCommittedHead,GuardianSignError>` through the pinned endpoint. It is not deserializable from a sign request. Call `psy_get_latest_checkpoint_id` (Coordinator `edge/api.rs:114-116` → `handler.rs:247-248`, durable marker) to obtain C; call `psy_get_checkpoint_tree_root(C)` (`api.rs:151-153`) to obtain R. For historical P require P<=C, then fetch `psy_get_checkpoint_tree_merkle_proof(C,P)`, checkpoint leaf(P) and global roots(P) (`api.rs:131-133,159-164`). Verify fixed-height/indexP/canonical fields, checkpoint leaf hash/path value and rootR, then hash global roots into its global-chain commitment before any account/UCON/CSTATE/global-contract proof. Re-read durable marker and root at the **same selected C** before accepting the observation. If marker advanced, unchanged rootC and verified ancestry remain valid; if marker regressed or authenticated saved history is contradicted, apply durable halt rules; missing data returns unavailable. Persist C/R only after history consistency checks. Restart reauthenticates saved observations before serving signatures, including cached signatures.

Never use `get_coordinator_latest_block_state().checkpoint_id`, `psy_get_latest_l2_block_state`, a MAX_CHECKPOINT_ID root, or independently fetched latest id/root as committed authority. Normal commit writes latest singleton before checkpoint leaf/root and the durable marker (`psy_node_common/src/coordinator/processor/db.rs:1240-1262`); administrative rollback also writes singleton before marker (`:721-722`). `coordinator/edge/api.rs:139-148` exposes singleton/latest-root independently. Merkle checks cannot repair a mixed snapshot. Pure evidence verifiers receive only service-acquired head/root and approved historical paths; relayer/archive cannot override the trust root.

Protected-file grammar: resolve runtime/config-relative paths beneath an operator-approved directory handle using fd-relative `openat` and `O_NOFOLLOW` for **each** component; reject symlinks, traversal (`..`), nonregular final files and ownership/mode violations. Ancestors are owned by root or effective service uid and not group/other writable; secret/config/approval/database files are owned by effective uid with mode0600. Hold the verified file descriptor for each read/use; do not validate a path then reopen it unchecked. Immutable inputs compare descriptor metadata before/after read and fail on modification. Configuration/approval JSON uses the strict duplicate/unknown-key grammar already specified, maximum64MiB; encrypted key maximum1MiB; password1..4096 bytes valid UTF-8 with no NUL, CR or LF, no BOM and no trimming. The mutable database is opened read/write without creation by normal service startup; it has no content digest or connection secret. Empty, missing, unreadable or invalid databases disable startup. No stdin, environment, raw-key or default-keystore fallback.

Load the encrypted key from the held verified descriptor and password borrowed from a zeroizing buffer; never log either. The existing `Wallet::load` copies its password to an ordinary String at `client_prover/psy_provider/src/wallet/secp_wallet.rs:219-235`; a narrowly scoped borrowed-password encrypted-keystore helper must call the existing decrypt routine without that avoidable copy. On Linux a held `/proc/self/fd/<fd>` handle can supply its path-only decrypt API while retaining the verified descriptor. Erase the password buffer immediately after use, including error exits; this does not promise erasure of opaque library internals. Expose no raw private key. This helper and approved provider-transport wiring are amendment implementation scope, not permission to run or generate anything.

`SigningAuthorization` is protected local JSON with exactly `network_magic:u64,user_id:u64,public_key:Hex33,db_path:String,not_before_unix:u64,expires_at_unix:u64,exclusive_key_use:bool,complete_journal:bool,revoked:bool`. It is an authenticated operator-file assertion, not a threshold signature or on-chain policy. Require exact canonical network/user/key match to authorization and the database's immutable33-byte key singleton, exact relative `db_path` match to runtime configuration, true exclusive/complete, false revoked, and `not_before<=trusted_OS_unix_time<expires_at` with not_before<expires_at. Capture device/inode from the held database descriptor. Before each signature response and observer iteration, reopen the configured path through protected-file rules and require the same device/inode; a missing or replaced file stops release without switching the live database. Do not hash evolving database contents or compare mutable size/timestamps. No random database identity or incarnation mechanism is introduced: cloned databases/configurations and stale restored state remain external key-use risks despite matching key/path. The removed PostgreSQL connection-secret field and old `exclusive_custody` key are rejected, not aliased.

At startup retain exact approval bytes. Re-read and compare protected approval bytes and validity before every new/cached signature response and on the one-second observer. Initial missing/invalid/expired approval disables signing. During service, missing/unreadable approval or expiry stops signature release as unavailable; readable changed bytes, `revoked=true`, `exclusive_key_use=false`, or `complete_journal=false` commits terminal `SigningAuthorizationInvalid` halt before release. Planned approval renewal is stop process, replace protected approval/config, restart; restart can proceed only if the existing journal account is still Active and all saved history reauthenticates. New approval never clears Halted, resets decisions or proves clone absence. Detect process-local backward wall-clock movement and stop release as unavailable; across restarts trust the operator-managed OS clock. Historical import remains read-only while the signing authorization is unavailable, but no signature response escapes. Revocation races after the final observation are an operational limitation, not instantaneous detection.

Amendment acceptance (unexecuted): explicit durable C/rootC rejects singleton/MAX mixes; advancing marker with unchanged rootC succeeds, historical contradiction halts, missing data is unavailable; wrong DER pin/genesis/magic/config route fails before replay; request URL override is impossible; symlink/mode/traversal/changed-descriptor/password-newline files reject; wrong database path/inode/key, expiry, missing approval, live approval mutation/revocation and terminal-halt restart obey the exact rules above. Normal database writes do not invalidate the signing authorization. English-only documentation and existing policy/business predicates are unchanged.

`psy_relayer_cli guardian-create-db --runtime-config PATH` is the sole database initializer. It validates protected configuration, approvals, key and authenticated Genesis before exclusive `O_CREAT|O_EXCL` creation, commits four typed tables plus signer and initial account atomically, then syncs the parent directory. Parents must already exist. Existing files, including empty files, are never overwritten; a failed initialization retains its partial file for operator investigation. The command does not sign or start a listener. `guardian-service` only reopens existing state, requires its signer and account, and never recreates missing tables or clears Halted. redb engine crash recovery can write engine metadata before application validation; it does not authorize application repair or state reset.

Creation is only for a genuinely new signing key without prior reservations/signatures, including a new replacement key that subsequently authenticates canonical history. Existing PostgreSQL journal evidence remains untouched. No PostgreSQL-to-redb importer is supplied: an already-used key must not receive a fresh redb database, even at chain nonce zero, because uncommitted reservations/signatures are not recoverable from canonical history. Existing-key migration and deployment require separate authorization and an evidence-preserving migration procedure. Stop/drain the exclusive owner before offline inspection or backup; never operate a signing clone or restore stale bytes as ordinary restart. The unrelated Envio/indexer PostgreSQL dependency remains.

## Data Structures

### Policy and approval types

`StoredMultisigPolicy {header:Hash4,members:[Hash4;3]}` is exactly four CSTATE slots. Header example `[1,2,3,0]`; members are the three actual computed sorted fixture commitments, not arbitrary numeric fake keys. Current policy owns state; wallet/circuit reads, precompile atomically mutates. Derived `MultisigPolicy` uses version/header and constants2/3 plus five zeros only for existing commitment encoding. `MultisigAccount {contract_id:u32,initial_policy:MultisigPolicy}` remains immutable enrollment, contract_id6. Updated `MultisigSignatureWitness` fields exactly: account, start_state, end_state, sig_data, sign_context, start_session_user_leaf, nonce, using existing field types (`psy_vm/src/ups/multisig.rs:92-101`) but **without current_policy/ending_policy fields**. Start/end StateReaderResults contain the eight proofs specified in section3. MultisigSignatures remains matching two-element vectors of indices and existing signatures.

`ApprovedContract` fields exactly: `contract_id:u32`, `contract_leaf_json:JsonText<PsyContractLeaf<GoldilocksField>>`, `compiler_artifact_json:JsonText`, `compiler_artifact_sha256:Hex32`. Digest is SHA-256 of exact UTF-8 artifact bytes. Artifact has required state_tree_height:u16, circuit_definitions:Vec<DPNFunctionCircuitDefinition>, abi:Abi using existing ABI2.0.0; strict missing/duplicate/unknown envelope-field rejection and imported-type round trip apply. Full expected leaf includes deployer,function root,code root,height and existing layout fields; authenticate all without deriving new layout commitments. Rebuild deployment roots from complete definitions, compare expected leaf, then matching ABI height/methods. For token0/USDT4 derive unique visible state_map offset/capacity and compare compiled namespace6 constants as section4; no separately configured map offset/capacity or partial ABI authority. For policy6 approve direct slots0..3 operations, not a generic layout proof. Retained actual artifact bytes/digest and safe-upgrade approval are operational authority; hashes are actual build outputs, never invented fixtures.

`GuardianAuthorization` fields in order: `version:u32`, `network_magic:u64`, `genesis_hash:Hex32`, `user_id:u64`, `account_json:JsonText<MultisigAccount>`, `account_public_key:Hash4`, `multisig_fingerprint:Hash4`, `deposit_contract_id:u32`, `withdrawal_contract_id:u32`, `fee_contract_id:u32`, `guta_fee:u64`, `da_fee:u64`, `max_fee:u64`, `max_endcap_proof_bytes:u32`, `approved_contracts:Vec<ApprovedContract>`, `chains:Vec<ChainAuthorization>`. Require version>0, canonical0<magic<p, user524288, policy contract6, deposit2/withdrawal3, fee contract0, guta_fee/da_fee equal pinned network artifact constants, max_endcap_proof_bytes positive and equal the approved verifier serialization bound, exact derived registered key, approved contracts unique sorted id covering policy/deposit/withdrawal/fee and every token mapping. Initial-policy identity is not a current membership cache.

`ChainAuthorization` fields: `chain_index:u8`, `chain_id:u256`, `genesis_hash:Hex32`, `bridge:Hex20`, `state_manager:Hex20`, `bridge_code_hash:Hex32`, `bridge_implementation:Hex20`, `bridge_implementation_code_hash:Hex32`, `state_manager_code_hash:Hex32`, `state_manager_implementation:Hex20`, `state_manager_implementation_code_hash:Hex32`, `deployment_block:u64`, `token_mappings:Vec<TokenMapping>`. Nonzero pinned identities,1..256 sorted unique chains. Nonproxy implementation=contract. `TokenMapping {token:Hex20,l2_contract_id:u32}` sorted unique token,1..65536 entries, each id approved. Unlike event bytes32 input, typed L2 id is u32 and event value must encode that id canonically.

### Runtime and signing wire

`GuardianRuntimeConfig` fields: `authorization_path:String`, `authorization_archive_path:String`, `authorization_index_path:String`, `rpc_config_path:String`, `listen_address:String`, `tls_certificate_path:String`, `tls_private_key_path:String`, `client_ca_path:String`, `allowed_client_certificate_sha256:Vec<Hex32>`, `db_path:String`, `signing_key_secret_path:String`, `signing_key_password_secret_path:String`, `signing_authorization_path:String`, `l2_rpc_url:String`, `l2_rpc_endpoint_pins:Vec<L2RpcEndpointPin>`, `l1_rpc_urls:Vec<ChainEndpoint>`, `history_urls:Vec<String>`. `ChainEndpoint {chain_index:u8,rpc_url:String}` exactly covers chains; history_urls1..4 pinned mutual-TLS origins; caller pins1..16 distinct. Section8 defines L2RpcEndpointPin and exact protected-file/route/network/approval validation. Paths are nonempty config-relative, secrets owner-only, no environment key fallback. Example fixture listen127.0.0.1:9443, db_path guardian.redb, authorization version1/magic90101/user524288; actual role/realm URLs are retained from approved NetworkConfig and individually pinned. Old `custody_attestation_path` is rejected.

The archive directory and index paths are config-relative and locally Psy-approved. The index type is `GuardianAuthorizationIndex {active_version:u32,versions:Vec<GuardianAuthorizationVersion>}`; each record is `GuardianAuthorizationVersion {version:u32,sha256:Hex32}` in strictly increasing version order, positive unique versions, active_version present. Filename is decimal version plus `.json` under archive directory, not peer-selected path. `authorization_path` must name the active archive file; there is no separately editable active copy. Example index active2 with retained versions1 and2 uses exact computed file digests. Archive approval is independent of account member authority and per-key signature decisions. Existing GuardianSigned authorization_bytes are retained evidence and must match the archive digest; they cannot introduce another approved version.

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

## Core Functions

Proposed interfaces, not existing implementation claims. Types are defined above; errors omit credentials/witness dumps.

```rust
pub async fn generate_tx_trace_at_checkpoint(
    &self, public_key: QHashOut<GoldilocksField>, calls: ContractCallData,
    checkpoint_id: u64, expected_nonce: u64,
) -> anyhow::Result<TxTrace>;
```

Owner existing `session.rs:3270-3276`. Authenticate start checkpoint/leaf; derive nonce and require expected equality before begin_trace_build; configure all reads to that checkpoint; run existing trace_call/finalization; reject a later-head fallback. Normal entry resolves checkpoint once and delegates. No proof/signing before unsigned trace.

```rust
pub async fn get_withdrawal_burn_proof(
    &self, checkpoint_id: u64, record: &WithdrawalBurnRecord,
    approved_contract: &ApprovedContract,
) -> Result<psy_provider::lps::WithdrawalBurnProof, GuardianSignError>;
pub fn verify_withdrawal_burn(
    authorization: &GuardianAuthorization, record: &WithdrawalBurnRecord,
    proof: &psy_provider::lps::WithdrawalBurnProof, verified_checkpoint_root: Hash4,
) -> Result<(), GuardianSignError>;
```

Scoped membership RPC remains `(checkpoint_id:u64,user_id:u64,contract_id:u32,key:Hash4,state_slot_base:u64,capacity:u64)`; server/client validate map and successor range, no unscoped overload. Pure verifier joins destination/token/L2-contract and recipient checks, integer amount, current whole-leaf/code identity against complete approved artifact, ABI/executable-constant map agreement, then namespace/value and checkpoint/user/UCON/global-contract paths. Missing artifact/proof fails unavailable/mismatch, never zero-layout fallback. Existing source seams handler.rs:1433-1467 and lps.rs:111-168,235-273,742-768 remain.

```rust
pub async fn verify_guardian_session(
    authorization: &GuardianAuthorization, request: &GuardianSignRequest,
    wallet: &WalletSession,
) -> Result<TxTrace, GuardianSignError>;
pub async fn import_session(
    record: GuardianSessionRecord,
) -> Result<GuardianSession, GuardianSignError>;
pub async fn verify_guardian_account(
    context: &GuardianVerificationContext, authorization: &GuardianAuthorization,
    signed_records: &[GuardianSigned], approved_authorizations: &[GuardianAuthorization],
    sessions: &[GuardianSession],
) -> Result<(), GuardianAccountError>;
```

Verification authenticates policy fields/code, catches history up to pinned starting nonce, verifies custody/burn asset mapping/uniqueness/order, independently derives the exhaustive section5 call list and generated fee, requires requested calls equal that list, generates the checkpoint-and-nonce-pinned trace and compares the entire trace. Import first resolves exact historical authorization bytes/digest from the local approved archive, then runs the same business verification at original historical anchors without active-version or importing-key-membership requirements; it verifies two signatures/EndCap, canonical checkpoint/user ending leaf, history continuity, and atomically imports without creating an own signature. Account anchor verification performs explicit section7 paths/ancestry checks; incomplete history invokes import, contradictory verified evidence commits halt.

```rust
pub async fn sign_guardian_session(request: GuardianSignRequest)
    -> Result<GuardianSignResponse, GuardianSignError>;
pub async fn reserve_guardian_nonce(value: &GuardianSigned)
    -> Result<GuardianSigned, GuardianSignError>;
pub async fn save_guardian_signature(request_id: [u8;32], signature: [u8;64])
    -> Result<GuardianSigned, GuardianSignError>;
pub async fn build_multisig_signatures(
    request: &GuardianSignRequest, endpoints: &[url::Url;3],
) -> Result<MultisigSignatures, GuardianSignError>;
```

Service parses/canonicalizes, checks own row equality and canonical history, verifies observation/replay, commits reservation inside a write transaction, signs exact reserved message, verifies and commits Signed before response. Cached response repeats observation then checks Active inside a write transaction. Reserve compares full bytes under the exclusive writer; save requires exact reservation/signature compatibility. Relayer sends identical bytes to three pinned endpoints, verifies current on-chain membership/message, returns exactly two sorted members; ten-second timeout retains request and retries after one second. Inject existing signatures and prove exact trace, not fresh exec_contract_call. No local signing for already consumed reservation; history-only catch-up never returns an invented signature.

Precompile function internal flow is normative in section3; host `load_multisig_policy(checkpoint_id,user_id,contract_id)->StoredMultisigPolicy` authenticates four fields, validates fixed header and sorted members, then derives hash-format policy. No `set_multisig_policy` local override survives.

## Core Loops

**Startup/request:** acquire key-instance lock and signing authorization; validate artifacts/authorization/id524288; authenticate policy/code; catch history up; verify saved anchors. If unavailable, keep signing disabled but continue history retrieval. At most four HTTP requests, one account verification active. Read-only pre-reservation deadline120s; cancellation never deletes reservation. Shutdown stops intake and commits outstanding journal transaction before any response.

**Observer:** once per second authenticate current canonical head; fetch/import missing next GuardianSession until imported nonce reaches head or evidence unavailable; then check saved history/decision anchors and explicit contradiction predicates. Verify old GuardianSession against historical leaf, not latest state. If two others included the exact locally Reserved request, link canonical history, keep own record unchanged and never sign it after consumption. Different canonical request at reserved nonce halts. Exit scan at current head, wait. Missing archive/node is unavailable, not halt.

**Relayer:** if immutable pending request exists, retry it or exact EndCap; authenticate inclusion; publish retained included envelope. Otherwise authenticate policy/head/counts, retrieve complete history, discover/sort candidates by new deterministic per-chain selector, verify plan, produce pinned unsigned trace, save request, collect two, prove/save, submit/wait. Empty plan waits1s. No concurrent account sessions or service-offset branch. Current L1 proof/append/finalize/claim pipeline follows committed UPS; future A/B is not invoked.

**Rotation:** quiesce new bridge requests; validate proposed three individual commitments and signing authorization; current two sign policy-only version+1; wait canonical inclusion; all guardians import; replaced node catches history up through rotation with its new key; resume. Authenticated stored state, not local member list, chooses current indices. If quorum unavailable there is no master recovery bypass.

## Module Changes

Policy precompile owns stored members/version; revised circuit independently authenticates those fields and fixed2/3. Session/wallet owns loading authenticated policy and pinned replay. Guardian protocol owns strict encoding, verification owns pure predicates, journal owns own decisions/canonical imports, service owns ordering/key access. Relayer owns request/archive availability, not history truth. Provider adds scoped membership and global contract proof composition. Current L1 bridge formats are unchanged; EndCap and dependent artifacts change because account constraints change.

## File Changes

Only this document changes now. One normative conceptual hunk plan follows; generated artifacts are applicability outputs, not permission to run generators. Existing numeric524288 consumers remain unchanged, while every obsolete commitment-only signature caller is cut over.

```diff
--- /dev/null
+++ b/../psy-compiler/psy-precompiles/multisig_policy/Dargo.toml
@@ +1 @@
+Package multisig_policy, bin, same precompile package convention as faucet/Dargo.toml:1-6.
--- /dev/null
+++ b/../psy-compiler/psy-precompiles/multisig_policy/src/main.psy
@@ +1 @@
+Implement four-slot StoredMultisigPolicy, get_policy and atomic set_policy from section3; fixed header2/3.
--- a/../psy-compiler/psy-precompiles/precompiles.json
+++ b/../psy-compiler/psy-precompiles/precompiles.json
@@ 81-88: after faucet @@
+Append multisig_policy, methods get_policy/set_policy, declared state height4; generated id6.
--- a/client_prover/psy_core/psy_config/src/lib.rs
+++ b/client_prover/psy_core/psy_config/src/lib.rs
@@ 134: ContractConfig declaration @@
+Add declared_state_tree_height:Option<u8>; when present require inferred<=declared<=32 and bind both artifact and ABI height.
--- a/../psy-compiler/psy-precompiles/build.rs
+++ b/../psy-compiler/psy-precompiles/build.rs
@@ 93-98,214-215 @@
+Honor validated declared height4 for policy, keep ordered generated IDs; fail missing/invalid required policy artifact.
--- a/../psy-compiler/psy-precompiles/src/lib.rs
+++ b/../psy-compiler/psy-precompiles/src/lib.rs
@@ 12-20: registry contract @@
+Include generated multisig_policy id6 and methods; preserve existing ids0..5.
--- a/../psy-compiler/psy-dargo-cli/examples/multisig_policy/src/main.psy
+++ b/../psy-compiler/psy-dargo-cli/examples/multisig_policy/src/main.psy
@@ 3-18 @@
+Remove obsolete standalone commitment-only deployment example; precompile is the sole policy implementation.
--- a/client_prover/psy_vm/src/ups/multisig.rs
+++ b/client_prover/psy_vm/src/ups/multisig.rs
@@ 20-107 @@
+Add field-derived fixed2/3 policy validation; remove witness current/ending preimages; retain initial identity parameter.
--- a/client_prover/psy_circuit/psy_ups_circuit/src/signature/multisig.rs
+++ b/client_prover/psy_circuit/psy_ups_circuit/src/signature/multisig.rs
@@ 134-162,190-212,264-329 @@
+Authenticate start/end slots0..3, fixed2/3, initial-only bootstrap and version replacement; eight reader proofs each.
--- a/client_prover/psy_prover/src/session/session.rs
+++ b/client_prover/psy_prover/src/session/session.rs
@@ 957-979,1718-1741,2679-2746,3270-3276 @@
+Load on-chain fields; cut local policy authority; build revised witness; add pinned checkpoint+expected nonce entry.
--- a/client_prover/psy_prover/src/wallet/memory_wallet.rs
+++ b/client_prover/psy_prover/src/wallet/memory_wallet.rs
@@ 625-666 @@
+Keep public enrollment/signature injection; remove local authoritative current/ending policy setter.
--- a/client_prover/psy_prover/src/signature/users/multisig_user.rs
+++ b/client_prover/psy_prover/src/signature/users/multisig_user.rs
@@ 48-107 @@
+Derive current membership from authenticated field witness; exact two external signatures.
--- a/client_prover/psy_prover/src/local/native/mod.rs
+++ b/client_prover/psy_prover/src/local/native/mod.rs
@@ 53-57,298-315 @@
+Remove set_multisig_policy RPC/callers; expose authenticated policy loading and existing external signature injection.
--- a/client_prover/psy_provider/src/request.rs
+++ b/client_prover/psy_provider/src/request.rs
@@ 257-265 @@
+Typed scoped IMT membership request with state_slot_base and capacity.
--- a/client_prover/psy_provider/src/provider.rs
+++ b/client_prover/psy_provider/src/provider.rs
@@ 766-792: bridge helpers @@
+Assemble burn proof with checkpoint/user/UCON/global-contract/IMT paths and cached approved artifact-derived map descriptor.
--- a/psy_node_common/src/realm/edge/handler.rs
+++ b/psy_node_common/src/realm/edge/handler.rs
@@ 1433-1467 @@
+Require scoped membership range and successor range; reject wrong-map key lookup.
--- a/psy_node_common/src/realm/edge/api.rs
+++ b/psy_node_common/src/realm/edge/api.rs
@@ membership RPC declaration @@
+Update existing membership API arguments with map range; all callers cut over, no overload.
--- /dev/null
+++ b/psy_cli/psy_relayer_cli/src/guardian/mod.rs
@@ +1 @@
+Declare protocol, verify, db, service modules with minimal public surface.
--- /dev/null
+++ b/psy_cli/psy_relayer_cli/src/guardian/protocol.rs
@@ +1 @@
+Complete schema, canonical encoding, approved contract/ABI and retained envelope types.
--- /dev/null
+++ b/psy_cli/psy_relayer_cli/src/guardian/verify.rs
@@ +1 @@
+Custody/burn/current-code/artifact-map/policy predicates, pinned replay and canonical history verification.
--- /dev/null
+++ b/psy_cli/psy_relayer_cli/src/guardian/db.rs
@@ +1 @@
+Own decisions and canonical GuardianSession import are separate tables; account observation/halt transactions.
--- /dev/null
+++ b/psy_cli/psy_relayer_cli/src/guardian/service.rs
@@ +1 @@
+Authenticated sign/history endpoints, signing authorization, catch-up, observer and bounded request loop.
--- /dev/null
+++ b/psy_cli/psy_relayer_cli/src/bridge/guardian_client.rs
@@ +1 @@
+Exactly-two collection and immutable request/included-envelope archive.
--- a/psy_cli/psy_relayer_cli/src/bridge/mod.rs
+++ b/psy_cli/psy_relayer_cli/src/bridge/mod.rs
@@ module declarations @@
+Declare guardian_client.
--- a/psy_cli/psy_relayer_cli/src/bridge/daemon.rs
+++ b/psy_cli/psy_relayer_cli/src/bridge/daemon.rs
@@ 292-347,2669-2793,2992-3095 @@
+Remove secret-backed session construction and fallback; all relayer L2 paths use one multisig client and selector.
--- a/psy_cli/psy_relayer_cli/src/bridge/propose_withdrawals.rs
+++ b/psy_cli/psy_relayer_cli/src/bridge/propose_withdrawals.rs
@@ 461-561,654-655 @@
+Discovery offset0, selected per-chain canonical order and included history; remove event_id/cursor authority.
--- a/psy_cli/psy_relayer_cli/src/bridge/deposit_logs.rs
+++ b/psy_cli/psy_relayer_cli/src/bridge/deposit_logs.rs
@@ 55-161 @@
+Pinned finalized bound and receipt/block/log provenance for current tree reconstruction.
--- a/psy_cli/psy_relayer_cli/src/main.rs
+++ b/psy_cli/psy_relayer_cli/src/main.rs
@@ 21-77,406-407 @@
+Guardian command/history server, public enrollment; remove relayer L2 secret config and alternate submission bypass.
--- a/psy_cli/psy_relayer_cli/Cargo.toml
+++ b/psy_cli/psy_relayer_cli/Cargo.toml
@@ 10-59 @@
+Use workspace HTTP/crypto dependencies and redb; retain tokio-postgres only for the unrelated indexer.
--- a/client_prover/psy_cli/psy_user_cli/src/subcommand/generate_tx_trace.rs
+++ b/client_prover/psy_cli/psy_user_cli/src/subcommand/generate_tx_trace.rs
@@ 10-68 @@
+Public multisig account input; load current fields from policy precompile, no current-policy override files.
--- a/docs/src/dev/TERMINOLOGY.md
+++ b/docs/src/dev/TERMINOLOGY.md
@@ 238-255 @@
+Make stored header/individual members authority, derived commitment/initial identity distinct, add GuardianSession.
--- /dev/null
+++ b/psy_cli/psy_relayer_cli/tests/guardian_signing.rs
@@ +1 @@
+Observable policy, registration, proof, catch-up, encoding, crash and halt acceptance below.
```

Compiler ABI generation exports the new policy's existing ABI through the precompile/Genesis flow; generated id6, artifact-derived code/function roots, height4 and initial account fingerprint form one approved input set. Existing whole-leaf layout fields are compared as approved expected metadata, **not derived from ABI or promoted into a new layout proof**. Registry changes classify Genesis bundle/ABI/config inputs as affected generation outputs; authentication circuit changes classify EndCap verifier metadata and generated circuit library/common-data pair as affected. Downstream SDK/WASM/services adopt the same approved source/artifact cohort. Numeric fingerprints/generated bytes remain future measured outputs. Generation/publication requires separate authorization; no alternative policy authority or new Genesis layout schema is retained.

## Rationale

Four member slots/fixed2of3 satisfy policy without hash mirror; initial identity/prehash avoid a new signature scheme. Current authenticated executable plus uniformly approved complete artifact gives the existing visible token-map interpretation, and scoped paths prevent wrong-map acceptance. GuardianSession differs from own decisions and permits offline catch-up. Exact business-call derivation, trace equality and irreversible reservations retain safety. A global Genesis layout transport/full-private ABI producer is unnecessary for these approved visible bridge fields and is excluded rather than bypassed.

## Security Considerations

Two compromised Psy keys can approve false business evidence despite valid account proof; fixed2/3 constraints do not prove custody. Shared Psy administration is not institutional independence. Per-key journals do not provide Byzantine consensus: two conflicting threshold certificates can exist with a malicious intersection member, but canonical account nonce permits only one canonical history. A stale reservation can stall a key; no master reset exists.

Bootstrap requires pristine registered initial identity; initialized policy Genesis uses ordinary nonce1. Approved executable/ABI changes need new historical artifact approval and current-leaf verification. Psy's canonical network/safe-upgrade approval establishes historical writer safety; neither current code nor layout membership independently proves lineage. Amount/network aliases reject before conversion. Missing RPC/archive evidence is unavailable, not canonical completeness. No automatic purge at occupied index2. Current L1 proofs/roles remain mandatory and artifact approval grants no bypass.

## Future Acceptance

All planned, unexecuted. After required independent design/reviewer gates, proposed target `cargo test --release -p psy_relayer_cli --test guardian_signing` exercises real Plonky2 and current bridge protocol. No future A/B proof is needed.

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

## External Prerequisites

Actual Psy signing keys, signing authorization, TLS, target network canonical magic/genesis, available registration slot2 or exact already-registered key, approved compiler ABI/code/layout outputs, chain/deployment/finality identities and L1 role credentials are operating inputs. The design fixes id524288/precompile6/three members/two signatures; it does not defer those choices. An occupied local slot blocks that registration action until the user authorizes an environment action; it does not create a production migration requirement or permit deletion. L1 deposit custody inputs remain separate.

The normative v14 design received independent GPT/Grok PASS and final design-reviewer approval; its approved pre-status-update digest is `c5ced957c602b0e8980782af8433d6985969908291edf07c02407af968a1a669`. External canonical specification access/reconciliation is complete at the revision cited in section1. Implementation and scoped QA are in progress under `T-BRIDGE-GUARDIANS`; this document's acceptance descriptions are requirements, not a complete execution report. Remaining real three-guardian/end-to-end acceptance, artifact compatibility and final delivery gates are not passed by design approval or fixture-only proof results. Generation, environment changes, deployment, publication and push retain their separate authorization boundaries. Current multisig precedes merge; future Spiderman/two-Groth16 and rewards remain separate work.
