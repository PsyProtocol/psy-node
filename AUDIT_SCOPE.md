# AUDIT_SCOPE

External audit inventory for PsyProtocol core: circuits, node, compiler, bridge relayer, Ethereum contracts.

All GitHub paths and line counts are taken from `origin/mainnet-beta` (not a local feature branch). Line counts are source lines at the pinned commit.

Every `tree/` / `blob/` URL below was checked with `git cat-file` against the three SHAs in the pin table.

## Pin

| Repo | URL | Branch | Commit |
|---|---|---|---|
| psy-node | https://github.com/PsyProtocol/psy-node | `mainnet-beta` | `e7c0ec1c2ce67d7677d54831089e4633d090e8cb` |
| psy-compiler | https://github.com/PsyProtocol/psy-compiler | `mainnet-beta` | `679adf43af625a41e6c5132f45034b0216f8cc47` |
| psy-contracts | https://github.com/PsyProtocol/psy-contracts | `mainnet-beta` | `ba063fb8dcb9b3695f1588519a53b9578bde3763` |

Branch URLs use `tree/mainnet-beta` or `blob/mainnet-beta`. To freeze a file, replace `mainnet-beta` with the SHA.

`psy-compiler` at this pin depends on psy-node [`5fe0fc252c90b3aa5600229112b05c02c973e73b`](https://github.com/PsyProtocol/psy-node/tree/5fe0fc252c90b3aa5600229112b05c02c973e73b) for VM / circuit crates. Review compiler against that node rev for type/gadget compatibility; review node/circuits/relayer against `e7c0ec1`.

## Totals

| Surface | Files | Lines | Repo |
|---|---:|---:|---|
| Circuits (UPS + DPN + network + common **core** + node Plonky2 + helpers) | ~420 | ~82,100 | [psy-node](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta) |
| Client proving (prover / VM / crypto; no CLI, no `psy_data`) | 179 | 56,266 | [client_prover](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover) |
| Node (coordinator / realm / storage; no CLI, no `psy_data`) | 437 | 99,919 | [psy-node](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta) |
| Bridge relayer | 16 | 11,715 | [psy_relayer_cli](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_cli/psy_relayer_cli/src) |
| Compiler core | 131 | 26,327 | [psy-compiler](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta) |
| Ethereum contracts (production Solidity, no mocks) | 19 | ~4,066 | [psy-contracts/src](https://github.com/PsyProtocol/psy-contracts/tree/mainnet-beta/src) |
| **In-scope production** | **~1,202** | **~280,400** | |

Line counts already exclude `tests/`, `test/`, `examples/`, `benches/`, `generated/`, `*_test.rs`, `*.test.ts`. Embedded `#[cfg(test)]` blocks that still sit inside a production file are **not** in scope.

Dropped from the first 354k inventory:

| Drop | Lines | Why |
|---|---:|---|
| `common_circuit` KZG | 2,435 | unused generic crypto |
| `common_circuit` BN254 pairing / Fp12 | 9,945 | unused generic crypto |
| `common_circuit` generic secp256k1 ECDSA library | 4,608 | generic curve arithmetic |
| lookalikes / debug / wallet / dummy treeprover | 1,323 | mock / unused |
| compiler fmt + LSP + WASM + dargo + package | 7,356 | toolchain |
| `psy_node_cli` + `psy_worker_cli` + `psy_user_cli` | 11,821 | CLI |
| node `psy_data` + client `psy_data` | 36,032 | data types / serde / field hashes |
| Ethereum `Mock*` / harness / test proxies | ~134 | mock |
| compiler `tests/` | 6,319 | unit / language tests |

## In scope

1. Client circuits: UPS, DPN, network, and Psy-owned common gadgets (hash / Merkle / treeprover / builder / signature wrappers).
2. Node circuits: GUTA / coordinator / EndCap / bridge. Not dummy EndCap.
3. Node runtime: coordinator, realm, GUTA planner, queues, commit/recovery, storage, worker.
4. Client prover + VM (witness construction).
5. Bridge relayer (`psy_relayer_cli`).
6. Compiler: `psy-sema`, `psy-interpreter`, AST/parser/lexer, `psy-precompiles` (except faucet), `psy-std`.
7. Ethereum Solidity: StateManager, Bridge, gateways, Groth16 verifiers, governance.

## Out of scope

- Local branches such as `feat/p2p`. Audit `mainnet-beta` only.
- Nested copy [`client_prover/psy_compiler`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_compiler). Use [psy-compiler](https://github.com/PsyProtocol/psy-compiler).
- Dummy prover / dummy proof / JTMB testbed / `psy_plonky2_testbed`.
- Generated circuit cache [`psy_plonky2_circuits/src/generated`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/generated).
- Wallet, explorer, IDE, dapp, TypeScript SDK, services.
- Genesis blobs, logs, deploy artifacts, OpenZeppelin under `psy-contracts/lib/`.
- **Unit tests:** any `tests/`, `test/`, `*_test.rs`, `*.test.ts`, `#[cfg(test)]` module, Foundry/Hardhat tests, compiler `tests/*.psy`.
- **Mocks / dummies / lookalikes:** [`circuits/lookalikes/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/circuits/lookalikes), dummy treeprover, [`end_cap/dummy.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_plonky2_circuits/src/end_cap/dummy.rs), [`end_cap/dummy_prover.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_plonky2_circuits/src/end_cap/dummy_prover.rs), Ethereum `Mock*.sol` / harness / `Test*Proxy.sol`.
- **Generic crypto:** KZG, BN254 pairing, BLS12-381, generic secp256k1 ECDSA field/curve library.
- **common leftovers:** [`crypto/kzg/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/kzg), [`crypto/bn254/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/bn254), [`crypto/secp256k1/ecdsa/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/secp256k1/ecdsa), `debug/`, `wallet/`, `old_gadget.rs`.
- **Compiler toolchain:** [`psy-fmt`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-fmt), [`psy-lsp-server`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-lsp-server), [`psy-wasm`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-wasm), [`psy-dargo-cli`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-dargo-cli), [`psy-package`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-package).
- **CLIs:** [`psy_cli/psy_node_cli`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_cli/psy_node_cli), [`psy_cli/psy_worker_cli`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_cli/psy_worker_cli), [`client_prover/psy_cli/psy_user_cli`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_cli/psy_user_cli). Relayer stays.
- **Data types:** [`psy_data`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_data/src) and [`client_prover/psy_core/psy_data`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_core/psy_data/src). Structs, serde, FFS, field-hash wrappers. Algorithms live in circuits / prover / VM.
- **Non-custody precompile:** [`psy-precompiles/faucet`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-precompiles/faucet).

## Suggested order

| Pri | Why | Paths |
|---|---|---|
| P0 | Soundness of every user / node / bridge proof | UPS, DPN, network, common **core**, node GUTA, bridge circuits |
| P0 | Ethereum fund custody and proof verification | `StateManager.sol`, `Bridge.sol`, Groth16 verifiers |
| P0 | Relayer glue that can steal or stall exits | `daemon.rs`, `claim_withdrawals.rs`, `prove_bridge.rs` |
| P1 | State transition / inclusion / recovery | coordinator + realm processors, GUTA planners, `commit.rs` / `init.rs` |
| P1 | Witness construction matching circuits | `psy_prover`, `psy_vm` |
| P2 | Psy program → VM / precompile correctness | `psy-sema`, `psy-interpreter`, `psy-precompiles` |
| P3 | Availability, not consensus | Redis / Scylla / NATS |

---

## 1. Circuits — psy-node

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta

Two stacks:

- Client circuits under [`client_prover/psy_circuit/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit) — UPS / DPN / network / common.
- Node circuits under [`psy_plonky2_circuits/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits) — GUTA, coordinator, EndCap, bridge.

### 1.1 UPS

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_ups_circuit/src

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`client_prover/psy_circuit/psy_ups_circuit/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_ups_circuit/src) | 9 | 4,699 | UPS session, circuit manager, signature gadgets |
| [`…/session.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/client_prover/psy_circuit/psy_ups_circuit/src/session.rs) | 1 | ~2.3k | UPS step / start / CFC witness |
| [`…/circuit_manager/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_ups_circuit/src/circuit_manager) | 2 | ~1.0k | circuit selection |
| [`…/signature/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_ups_circuit/src/signature) | 5 | ~1.4k | SDK / SD / software-defined keys |

Network-side UPS wrappers are also in [`psy_network_circuit/src/ups/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_network_circuit/src/ups) (24 files / 3,720 lines). Audit both.

### 1.2 DPN

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_dpn_circuit/src

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`client_prover/psy_circuit/psy_dpn_circuit/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_dpn_circuit/src) | 18 | 7,113 | contract-execution circuit |
| [`…/circuits/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_dpn_circuit/src/circuits) | 7 | 1,808 | CFC + privacy |
| [`…/vm/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_dpn_circuit/src/vm) | 10 | 5,303 | opcode gadgets, keccak, compile |

Pair with [`client_prover/psy_vm/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_vm/src) (14,264).

### 1.3 Network

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_network_circuit/src

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`client_prover/psy_circuit/psy_network_circuit/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_network_circuit/src) | 52 | 7,586 | EndCap / UPS-in-network / GUTA gadgets |
| [`…/ups/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_network_circuit/src/ups) | 24 | 3,720 | EndCap, UPS start, CFC standard/deferred |
| [`…/gadgets/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_network_circuit/src/gadgets) | 21 | 2,862 | qdata / stack / sig_action |
| [`…/verify_witness.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/client_prover/psy_circuit/psy_network_circuit/src/verify_witness.rs) | 1 | 656 | public-input / witness checks |
| [`…/guta/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_network_circuit/src/guta) | 3 | 132 | GUTA stats gadgets |
| [`…/circuits/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_network_circuit/src/circuits) | 2 | 209 | CFC placeholder |

### 1.4 Common circuit

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src

Crate is 223 files / 47,521 lines. Most of that is not Psy core.

**Audit this (~29k):**

| Path | Files | Lines | Why it is core |
|---|---:|---:|---|
| [`…/hash/merkle/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/hash/merkle) | 31 | 9,920 | Merkle / IMT / historical-root gadgets |
| [`…/hash/base_types/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/hash/base_types) + [`hash_ops.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/hash/hash_ops.rs) | 9 | 1,429 | Poseidon / hash256 types |
| [`…/treeprover/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/treeprover) except dummy | 38 | 4,693 | recursive tree aggregation you run |
| [`…/u32/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/u32) | 17 | 5,108 | u32 gates used by Merkle / IMT |
| [`…/builder/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/builder) | 16 | 2,993 | compare / select / pad / verify |
| [`…/circuits/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/circuits) `zk_signature*` + [`secp256k1_signature`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/circuits/secp256k1_signature) | 8 | 1,254 | Psy signature-binding circuits |
| [`gadget.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/secp256k1/gadget.rs) + [`signature_circuit.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/secp256k1/signature_circuit.rs) | 2 | 827 | prefix wrapper around generic ECDSA |
| [`…/proof_minifier/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/proof_minifier) + [`verify_template/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/verify_template) | 10 | 1,351 | used by the wrappers above |
| remainder (`lib.rs`, `traits.rs`, `serialization.rs`, `vector_builder.rs`) | 4 | ~740 | crate glue |

**Do not audit (~18.3k):**

| Path | Lines | Why drop |
|---|---:|---|
| [`…/crypto/kzg/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/kzg) | 2,435 | unused |
| [`…/crypto/bn254/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/bn254) | 9,945 | generic pairing / Fp12, unused |
| [`…/crypto/secp256k1/ecdsa/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/secp256k1/ecdsa) | 4,358 | generic secp256k1 field/curve/MSM |
| [`old_gadget.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/crypto/secp256k1/old_gadget.rs) | 250 | dead |
| [`…/circuits/lookalikes/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/circuits/lookalikes) | 362 | mock |
| [`…/debug/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/debug), [`…/wallet/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_circuit/psy_common_circuit/src/wallet) | 453 | tracer / unused wallet |
| dummy treeprover dirs | 508 | mock aggregation |

Node-side shared helpers (keep):

| Path | Files | Lines |
|---|---:|---:|
| [`psy_plonky2_common_circuits/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_common_circuits/src) | 20 | 7,251 |
| [`psy_plonky2_basic_helpers/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_basic_helpers/src) | 41 | 7,912 |

### 1.5 Bridge circuit

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/bridge

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`psy_plonky2_circuits/src/bridge`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/bridge) | 11 | 4,037 | wrap / agg / claim |
| [`bridge_wrap.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_plonky2_circuits/src/bridge/circuits/bridge_wrap.rs) |  |  | wrap public inputs |
| [`bridge_agg.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_plonky2_circuits/src/bridge/circuits/bridge_agg.rs) |  |  | agg entry |
| [`bridge_agg_chain.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_plonky2_circuits/src/bridge/circuits/bridge_agg_chain.rs) |  |  | chain aggregation |
| [`bridge_agg_final.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_plonky2_circuits/src/bridge/circuits/bridge_agg_final.rs) |  |  | final Groth16-facing agg |
| [`…/gadgets/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/bridge/gadgets) |  |  | deposit/withdraw slot + checkpoint transition |

Skip any `#[cfg(test)]` modules in these files.

### 1.6 Other node circuits

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`psy_plonky2_circuits/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src) **total** | 122 | 18,341 | includes bridge 4,037 |
| [`…/guta/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/guta) | 19 | 2,722 | GUTA v1 |
| [`…/guta_v2/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/guta_v2) | 10 | 2,157 | GUTA v2 |
| [`…/coordinator/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/coordinator) | 15 | 3,260 | coordinator checkpoint circuits |
| [`…/agg/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/agg) | 5 | 677 | generic aggregation |
| [`…/gadgets/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/gadgets) | 16 | 1,665 | qdata / UPS / tag tree |

Do not audit: [`end_cap/dummy.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_plonky2_circuits/src/end_cap/dummy.rs), [`end_cap/dummy_prover.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_plonky2_circuits/src/end_cap/dummy_prover.rs).

---

## 2. Node — psy-node

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta

### 2.1 Runtime (must read)

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`psy_node_common/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_common/src) | 91 | 21,910 | coordinator + realm + planner |
| [`…/coordinator/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_common/src/coordinator) | 23 | 8,087 | edge admission, processor, roster |
| [`…/realm/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_common/src/realm) | 27 | 6,519 | edge, processor, gatherer, commit |
| [`…/guta_planner/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_common/src/guta_planner) | 6 | 3,820 | realm + coordinator GUTA plans |
| [`…/backup/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_common/src/backup) | 19 | 2,353 | checkpoint / realm backup restore |
| [`…/queue/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_common/src/queue) | 5 | 868 | EndCap gatherer |
| [`psy_node_core/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_core/src) | 107 | 24,967 | DB traits, temp DB, blob, genesis |
| [`…/psy_core_db/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_core/src/psy_core_db) | 15 | 6,924 | store traits |
| [`…/store/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_core/src/store) | 7 | 2,621 | proof store |
| [`…/qblob/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_core/src/qblob) | 14 | 3,850 | blob encoding |
| [`…/psy_temp_db/`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_core/src/psy_temp_db) | 21 | 2,182 | ephemeral proving state |
| [`parth_core/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/parth_core/src) | 109 | 16,178 | hashes, Merkle, job IDs |
| [`parth_common/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/parth_common/src) | 24 | 11,457 | memory trees, realm rotation |
| [`psy_core/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_core/src) | 26 | 4,224 | job types, circuit-type enum |

Do not audit: [`psy_data/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_data/src) (16,438) — data types.

### 2.2 Storage / API

| Path | Files | Lines | Note |
|---|---:|---:|---|
| [`psy_node_scylla/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_scylla/src) | 45 | 14,394 | durable node DB |
| [`psy_node_redis/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_redis/src) | 6 | 2,315 | queues / temp |
| [`psy_node_nats/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_node_nats/src) | 3 | 1,444 | work queues |
| [`psy_worker_core/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_worker_core/src) | 18 | 2,433 | worker loop |
| [`psy_api_core/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_api_core/src) | 8 | 597 | RPC types |

Do not audit: [`psy_cli/psy_node_cli`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_cli/psy_node_cli) (1,738), [`psy_cli/psy_worker_cli`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_cli/psy_worker_cli) (743).

### 2.3 Client proving

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`client_prover/psy_prover/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_prover/src) | 33 | 17,829 | session, local prove, traces |
| [`client_prover/psy_vm/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_vm/src) | 38 | 14,264 | DPN + UPS interpreters |
| [`client_prover/psy_core/psy_crypto/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_core/psy_crypto/src) | 57 | 11,569 | hashes, Merkle, signatures |
| [`client_prover/psy_core/psy_common/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_core/psy_common/src) | 33 | 3,952 | job IDs, felt types |
| [`client_prover/psy_core/psy_config/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_core/psy_config/src) | 2 | 1,089 | network constants |
| [`client_prover/psy_core/kvq/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_core/kvq/src) | 7 | 1,034 | KV Merkle store |
| [`client_prover/psy_provider/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_provider/src) | 9 | 6,529 | RPC provider |

Do not audit: [`client_prover/psy_core/psy_data`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_core/psy_data/src) (19,594), [`client_prover/psy_cli/psy_user_cli`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/client_prover/psy_cli/psy_user_cli) (9,340).

---

## 3. Bridge relayer — psy-node

https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_cli/psy_relayer_cli/src

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`psy_cli/psy_relayer_cli/src`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_cli/psy_relayer_cli/src) | 16 | 11,715 | Ethereum ↔ Psy bridge agent |
| [`daemon.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_cli/psy_relayer_cli/src/bridge/daemon.rs) | 1 | 4,721 | deposit/withdraw loop, scheduling |
| [`prove_bridge.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_cli/psy_relayer_cli/src/bridge/prove_bridge.rs) | 1 | 1,465 | calls bridge circuits |
| [`claim_withdrawals.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_cli/psy_relayer_cli/src/bridge/claim_withdrawals.rs) | 1 | 1,206 | Ethereum claim path |
| [`propose_withdrawals.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_cli/psy_relayer_cli/src/bridge/propose_withdrawals.rs) | 1 | 800 | Psy → Ethereum propose |
| [`regen_groth16_keystore.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_cli/psy_relayer_cli/src/bridge/regen_groth16_keystore.rs) | 1 | 767 | Groth16 key material |
| [`l1_client.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_cli/psy_relayer_cli/src/bridge/l1_client.rs) | 1 | 561 | Ethereum contract calls (filename is historical) |
| [`finalize_bridge.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_cli/psy_relayer_cli/src/bridge/finalize_bridge.rs) | 1 | 357 | finalize |
| [`main.rs`](https://github.com/PsyProtocol/psy-node/blob/mainnet-beta/psy_cli/psy_relayer_cli/src/main.rs) | 1 | 940 | process entry |
| remainder | 7 | 898 | logs, leaf, proxy, signer |

Audit together with §1.5 and §5.

---

## 4. Compiler — psy-compiler

https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta

| Path | Files | Lines | What to read |
|---|---:|---:|---|
| [`psy-sema/src`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-sema/src) | 48 | 10,419 | typecheck, rewrite, resolve |
| [`psy-interpreter/src`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-interpreter/src) | 4 | 5,288 | bytecode / exec |
| [`psy-ast/src`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-ast/src) | 47 | 2,571 | AST |
| [`psy-parser/src`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-parser/src) | 3 | 2,006 | grammar |
| [`psy-lexer/src`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-lexer/src) | 4 | 532 | lexer |
| [`psy-std`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-std) | 8 | 1,057 | Psy stdlib (`.psy`) |
| [`psy-abi/src`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-abi/src) | 3 | 860 | ABI |
| [`psy-common/src`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-common/src) | 5 | 615 | shared |
| [`psy-precompiles`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-precompiles) minus faucet | 9 | 2,979 | Psy system contracts |
| **Compiler core** | **131** | **26,327** | |

Psy precompiles (audit):

| Path | Lines |
|---|---:|
| [`psy-precompiles/token`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-precompiles/token) | 659 |
| [`psy-precompiles/usdt_token`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-precompiles/usdt_token) | 659 |
| [`psy-precompiles/withdrawal_tree`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-precompiles/withdrawal_tree) | 529 |
| [`psy-precompiles/deposit_tree`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-precompiles/deposit_tree) | 387 |
| [`psy-precompiles/mining_rewards`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-precompiles/mining_rewards) | 275 |

Do not audit: [`psy-fmt`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-fmt), [`psy-lsp-server`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-lsp-server), [`psy-wasm`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-wasm), [`psy-dargo-cli`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-dargo-cli), [`psy-package`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-package), [`psy-precompiles/faucet`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/psy-precompiles/faucet), [`tests/`](https://github.com/PsyProtocol/psy-compiler/tree/mainnet-beta/tests).

---

## 5. Ethereum contracts — psy-contracts

https://github.com/PsyProtocol/psy-contracts/tree/mainnet-beta/src

Solidity 0.8.24. Upgradeable core is OpenZeppelin v5 transparent proxy.

These contracts custody bridged funds and verify Groth16 proofs produced by the Psy bridge circuits.

### 5.1 Production

| Path | Lines | What to read |
|---|---:|---|
| [`src/Bridge.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/Bridge.sol) | 631 | deposits, wrap, rescue, gateway-only record |
| [`src/StateManager.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/StateManager.sol) | 333 | checkpoint finalize, deposit/withdraw trees |
| [`src/BridgeWrapVerifier.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/BridgeWrapVerifier.sol) | 540 | Groth16 wrap |
| [`src/DepositBatchVerifier.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/DepositBatchVerifier.sol) | 540 | Groth16 deposit batch |
| [`src/WithdrawalClaimVerifier.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/WithdrawalClaimVerifier.sol) | 540 | Groth16 claim |
| [`src/GnarkGroth16Verifier.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/GnarkGroth16Verifier.sol) | 540 | shared verifier |
| [`src/Router.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/Router.sol) | 89 | token routing |
| [`src/ETHGateway.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/ETHGateway.sol) | 94 | ETH in/out |
| [`src/ERC20Gateway.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/ERC20Gateway.sol) | 79 | ERC20 in/out |
| [`src/IncrementalMerkleTree.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/IncrementalMerkleTree.sol) | 94 | deposit/withdraw IMT |
| [`src/PsyACLManager.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/PsyACLManager.sol) | 59 | roles |
| [`src/PsyAddressesProvider.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/PsyAddressesProvider.sol) | 46 | address book |
| [`src/governance/ExecutorWithTimelock.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/governance/ExecutorWithTimelock.sol) | 143 | timelock |
| [`src/governance/IExecutorWithTimelock.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/governance/IExecutorWithTimelock.sol) | 71 | timelock iface |
| [`src/IGateway.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/IGateway.sol) | 9 | gateway iface |
| [`src/WETH9.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/WETH9.sol) | 62 | WETH |
| [`src/PsyToken.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/PsyToken.sol) | 19 | PSY token |
| [`src/USDTToken.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/USDTToken.sol) | 19 | USDT test token |
| [`src/TokenFaucetManager.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/TokenFaucetManager.sol) | 158 | faucet (non-custody, optional) |

### 5.2 Do not audit

Mocks / harness:

- [`MockERC20.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/MockERC20.sol)
- [`MockWETH.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/MockWETH.sol)
- [`MockZKVerifier.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/MockZKVerifier.sol)
- [`MockGnarkVerifier.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/MockGnarkVerifier.sol)
- [`IncrementalMerkleTreeHarness.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/IncrementalMerkleTreeHarness.sol)
- [`TestERC1967Proxy.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/TestERC1967Proxy.sol)
- [`TestTokenB.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/TestTokenB.sol)
- [`TestTransparentUpgradeableProxy.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/TestTransparentUpgradeableProxy.sol)
- [`Multicall3.sol`](https://github.com/PsyProtocol/psy-contracts/blob/mainnet-beta/src/Multicall3.sol)

Tests: [`test/foundry/`](https://github.com/PsyProtocol/psy-contracts/tree/mainnet-beta/test/foundry), [`test/hardhat/`](https://github.com/PsyProtocol/psy-contracts/tree/mainnet-beta/test/hardhat).

Optional (not consensus): [`deploy/`](https://github.com/PsyProtocol/psy-contracts/tree/mainnet-beta/deploy), [`helpers/`](https://github.com/PsyProtocol/psy-contracts/tree/mainnet-beta/helpers).

Invariants to check against the node/relayer:

- `Bridge.recordDepositFromGateway` only from Router-resolved gateway.
- `StateManager.appendDeposit` only Bridge; `finalize` only proposer.
- Verifier addresses on `StateManager` / `Bridge` match the Groth16 keys produced by [`psy_plonky2_circuits/src/bridge`](https://github.com/PsyProtocol/psy-node/tree/mainnet-beta/psy_plonky2_circuits/src/bridge).

---

## 6. How line counts and links were produced

```text
git -C <repo> ls-tree -r --name-only origin/mainnet-beta <prefix>
# keep .rs .sol .psy .ts .lalrpop
# drop tests/, test/, examples/, benches/, generated/, lib/, artifacts/,
#     cache/, typechain-types/, node_modules/, *_test.rs, *.test.ts
# line count = newline count of `git show origin/mainnet-beta:<path>`
# every URL checked: git cat-file -e origin/mainnet-beta:<path>
```

Do not treat a dirty or `feat/*` worktree as the audit corpus.

## 7. Assignment slices

| Slice | Owner-sized chunk | Lines |
|---|---|---:|
| A | Common **core**: Merkle / Poseidon / treeprover / builder | ~29k |
| B | UPS crate + network UPS + prover session | ~26k |
| C | DPN circuit + `psy_vm` | 21,377 |
| D | Node GUTA + coordinator circuits + planners | ~12k |
| E | Bridge circuits + relayer + Ethereum Bridge/StateManager/verifiers | ~20k |
| F | Coordinator/realm processors + commit/recovery | ~15k |
| G | Compiler sema + interpreter + precompiles | ~18.7k |
| H | Storage backends + remaining node | ~20k |
