# Internal: Fn-Circuit Fingerprint and Uninitialized-Contract Proving Playbook

> Internal — NOT published to mdBook (dev/ section, no SUMMARY registration).
> Last updated: 2026-09-06
> Repositories: `psy-node`, `psy-compiler`, `psy-genesis`
> 触发背景: audit 分支纯节点 Plonky2 E2E，faucet claim 三层故障链 + EndCap proposer 验证失败

## Overview

本文记录 2026-09-06 E2E 中 faucet claim / EndCap 提交的三层故障链、每层的根因证据、修复方法、验证命令，以及纯节点 devnet 的实测运行时长。任何人对 `DapenContractFunctionCircuit`、UPS 签名电路、或 `UPSEndCapCircuit` 约束做变更前，必须先读本文与 `docs/src/node/circuit-and-verifier-operations.md`。

## 1. 第一层：未初始化合约的 ZERO 叶子 vs 空树根（电路约定缺口）

**症状**: prove-proxy 报 `Partition containing VirtualTarget { index: N } was set twice with different values: <zero_hash_literal> != 0`（如 `8603459983426387388 != 0`，该字面量 = `CACHED_ZERO_HASHES[31]`，高度 31 合约的空树根，可逐位比对确认）。

**根因**: operator 首次调用某合约时，该合约在用户合约树（UCON）中从未初始化，叶子值 = `ZERO`；但 session 侧 `get_call_start_data` 对未初始化合约返回 `get_zero_hash(state_tree_height)`（`psy_core/psy_data/src/qstore/controllers/proving_session.rs:621-641`）。任何把 UCON 叶子值与合约存储起始根无条件 `connect_hashes` 的电路都会在首次调用时 witness 冲突。

**约定**（UPS 层早已有注释佐证，`psy_network_circuit/src/ups/gadgets/ups_standard_cfc_state_delta.rs:193-230`）: `is_zero_hash(leaf_value)` 为真时，起始 root 必须绑定到该合约编译期高度的默认空树根，否则精确相等。

**修复模式**（对每个触点，共 4 处）:

```rust
let default_root = builder.constant_hash(<H as MerkleZeroHasher<_>>::get_zero_hash(contract_state_tree_height));
let is_first = builder.is_zero_hash(<leaf_value_target>);
builder.connect_hashes_switch(is_first, <start_root_target>, default_root, <leaf_value_target>);
```

| 触点 | 文件 |
|---|---|
| DPN fn_circuit 起始合约根 | `psy_dpn_circuit/src/vm/compile.rs`（`get_self_user_current_contract_state_slot_hash` 路径） |
| UPS 签名电路 current | `psy_ups_circuit/src/signature/state_reader.rs:102` |
| UPS 签名电路 external | 同文件 :237（`get_self_user_external_contract_state_slot_hash`，`slot_proof.root <- uct_proof.value`） |
| UPS 签名电路 other-user | 同文件 :385（`get_other_user_contract_state_slot_hash`，同模式） |

**定位方法**（VT-index map，决定性而非猜测）: 复刻电路构造过程，记录每个 `connect_hashes`/`connect` 的 target index，把报错的 `VirtualTarget index N` 映射回 gadget。参考 `psy_network_circuit/src/ups/circuits/ups_cfc_standard.rs` 中 `vt626_index_map` 测试（cfg(test) 诊断工具）。

**验证**: `cargo test --release -p psy_dpn_circuit`（ucon_leaf_prove_tests：未初始化 prove、已初始化行为不变、负向对照复现 set-twice）。

## 2. 第二层：函数树 whitelist 指纹失配（VT626，两个非零值）

**症状**: `ups_cfc_standard_tx proving error: Partition containing VirtualTarget { index: 626 } was set twice: 7671487131530644792 != 4162245137908165195`（两值均非零）。

**根因**: 合约函数树的 whitelist 叶子 = fn_circuit 的 plonky2 电路指纹（`psy_prover/src/session/session.rs:181` `whitelist_leaves.push(c.get_fingerprint())`，与 `(method_id, io_combo)` 叶子交错）。函数树是链上状态（`CONTRACT_FUNCTION_TREE_ID=4`，锚定在 `PsyContractLeaf.function_tree_root`）；genesis 合约的 whitelist 在 genesis 生成时按**当时的电路约束**烘进 genesis.json。任何 `DapenContractFunctionCircuit` 约束变更（包括第一层的修复本身）都会改变所有 fn_circuit 指纹 → 链上旧指纹 ≠ 运行时新电路 attest 指纹 → `ups_cfc_verify_inclusion.rs:87` 等式冲突。

**这是设计行为**：指纹绑定保证只有链上登记过的电路才能执行。代价 = 每次改 fn_circuit 约束必须走完整再生成链（见 §4）。

**区分诊断**：第一层错误值命中 zero-hash 表；第二层两值均非零（新旧指纹 limb）。用 VT-index map 定位冲突目标是 copy-connect 的哪一侧（本例：VT626 = 函数树叶子，VT297-300 = attest 指纹，`connect_hashes(fn_fp, attest_fp)`）。

## 3. 第三层：EndCap proposer 验证失败（Verifier Artifact Boundary）

**症状**: EndCap forward 被 proposer 拒绝，真实错误（非 schedule 拒绝）: `Condition failed: vanishing_polys_zeta[i] == z_h_zeta * reduce_with_powers(...)`。

**根因**: DPN / UPS 电路变更改变了 EndCap 电路形状 → 用户二进制生成的新 EndCap proof 与 proposer 端**promoted 的** `END_CAP_ALT_VERIFIER_DATA_SERIALIZED`（旧常量）不匹配。触发 `AGENTS.md` End-Cap Verifier Artifact Boundary + 文档 §3.1 第一行（EndCap metadata: Yes，cache pair: Yes，Genesis outputs: No）。

**修复序列**（完整命令见 `docs/src/node/circuit-and-verifier-operations.md` §4-§5）:

1. `PSY_CONFIG_PATH=<repo>/psy-genesis/config.json PSY_NETWORK=localhost cargo run --release -p psy_user_cli --no-default-features -- get-user-end-cap-common-data`（四个输出记录来自同一次成功调用；magic 与 config.json 数值比较，不等即停）
2. `alt_verify_data` 逐字复制进 `psy_plonky2_circuits/src/circuit_library/end_cap_verifier_data.rs:27`；`endcap_fingerprint_u64x4` 四 limb 按打印顺序逐字复制进 localhost 常量（**注意位置在 `psy_core/src/network_config/local_devnet.rs:17`，不在 verifier data 文件里**——易漏点）
3. `RUST_MIN_STACK=134217728 cargo run --release -p psy_plonky2_circuits --example config_gen_v2 --no-default-features --features std,serialize_rkyv,serialize_speedy,serialize_postcard`
4. 同命令再跑一次，两个 generated 文件须双 "up to date"（稳定性环）
5. `make build` + `make shutdown` + `PSY_SKIP_BUILD=1 PSY_SKIP_BRANCH_CHECK=1 PSY_SKIP_KEYSTORE=1 RUST_LOG=info make run-all`
6. 重新注册 → faucet（应仍过）→ 重交 EndCap

**禁**: `make config_gen_v2` / 缺 `--no-default-features`（默认 features 含 gnark-wrap，会动 Groth16 setup）。

**不触发**: genesis 再生成、token privacy fingerprints（`private_note_inclusion`/`shield_claim`）、Groth16/Bridge cohorts（bridge_agg 仅在其消费的电路形状变化时）。

## 4. fn_circuit 约束变更的完整再生成链（node → compiler → genesis）

1. 提交 psy-node 电路交付，记录 SHA（R_node）
2. `../psy-compiler/Cargo.toml`：注释 remote rev pins（:31-41），启用本地 path 依赖（:44-54）——本地 dev 的正规机制，无需 push
3. compiler: `cargo` 重生成 Cargo.lock → `make check && make build`
4. `make gen-deploy-json` → 产出含新指纹的 genesis.json + token.json
5. 校验两个 compiler-artifact 戳（`../psy-sdk/psy-ts-sdk/packages/psy-sdk/.compiler-artifact.json` 与 `psy-genesis/.genesis_contracts.compiler-artifact.json` 的 `compilerRevision`）
6. `make shutdown` → 安装新 genesis.json → launcher 重跑 setup（`injectGenesisValidators`，**确认 validators 数组非空再启动 processors**）→ `run-all`
7. 重新注册 → faucet → transfer

**禁**: 手改 genesis.json 指纹；为 pinned rev 加 [patch]/[replace]。

## 5. 实测运行时长参考（16 核 9950X，纯节点 2 realms 栈）

| 事项 | 实测 | 备注 |
|---|---|---|
| prove-proxy 预热（9999 监听前） | **~5-10 分钟** | 构建 UPS 电路管理器 + 合约函数电路注册 + BatchDeployContracts ~8000 行大电路；与 4 个 realm processor 电路预热并发时被拉长。9999 出现即就绪，随后 9998 (faucet) 起动 |
| psy-node 全量 release build | ~4-4.5 分钟 | `make build` 含全部 CLI |
| compiler 本地 path release build | ~2m16s | 切换 pin 后首次全量编译 |
| `make gen-deploy-json`（genesis 再生成） | 分钟级 | 产出 782MB genesis.json |
| config_gen_v2 cache 单跑 | ~1.5 分钟 | 稳定性环需两跑 |
| coordinator 出快节奏（空 checkpoint） | ~5-8 秒/个 | 全新链几分钟可推进上百个 checkpoint |
| 全新链 validators 注入 | 每次重启后必须 | genesis.json 的 validators 字段由 launcher 注入，重启后为 `[]` 直到注入完成 |

## 6. 排查顺序速查

1. `PartitionWitness set twice` → 先比对错误字面量是否命中 `CACHED_ZERO_HASHES`（第一层）还是两个非零值（第二层/第三层）
2. 第二层 → 用 VT-index map 测试定位 connect 对侧，判断是函数树叶子还是 attest 指纹
3. 第三层（vanishing_polys）→ 检查 promoted EndCap metadata 是否早于当前电路源码
4. 任何电路约束变更 → 先过 §3.1 触发矩阵，再按需走 §4 再生成链或 §3 promote 序列
5. 改动 fn_circuit 后**必须同时改** `session.rs` 无关但受指纹影响的下游（genesis whitelist），不可只改电路


## Related documents

- `psy-node: docs/src/node/circuit-and-verifier-operations.md` — EndCap metadata promote 权威流程（§4 生成/§4.3 promote/§5 cache 稳定性环）
- `psy-node: docs/src/node/token-privacy-circuit-fingerprints.md` — 触发矩阵 §3.3 的独立流程
- [common errors](common-errors.md) — 通用错误速查