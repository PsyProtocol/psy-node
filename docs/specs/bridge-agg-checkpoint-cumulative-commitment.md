# Bridge Agg + Checkpoint Cumulative Commitment — Implementation Spec

## Spec Goal

把 checkpoint state transition proof 的公开语义从“单步 transition hash”升级为“从 genesis 到当前 checkpoint 的 **hash chain cumulative commitment**”，并让 bridge agg 在 batch finalize 场景下采用 **仅验证 end checkpoint proof** + 区间 steps fold 约束，避免逐个验证中间大量 checkpoint proofs。

目标是：

1. 保持现有递归验证安全性（fingerprint/genesis anchor 不丢）。
2. 让 bridge agg 复杂度从 `O(num_checkpoints)` proofs 验证收敛到“边界 proof + 区间 fold”。
3. 不破坏现有 coordinator/worker 的 expected public input 校验路径。

## Scope and Success Criteria

### In Scope

- 修改 checkpoint transition circuit public input 语义为 cumulative commitment。
- 修改 coordinator 输出 expected public inputs hash 计算逻辑对齐新语义。
- 修改 bridge agg **final** 电路以消费 cumulative commitment（边界证明 + 区间 fold，`<=32`）。
- 补充必要的测试与日志验证路径。

### Out of Scope

- 不修改 bridge wrap/groth16 wrapper 的外部接口格式（除非必须随 PI 变化调整）。
- 不改业务层 deposit/withdraw 状态机。
- 不做历史已上链 proofs 的兼容迁移方案（另开迁移 spec）。
- 不实现 bridge agg 新递归聚合层（未来再做“每段 32 checkpoints 的 bridge-agg 递归”）。

### Success Criteria

| Area | Check | Target |
|---|---|---|
| Checkpoint PI | transition proof 输出 `chain_i` | `cargo test/check` 通过，PI 长度保持 4 felts |
| Coordinator | expected_public_inputs_hash 与 prover 实际输出一致 | 无 mismatch，job 正常完成 |
| Bridge Agg | batch finalize 可在只验 end proof 下完成区间约束 | 支持 `end-start <= 32` 且不需逐 proof verify |
| Security | 无中间 preimage 伪造窗口 | 必须有 fold 等式 + checkpoint_id 连续性约束 |

## Repositories and Branches

| Repo | Branch | Required? | Purpose | URL |
|---|---|---|---|---|
| `local/parth-generic-v1` | `feat/shield-poseidon-bridge` | Yes | 主实现仓，电路+coordinator+bridge 改动 | local filesystem |
| `local/memory` | `master` | No | 文档参考（已有 bridge 设计说明） | local filesystem |

### Repository Relationships

| From Repo | To Repo | Relationship Type | What Flows / Depends On | Notes |
|---|---|---|---|---|
| `parth-generic-v1` | `parth-generic-v1` | consumes | `psy_data` 类型定义被 `psy_plonky2_circuits` / `psy_node_common` / bridge circuits 共同依赖 | 单仓多 crate 联动 |
| `memory` | `parth-generic-v1` | verifies | 设计文档用于实现校对 | 只读参考 |

## Environment and Resources

| Item | Value | Required? | Notes |
|---|---|---|---|
| Working Directory | `parth-generic-v1/` | Yes | 主改动目录 |
| Toolchain | `cargo`, `rg`, `bun` | Yes | 编译与检索 |
| Dependent Services | coordinator/worker 本地进程 | No | 仅做集成 smoke 时需要 |
| Resource Budget | >= 8 CPU / 16GB RAM | Yes | 电路编译+check 较重 |

## Starting Point

| Repo | Branch | Start Commit | Local Path | Working Tree State | Notes |
|---|---|---|---|---|---|
| `local/parth-generic-v1` | `feat/shield-poseidon-bridge` | current HEAD | `.` | dirty allowed | 仅本 spec 涉及文件精确提交 |

## Roles

| Role | Typical Agent | Responsibility |
|---|---|---|
| Operator | codex | 实现、验证、提交 |
| Human Reviewer | human | 方案与结果验收 |

## Technical Design

### Current Public Input (Checkpoint Transition)

当前 `CheckpointStateTransitionPublicInputs` 的 hash 为：

`H(step_transition_hash(old/new roots + old/new leafs), H(genesis_hash, fingerprint))`

该值只直接承诺“当前一步”，历史连续性依赖递归中对 previous proof 的单步重算。

### Target Public Input (Hash Chain Cumulative)

定义：

1. `step_i = H(checkpoint_tree_root_i, checkpoint_leaf_hash_i, checkpoint_transition_fingerprint)`
2. `chain_0 = H(genesis_checkpoint_tree_root, genesis_checkpoint_leaf_hash)`
3. `chain_i = H(chain_{i-1}, step_i)`（**必须是 hash chain**）
4. 最终 public input：
   `public_i = chain_i`（4 felts）

说明（强约束）：

- fingerprint 绑定进入 `step_i`，并由 verifier-data fingerprint 约束保证其真实性。
- cumulative 语义进入 PI，bridge 只需验证边界承诺。
- 本 spec 明确禁止“仅单步 transition hash + 外部 preimages”作为最终安全模型。

### Bridge Agg Target (End-Proof-Only)

bridge agg 在 batch finalize 中：

1. 验证 `end_checkpoint_transition_proof`（含 fingerprint 约束）。
2. 从 end proof 获取 `chain_end`（PI 直接是 chain）。
3. 输入 `chain_start`（作为用户提供的起点承诺，不做 start proof 验证）。
4. 输入 `[start+1, end]` 区间 steps preimages，在电路中做 hash-chain fold：
   - `h_0 = chain_start`
   - `step_k = H(checkpoint_tree_root_k, checkpoint_leaf_hash_k, checkpoint_transition_fingerprint)`
   - `h_k = H(h_{k-1}, step_k)`
   - 约束 `h_last == chain_end`
5. 本版不做 checkpoint_id/old-new 连续性约束（最简版）。

### Fixed Capacity and Padding (MAX_STEPS = 32)

为控制电路规模，本方案固定单次 bridge range fold 容量：

- `MAX_STEPS_PER_PROOF = 32`

输入增加：

- `active_len`（`0 <= active_len <= 32`）
- `steps[32]`（固定长度数组）

约束规则：

1. 对 `i < active_len`：
   - 执行真实 step fold：`h_{i+1} = H(h_i, step_i)`
2. 对 `i >= active_len`：
   - 使用 no-op padding：`h_{i+1} = h_i`（条件选择保持 `h` 不变）
3. 末尾约束：
   - `h_32 == chain_end`

工程建议：

- 若区间步数 `N > 32`，本版不处理（后续再引入分段/递归聚合）。
- 若 `N < 32`，通过 `active_len` + padding 统一电路形状。

语义边界：

- 本方案证明“从输入的 `chain_start` 到已验证 `chain_end` 存在一条有效区间链”。
- 本方案不证明 `chain_start` 本身来源于链上已验证 start proof（这是明确取舍）。

### Bridge Agg PI Compatibility (Hard Constraint)

bridge agg proof 的 public inputs **不得改变**（长度、顺序、语义全部保持现状），因为最终唯一消费方是 `psy_contracts` 的 `StateManager` 路径。

本次改动仅允许：

- 修改 bridge agg 电路内部约束（新增 hash-chain fold 验证逻辑）
- 修改内部 witness 结构/私有输入
- 仅使用 `bridge_agg_final` 作为执行路径

本次改动禁止：

- 增删/重排 bridge agg public inputs
- 把 `start_chain/end_chain` 替换进原有 onchain 公开输入位
- 在本阶段继续依赖 `bridge_agg_base` / `bridge_agg_recursive` 参与主流程

### Canonical Sources (Must)

为避免多口径，以下来源在本 spec 中固定：

1. `previous_chain_hash`（checkpoint transition 递推输入）的 canonical source：
   - **电路内**：始终来自 `previous_checkpoint_state_transition_proof.public_inputs`（4 felts）。
   - **coordinator expected PI 计算**：始终来自 `CoordinatorProcessorLastCommittedState.last_chain_hash`（持久化缓存）。

2. `chain_end`（bridge agg 终点承诺）的 canonical source：
   - 始终来自 `end_checkpoint_transition_proof.public_inputs`（4 felts）。

## Implementation Tasks

### Task 1 — Data Model Helpers

Files:

- `psy_data/src/protocol/checkpoint_transition_hash.rs`
- `psy_data/src/protocol/circuit_inputs/checkpoint_transition.rs`

Changes:

- 增加 `step_i` 计算函数。
- 增加 `chain_i_from_previous` 计算函数。
- 增加用于 coordinator 的 expected PI 计算函数（基于 previous proof public hash）。

### Task 2 — Checkpoint Transition Circuit

Files:

- `psy_plonky2_circuits/src/coordinator/gadgets/recursive_checkpoint_state_transition_verify.rs`
- `psy_plonky2_circuits/src/coordinator/circuits/checkpoint_state_transition.rs`
- `psy_plonky2_circuits/src/coordinator/gadgets/checkpoint_state_transition.rs`

Changes:

- recursive gadget 暴露 previous proof 的 public hash target（作为 `chain_{i-1}`）。
- 主电路改为计算 `step_i` 并 fold 到 `chain_i`。
- register public inputs 为 `chain_i`（4 felts）。

### Task 3 — Coordinator Expected PI Alignment

Files:

- `psy_node_common/src/backup/output/coordinator_output_builder.rs`
- （必要时）`psy_node_common/src/coordinator/processor/core/process_block.rs`
- `psy_node_common/src/coordinator/processor/db.rs`

Changes:

- `expected_public_inputs_hash` 从旧单步语义改为 `chain_i` 语义。
- `CoordinatorProcessorLastCommittedState` 新增 `last_chain_hash` 字段，并在 commit 后更新。
- 保证 worker handler 校验路径无需改字段长度。

### Task 4 — Bridge Agg Circuits (End-Proof-Only)

Files:

- `psy_plonky2_circuits/src/bridge/gadgets/verify_checkpoint_state_transition.rs`
- `psy_plonky2_circuits/src/bridge/circuits/bridge_agg_final.rs`
- `psy_plonky2_circuits/src/bridge/circuits/bridge_agg.rs`（构建/调用路径裁剪）
- （必要时）`psy_plonky2_circuits/src/bridge/mod.rs`、helper 路由文件

Changes:

- 解释 checkpoint proof PI 为 `chain_i`（仅 end proof 验证）。
- 添加区间 steps fold gadget 约束（或内联实现），并接收 `chain_start` 输入。
- 实现固定容量 `MAX_STEPS_PER_PROOF=32` 与 `active_len`/padding 约束。
- bridge agg 公共输出布局保持现状（完全兼容 StateManager）。
- 本阶段移除/停用 `bridge_agg_base` 与 `bridge_agg_recursive` 在主执行路径中的引用。

### Task 5 — Tests and Smoke

Minimum checks:

- `cargo check -p psy_data`
- `cargo check -p psy_plonky2_circuits`
- `cargo check -p psy_node_common`
- checkpoint transition proving test（若已有）通过
- bridge agg base/recursive/final 相关测试通过

Optional integration:

- 本地 coordinator 跑一个 `end-start <= 32` 的 batch finalize smoke，确认无中间 proof 依赖（仅 end proof + range preimages）。

## Deletion / Deactivation Plan (Bridge Agg Base & Recursive)

本阶段目标是降低实现复杂度，避免多路径并存：

1. 先在构建路径中断开 `bridge_agg_base` / `bridge_agg_recursive` 的调用入口。
2. 若无编译依赖阻塞，则删除对应源文件；若有共享类型依赖，则先保留文件但不可达并标注 `TODO(remove in next cleanup commit)`。
3. 所有 bridge agg 相关命令/入口统一指向 `bridge_agg_final`。

验收：

- 全仓编译通过
- 不存在运行时分支会落到 base/recursive
- final 仍产出原有 StateManager 可消费 PI

## Risks and Mitigations

1. **Risk**: PI 语义变化导致现有 verifier/wrapper 预期不一致  
   **Mitigation**: 保持 PI 仍为单 hash（4 felts），仅改变 preimage 语义。

2. **Risk**: Bridge agg 区间 hash-chain fold witness 过大
   **Mitigation**: 先做线性版本验证正确性，再评估二叉 fold/分段聚合优化。

3. **Risk**: 历史 proofs 不兼容  
   **Mitigation**: 本 spec 仅定义新语义，不处理历史迁移；单独 migration spec。

## Verification Plan

1. Unit-level:
   - 对同一组 step 序列，`cum_commit` 在 data helper 与 circuit 计算一致。
2. Circuit-level:
   - 错误的中间 step preimage 必须导致 bridge agg 约束失败。
   - `fold(chain_start, steps[0..active_len]) != chain_end` 必须失败。
3. Processor-level:
   - `expected_public_inputs_hash` 与实际 proof PI 一致，不出现 job reject。

## Final Explanation Requirement

实现完成后必须报告：

1. 改动的每个文件与目的。
2. cumulative commitment 的确切公式（代码位置）。
3. bridge agg 如何使用 start/end commitment + range fold。
4. 验证命令与结果。
5. 未覆盖风险（若有）。
