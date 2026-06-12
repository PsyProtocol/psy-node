# Checkpoint State Transition Public Inputs -> Hash Chain

## Goal

将 coordinator checkpoint state transition proof 的 public input 语义升级为 hash chain：

- `step_hash_n`: 当前 checkpoint transition 的单步哈希（保留）
- `chain_hash_n`: 递归链哈希，定义为 `H(chain_hash_{n-1}, step_hash_n)`

bridge agg 后续只需消费边界 checkpoint proofs（start/end）和区间转换约束，不再依赖 checkpoint 内层 base/recursive 展开细节。

## Scope

### In Scope

- checkpoint transition circuit public input 从单步 hash 切换到 chain hash。
- recursive verify gadget 明确约束上一条 proof 的 public hash 输入参与当前链式 hash。
- coordinator witness/metadata 计算路径切到 chain hash 语义。

### Out of Scope

- bridge agg 本轮不做结构重写，仅保持兼容。
- 历史 checkpoint 数据迁移策略（单独出迁移方案）。

## Design

### Current

- 当前 public input（4 field）是：
  - `public_hash_n = H(step_hash_n, H(genesis_hash, fingerprint))`
- recursive gadget 校验上一个 proof 的 public hash 是否匹配“上一步结构化 preimage”。

### Target

- 保留 `step_hash_n` 的定义（作为局部 transition 语义）。
- 新 public input 改为：
  - `chain_hash_n = H(chain_hash_{n-1}, step_hash_n)`
- `chain_hash_0` 使用 genesis proof 的 public hash（由现有 genesis 电路产出）。

## Rollout Plan

### Phase 1 (Non-breaking scaffolding)

- 在 `psy_data::checkpoint_transition_hash` 增加链式哈希 helper：
  - `get_chain_hash_from_previous(previous_public_hash)`
- 不改变现有调用方行为。

### Phase 2 (Circuit switch)

- `checkpoint_state_transition.rs`：
  - 保持 recursive proof 验证约束不变。
  - public inputs 改为注册 `chain_hash_n`（而非旧 `public_hash_n`）。
- `recursive_checkpoint_state_transition_verify.rs`：
  - 暴露 `actual_previous_proof_public_inputs_hash` target 供主电路链式组合。

### Phase 3 (Coordinator metadata switch)

- `coordinator_output_builder.rs`:
  - `expected_public_inputs_hash` 改为链式 hash 结果。
- `QCQEDCheckpointStateTransitionInput` 增加辅助方法，支持传入 `previous_public_hash` 计算当前 expected hash。

### Phase 4 (Bridge consumption simplification, later)

- bridge agg 仅消费 checkpoint proof 边界 hash + 区间转换约束。

## Verification

- 编译：`cargo check -p psy_data -p psy_plonky2_circuits -p psy_node_common`
- 单测：checkpoint transition 相关 proving tests
- 集成：coordinator 能持续出 checkpoint transition proof，expected hash 匹配 worker 输出。

