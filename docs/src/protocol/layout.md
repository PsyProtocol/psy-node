# 规范状态布局（Canonical State Layout）

本文档描述 PSY 合约部署（deploy）和更新（update）流程中使用的**规范状态布局**设计。该设计将合约存储从“无认证的扁平 slot 空间”转变为“带类型的、Merkle 承诺的、append-only 数据结构”。

---

## 1. 设计动机

旧版 V1 合约叶子 `PQEDContractLeafLegacy` 只承诺了以下内容：

- `deployer`
- `function_tree_root`
- `code_root`
- `state_tree_height`

这带来了两个问题：

1. **存储 slot 与 ABI 类型之间没有绑定。** VM 可以直接读写原始 slot，而无需证明该访问符合合约声明的状态结构。
2. **合约升级不安全。** 更新时可以静默修改已部署 storage slot 的含义，或删除/重排字段而不被协议察觉。

V2 合约叶子通过承诺一棵**规范布局树**来解决这些问题。该树的叶子描述 `ContractState` 的每个直接字段：其占用的物理 slot 范围、类型布局 hash 和编码版本。

---

## 2. Field 与 Slot

- **Field（字段）**：`ContractState` 顶层结构体的一个直接成员。
- **Slot（槽）**：一个物理 felt 大小的存储单元。

示例：

```text
owner    : slot [0, 1)     // 1 个 slot
account  : slot [1, 3)     // struct，2 个 slots
flags    : slot [3, 5)     // [Bool; 2]
balances : slot [5, 12)    // Map，3 padding + 4 payload
epoch    : slot [12, 13)   // 1 个 slot

field_count = 5
slot_count  = 13
```

布局规则：

- 字段按声明顺序排列。
- `field_id = field_index + 1`（从 1 开始）。
- 下一个字段的 `start_slot` 等于前一个字段的 `start_slot + slot_count`。
- 对于固定容量的 `Map`，对齐 padding 归该 `Map` 字段所有，因此全局 slot 边界保持无空洞。

---

## 3. 核心数据结构

### 3.1 `CanonicalLayoutManifest`

Manifest 是本地布局证明器的编译器无关输入，将 ABI 解析与证明过程解耦。

```rust
pub struct CanonicalLayoutManifest<Hash> {
    pub layout_version: u16,
    pub state_tree_height: u16,
    pub layout: CanonicalContractStateLayout<Hash>,
    pub field_type_dags: Vec<CanonicalTypeLayoutDag>,
}
```

*位置：* `psy_data/src/v1/qdata/contract/layout.rs:841`

### 3.2 `CanonicalContractStateLayout`

```rust
pub struct CanonicalContractStateLayout<Hash> {
    pub contract_layout: ContractStateLayout<Hash>,
    pub field_type_layouts: Vec<StateTypeLayoutWitness<Hash>>,
    pub struct_layouts: BTreeMap<String, StructTypeLayout<Hash>>,
}
```

*位置：* `psy_data/src/v1/qdata/contract/layout.rs:828`

### 3.3 `ContractStateLayout`

顶层状态布局的承诺摘要。

```rust
pub struct ContractStateLayout<Hash> {
    pub fields: Vec<StateFieldLayoutLeaf<Hash>>,
    pub state_layout_root: Hash,
    pub state_layout_field_count: u64,
    pub state_layout_slot_count: u64,
}
```

*位置：* `psy_data/src/v1/qdata/contract/layout.rs:820`

### 3.4 `StateFieldLayoutLeaf`

顶层状态布局树的叶子。

```rust
pub struct StateFieldLayoutLeaf<Hash> {
    pub field_id: u64,
    pub start_slot: u64,
    pub payload_offset: u64,
    pub slot_count: u64,
    pub type_layout_hash: Hash,
    pub encoding_version: u16,
}
```

*位置：* `psy_data/src/v1/qdata/contract/layout.rs:659`

### 3.5 `CanonicalTypeLayoutDag`

每个顶层字段被表达为一个大小受限的小 DAG，以便协议使用固定 verifier 验证类型证明。

```rust
pub struct CanonicalTypeLayoutDag {
    pub nodes: Vec<CanonicalTypeLayoutNode>,
    pub root: u16,
}

pub enum CanonicalTypeLayoutNode {
    Primitive { type_tag: StatePrimitiveTypeTag },
    FixedArray { element: u16, length: u64 },
    FixedMap { map_kind, key, value, capacity, alignment_slots },
    Struct { members: Vec<u16>, members_tree_height: u8 },
}
```

*位置：* `psy_data/src/v1/qdata/contract/layout.rs:308`

---

## 4. 树结构

### 4.1 顶层状态布局树

- 固定高度 `STATE_LAYOUT_TREE_HEIGHT = 6`，因此最多支持 `2^6 = 64` 个顶层字段。
- 叶子 `i` 保存字段 `i` 对应的 `StateFieldLayoutLeaf`。
- 有效字段在左侧连续排列；空叶子填充 `HashOut::ZERO`。

### 4.2 结构体成员树

- 固定高度 `CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT = 5`，因此每个 struct 最多支持 32 个成员。
- 成员以 `StructMemberLayout` 叶子形式存储。

### 4.3 Hash 规则

- 字段叶子使用 domain `STATE_FIELD_LAYOUT_DOMAIN` 进行 hash。
- Struct 类型 hash 绑定 `member_count`、`total_slot_count`、`members_root` 和 encoding version。

---

## 5. Deploy 的布局证明

Deploy 证明是从空树到初始合约布局的递归布局转移。由于真实 `contract_id` 由 coordinator 分配，deploy proof 使用保留 id：

```rust
pub const STATE_LAYOUT_DEPLOY_CONTRACT_ID: u64 = 0;
```

本地布局管理器（`psy_plonky2_circuits/src/coordinator/state_layout_helper.rs:275`）证明以下内容：

1. `manifest.layout_version == STATE_LAYOUT_VERSION`。
2. 布局能够放入 `state_tree_height` 的容量范围内。
3. 每个顶层字段都有合法的 canonical type proof。
4. 字段从空叶子开始，通过 Spiderman 严格追加。
5. Field ID 和 slot 范围连续。
6. 最终的 `state_layout_root`、`field_count` 和 `slot_count` 与 manifest 一致。
7. 多个 Spiderman window 被递归聚合，并包裹一层 canonical wrapper 电路。

最终产物为 `LocalInitialLayoutProof`：

```rust
pub struct LocalInitialLayoutProof<F> {
    pub layout: CanonicalContractStateLayout<QHashOut<F>>,
    pub canonical_verifier_fingerprint: QHashOut<F>,
    pub canonical_layout_proof: Vec<u8>,
}
```

该产物被附加到 `QBCDeployContract`
（`client_prover/psy_core/psy_data/src/qblock/cmds/deploy_contract.rs:71`）。

---

## 6. Update 的布局证明

Update 证明针对特定真实 `contract_id`，从旧 manifest 到新 manifest 的严格 append-only 转移。

本地布局管理器（`psy_plonky2_circuits/src/coordinator/state_layout_helper.rs:545`）证明：

1. `contract_id != 0`。
2. `state_tree_height` 不变。
3. 新布局的字段前缀与旧布局完全一致。
4. 仅追加了一段连续的新字段后缀。
5. 可以从旧字段叶子复现旧 root。
6. 新字段通过 Spiderman 追加，并具有合法的 type proof。
7. Slot/frontier 和容量约束满足。
8. 最终 canonical proof 绑定旧/新布局端点。

客户端兼容性预检位于 `client_prover/psy_prover/src/session/compile_bridge.rs:209`：

```rust
new_contract_output
    .abi
    .validate_layout_update_from(&old_contract_output.abi)?;
```

共识 adapter 强制前缀相等：

```rust
anyhow::ensure!(
    new_layout.contract_layout.fields[..old_count]
        == old_layout.contract_layout.fields,
    "existing layout fields were modified or reordered"
);
```

*位置：* `psy_data/src/v1/qdata/contract/layout.rs:584`

最终 proof 被存入 `QBCUpdateContract`
（`client_prover/psy_core/psy_data/src/qblock/cmds/deploy_contract.rs:172`）。

---

## 7. 升级兼容性

兼容性在三个层级被强制执行：

| 层级 | 位置 | 检查内容 |
|---|---|---|
| 客户端 ABI 校验 | `compile_bridge.rs:224` | `validate_layout_update_from` |
| 共识 adapter | `layout.rs:2426` | `state_tree_height` 不变；新字段数 ≥ 旧字段数；`new.fields[..old] == old.fields[..old]`；slot 数只增不减 |
| 电路约束 | `state_layout.rs:1094`、`batch_update_contract_v2.rs:141` | 旧/新 leaf 的 layout root、field/slot count、deployer、`state_tree_height` 匹配；容量检查 |

修改已有字段会改变其叶子 hash，从而破坏 adapter 中的前缀相等检查，以及电路中 Spiderman “旧非零叶子不可变”的检查。

---

## 8. Append-Only 语义

Append-only 意味着：

- **允许：** 在末尾追加新的顶层字段；纯代码更新使用 identity transition。
- **禁止：** 删除或重排字段；修改已有字段的 start/slot/type/encoding；修改 struct 定义；产生 slot 空洞；超过容量。

Spiderman append 使用 strict 模式（`add_virtual_to`），要求：

- 旧非零叶子保持不变。
- 新叶子只能替换零叶子。
- 追加内容在窗口内连续。
- 一旦旧/新叶子都为零，后续所有叶子必须为零。

Slot frontier 通过将第一个追加字段的 `start_slot` 连接为 `old_layout_slot_count`，并将后续每个字段连接为 `prev_start + prev_slot_count` 来强制。

在聚合多个 window 时，连续性被强制：

```text
left.new_layout_root        == right.old_layout_root
left.new_layout_field_count == right.old_layout_field_count
left.new_layout_slot_count  == right.old_layout_slot_count
```

---

## 9. 电路验证

### 9.1 Type proof

每个追加字段都携带一个 canonical recursive type proof。基础类型电路包括：

- `PrimitiveTypeLayoutCircuit`
- `FixedArrayTypeLayoutCircuit`
- `FixedMapTypeLayoutCircuit`
- `StructTypeLayoutCircuit`

它们暴露统一的 public input 接口：

```rust
pub struct TypeLayoutProofPublicInputs<Hash> {
    pub type_layout_hash: Hash,
    pub total_slot_count: u64,
}
```

异构 type proof 通过 `CanonicalTypeLayoutWrapperCircuit` 归一化，使得 append 电路只需一个固定 verifier。

### 9.2 Append 电路

`StateLayoutAppendCircuit` 对每个 web 位置验证：

- Canonical type proof 合法。
- 重算的 field leaf hash 与 Spiderman new leaf 一致。
- `field_id`、encoding、`start_slot`、`slot_count`、`payload_offset` 一致。
- 有序追加字段的 commitment 计算正确。

### 9.3 聚合电路

`StateLayoutAppendAggregateCircuit` 递归验证两个子证明并聚合它们的 public input。

### 9.4 Canonical wrapper

`CanonicalStateLayoutAppendWrapperCircuit` 将所有聚合深度归一化为一个统一的 verifier data endpoint，并检查 inner verifier fingerprint 在白名单中。

### 9.5 Batch deploy 电路

`BatchDeployContractsCircuit` 验证：

- Contract tree 的 Spiderman append。
- 每个新 V2 contract leaf 与其位置匹配。
- 每个新 leaf 携带的 layout proof：`old_layout_root` 是规范空 root，`old_layout_field_count` 和 `old_layout_slot_count` 为 0，`contract_id` 为 0。
- 状态容量不超限。

### 9.6 Batch update 电路

`BatchUpdateContractsCircuit` 验证：

- Contract tree 的 Spiderman update（允许覆盖以支持纯代码变更）。
- 旧/新 V2 leaf preimage 与 proof 匹配。
- Layout proof 端点与旧/新 leaf 的 layout 字段匹配。
- Deployer 和 state tree height 保持不变。

---

## 10. Verifier Fingerprint

`canonical_layout_verifier_fingerprint` 是 canonical layout wrapper 电路的密码学身份，由 plonky2 verifier-only 数据派生：

```rust
self.canonical_layout_append.get_fingerprint()
```

*位置：* `psy_plonky2_circuits/src/coordinator/state_layout_helper.rs:539`

它被存储在 deploy/update 命令中，与 proof 一起提交：

```rust
pub struct QBCDeployContract<F> {
    ...
    pub canonical_layout_verifier_fingerprint: QHashOut<F>,
    pub canonical_layout_proof: Vec<u8>,
}
```

Wrapper 电路强制只接受白名单中的 verifier data：

```rust
let actual_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_target);
...
builder.connect(allowed_fingerprint, one);
```

这防止恶意 prover 使用另一个 public input 形状相同但 verifier 不同的电路伪造 layout proof。本地管理器还按 fingerprint 缓存 proof（`client_prover/psy_prover/src/session/compile_bridge.rs:83`），因此使用错误 verifier 数据缓存的 proof 会在命令校验阶段被拒绝。

---

## 11. 关键常量

| 常量 | 值 | 位置 |
|---|---|---|
| `STATE_LAYOUT_VERSION` | `1` | `psy_data/src/v1/qdata/contract/layout.rs:22` |
| `STATE_LAYOUT_ENCODING_VERSION` | `1` | `psy_data/src/v1/qdata/contract/layout.rs:23` |
| `STATE_LAYOUT_DEPLOY_CONTRACT_ID` | `0` | `psy_data/src/v1/qdata/contract/layout.rs:28` |
| `STATE_LAYOUT_TREE_HEIGHT` | `6`（64 个字段） | `psy_core/src/constants/protocol.rs:92` |
| `STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT` | `2`（4 字段窗口） | `psy_core/src/constants/protocol.rs:97` |
| `STATE_LAYOUT_MAX_AGGREGATION_DEPTH` | `2` | `psy_core/src/constants/protocol.rs:99` |
| `STATE_LAYOUT_MAX_PROOF_BYTES` | `16 MiB` | `psy_core/src/constants/protocol.rs:102` |
| `STATE_LAYOUT_MAX_BATCH_ITEMS` | `2` | `psy_core/src/constants/protocol.rs:104` |
| `GLOBAL_CONTRACT_TREE_HEIGHT` | `24` | `psy_data/src/network_constants.rs:7` |
| `MAX_CONTRACT_STATE_TREE_HEIGHT` | `32` | `psy_data/src/network_constants.rs:16` |

---

## 12. 总结

规范状态布局将合约存储从“无认证的扁平 slot 空间”转变为“带类型的、Merkle 承诺的、append-only 数据结构”。Deploy 证明从空树到初始布局；Update 证明严格的 append-only 转移。兼容性由 ABI 校验器、本地 layout adapter 和递归电路三层保证。Verifier fingerprint 确保只有协议批准的 wrapper circuit 才能验证这些 proof。
