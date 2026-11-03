# Worker PoW 接入与信誉机制交接

交接日期：2026 年 11 月 3 日。接手对象：继续实现 worker 接入防护的 agent。

**当前完成了设计和第一阶段代码，尚未完成实际任务防护。** 第一阶段实现 PoW challenge、签名、Redis 原子接入状态和独立接入 RPC；原有证明任务仍使用旧信誉规则。下一步是任务租约、主动超时回收和证明接受与发布的一致性处理。本会话没有部署这些改动，也没有启用线上接入策略。

接手时按以下顺序阅读：

1. 本文，了解实际完成范围、工作区状态和下一步任务。
2. [完整设计](./WorkerAdmissionPoW.md)，了解目标协议、状态机、故障处理和验收场景。
3. [第一阶段实现与联调说明](../../../psy_worker_admission/README.md)，了解当前代码可执行的行为。

完整设计描述目标，README 和源码描述已实现行为；不要把设计中的租约、并发限制和 outbox 当成现有功能。

## 用户目标与已确认方向

用户最初希望 worker 接入时先完成一次 PoW，取得基础信誉；作恶后信誉归零，必须重新完成 PoW 才能恢复，从而提高恶意 worker 的攻击成本。用户确认 challenge 从 edge 领取，认可完整设计，并授权开始实施。最近一次讨论明确下一阶段优先做任务租约闭环，尚未开始该阶段代码。

已确定的设计方向：

- Worker 向目标 realm 或 coordinator 的 edge 领取 challenge，由 edge 验证解答、赋予基础信誉；不是每次 TCP 重连都重新计算。
- 同一作用域的多个 edge 共用权威状态，不能通过切换 edge 绕过处罚。第一版跨 realm、跨 coordinator 分别接入和积累信誉。
- 接入作用域包含网络标识、admission epoch、节点角色、realm ID 和 sub-ID，不能按 edge URL 划分身份。
- 身份由压缩 secp256k1 公钥标识。归零时递增 generation，旧 challenge、旧任务和迟到加分不能恢复新代次的资格。
- PoW 证明付出了成本；ZK 验证、有限并发和任务租约共同限制实际损害，不能假定完成 PoW 就一定诚实。

分值和额度的设计初值是：PoW 成功恢复到 3 分；有效完成任务加 1，上限 10；普通租约超时扣 1；可归责违规直接归零；信誉 1 至 3、4 至 6、7 至 10 分别允许 1、2、4 个并发任务。除 PoW 恢复到 3 分及返回额度建议值外，任务加减分与额度执行尚未接入第一阶段。

PoW 基础难度必须显式配置，生产难度没有完成硬件基准或定值。参考 CPU 平均计算 30 至 60 秒只是设计中的候选目标，不能写成已验证的生产参数。低信誉任务池的总额度也还需要实现与压测。

## 仓库与未提交状态

实现仓库位于：

```text
/home/peter/git/bridge_zilong/psy-node
```

2026 年 11 月 3 日核对时，分支为 `feat/rollback-r1`，HEAD 为 `b958d7be`，相对 `origin/feat/rollback-r1` ahead 6。这个 HEAD 是已有 rollback 工作，不是 PoW 功能提交。本会话未为 PoW 创建 commit 或 push。

**PoW 代码仍在工作区，整个 `psy_worker_admission/` 和设计文档尚未被 Git 跟踪。** 不能只依靠 `git diff` 或从 HEAD 新建 checkout 来取得全部成果；迁移或整理提交时必须一并保留未跟踪文件。无需为了继续本任务先清空工作区。

本任务对应的改动：

| 路径 | 用途 |
| --- | --- |
| `psy_worker_admission/` | 新 crate，含协议、存储、服务、RPC、测试和 probe |
| `Cargo.toml` | 增加 workspace member 和 workspace dependency |
| `Cargo.lock` | 增加新 crate 及对应依赖引用 |
| `psy_node_common/Cargo.toml` | 引用新 crate |
| `psy_node_common/src/realm/edge/server.rs` | 可选合并接入 RPC，角色值 1 |
| `psy_node_common/src/coordinator/edge/server.rs` | 可选合并接入 RPC，角色值 2 |
| `docs/src/protocol/WorkerAdmissionPoW.md` | 完整设计与阶段进度 |
| `docs/src/protocol/WorkerAdmissionPoWHandoff.md` | 本交接记录 |
| `docs/src/SUMMARY.md` | 设计与交接入口 |

以下改动在 PoW 实施前已经存在，属于其他工作，不能重置、删除或混入 PoW 提交：

```text
M  Makefile
M  psy-dapp
?? dev/run-db-integration.sh
?? dev/run-db-integration.test.sh
?? psy_node_core/src/store/rollback_participation_report.rs
?? psy_node_scylla/src/rollback/participation_report_store.rs
```

重新接手时先执行 `git status --short --branch`，因为这份清单只是交接时快照。父目录还有大量其他 checkout；不要假定那些目录含有本任务改动。

## 第一阶段已实现内容

| 代码入口 | 已实现行为 |
| --- | --- |
| [protocol.rs](../../../psy_worker_admission/src/protocol.rs) | 固定二进制编码、SHA256 challenge 与 solution、secp256k1 请求签名、严格 hex 与 u64 十进制字符串、可取消的有界求解批次 |
| [store.rs](../../../psy_worker_admission/src/store.rs) | WorkerRecord、激活与撤销回执、状态校验、AtomicAdmissionStore 抽象 |
| [redis_store.rs](../../../psy_worker_admission/src/redis_store.rs) | Redis 服务端时间、共享请求额度、pending challenge 总容量、精确字节 CAS、策略指纹、审计 stream |
| [service.rs](../../../psy_worker_admission/src/service.rs) | 查询、签发、原子激活、最近激活回执查询、内部可归责处罚与冷却恢复 |
| [rpc.rs](../../../psy_worker_admission/src/rpc.rs) | 五个 RPC、稳定业务错误类别、默认关闭的环境配置、只允许 observe |
| [pow_probe.rs](../../../psy_worker_admission/examples/pow_probe.rs) | 对可信测试 edge 执行签名查询、领题、计算和提交；校验预期网络 |
| [协议与服务测试](../../../psy_worker_admission/tests/protocol_and_service.rs) | 编码向量、字段绑定、签名、状态机、并发与 RPC 调用 |
| [Redis 集成测试](../../../psy_worker_admission/tests/redis_integration.rs) | 独立 Redis 的并发、重启、故障、限流、容量和损坏状态测试 |

### 接口和状态

已注册的接口是：

```text
psy_worker_get_admission_info
psy_worker_get_admission_status
psy_worker_get_pow_challenge
psy_worker_submit_pow
psy_worker_get_request_status
```

未创建资格的身份查询为 0 分，查询本身不创建记录。同一身份、同一 generation 的有效 challenge 重复领取时复用原题；通过 PoW 后清除 pending challenge，原子设置 Active 和 3 分。相同成功提交重试返回原回执及当前状态，不重复激活。

`revoke_for_verified_violation` 是可信内部接口，不是公开 RPC。它接受当前代次和证据摘要，归零、递增 generation、增加违规计数并设置冷却。现有 proof handler 尚未调用它。接手时必须先建立当前租约和签名归责证据，再接入处罚，不能直接把所有旧 tag mismatch 接到这个接口。

内部状态名称为 `NeedsPow` 和 `Active`。第一次成功后 generation 仍为 0；处罚后变为 1，恢复在代次 1 内完成。历史激活回执仍可查询，但当前信誉为 0 时，历史回执不能改变当前资格。

请求方法 ID 为：状态 1、challenge 2、提交 3、回执查询 4。签名绑定完整作用域、公钥、方法、request ID、时间窗口、expected generation 和 payload hash。实际 PoW 验证绑定服务端存储的 header，不能接受客户端改写难度或恢复分数。

### Redis 实现边界

Keys 位于 `admission:{scope_hash}:...`。同作用域 keys 使用相同 hash tag。策略指纹不一致时拒绝访问，当前实现按整个作用域固定策略；尚未实现有效 challenge 跨策略版本迁移。

当前 `AtomicAdmissionStore` 只有 `request_budget`、`load` 和 `compare_exchange`。CAS 原子更新一个身份记录、pending 索引和审计事件，**不是已经实现了 worker、任务、配额和 outbox 的多记录业务事务**。下一阶段需要扩展存储接口和事务，不能把多个独立 CAS 拼起来当作原子租约结算。

未激活且无处罚的临时记录会过期；已激活和受处罚的身份保留。generation 以精确字符串或字节比较，不转换成 Lua double。Redis 时间用于授权相关期限。连接与响应有超时，故障不返回默认正信誉。

审计 stream 约保留最近 10,000 条事件，它不是持久 outbox，也不是永久审计归档。当前未自动检查 Redis 的 AOF、eviction、单写主节点或故障切换安全性。Keys 同槽也不代表 Redis Cluster 连接路由与故障转移已验证。

### 当前运行模式

默认不注册接入模块。只有设置 `PSY_WORKER_ADMISSION_MODE=observe` 才启用这五个接口；`enforce` 会拒绝启动。返回值明确包含：

```json
{"mode":"observe","task_enforcement":false}
```

Observe 在这里表示独立的接入实验与影子信誉，尚未把全部旧任务操作镜像进新状态机。`max_inflight` 目前只是按信誉计算的策略建议值，没有真实占用计数，也不会限制旧任务接口。

可选环境变量的实际必需项为：

```text
PSY_WORKER_ADMISSION_MODE=observe
PSY_WORKER_ADMISSION_NETWORK_ID
PSY_WORKER_ADMISSION_EPOCH
PSY_WORKER_ADMISSION_BASE_BITS
PSY_WORKER_ADMISSION_REDIS_URL
```

网络标识与 epoch 都为非零的 32 字节小写 hex。不要把真实 Redis URL 或私钥写进交接文档。Probe 额外使用 `PSY_WORKER_ADMISSION_PROBE_PRIVATE_KEY`；本任务没有在真实 edge 上执行该 probe，也没有启用现有部署的环境变量。

## 验证结果与复现

2026 年 10 月 26 日实现时的验证结果：

- 11 项协议与服务测试通过，含内存存储并发及进程内 RPC 调用。
- 6 项真实 Redis 集成测试通过，总计 17 项。Redis 测试默认 ignored，执行时必须显式包含。
- 新 crate 所有 target 的 Clippy 检查通过，使用 `-D warnings`。
- `cargo check -p psy_node_common` 通过，覆盖 realm 和 coordinator edge 的新 RPC 编译接入；当时有 13 条来自现有代码的 warning。
- `pow_probe` example 编译通过；没有宣称已做真实 proving 任务 E2E、线上探测或正式防护验证。

2026 年 11 月 3 日这次交接核对了源码、工作区和旧构建日志，没有重跑上述测试，也没有改变运行代码。接手 agent 应先复现基线：

```sh
cd /home/peter/git/bridge_zilong/psy-node
git status --short --branch
git ls-files --others --exclude-standard -- psy_worker_admission docs/src/protocol
export CARGO_TARGET_DIR=/tmp/psy-worker-admission-target
cargo test --offline -p psy_worker_admission --all-targets -- --include-ignored
cargo clippy --offline -p psy_worker_admission --all-targets -- -D warnings
cargo check --offline -p psy_node_common
git diff --check
```

仓库固定工具链为 `nightly-2025-09-20`。Redis 集成测试要求 PATH 中有 `redis-server`，每项测试在自己的临时目录使用 Unix socket、AOF 和 `appendfsync always`，不会连接已有 Redis。内存实现只用于测试，不是生产 fallback。`--offline` 依赖本机已有 Cargo 缓存，换机器后需要按环境规则准备依赖。

历史构建日志 `/tmp/psy-worker-admission-edge-check-final.log` 和 target 目录目前仍在，但 `/tmp` 不是交付依赖，也不能替代接手时重新验证。源码和测试才是可复现依据。

## 2026 年 11 月 3 日续接：租约状态机（第二阶段第一步）

接手 agent 先复现了第一阶段基线（17 项测试、Clippy 均通过），然后完成了本节下文要求的“第一个可交付结果”：可复现的租约状态机和真实 Redis 多记录事务测试。**仍未接入 handler、NATS 或 RPC；旧任务路径、`task_enforcement: false` 和 observe 限制都不变。** 仍未 commit。

| 改动 | 内容 |
| --- | --- |
| `src/store.rs` | `StoreKey`、`StoreIndex`、`Transaction`、`AtomicLeaseStore`：一次事务比较多条记录的精确字节、增减带上限的计数器、更新 due 与 outbox 索引 |
| `src/redis_store.rs` | `LOAD_MANY`、`COMMIT`、`RANGE` 三个脚本；`COMMIT` 在第一次写入前完成全部类型、字节比较和计数器上限检查 |
| `src/lease.rs` | `LeaseService`：`reserve_claim`、`attach_lease`、`release_claim`、`begin_verification`、`accept_verified_result`、`fail_verification`、`apply_attributable_violation`、`reconcile`、`pending_publications`、`mark_published` |
| `src/protocol.rs` | 签名方法 5（领取）和 6（提交证明）；策略增加 `task_budget` 256、`low_reputation_budget` 52、预约 30 秒、租约上限 900 秒、验证 120 秒、回执保留 1 小时（均为未压测的初值，改变了策略指纹） |
| `src/service.rs` | 抽出 `revoke` 纯转换，供处罚与超时归零共用；超时归零不增加违规次数、不设冷却 |
| `tests/lease_state_machine.rs` | 10 项内存测试，覆盖第二阶段验收表中除崩溃恢复、旧 API 旁路和 Redis 故障切换以外的场景 |
| `tests/redis_integration.rs` | 新增 5 项真实 Redis 测试：多 edge 并发领取与池额度、重启后接受与发布、并发 reconciler 只扣一次分、被拒事务零写入、接受与处罚竞争（两种顺序都实测出现） |

验证（2026-11-03）：`cargo test --offline -p psy_worker_admission --all-targets -- --include-ignored` 共 32 项通过；`cargo clippy ... -D warnings` 通过；`cargo check -p psy_node_common` 通过（13 条既有 warning）；`git diff --check` 无输出。另做了一次变异检查：去掉 Lua 计数器上限后，多 edge 领取测试失败，恢复后通过。

设计取舍：

- 额度在预约时扣，附着租约时转给租约，租约或预约关闭时按原池归还一次。处于 Reserved 的预约记录不设 TTL，否则过期会泄漏额度。
- 每身份在途计数跨 generation 累计：被处罚身份恢复后，旧代次租约回收前仍占它的额度（设计要求不能提前腾空）。
- `begin_verification` 遇到当前领取者签名的 tag 不一致只返回证据，是否调用处罚由调用方决定；过期租约的提交只返回 `LEASE_STALE`，扣分只发生在 reconciler。
- Lease 记录目前没有 TTL 或 GC；回执记录在附着后保留租约期限加 1 小时。

仍未完成（按原顺序）：V2 任务 RPC 与 realm/coordinator handler 接入、NATS progress ACK 与按投递绑定的 ACK、不可变证明暂存和发布器、验证资源信号量、服务整体故障时的超时豁免、lease 记录保留策略、Redis 持久性检查、worker 自动恢复。

## 2026 年 11 月 3 日续接（二）：任务流程接入 edge 与 worker

分支 `feat/worker-admission-pow`（从 `feat/rollback-r1` 的 `b958d7be` 拉出，仅本地，未 push）。提交按模块拆分，`git log b958d7be..` 可见。

| 提交内容 | 说明 |
| --- | --- |
| `flow.rs` | `TaskFlow`：领取、验证、接受、发布、最终 ACK 的顺序与失败处理；edge 只实现 `TaskQueue` 和 `ProofPipeline`。验证并发用信号量限制；发布失败留在 outbox，由 `maintain` 重试且不重复加分 |
| 安全开关 | `FlowConfig::attribute_invalid_proofs` 默认关闭：确定性验证失败只退回任务，不处罚。验证器失败类别未经证实前，不让验证器故障误罚诚实 worker |
| 领取签名 | V2 领取签名覆盖 worker 自己的 reward tag；绑定的 tag 不一致时拒绝 |
| 证明暂存 | 接受前把证明按内容摘要写入 admission Redis，读取时重新校验摘要 |
| NATS | `worker_queue_control_job`：progress、延迟 NAK、立即 NAK、最终 ACK。真实 nats-server 实测：ACK 作用于消息，重投后用旧投递的 reply 仍能确认；progress 能阻止重投；延迟 NAK 生效 |
| Realm 与 coordinator edge | `task_adapter.rs` 复用旧路径的输入加载、子 tag、验证与奖励树写入，不写旧 claim 和旧信誉。仅在 `PSY_WORKER_ADMISSION_MODE=observe` 且 `PSY_WORKER_ADMISSION_TASKS=v2` 时注册 `psy_worker_claim_task_v2`、`psy_worker_submit_proof_v2`，并每 5 秒运行回收、保活和发布 |
| Worker | `PSY_WORKER_TASK_PROTOCOL=v2` 时 basic fetcher 改走 V2；遇到 `POW_REQUIRED` 或 `ADMISSION_STALE` 按作用域串行完成一次 PoW 恢复。默认仍是旧协议 |

修复的两个问题：处理实例 ID 在节点里是 u128（原先按 u64 处理）；最终 ACK 是不等待确认的 publish，丢失后已发布任务的重投会被无限延迟，现在直接 ACK。

验证：`psy_worker_admission` 43 项测试（含 12 项真实 Redis），`psy_node_nats` 的 5 项真实 nats-server 测试，worker 钱包签名与 edge 校验的交叉测试，均通过；`psy_node_cli`、`psy_worker_cli` 编译通过。**尚未做真实 proving 端到端运行**：本机当前没有运行 Scylla 和 NATS，需要启动本地栈（coordinator processor、开启 V2 的 coordinator edge、`PSY_WORKER_TASK_PROTOCOL=v2` 的 worker）后验证一个 checkpoint 完整走通。

已知限制：V2 与旧协议共用同一个队列，旧 worker 领取同一任务不受租约约束，因此只能在全部 worker 都使用 V2 的隔离环境开启；租约期限固定 300 秒；lease 记录尚无 GC；enforce 模式仍不可选。

## 下一阶段任务租约闭环

优先按以下顺序实现，保持 observe 和 enforce 的边界清楚。

### 统一领取和原子预约

两个领取方法共用同一业务流程，跨 edge 原子统计身份、同域总预算和低信誉池占用。先预约额度，再取队列与依赖，最后附着唯一任务租约。没有任务、缺依赖、请求失败或 edge 崩溃时，预约可幂等释放或超时清理。

同一 request ID 重试必须返回原任务与租约，不能再取走新任务。租约绑定 scope、unique_pending_id、unique_proc_id、规范 job_id、公钥、generation、lease_id、lease_version、reward tag、任务摘要和服务端截止时间。任务 ID 不能省略 checkpoint 或 processing 实例信息。

### 主动超时回收和 NATS 重投

Worker 永不返回也要触发一次超时扣分和任务回收，不能继续依赖提交时才计算超时。普通超时扣 1，扣到 0 后撤销资格并递增 generation。

当前源码中 NATS worker ACK wait 默认 30 秒，而旧信誉完成期限是 300 秒。业务租约硬期限与消息重投计时必须分开；有效租约期间的消息保活或延迟重投不能把任务错误分配给另一人。重新分配增加 lease_version，旧 worker 迟到时返回 stale，不因新旧 tag 不同而误罚。

### 提交归责与资源限制

新增 V2 任务请求，签名覆盖任务实例、租约、generation、tag 和 proof hash。验证提交者为当前领取者后，才进入有界 ZK 验证池；相同提交只占一个验证位置。无 claim 的提交直接拒绝，不向历史 pending_id 搜索后猜测任务归属。

请求体、签名、租约或依赖错误先分类。内部存储失败和验证服务异常不能算 worker 作恶；当前领取者签名绑定的确定性无效证明才可触发内部归零接口。无效签名不能惩罚被冒用的公钥。

### 原子接受与持久发布

ZK 验证通过后先把证明写入不可变的暂存位置，再以同一事务检查当前代次和租约、设置 Accepted、加分一次、释放额度并写持久 outbox。

发布器根据已接受事件，幂等写 canonical proof、奖励树和依赖队列；全部持久发布后才最终 ACK。不能在最终代次校验前先修改奖励树，也不能把 Redis、证明存储和 NATS 当成具有跨系统事务。

归零先于最终接受时，旧证明不能加分或发布；接受先于归零时，已经接受的有效结果仍可发布，但处罚后的当前信誉保持 0。重复请求、重投和发布重试都不能重复加分或发奖。ACK 必须受持久接受结果约束，不能通过 job 对应的可覆盖 ACK 地址误确认另一次投递。

### 后续 worker 和正式启用

任务闭环之后再把自动 PoW 恢复接到现有 proving worker；当前 standalone probe 不等于真实 worker 已自动恢复。最后补齐存储持久性与 failover 检查、硬件难度基准、版本迁移和全入口审计，才允许增加 enforce。

正式启用前必须确保旧领取、旧提交、不带 child proofs 的入口和未升级 edge 都不能成为旁路。PoW 模块默认关闭和 observe 的限制应保留到闭环验收完成。本次交接请求没有要求上线、重启或修改生产配置。

## 下一阶段主要代码入口

| 路径 | 接手用途 |
| --- | --- |
| [Realm worker handler](../../../psy_node_common/src/realm/edge/worker_handler.rs) | 合并领取流程、租约校验、证明提交和发布路径 |
| [Coordinator worker handler](../../../psy_node_common/src/coordinator/edge/worker_handler.rs) | 与 realm 保持一致的租约和提交行为 |
| [旧 worker RPC](../../../psy_api_core/src/worker/standard_worker_rpc.rs) | 新增 V2 方法，保持 canonical response 的版本兼容 |
| [任务响应结构](../../../psy_data/src/worker/api_response.rs) | V2 包装租约信息，避免直接改变旧结构的二进制编码 |
| [NATS 队列](../../../psy_node_nats/src/queue.rs) | 领取、重投、progress 和完成 ACK 的归属处理 |
| [NATS 配置](../../../psy_node_nats/src/psy_queue.rs) | ACK wait 与 consumer 行为 |
| [任务队列抽象](../../../psy_node_core/src/queue/worker_queue.rs) | 扩展投递回执和租约所需操作 |
| [旧信誉存储](../../../psy_node_core/src/psy_temp_db/v3_implementation/core.rs) | 旧默认 5 分和 claim 的兼容处理 |
| [旧信誉更新](../../../psy_node_common/src/reputation/worker_reputation_ops.rs) | 迁移完成与处罚的非原子读写 |
| [原 worker fetcher](../../../psy_worker_core/src/api/basic_job_fetcher.rs) | 后续接 V2、按作用域复用资格、自动恢复与重试 |

旧代码中的主要问题仍未修复：新公钥默认 5 分；旧领取只检查信誉大于 0；信誉更新先读后写；超时扣分依赖实际提交；Realm 两个领取入口的 claim 写入不一致；证明提交没有新协议的完整租约绑定。阅读 handler 时注意其中保留了注释掉的旧实现，修改实际生效的方法。

## 第二阶段验收标准

| 场景 | 必须达到的结果 |
| --- | --- |
| 多 edge 并发领取与重复 request ID | 每个身份和池额度不超限，同一请求只领一次 |
| Worker 领取后退出或永不返回 | 到期回收、只扣一次分，最终需重新 PoW |
| NATS 提前重投但业务租约有效 | 领取者与 tag 不被覆盖，不误罚正常 worker |
| 任务重分配后旧 worker 提交 | stale，不加分、不重复扣分、不误 ACK |
| 验证期间信誉被归零或已恢复到新代次 | 旧任务不能接受、加分或恢复新资格 |
| 冒用他人 lease 或篡改未签名的 proof 参数 | 拒绝，不处罚被冒用公钥 |
| 验证服务或存储内部失败 | 不作为 worker 确定性无效证明处罚 |
| 同一证明重复、并发提交 | 一次验证占用、一次结算、一次奖励 |
| 预约、返回、暂存、接受、发布、ACK 前后崩溃 | 可恢复，不永久丢任务，不重复加分和发奖 |
| 大量新身份同时领取 | 受低信誉池总额度约束 |
| Redis 状态丢失、回滚或故障切换 | 不恢复默认正信誉，不确定连续性时先停止授权并按设计轮换 epoch |
| 旧 API 和未升级 edge | 正式强制模式没有接入旁路 |

接手的第一个可交付结果应是可复现的租约状态机和真实 Redis 多记录事务测试，再逐步连接队列与 proof handler；不要只把 `task_enforcement` 改成 true，或直接放开配置中的 enforce。
