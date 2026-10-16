# 阶段二：证明内部阶段与资源等待

开销来源、已有测量的适用范围和后续 release A/B 记录见 [OVERHEAD.md](OVERHEAD.md)。

首版已提交 `psy-node 2f155713e39eff838adb945ede33f554c834b5c7`，未推送或部署。本阶段继续在同一个隔离工作区，`plonky2-hwa` 分支为 `obs/prove-proxy-stages-20261016`，基线 `3b79153477d234fc4c8d2b310c83f4d41f71255a`。

两个仓库的本阶段改动需要配套使用：psy-node 的本地 `[patch]` 已指向旁边的 plonky2-hwa；不能只取 psy-node 的 hooks feature 而继续使用没有 hook API 的旧 plonky2。仍然是本地候选，不是新的远端依赖 pin 或生产 release。

## 实现

plonky2 增加可选、线程局部的同步 phase hook。没有安装 hook 时不创建日志、读时钟或分配 guard。Observer 在已有 blocking job/build context 中安装 hook；结束或 panic 时恢复前一个 hook。不存在新增全局锁或修改 proving 算法/slot 数量/GPU lane 策略。

新增固定阶段：

| 阶段 | 观测含义 |
|---|---|
| witness | 生成 witness，包含主线程等待 Rayon 的时间 |
| wires_commit / zs_commit / quotient_commit | 现有对应 commitment 外层 |
| partial_products / quotient / openings / fri | 对应证明阶段的调用方墙钟时间 |
| large_proof_wait | 大证明限流器的互斥获取和条件变量等待 |
| large_proof_held | 槽位持有期；permit 归还后才记录结束 |
| gpu_buffer_wait | GPU output set 池 acquire 等待 |
| gpu_lane_wait | commitment 选择/获取 lane 的等待；可能是主 lane mutex 或额外 lane 条件等待 |
| gpu_lane_held | commitment 从取得 lane 到归还 lane 的持有期 |
| gpu_device | 原有 GPU run 调用，包括提交/传输/同步等，不是纯 kernel 时间 |
| gpu_rebuild | 主机侧 rebuild |
| gpu_quotient_wait / gpu_fri_wait | 现有对应主状态 mutex 获取位置 |

审阅补强：取得 permit 后先构造 RAII guard，再结束等待 span/调用持有 span 的回调。即使回调或等待 span 析构 panic，也归还 permit、清除线程 HELD；GPU lane guard 也先于其观测 span 析构，正常和 unwind 路径顺序一致。

这些阶段通过同一 activity/request_id 进入现有有界日志与独立 watchdog。所有嵌套耗时有重叠，不能相加当作总耗时。持有期在内部阶段执行时会被当前更细的阶段覆盖，使用 begin/end 事件补充 owner 的持有区间。

限制：

- 没有给额外 GPU lane 新增稳定编号，也没有把某个 lane waiter 精确关联到某个 holder。不能由“GPU lane wait”直接宣称持有者是谁。
- 没有把 RPC context 传播到独立 Rayon worker；主线程 phase 仍覆盖等待 Rayon 的时间，不声称能定位每个 worker 的内层任务。
- quick_cache 内部锁持有者、shard、eviction、定义版本仍待补；既有 cache_wait 的解释不变。
- 此阶段 hooks 只在 native Observer context 安装；WASM 不引入 native observer 依赖。

## 测试

工作区 `evidence/` 保存原始日志：

- `phase2-tests.log`：12 项 Observer/HTTP/生命周期测试通过；3 个独立性能/证明/slot fixture 默认忽略。
- `phase2-proof-equivalence.log`：真实小电路，未观测 CPU proof 与观测 CPU proof 字节相同，两份都验证通过。使用标准 recursion config，测试进程单独启用 deterministic random/PoW，GPU=0；不是 569 请求生产回放。
- `phase2-slot-contention.log`：真实 `proof_gate::acquire`，1 个槽位；owner 显示 held、waiter 显示 wait，放行后清理为 0。
- `phase2-hook-unit.log`：从实际源文件直接编译 observation/proof_gate 两个无外部依赖模块，4 项测试通过（线程隔离、嵌套/panic、现有槽位并发上限、观测回调/析构 panic 后归还 permit 并恢复线程状态）。由于 plonky2 是 workspace 外的 path dependency，不能直接在 psy-node 内 `cargo test -p plonky2`；用 `evidence/hook-test-harness.rs` 引用真实文件编译，未复制或替换模块实现。
- `phase2-tools-tests.log`：4 项 Python 测试通过。探针现在要求 curl_exit=0 且 HTTP 200 且 RPC role 合法，避免完整 JSON 与传输失败并存时误报健康。
- `phase2-cpu-check.log` / `phase2-cuda-check.log`：核心库 CPU/CUDA check。
- `phase2-wasm-check.log`：共享 `psy_ups_circuit` 的 wasm32-unknown-unknown check。

从 psy-node 根目录运行：

```bash
CARGO_BUILD_JOBS=2 cargo test --offline -p psy_prove_observe --features plonky2-hooks
PLONKY2_GPU=0 PLONKY2_POW_DETERMINISTIC=1 PLONKY2_DETERMINISTIC_RANDOM=1 \
  CARGO_BUILD_JOBS=2 cargo test --offline -p psy_prove_observe --features plonky2-hooks \
  real_proof_observation_equivalence -- --ignored --nocapture
PLONKY2_LARGE_PROOF_SLOTS=1 PLONKY2_LARGE_PROOF_MIN_DEGREE_BITS=16 \
  CARGO_BUILD_JOBS=2 cargo test --offline -p psy_prove_observe --features plonky2-hooks \
  real_large_proof_slot_wait_is_visible -- --ignored --nocapture
CARGO_BUILD_JOBS=2 PSY_NETWORK=testnet cargo check --offline -p psy_prover
CARGO_BUILD_JOBS=2 PSY_NETWORK=testnet \
  ZEKNOX_LIB_DIR=/home/peter/git/bridge_zilong/prove-proxy-gpu-20261001/zeknox/native/build \
  cargo check --offline -p psy_prover --features cuda
CARGO_BUILD_JOBS=2 PSY_NETWORK=testnet cargo check --offline -p psy_ups_circuit --target wasm32-unknown-unknown
(cd tools/prove-proxy-observe && python3 -m unittest -v test_tools)
```

## 下一个验收门槛

实际部署 binary/source/热修复核对 → release USER CLI 完整链接 → 生产请求离线 CPU/GPU 等价回放 → 相同负载的开销/日志/RSS A/B → 另行安排单 backend 灰度。没有执行显卡负载、生产探针或上线动作。小电路一致性和库级 check 不能替代这几个门槛。

还需覆盖大上传、慢读者和完整 ingress 关联，并对原 collector inventory 拒绝进行单独修复。本次没有认定 10 月 15 日故障的具体根因。
