# 本地验证记录 · 2026-10-16

此记录验证第一阶段观测代码，不是线上事故复现，也不是候选上线批准。

| 项目 | 结果 | 证据 |
|---|---|---|
| Observer 回归 | 11 passed，1 个性能探针默认 ignored | `evidence/observer-tests.log` |
| 外部工具 | 3 passed | `evidence/tools-tests.log` |
| Prove Proxy 核心库 CPU 检查 | `cargo check --offline -p psy_prover` 通过 | `evidence/cargo-check.log` |
| Prove Proxy 核心库 CUDA 检查 | `--features cuda` 通过，编译 CUDA，不执行 GPU workload | `evidence/cargo-check-cuda.log` |
| 源码 whitespace | `git diff --check` 通过 | 本工作区 |
| plonky2-hwa | 无本次改动 | detached `3b791534` |
| Lockfile | 没有依赖版本漂移；新增本地 observer 包及引用，继承的四个 plonky2 path 来源变化 | `Cargo.lock` diff |

## 已覆盖故障场景

- JSON-RPC 单请求、batch、空 batch、通知、非法条目、response-size-limit，与未安装中间件的同版本 jsonrpsee 输出逐字节相同。
- 传入参数、RPC id、错误消息/data 中的测试秘密不进入新日志；请求头关联 ID 验证。
- 使用真实 `quick_cache::sync::Cache` 模拟冷构建：能同时看到 owner/build 和同 key waiter，另一个 key 仍可前进。
- blocking executor 单 worker 饱和时显示 executor_queue，释放后才转 proof。
- RPC task abort 后后台 job 仍被跟踪，能看到 rpc_waiter_gone；释放 job 后无残留。
- 构建 panic 后 context 恢复，job/build tracker 清理；未改变 panic 传播。
- 当前线程 Tokio runtime 阻塞 5.6s，独立 watchdog 在其恢复之前已经写出 heartbeat 老化和 circuit_build 活动。
- 跟踪容量耗尽、日志队列满，均不阻塞或拒绝应用请求；溢出计数可见。
- 固定文件大小/数量轮转和 JSON 完整性。
- `/proc` PID 身份、采样速率、0600 日志权限、role 探针请求和隐私、离线过滤。

测试曾发现真实观测缺陷：阶段更新使用 try_lock 时，watchdog 的读取可能让一次更新被跳过。已改为原子字段+版本一致性快照；读者不阻塞/占用 writer 状态锁。并发 writer（不应把同一 activity 跨独立任务复用）会被计入 state_skipped；子 job 使用独立 activity。

## 开销与日志量：仅中间件探针

Debug 模式、本机 loopback、真实 jsonrpsee/HTTP、8 并发，work 返回固定值，包含一个 blocking job 和模拟 build。所有结果均正确。

无限速 2000 请求，ABBA：

| 开关 | 总时间 ms | dropped_events |
|---|---:|---:|
| off | 307.8 | — |
| on | 471.9 | 14,660 |
| on | 585.0 | 11,930 |
| off | 390.5 | — |

这是几千请求/秒的极短请求冲击，暴露 debug JSON 编码/写盘的开销和背压上限。不可宣称开销为零或把此百分比套用到证明时间。满队列时保持活性，**不保证所有慢/错误日志完整**；必须检查 dropped_events。

按约 40 请求/秒定速，每轮 400 请求，ABBA：

| 开关 | 总时间 ms | 日志字节 | 丢失/跟踪溢出 |
|---|---:|---:|---:|
| off | 10,056.6 | 0 | — |
| on | 10,056.3 | 1,390,322 | 0 / 0 |
| on | 10,059.2 | 1,390,285 | 0 / 0 |
| off | 10,060.4 | 0 | — |

末尾 inflight=0，writer_errors=0。约 3.5 KB/request；此 mock 负载下默认 64 MiB 总日志容量约保留 8 分钟。真实请求的 stage 数不同，保留时间须重测。定速等待主导总时间，**此表只能验证该速率下日志可持续写入，不能证明没有性能影响**。

原始证据：`middleware-overhead-debug.log`、`middleware-paced-debug.log`。测试使用较小轮转上限，突发测试 retained_bytes 已发生轮转，不能当总日志生成量。

## 尚未完成的任务书验收

1. 部署基线完整 binary hash / release manifest 审核，特别是 live 8c6232b0 与最新 lab HEAD 的差异。现在线上源码目录的 HEAD 不代表该 binary 的构建输入。
2. release CLI 构建、真实证明 CPU/GPU byte gate、同机交替性能/延迟/RSS A/B，及 WASM target 编译。当前通过的是核心库 check，不是已链接的发布二进制。
3. 大上传/慢读者 socket 场景，以及真实 Caddy→Nginx→backend 全链路关联；框架 encoding 独立计时还没实现。
4. quick_cache 内部锁 wait/hold/owner、驱逐/代际事件；当前只覆盖外围 single-flight 与 stale remove。
5. GPU lane/buffer、large-proof-slot 等内部 admission 与 RPC job 的关联；当前证明内部显示整体 proof，不能区分这些等待。
6. 更完整的固定标签计数/直方图导出。现有 JSON watchdog 是阶段直方图/活动快照，不是新的 Prometheus 服务；executor queue_ms、RPC 结果等仍需离线聚合。
7. 原监控 inventory 修复、磁盘延迟派生、Caddy logging 版本核查、Nginx 模板验证和轮转集成。未改生产配置。
8. 首版已完成不同模型逐行审阅并本地提交 `2f155713`，未推送或部署。阶段二验证见 [PHASE2.md](PHASE2.md)。

## 当前可支持的结论

观测路径可以在本地把“RPC 变慢”进一步拆成 executor_queue、cold build、single-flight wait、proof 或 runtime heartbeat 停滞，并保留后台任务持续执行的事实。

源码确认注册/解析的冷构建仍可能同步占用 async runtime worker。这是优先调查的风险，不是已经证明的 2026-10-15 故障根因。第一阶段数据若落到 cache_wait/proof，再针对内部资源增加下一层观测；不能提前改调度来掩盖故障。
