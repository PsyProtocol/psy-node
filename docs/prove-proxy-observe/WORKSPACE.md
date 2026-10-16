# Prove Proxy 阻塞观测工作区 · 2026-10-16

本工作区实现第一阶段观测候选：请求关联、USER 冷构建/缓存等待、blocking executor 生命周期、独立 watchdog 与外部采样。**未部署、未重启线上服务、未修改流量或计算策略。** 不是上次故障根因的最终结论。

## 基线与隔离

| 内容 | 来源 |
|---|---|
| psy-node worktree | `psy-node/`，分支 `obs/prove-proxy-stall-20261016` |
| psy-node 基线 | `16a4a4b9bf542f80c331d3eedc14f73a0b546090` |
| plonky2-hwa worktree | `plonky2-hwa/`，detached `3b79153477d234fc4c8d2b310c83f4d41f71255a`，本次未修改 |
| 继承的 GPU lab 配置 | `../../../../evidence/gpu-baseline.patch`；4 个 Cargo 文件的既有 local-path/CUDA 配置 |
| 本次新增代码 | `psy-node/client_prover/psy_core/psy_prove_observe/` 及 Prove Proxy / circuit manager 调用点 |
| 原任务书 | `../psy-memory/issues/prove-proxy-stall-observability-20261015/AGENT-HANDOFF.md` |

已核对最新远端 `release/testnet-stable=6eb535003bdab1fcdb27386dbcb93e8aa9727998`、`multi_chain=9ae879f3691590b1b7540605a36492378b3b2461`。直接切到 stable 会丢失专用 Prove Proxy 的缓存/执行路径改进，所以采用当前专用 GPU 源码线，而非批量合入主线。

只读核对 x1：`~/gpu-lab/psy-node` 和 `~/gpu-lab/plonky2-hwa` 的 HEAD 与上述相同；运行服务的路径仍为 `/opt/parth/user-gpu-releases/20261002-8c6232b00a22/psy_user_cli`。**未读取受保护的在运行二进制完整 hash，源码目录与线上二进制逐字节对应尚未证明。** 发布前必须核实构建 manifest 和所有既有热修复。

构建用 Genesis 文件直接复制自现有 lab，不生成、不改变 gitlink：

- config.json SHA256 `4737cc8dfff772235fcb5575aa60dd57e3c7d7fcdf056fbed2ab2827fe9ff2c7`
- genesis_contracts.json SHA256 `66e9687c21b4317d549eabe6b78cbf8ab4016c26b9a9311ad5bb4816701dedc2`

## 实现范围

- 默认关闭；`PSY_PROVE_OBSERVE_DIR` 指向独占私有目录才启用。编译时 `PSY_PROVE_BUILD_ID` 记录构建标识。
- HTTP 接收/响应准备；JSON-RPC 成功/失败、响应字节数；32 位十六进制 Nginx ID 透传。批请求用独立 activity ID 区分，不记录 JSON-RPC 原始 id/参数/错误内容。
- 请求、后台 job、build 分开跟踪。job 入队与真正执行分开；RPC future 消失后，已启动 job 仍可见，不能误报“证明已停止”。
- 缓存 hit/miss、stale remove、已采集的容量数据；冷构建 owner 与同 key 的 single-flight 等待分开。没有改 cache 锁或替换缓存实现。
- 每秒 Tokio heartbeat；每 5 秒独立线程读取原子状态并写最多 16 条最老活动。全局最多 1024 活动、4096 日志队列、4×16 MiB 文件。日志满时丢记录并计数，不阻塞证明。
- 外部 `/proc` / cgroup / PSI / swap / GPU 采样；轻量 role 探针；离线按 request_id 查时间线。

## 重要边界

`cache_wait` 是 `quick_cache::get_or_insert_with` 的耗时，包含 owner 的构建，并非测得其内部互斥锁持有时间。同 key 的 build 是关联证据；不能凭此声称已精确测得“锁被某线程持有 80 秒”。缓存 key 为 contract/function 的进程内关联 hash，不包含定义版本，不是协议指纹。

StageGuard 是嵌套阶段，时间可能重叠，不可把各层耗时直接相加。`completed` 表示 closure 返回；RPC 的 `rpc_success/rpc_error` 才表示业务结果。`future_dropped` 不等于已确认网络断开；Nginx 499 和客户端记录负责补足。

HTTP `response_prepared` 只代表框架准备响应，未测量客户端收到全部字节。编码已包括在 RPC 总时长中，目前只能取得编码完成的字节数，不能独立分出编码耗时。

一个 runtime heartbeat 正常不证明全部 worker 正常。watchdog 在主机严重压力下也可能迟到；日志可能因 queue overflow/磁盘错误丢失。请同时检查外部 `observer_log_age_s`、`dropped_events`、`tracker_overflow`、`snapshot_skipped`、`state_skipped` 和 `writer_errors`。

仅新观测日志保证无参数/证明/私钥/错误正文；本补丁不清洗项目原有日志。输出目录每进程独占，不放在公开 Web 路径。

## 本地验证

```bash
cd psy-node
CARGO_BUILD_JOBS=2 cargo test --offline -p psy_prove_observe
CARGO_BUILD_JOBS=2 PSY_NETWORK=testnet cargo check --offline -p psy_prover
CARGO_BUILD_JOBS=2 PSY_NETWORK=testnet \
  ZEKNOX_LIB_DIR=/home/peter/git/bridge_zilong/prove-proxy-gpu-20261001/zeknox/native/build \
  cargo check --offline -p psy_prover --features cuda
# 纯本地中间件压力测量，不是证明性能验收：
CARGO_BUILD_JOBS=2 cargo test --offline -p psy_prove_observe http_overhead_probe -- --ignored --nocapture
cd ../tools/prove-proxy-observe
python3 -m unittest -v test_tools
```

原始结果在 `../../../../evidence/`。最终状态与尚未完成的验收见 `docs/VALIDATION.md`，使用方法及上线边界见 `docs/RUNBOOK.md`。

## 后续施工

1. 复核第一阶段代码，在生产兼容二进制上离线跑真实证明输出/性能 A/B；目前还没有 release 二进制或真实证明开销结论。
2. 若观测指向 `cache_wait`，再对 quick_cache 的实际 shard/single-flight 原语增加 wait/hold/owner 证据，不能用外围计时冒充锁计时。
3. 若指向 `proof` 内部，再接 plonky2 现有阶段/GPU lane、buffer、large-proof-slot 信息与 RPC job 关联。本次未修改 plonky2，不引入不同版本的执行策略。
4. 将经验证的配置送入现有部署分支；另行安排单后端 USER 灰度窗口。上线、探测频率和 Nginx/Caddy reload 需明确授权。

本文是隔离工作区说明快照；路径与原始证据以 `/home/peter/git/bridge_zilong/prove-proxy-observability-20261016/` 为根。仓库内工具位于 `tools/prove-proxy-observe/`；部署配置草案留在工作区 `config/`，未纳入运行时代码提交。
