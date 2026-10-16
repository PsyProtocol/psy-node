# 运行与证据解读

以下命令均从 psy-node 仓库根目录执行。阶段二覆盖和当前测试状态见 [PHASE2.md](PHASE2.md)。

## 开启候选（仅离线 / 已批准的灰度）

在启动候选前设置 `PSY_PROVE_OBSERVE_DIR`，每进程使用独立目录。确保服务运行用户可写、目录 0700。默认不设置时没有诊断文件/后台线程。设置有误会使启动失败，不会悄悄把错误当成健康。

不要对正在运行的线上 PID 注入配置。本工作区只准备代码和模板，不提供自动重启脚本。

## 只读资源采样

```bash
python3 tools/prove-proxy-observe/observe_resources.py --pid <PID> --samples 720 --interval 5 \
  --gpu --diagnostic-dir <DIAG_DIR> --output <PRIVATE_DIR>/resources.jsonl
```

PID 身份由 `/proc/PID/stat` 的启动 tick 校验；退出或 PID 重用即停止。单次任务有上限，日志 4×4 MiB。无权限指标为 null/缺失，不解释成零。GPU 是整卡数据，PSI/swap 是主机/明确的 cgroup 数据，不能归因到单个请求。diskstats 是累计原始计数，尚未转换成磁盘 await；没有 IO 延迟直方图。交换分区占用不等于发生 swap IO。

对发生故障的 interval 对齐 epoch 时间，并检查 CPU 使用核数、major fault/s、swap pages/s、memory/io PSI、cgroup memory.events、采集输出间隔。不要只看 RSS。

## 轻量探针

```bash
python3 tools/prove-proxy-observe/probe_role.py --url <APPROVED_ENDPOINT> --label backend-x1 \
  --samples 6 --interval 10 --output <PRIVATE_DIR>/probe.jsonl
```

同一进程串行请求；每目标最多一条在途，无重试，curl 总超时 3s，记录连续失败 >=3 的证据，**不触发重启或切流**。只请求 `psy_get_prove_proxy_role`，`X-Psy-Probe: role-readiness` 标记负载。默认拒绝 URL 用户名/密码/query/fragment。HTTP 200 和 JSON-RPC 结果分别判定。

在公共入口、WireGuard LB、真实 backend 分别启动时，须先确认拓扑与允许频率。不要把本地测试授权理解为可以直接向线上启动持续探针。捕获 curl DNS/connect/TLS/TTFB/total 为累计分段时间；remote_ip 可能只是 gateway，实际 upstream 仍看 Nginx。

## 定位一个请求

1. Nginx 日志先找 request_id、upstream 地址、返回状态。完成时间减 request_time 找开始时间，查询完整重叠区间。
2. 把目标进程 events 文件拷到私有分析目录：

```bash
python3 tools/prove-proxy-observe/trace_request.py --request-id <ID> <DIR>/events.*.jsonl
```

3. 用 `instance + id` 关联；batch 中 `request_id` 相同但 RPC activity id 不同，job/build 通过 parent_id 关联。
4. executor_queue 长：还没有开始执行。cache_wait 长且同 key 出现 build：可能在等待该构建；区分 owner，并排除同 key 不同定义版本。circuit_build 长：正在构建；RPC 直接持有 build 且 heartbeat 同时老化是运行时受阻的证据。proof 长：只定位到 blocking closure，需下一层观测。
5. rpc_waiter_gone=true 而 job 还在：调用方 future 已结束，计算仍存活；不代表取消计算成功。还要对照 Nginx。
6. RPC 快速完成但 upstream 长：继续看 HTTP body/网络/encoding 与 gateway；不能直接把差值视为网络耗时。
7. 无活动不代表健康：同时检查 tracker overflow、snapshot skipped、采样间隔和日志写入是否中断。单次 watchdog 只展示最老 16 项，inflight 是已跟踪 activity 数（含 request/job/build），不是唯一请求数。

## 候选上线与回滚边界

- 配置片段在 `config/`，均是人工审核模板，不是安装脚本。Nginx/Caddy 必须先查当前版本、已有配置，保留现有 upstream、timeout、retry、流量权重。
- 一次只更换一个 USER backend；SYSTEM 不随之重启。不在本任务中发布 SDK、Genesis 或改电路。
- 上线前：记录部署二进制 hash、两仓 source revision + dirty patch hash、Genesis artifact hash、构建 target/features、与实际部署 hotfix 清单差异；不同模型审核、真实离线回放、release A/B 开销和日志量验收。
- 记录旧二进制和原 drop-in。移除仅本次新增的诊断 drop-in 并恢复旧 ExecStart 后，只有经授权才执行 daemon-reload/restart。不能删除现有 drop-in 或清理 keys/circuits。
- 日志只滚动自身固定文件；不改全局 journald、不清理其他目录。磁盘余量告警建议 <10% 或日志 30s 未更新（仅启用且进程存活时），观察后调整。4×16 MiB 是容量上限，保留时间取决于真实请求量；验收前不能承诺全天保留。
- x1/x3 原 collector inventory 拒绝问题尚未修复。临时采样结果不能代表原监控管线恢复。
