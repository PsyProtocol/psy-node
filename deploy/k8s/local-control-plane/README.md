# 本机控制面 + x2/x3/x4 工作节点（2026-10-16）

这是根据用户 2026-10-16 决定新建的独立目录，取代原三机六 VM 方案作为下一轮
本地实验的设计方向。用户已确认施工，并要求所有宿主机 sudo 步骤由本人执行。
[host-setup](host-setup/README.md) 提供对应管理员安装、网络/回退与新盘准备脚本；
`../platform/` 已发布脚本仍针对三机六 VM，尚不能直接执行来得到此新拓扑。
本轮仍不迁移或停止线上业务、不改动 x1、不自动重启任何机器。

## 物理布局

| 位置 | 新实验职责 | 起步 VM 候选资源 | 系统存储池可用空间门槛 |
| --- | --- | --- | --- |
| 本机 arch3900x | 单 K3s 控制 VM，taint 阻止普通业务调度 | 4 vCPU / 8 GiB / 60 GiB OS | 76 GiB |
| x2 | 一个业务工作 VM | 4 vCPU / 8 GiB / 40 GiB OS | 56 GiB |
| x3 | 一个业务工作 VM，后续重点承载证明 | 6 vCPU / 12 GiB / 40 GiB OS | 56 GiB |
| x4 | 一个业务工作 VM，优先承载持久化数据 | 8 vCPU / 20 GiB / 40 GiB OS，另 256 GiB 数据盘 | OS 56 GiB，新盘池 288 GiB |
| x1 | 继续承接线上业务，不加入实验集群 | 无 | 无 |

总计四个 Kubernetes 节点、48 GiB VM 内存预算。每个物理机还需额外预留内存。
这是平台起步档，不能声称装下完整桥接和高并发 System Proxy。完整业务的工作 VM
资源必须另按冷启动、峰值 RSS、CPU 和磁盘测量扩容。

本机只读观测：Ryzen 9 5900XT、约 125 GiB RAM、当前约 51 GiB MemAvailable、
根盘约 250 GiB 可用；本机地址为 192.168.5.20，**不是为控制 VM 预留的新 IP**。
本机当前无 /dev/kvm，CPU 暴露 flags 未见 svm，virsh/qemu-img/cloud-localds 未安装。
VM 方案须先确认虚拟化支持和配置，不能据 CPU 型号宣称 KVM 已可用。本轮不更改
BIOS、内核模块、软件包、宿主网桥或已有服务。重启后的只读预检已完成：三台有 KVM，
但尚缺 libvirt/QEMU/cloud-localds，x3 仍约 40 GiB 可用，x4 尚未看到新增盘。
x3 磁盘由用户处理。x2/x3/x4 仍有 Proxy 等旧服务在运行，脚本不自动停止它们。

## 独立运行目录

本机准备目录：`/home/peter/git/bridge_zilong/k8s-local-control-plane/`。

```text
config/        # 本地 inventory、实验 kubeconfig；不进 Git
vm/            # 控制 VM 的独立 qcow2 磁盘池；不进 Git
bundles/       # 每次生成的新部署包，不覆盖上次输出
backups/       # 控制面备份的本地暂存；必须另有异机副本
evidence/      # 只读预检和验收记录
```

初始目录私有；安装 libvirt 后，只给 QEMU 访问 VM 池所必需的遍历/读写权限，
config 与备份凭据继续受限。不使用 /tmp 存持久数据。源码脚本继续统一放在 deploy/k8s。

## 控制面与数据面

本机负责 Kubernetes API、调度和集群对象状态。业务请求、数据库连接、证明任务
在 x2/x3/x4 之间直接通信，正常请求不绕行本机控制面。
先按一个 server 的实验集群设计；即便采用单成员 embedded etcd，也不具备控制面 HA。
本机离线会失去调度、扩缩容和管理能力；已有工作负载可能继续提供部分服务，但依赖
API 的控制器、服务发现更新和故障恢复受限，不能承诺业务完全不受影响。
这一版本没有控制面 kube-vip 的故障切换收益，优先用控制 VM 的固定地址作为 API 入口。
应用入口仍用 MetalLB + 三副本 Traefik。

## Pod 与数据库

以下是完整实验业务目标，沿用已调研的 27 个业务 Pod，并非首次安装即全部启动：

| 业务 | Pod 数 | 说明 |
| --- | ---: | --- |
| Coordinator/Realm0/Realm1 Processor + 对应 Indexer | 3 | 各 Pod 两个容器，共享必要恢复文件；生命周期待验证 |
| 三类 Edge | 3 | 初期各 1，后续验证共享状态与去重后扩容 |
| 三类 Worker | 3 | 初期低并发；验证停止领取和在途提交 |
| User Proxy / System Proxy | 2 | 分开配额，System 需要更大内存预算 |
| 三类提交网关 | 3 | 方法级业务策略，不由 HTTP 路由代替 |
| Services / Faucet / Relayer / Envio / Hasura / Nostr / Anvil / 静态前端 | 8 | 各 1，使用独立实验配置与身份 |
| PostgreSQL | 2 | Services 和 Envio 分开实例与 PVC |
| Scylla / Valkey / NATS | 3 | 各 1、各有独立持久化目录 |
| 合计 | 27 | 不包含入口、DNS、监控或一次性 Job |

平台还需 CoreDNS、metrics-server、MetalLB、Traefik、Prometheus、Grafana、
Alertmanager、Operator、kube-state-metrics、每节点 node-exporter。新拓扑的
node-exporter 期望 4 份，不再使用旧 6 份验收；不部署旧 Collector/Controller。
blackbox 与镜像仓库如加装要单独计数，准确 Pod 数以新模板与现场验收为准。

Services PostgreSQL 和 Envio PostgreSQL 初期保持两套，避免把 schema/迁移耦合
合并。Processor 的实际 Scylla/Valkey/NATS 依赖按角色冻结；不能给每个程序全库权限。
Kubernetes 自身的集群状态数据库与上述业务数据库分开，控制面备份不等于业务备份。

## 通信与隔离

Pod 是运行单元，Service 是稳定内部入口，PVC 是持久存储申请。业务通过
`postgres-services.psy-data.svc.cluster.local:5432` 等 Service DNS 访问数据库，
不用易变的 Pod IP；跨物理机访问仍走容器网络。x4 承载 DB Pod 和本地数据卷，
其他主机通过数据库协议读写，不共享并发挂载数据库底层文件。

| 分区 | 规划内容 | 通信权限候选 |
| --- | --- | --- |
| psy-platform | Traefik 等入口 | 仅到明确公开的 API/Edge/前端端口 |
| psy-app | Services、Envio、Hasura、前端等 | 仅到各自所需 API/DB/实验 L1 |
| psy-chain | Processor、Edge、对应 Indexer | 按角色到指定状态库/队列 |
| psy-compute | Workers、证明 Proxy | 指定任务接口/证明接口；不授予全库访问 |
| psy-data | 两个 PG、Scylla、Valkey、NATS 等 | 仅允许明确的来源 Pod 与端口 |
| psy-observe | 监控 | 仅需要的 metrics/探测端口及最小 API 读取权限 |

Namespace 只做归属分组，不自动阻止互访。实际隔离依靠受支持的 NetworkPolicy，
逐命名空间默认拒绝入站/出站，再按依赖放行 DNS、监控、控制面必需通信和业务端口。
来源用 namespace + Pod label 组合约束，并实际测试允许与拒绝路径；不是只让 YAML
存在。数据库用 ClusterIP，不开公网、NodePort 或 LAN LoadBalancer。
ClusterIP 本身不阻止宿主机/特权节点访问；还需节点防火墙、数据库认证和最小权限。

数据库按应用创建账户，Secret 只挂给需要的 Pod；限制 ServiceAccount/RBAC，
API 权限与数据库权限分开。配置文件不包含生产钱包、生产 DB 凭据或生产连接串。
CPU/内存 requests/limits 与业务并发一起配置，单副本 Processor/Relayer 不盲目 HPA。
容器共享节点内核，不能当成 VM 级或不可信租户的安全边界。

DB Pod 经 PVC 使用 x4 本地 PV，Pod 重建可复用同一卷，x4 故障时不会自动得到
一套数据副本。先接受并验证数据单点，备份必须到另一台机器；数据库复制、高可用、
跨节点存储是后续独立工作。Kubernetes 重建 Pod 不能代替数据库复制或应用 fencing。

## 施工前的具体变更

1. 人执行 host-setup 的管理员步骤，解决本机 KVM 前提与地址/网桥，普通用户验收。
2. 共享 renderer 加入新 topology，生成 local 一个 server 与 x2/x3/x4 各一 agent；
   不再给三台工作机生成控制 VM，也不允许 x1 进入 inventory。
3. API 地址直接指向本机控制 VM，调整 bootstrap、etcd 备份与安装顺序。
4. 验收节点数量从 6 改为 4，node-exporter 从 6 改为 4，去掉 kube-vip 验收；
   保留三个 MetalLB speaker 与三个 Traefik 副本及可推进的滚动策略。
5. 重启后只读预检通过，再启动平台与跨节点 DNS/网络/隔离测试；业务分批迁入。

概念依据：[Service](https://kubernetes.io/docs/concepts/services-networking/service/)、
[NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)、
[PV](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)、
[K3s architecture](https://docs.k3s.io/architecture)。
