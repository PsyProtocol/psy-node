# x2/x3/x4 平台施工脚本

2026-10-16：用户已调整为本机控制面 + x2/x3/x4 工作节点，x1 不动。共享 lab.py
已适配；请按[四节点施工说明](../local-control-plane/RUNBOOK.md)及其 inventory 执行。
本文件以下保留旧六 VM inventory/root 创建器的历史说明，不是本次施工入口。

这一批交付是本地独立实验集群的平台施工工具。已提供六台 VM、K3s 三控制节点、
kube-vip、MetalLB、Traefik Gateway API、Prometheus/Grafana/Alertmanager 和本地 PV。
真实三机启动、LAN/VIP 故障切换、Psy 镜像与交易 E2E 是后续现场验收项目。
不部署旧 Collector/Controller；Kubernetes 的调度和重启不能替代 Psy 的交易进度、
任务积压、单写者 fencing 等业务语义，需要后续原生指标或只读 exporter。

## 资源与磁盘

| 物理机 | 控制 VM | 工作 VM | OS 虚拟磁盘 | 施工时 OS 池可用空间下限 |
| --- | --- | --- | --- | --- |
| x2 | 2 vCPU / 4 GiB | 4 vCPU / 8 GiB | 各 40 GiB | 96 GiB |
| x3 | 2 vCPU / 4 GiB | 6 vCPU / 12 GiB | 各 40 GiB | 96 GiB |
| x4 | 2 vCPU / 4 GiB | 8 vCPU / 20 GiB | 各 40 GiB | 96 GiB |

这是先安装平台的 52 GiB RAM 配置。可用内存还须额外保留至少 2 GiB，且此预算
不能叠加到已经占满资源的生产进程之上。完整业务的工作 VM 扩容另行检查。
qcow2 虽然按需增长，预检仍按虚拟容量保留磁盘空间，避免承诺容量大于实际容量。

三个控制 VM 的 OS/etcd 各落在所在物理机的 OS 池。x4 新增物理 SSD 推荐 2 TB
起步，挂载为专用 `data_pool`（示例 `/mnt/psy-k8s-lab`）；只能由人确认和挂载，
脚本不对宿主机磁盘分区或格式化。脚本检查它来自与根目录不同的物理磁盘。
工作 VM x4 另建 256 GiB 虚拟数据盘，数据池至少保留 288 GiB 空间。
该 VM 的 `/srv/psy-lab` 包含 containerd/K3s 工作目录及监控数据。
监控 PV 是 Retain + WaitForFirstConsumer + work-x4 节点亲和，x4 故障时监控也会
中断；须另设外部探针和备份。35 GB TSDB retentionSize 不包括全部 WAL/head 开销。

2026-10-14 已知基线中 x3 的 /home 约剩 40 GiB，x2 所在文件系统约剩 85 GiB，
均未达到此脚本的容量门槛。应保留现有服务数据与备份，清理后重新测量。

## 准备配置（此阶段不修改机器）

操作机需要 Python 3.11+、SSH；下载命令需要外网。默认目录均在本文件旁。

```bash
cd deploy/k8s/platform
cp inventory.example.json inventory.local.json
```

编辑本地 inventory：

1. 用专用实验 SSH **公钥**替换占位符。私钥、K3s token、生产签名密钥均不写入 Git。
2. `192.168.5.210–217` 都只是示例，不能假定空闲。确认 DHCP 排除/保留、ARP 探测，
   六个 VM IP、API VIP、入口 VIP、网关必须不同。补全 LAN/Pod/Service 与当前 VPN、
   Docker、云路由的非重叠检查。`reserved_cidrs` 记录当前已知网段，现场补充。
3. 确认已经存在的有线 LAN bridge。`br0` 是占位名，不能假定宿主机已经有它。
   如需配置桥接，须人在控制台准备网络配置和恢复方式，避免断开现有 SSH/服务。
4. 确认三个宿主机的独立 `os_pool` 和 x4 的新盘 `data_pool`。
   三个 OS 池须人工预先创建，QEMU 用户能遍历整个路径；助手不创建或 chmod 池。
5. 只读预检报告中的 `hostname` 写入每个 `hosts.<host>.expected_hostname`。

```bash
python3 lab.py plan --inventory inventory.local.json
python3 lab.py preflight --inventory inventory.local.json
```

预检通过 SSH 读取内存、KVM、路由、网卡、磁盘及 helper 状态；不读服务密钥或
进程参数，不停止服务。报告中所有 `checks` 应为 true。`preflight` 的退出码只表示
SSH/采集成功，不代表全部施工条件通过；VM 创建时重新强制检查容量和资源。

三台现有宿主机实测是 Arch Linux，须先准备 `qemu-base libvirt cloud-image-utils`
和 libvirt 系统连接；目前三台都缺少 virsh/qemu-img/cloud-localds，且没有 br0。
如使用 Ubuntu 宿主机，对应包是 `qemu-kvm libvirt-daemon-system libvirt-clients
cloud-image-utils`。新 VM 内统一采用固定 Ubuntu cloud image，和宿主机发行版独立。
确认 `/dev/kvm`、`qemu:///system`、桥接和启用的 AppArmor/SELinux 权限。
核对 libvirt 的实际 QEMU 用户/组，必要时填写 inventory 的 `qemu_user`/
`qemu_group`（默认 libvirt-qemu/kvm）；该用户必须能遍历 OS 池父目录，按最小范围
授予目录访问权。预检中的 `os_pool_exists` 必须为 true，VM 创建时再次验证整个
路径可遍历；磁盘文件自身保持 600。脚本不会更改 libvirt 的全局运行用户。
脚本不会自动安装宿主机包、改变 bridge、关闭现有 Proxy 或迁移生产负载。
人员确认上述条件后，设 `network_confirmed` 和 `storage_confirmed` 为 true。
false 时仍可渲染供审阅，但生成的安装脚本会拒绝执行。

## 固定下载与渲染

```bash
python3 lab.py fetch --assets assets --include-vm-image
python3 lab.py render --inventory inventory.local.json --output output/run-001
python3 lab.py charts --output output/run-001 --assets assets
```

下载全部固定 URL，核对 [assets.lock.json](assets.lock.json)。未带
`--include-vm-image` 则跳过约 626 MB 的 Ubuntu qcow2。输出目录不得已存在，避免
覆盖上一次施工证据。输出目录 700，配置 600，脚本 700。`charts` 校验 Helm 原始包
和可执行文件，生成真实 Helm 模板并复制固定 chart/CRD，安装时再次校验。
K3s、MetalLB、Prometheus cohort 与 `../build/versions.json` 一致；额外冻结
Helm 3.19.0、Traefik chart 41.7.1、Gateway API 1.5.1、Ubuntu noble 20260926。

2026-10-17 四节点现场发现：Traefik 3.7.14 启动 Gateway provider 时会等待
`TLSRoute` 的 v1 informer；1.4.0 Standard 没有该 API，导致 Pod Ready 但
Gateway 一直等待 controller。固定改用官方 1.5.1 Standard，下载摘要与 GitHub
release asset 的 SHA256 核对；安装等待所需 CRD Established，验收再等待 Gateway
Programmed，不能用 Pod Ready 代替入口可用。
Chart 内的运行时镜像及 kube-vip 当前按固定版本 tag；镜像 digest 锁定、镜像仓库、
签名与镜像拉取凭据在业务镜像发布阶段落实，本实验安装尚未做到全离线镜像供应。

如无 kubectl，可在操作机的 assets 目录建立 `kubectl -> k3s` 符号链接，加入 PATH；
K3s 提供同版本的 kubectl 多调用入口。设置 `K3S_DATA_DIR` 指向独立可写 client-cache
目录，供客户端解包内置工具；不要将这个操作机二进制作为宿主机服务启动。

## 六个 VM 的创建

将 `output/run-001/hosts/x2/` 的内容复制到 x2 上新的施工目录，同时复制
`assets/ubuntu.img`、输出根目录的 `assets.lock.json` 到该目录。x3、x4 同理，
每个宿主机只拿到自己的两台 VM 文件。人在对应宿主机执行：

```bash
sudo python3 create-vms.py --create arc99x2
```

x3/x4 最后参数分别改为其 SSH alias。脚本核对物理 hostname、已有域/磁盘、
桥接、KVM、内存、空间、新数据盘挂载，再定义并启动两台 `psy-lab-*` VM。
OS qcow2 是独立拷贝，不依赖施工目录中的共享 backing image。cloud-init 配置
静态 eth0、公钥、guest-agent 和实验身份文件。没有启用 autostart；验收后再决定。

检查新 VM 的 `cloud-init status --wait`、SSH、`ip route`，确认没有 IP 冲突。
任何部分失败都会保留已建域/磁盘，重复创建会拒绝覆盖：先查看 `virsh list --all`
和池目录，修正问题后只恢复属于本实验的已建 VM，不重建磁盘。

## K3s 安装与 API VIP 引导

每台新 VM 接收对应 `output/run-001/nodes/<name>/` 文件和 `assets/k3s`。
施工机用 `umask 077; openssl rand -hex 32 > lab-token` 创建实验 token，安全复制
到每台 VM 的临时目录，再 `sudo install -m 600 lab-token /root/psy-lab-token`。
六台必须使用同一 token。不要使用生产集群 token，不要打印 token，不提交 token。

1. work-x4 VM 内执行 `sudo bash initialize-data.sh --initialize-empty-virtual-disk`。
   该入口检查 KVM、hostname、cloud-init 身份、虚拟盘 serial、vdb、无分区/挂载/
   签名，才初始化**新 VM 的空白虚拟盘**并建立数据目录。它不运行在物理机上。
2. cp-x2 VM 内执行 `sudo bash install-k3s.sh /root/psy-lab-token`。
   这一台开启 cluster-init；其余五台通过预置 API VIP 加入。
3. 将 cp-x2 的 `/etc/rancher/k3s/k3s.yaml` 安全取到操作机独立文件（chmod 600），
   仅将 server 的 127.0.0.1 改为 cp-x2 的实际 IP，设置绝对路径 KUBECONFIG。
4. 在 `output/run-001/platform/` 执行 `./bootstrap-vip.sh --bootstrap`。脚本要求
   只有 cp-x2 一个 Ready 节点且标签/IP 匹配，安装仅管理控制面 VIP 的 kube-vip，
   再验证 VIP 的 TLS 和 `/readyz`。
5. 顺序安装 cp-x3，再 cp-x4，确认三个 server Ready，然后安装三个 work VM。
   每台执行相同的 `sudo bash install-k3s.sh /root/psy-lab-token`。
6. 将操作机 kubeconfig 的 server 改为 `https://<api_vip>:6443`，确认六个 Ready。

server 关键参数一致；禁用自带 Traefik/ServiceLB/local-storage，保留 CoreDNS 和
metrics-server，开启 secrets encryption。控制 VM 污点禁止普通业务调度。
K3s 用固定二进制和自有 systemd unit 安装，不执行未锁定的在线安装脚本。
安装入口检测到已有 K3s 文件就停止，不覆盖已有集群。修复中断时在新 VM 人工
检查 unit/config/log，必要时继续 `systemctl start psy-lab-k3s`，不要删除 etcd 目录。

## 入口、存储与监控

在操作机的 platform 输出目录、lab kubeconfig 下执行：

```bash
./install-platform.sh --install
./verify-platform.sh
```

六个节点名/标签/IP 和 API VIP 必须全部匹配才能安装。MetalLB speaker 仅在
三个 worker 上发布独立入口 VIP；Traefik 三副本通过强制反亲和分布三机。
滚动更新使用 maxUnavailable=1/maxSurge=0，每次保留两个副本，避免要求第四个
worker 才能推进升级。虚拟磁盘为 QEMU 用户所有且 600，cloud-init seed 为 640。
默认 HTTP Gateway 只接受同 namespace 的 HTTPRoute，未来业务 HTTPRoute 需
明确 namespace selector/ReferenceGrant 和 TLS；当前没有暴露 Grafana 管理入口。
Grafana 使用自动创建的独立 Secret，人员需要访问时用 port-forward 和安全读取
该实验 Secret。Alertmanager 默认配置没有接收人，通知路由需要后续单独配置。

Prometheus 抓取 API server、kubelet/cAdvisor、CoreDNS、node-exporter、
kube-state-metrics 和 Operator。K3s 内嵌 etcd/controller/scheduler/proxy 不采用
kubeadm 的默认抓取方式，本批关闭对应错误监控与告警规则；K3s 专属端点/TLS
及 Psy 业务指标后续专项验证，不表示它们已获完整覆盖。node-exporter 观测的是
六个 VM，物理机健康、独立 blackbox 和 x4 磁盘外部告警仍是后续任务。

安装后人工验收：LAN 客户端访问 API VIP、入口 VIP；部署一次性 HTTPRoute
验证入口；检查 Prometheus targets 为 UP；Pod 重启后 PV 数据仍在；轮流停止
一个控制 VM 验证 etcd/VIP（每次只停一个且恢复 Ready 后再继续）；停止一个
worker 验证入口可用。x4 数据单点实验必须记录实际恢复步骤与备份耗时。
这些测试通过以后，才推进 Psy 业务 Deployment/StatefulSet、NetworkPolicy、
配额/权限、镜像仓库、blackbox 与交易 E2E；此脚本没有宣称整套业务已可上线。

## 停工与恢复

脚本无自动卸载或删除 PVC。平台失败先保留现场，用 `helm status`、`kubectl
describe` 和只针对实验 VM 的 `journalctl -u psy-lab-k3s` 查原因。修复输入后
重跑平台安装属于同名 Helm release 的更新，涉及 chart/CRD 升级应另作备份审查。
Retain PV 不会因删除 PVC 自动清空，重绑定需要人工确认 claimRef 和原数据。

需停止实验时，只停止清单里的 `psy-lab-*` VM；禁止匹配并停止宿主机的生产
服务。删除 VM/虚拟磁盘、移除宿主机网络配置和新 SSD 格式化不在自动流程内。
保存三控制 VM 的 etcd snapshots **和同一 server token**到独立备份位置；仅保存
etcd snapshot 而丢失 token 不足以恢复加密的集群引导数据。Prometheus/Grafana
数据也须做 x4 以外的备份。施工 token/kubeconfig 应保留为 600，勿放入 Git。

## 离线检查

```bash
python3 test_lab.py
```

发布前执行：配置/身份/资源拒绝测试、生成脚本 ShellCheck、固定包校验、真实
Helm 渲染及滚动策略检查、VM XML schema，以及隔离 K3s API 对清单的校验。实际三机 KVM、网桥、L2/VIP、磁盘
吞吐和交易流程须在现场验收，无法由离线渲染代替。

设计依据：[K3s embedded etcd](https://docs.k3s.io/datastore/ha-embedded)、
[K3s 配置](https://docs.k3s.io/installation/configuration)、
[K3s kube-vip 引导](https://docs.k3s.io/datastore/cluster-loadbalancer)、
[MetalLB L2](https://metallb.io/configuration/)、
[Traefik Helm](https://github.com/traefik/traefik-helm-chart)、
[Prometheus Helm](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)、
[Arch cloud-localds 包](https://archlinux.org/packages/extra/any/cloud-image-utils/files/)。
