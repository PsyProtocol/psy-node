# 四节点实验施工顺序

本机仅控制面，x2/x3/x4 各一个工作节点，x1 排除。所有 Pod（含 DNS、监控与入口）
放在远端三个 worker。本机是单控制面，不提供控制面 HA。

## 目前已验证

用户执行四台宿主机 install 后，KVM、QEMU/libvirt/cloud-localds、普通用户
libvirt 连接、OS 池和内存通过。x3 OS 池约 139 GiB 可用。本机旧会话的组权限
可能尚未刷新，重新登录后生效；已核实数据库中的 libvirt 组包含 peter。
2026-10-16 用户确认路由器已保留前述地址；部署前仍需现场 ARP 冲突检查。

| 用途 | 地址 |
| --- | --- |
| 本机 / x2 / x3 / x4 宿主机 | 192.168.5.20 / .35 / .41 / .43 |
| 控制 VM | 192.168.5.210 |
| work-x2 / work-x3 / work-x4 | 192.168.5.211 / .213 / .215 |
| MetalLB 应用入口 | 192.168.5.217 |

本机普通用户实测无法创建 ARP raw socket。人可先运行
`sudo bash check-addresses.sh`（在本文件的源码目录或交付副本目录），验证这五个
地址现在没有 ARP 回复。探测不修改网卡/地址，不能发现关机设备或替代路由器保留。

## 下一步由人执行：网桥

四台尚未发现 br0。在各机物理/带外控制台操作，一次一台，短暂网络中断后确认
SSH、网关、DNS 和原服务恢复再继续。完整细节及回退见 [host-setup](host-setup/README.md)。

本机：

```bash
cd /home/peter/git/bridge_zilong/k8s-local-control-plane/host-setup-20261016
sudo python3 host_setup.py local bridge --apply --console-confirmed --ip-reservation-confirmed
```

分别在 x2、x3、x4 执行对应的一条（不是在同一机器执行三条）：

```bash
cd /home/psy/k8s-host-setup-20261016
# x2
sudo python3 host_setup.py x2 bridge --apply --console-confirmed --ip-reservation-confirmed
# x3
sudo python3 host_setup.py x3 bridge --apply --console-confirmed --ip-reservation-confirmed
# x4
sudo python3 host_setup.py x4 bridge --apply --console-confirmed --ip-reservation-confirmed
```

每台检查 `ip -4 address show br0`、`ip route get 192.168.5.1`、
`resolvectl query github.com`。失败时在控制台执行同角色
`sudo python3 host_setup.py ROLE rollback --apply --console-confirmed`。

## 下一步由人执行：x4 新数据盘

2026-10-17：已发现新增 SanDisk SSD PLUS 1000GB，serial `2113C4462901`，
ext4 分区 UUID `d6d4015e-098a-4d6d-842d-6304bc015132`，已挂载 `/data`，
fstab 已配置开机挂载，约 915 GiB 可用。`/data` 由 psy 所有，允许普通用户准备
独立目录。该盘不用重新格式化，不改挂载点，不使用另一块 4 TB NTFS 盘。

当前改为普通用户执行 `adopt-data.py`（和 host_setup.py 一同交付），先不带参数
只读核对，再加 --apply：

```bash
python3 adopt-data.py
python3 adopt-data.py --apply
```

入口核对 x4 物理身份、普通 psy、UUID、serial、ext4、与根盘和 /home 不同的底盘、
可用空间和已有父目录访问权限。只在 `/data/psy-k8s-lab/vm-data` 创建新池，并对
新建两层目录授予 QEMU 最小访问 ACL；不修改 `/data` 根目录或已有文件权限，
不 chown、不递归授权、不运行 sudo/mount/mkfs/fstab 操作。相同 receipt 可重复检查，
已有不同目录、软链接或不完整准备现场会拒绝覆盖。VM 创建时再次核对 SSD 身份。

旧 `/mnt/psy-k8s-lab` 布局仅保留兼容；不要为迁就旧路径重挂或重格式化当前 SSD。

## 普通用户后续流程

源码入口：`deploy/k8s/platform/lab.py`；inventory 使用本目录的
[inventory.example.json](inventory.example.json)，不能使用 platform/ 的旧示例。

1. 独立实验 SSH key、私有 inventory、固定下载资产放在本机
   `/home/peter/git/bridge_zilong/k8s-local-control-plane/`。不复用生产凭据。
2. `lab.py preflight --inventory /absolute/inventory.json` 读取四机，所有 checks 为
   true 才返回成功。路由器地址保留不能代替 br0 验收；新包的 network_confirmed
   保持 false，直到四台 br0 都已确认。
3. 只有新盘验收通过才设 `storage_confirmed: true`，渲染到新的输出目录。
   旧的 storage=false 包保留为证据，所有安装入口仍会拒绝执行。
4. 执行 `lab.py fetch --assets /absolute/assets --include-vm-image`，随后
   `lab.py render --inventory /absolute/inventory.json --output /absolute/new-bundle`，
   `lab.py charts --output /absolute/new-bundle --assets /absolute/assets`。
5. 每台只接收 `hosts/<role>/` 自己的文件，另加固定 `ubuntu.img` 和根目录
   `assets.lock.json`。以 peter/psy 执行 `python3 create-vms.py --create ROLE`
   审阅计划，再加 `--apply` 创建。ROLE 是 local/x2/x3/x4；不使用 sudo。
   创建器拒绝 root、错误物理身份、已有域/磁盘、资源不足或未准备的新盘。
   libvirt 使用默认 DAC dynamic ownership 管理磁盘，创建器不 chown 或改全局配置。
6. 等待每台新 VM 的 `cloud-init status --wait`，使用专用 key 验证 SSH、地址、路由。
   agent 不经宿主机 sudo；VM 内 ubuntu 可运行生成且受 KVM/hostname/marker 保护的
   管理脚本，授权范围仅这个新 VM。
7. 给四台 VM 传对应 `nodes/<name>/` 和固定 `k3s`。创建实验 token（mode 600），
   安全复制到 VM，`sudo install -m 600 lab-token /root/psy-lab-token`，四台用同一个。
   不打印 token，不进 Git。work-x4 VM 先执行
   `sudo bash initialize-data.sh --initialize-empty-virtual-disk` 初始化其新空白虚拟盘。
8. 控制 VM 先执行 `sudo bash install-k3s.sh /root/psy-lab-token`，安全取回独立
   kubeconfig（600），server 改为 `https://192.168.5.210:6443`。在 platform/ 执行
   `./check-bootstrap.sh`；此时只要求控制节点 Ready，DNS/metrics 等待 worker。
   不安装 kube-vip，也不占用 .216。
9. 三个 worker VM 各执行同一安装入口，全部 Ready 后，在对应 platform/ 和
   显式绝对路径 `KUBECONFIG` 下执行 `./install-platform.sh --install`。
   `./verify-platform.sh` 检查四节点身份/污点、控制节点零 Pod、三个 speaker、
   三份 node-exporter、三机 Traefik、入口 IP、监控 Ready 和 PVC Bound。
10. 继续跨节点 DNS/HTTP、NetworkPolicy allow/deny、Pod/PV 恢复、入口故障实验，
    然后分批部署 Psy 业务并跑交易 E2E。配置生成通过不等于集群或业务已跑通。

可用固定 k3s 多调用入口提供 kubectl：在资产目录建立 `kubectl -> k3s`，加入 PATH，
设置独立可写 `K3S_DATA_DIR` 客户端缓存；不在操作机启动 k3s server/agent 服务。

保留本机控制 VM 的 etcd snapshot **和同一 server token**到另一台物理机；它们
不替代 x4 数据备份。中断时保留域/磁盘/etcd，先查原因，不运行删除或自动重建。

## 一次生成每台机器的完整输入包

`prepare-delivery.py` 在本机生成 bundle，并为 local/x2/x3/x4 分别组装完整输入：
对应的 host.json/XML/cloud-init、独立 Ubuntu 镜像副本、对应 guest/ 安装文件、
固定 K3s 二进制、资产锁、源码提交与 SHA256SUMS。包内没有私钥、token 或 kubeconfig。
输出本身约 3 GiB，提前检查本机空间；它只写本机的新目录，不连接或启动远端机器。

从干净且已提交的源码根目录执行：

```bash
python3 deploy/k8s/local-control-plane/prepare-delivery.py \
  --inventory /absolute/inventory.json \
  --assets /absolute/assets \
  --output /absolute/new-delivery
```

只向对应机器复制 `host-packages/<role>/`，进入该目录先执行
`sha256sum --check SHA256SUMS`，再运行不带 --apply 的创建计划。
storage_confirmed=false 的包可预先分发，但拒绝安装。磁盘/网络就绪后重新预检，
生成新的、已确认的交付包；保留旧包，不在已分发包中手改确认状态。

## 平台启动后的网络与隔离验收

新的四节点 platform/ 包含 `network-acceptance.py` 和对应只含非敏感配置的 JSON。
先 `python3 network-acceptance.py --plan` 离线检查清单；真实平台验证通过后，在
同一 platform/ 目录和明确的实验 `KUBECONFIG` 下执行：

```bash
python3 network-acceptance.py --run --evidence /absolute/new-evidence-directory
```

入口会重新核对 API/四节点身份、控制面污点及平台就绪，再创建两个带随机后缀的
专用实验 namespace，全部测试 Pod 固定在三个 worker，不调度到本机。
它先验证五个客户端的基线 DNS/HTTP，再施加两个 namespace 的默认入站/出站拒绝、
DNS 放行、namespace AND Pod label 限定的 HTTP 放行。三个合法客户端必须成功，
错误 namespace、错误 Pod label 的两个对照客户端必须被阻断，且 DNS 仍正常。
拒绝判定要求实际 wget 超时；exec/认证错误、DNS 失败或 HTTP 404 不算隔离成功。

最后创建专属 HTTPRoute（psy-platform）和仅授权测试 Service 的 ReferenceGrant，
从操作机经 LAN VIP/Traefik 访问后端并核对本轮唯一响应体。它不修改现有 Gateway
或业务 NetworkPolicy，不部署 Psy 数据库、不验证交易与持久卷恢复。

清单和结果以 mode 600 保存在新证据目录。成功/失败都保留现场，不自动清理；
测试 Pod 最长运行 30 分钟，不自动重启。检查 result.json 中的随机 namespace、
HTTPRoute 名字及它们的 `psy.local/acceptance-run` 标签，确认属于本轮后再删除
这些测试资源。不要删除 psy-platform namespace 或其他实验/业务资源。

协议依据：[NetworkPolicy 选择器组合](https://kubernetes.io/docs/concepts/services-networking/network-policies/)、
[Gateway API ReferenceGrant](https://gateway-api.sigs.k8s.io/api-types/referencegrant/)。
