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

现场仍只看到原系统盘，不能对它格式化。先扩容 SSD 并持久挂载到
`/mnt/psy-k8s-lab`，至少 288 GiB 可用，与根盘和 /home 底盘均不同，再在 x4：

```bash
cd /home/psy/k8s-host-setup-20261016
sudo python3 host_setup.py x4 storage --apply
```

完全空白的新盘如需初始化，按 host-setup 文档核对 by-id 与 SERIAL 后使用其
可选入口；本文件不猜测设备名。数据池叶目录为 `/mnt/psy-k8s-lab/vm-data`，
它本身不是 mountpoint，创建器验证的是父级挂载和底层物理盘。

## 普通用户后续流程

源码入口：`deploy/k8s/platform/lab.py`；inventory 使用本目录的
[inventory.example.json](inventory.example.json)，不能使用 platform/ 的旧示例。

1. 独立实验 SSH key、私有 inventory、固定下载资产放在本机
   `/home/peter/git/bridge_zilong/k8s-local-control-plane/`。不复用生产凭据。
2. `lab.py preflight --inventory /absolute/inventory.json` 读取四机，所有 checks 为
   true 才返回成功。`network_confirmed` 仅表示地址已确认，不能代替 br0 验收。
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
