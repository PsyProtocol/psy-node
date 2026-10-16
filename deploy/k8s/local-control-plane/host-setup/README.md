# 操作员执行：四台 Arch 宿主机的一次性管理员准备

范围是本机 arch3900x、arc99x2、arc99x3、arc99x4。**脚本拒绝 x1/其他机器**。
普通用户分别为本机 peter、三台远端 psy。所有修改动作都要求人执行 sudo 和
显式 `--apply`；脚本自身从不调用 sudo，也不添加任何 NOPASSWD sudo 规则。
不停止 Proxy、Collector、Docker 等已有业务，不删除现有数据，不自动重启机器。

## 每台机器先安装程序和准备权限

整个 host-setup 目录需保持一起，至少保留 host_setup.py、check_host.sh。
在**对应机器**进入该目录，按角色执行一个命令：

| 机器 | 操作员执行 |
| --- | --- |
| 本机 arch3900x | `sudo python3 host_setup.py local install --apply` |
| x2 | `sudo python3 host_setup.py x2 install --apply` |
| x3 | `sudo python3 host_setup.py x3 install --apply` |
| x4 | `sudo python3 host_setup.py x4 install --apply` |

不加 `--apply` 只打印计划，可以先审阅。脚本核对物理 hostname、网卡 MAC 和 Arch。
安装 `qemu-base libvirt cloud-image-utils acl polkit`，不运行 pacman -Sy 或全系统升级。
如系统更新后内核模块目录与运行内核不一致，先按用户自己的维护安排重启，再执行。

本机此前未暴露 svm、没有 /dev/kvm：需要在 BIOS/UEFI 开启 SVM/AMD Virtualization，
正常启动后再运行；脚本会在安装前检测并停止，不擅自改 BIOS 或重启。
其他三台此前有 KVM。默认使用单体 libvirtd；已有活动 modular virtqemud 时拒绝切换。

安装动作把指定用户加入 kvm/libvirt，并授予该用户通过 libvirt 本地 UNIX socket
管理 VM 的权限，**包括 SSH 会话**。这是可信管理员级的 VM 管理能力，不是只授权
某个 VM 名字；仅用于用户自己的实验主机。使用 polkit 固定用户名，不开放 TCP
libvirt 监听、不依赖 root SSH、不开放免密 sudo。仅为 QEMU 增加到专用 VM 池的
目录遍历权限，不递归改动 /home、项目或业务文件的所有者。

安装完后退出并重新 SSH/登录，使新组生效。后续 VM 创建使用 `qemu:///system`
和 libvirt 默认 DAC dynamic ownership，由 libvirt daemon 处理 QEMU 访问磁盘所需
的所有权；后续普通用户创建入口必须使用此路径，不再使用旧版要求 EUID=0 的
`platform/create-vms.py`。默认 qemu.conf 中显式覆盖 user/group/dynamic_ownership
的主机先人工检查，脚本不会为兼容旧 helper 而把 QEMU 改成 root。

## 配置 br0：只在物理/带外控制台执行

四台现有 LAN IPv4 都来自 DHCP。本步骤改为 br0 使用当前固定 IPv4，保留原网卡
MAC；**先在路由器为该 MAC 保留/排除这个 IPv4**，避免 DHCP 把同地址发给其他设备。
本机 .20，x2 .35，x3 .41，x4 .43；网关/DNS 都为 192.168.5.1，掩码 /24。
这只固定宿主机地址，不代表未来 VM IP 或应用 VIP 已获预留。

网络变更会短暂影响 SSH 和机器上仍运行的服务。必须从物理控制台或带外控制台
操作，一次一台，验证恢复再做下一台。不要因为 x1 不动就假定 x3 的旧 Proxy 已下线。

```bash
# 在本机，角色 local；x2/x3/x4 各替换为对应角色。
sudo python3 host_setup.py local bridge --apply --console-confirmed --ip-reservation-confirmed
```

脚本已按只读盘点区分：本机用 NetworkManager，新建 psy-k8s-br0/psy-k8s-port
两个 profile；三台远端用 networkd，只添加 00-psy-k8s-* 三个文件。
保留原 profile 和 .link 文件，不停止或禁用任一网络管理器，不改 WG/Tailscale 配置。
已有 br0、同名 profile 或配置文件时拒绝覆盖。迁移期间原 IPv6 连接可能中断，
br0 将重新接受 IPv6 RA；依赖既有 IPv6 地址的业务需要另行验证。

在另一终端验证：

```bash
ip -4 address show br0
ip route get 192.168.5.1
resolvectl query github.com
# 再验证该机器原有服务的连接；只有网络恢复才继续下一台。
```

如失败，在控制台执行对应角色的回退：

```bash
sudo python3 host_setup.py local rollback --apply --console-confirmed
```

回退只移除本脚本拥有且内容未变化的 networkd 文件，或两个专属 NM profile，
再激活保留的原网络配置。记录在 /var/lib/psy-k8s-host-setup/bridge.json。
没有自动回退计时器，网络操作期间请保持控制台可用。

## x4 扩容盘：按实际情况执行，禁止用现有系统盘

本次检查仍只见 x4 的原 238.5 GiB sda，**尚未发现新增盘**。新增 SSD 接好后，
若已经持久挂载到 /mnt/psy-k8s-lab，只需：

```bash
sudo python3 host_setup.py x4 storage --apply
```

它只采用已挂载的新盘，验证其来自与 / 和 /home 都不同的物理盘、至少 288 GiB
可用，然后准备 /mnt/psy-k8s-lab/vm-data。不会格式化或分区已有文件系统。

若新盘完全空白，可用下面的**可选初始化入口**，先确认 by-id 与 SERIAL：

```bash
lsblk -o NAME,SIZE,TYPE,SERIAL,FSTYPE,MOUNTPOINTS
ls -l /dev/disk/by-id/
# 以下是占位参数，必须替换成实际新增盘，不得原样运行。
sudo python3 host_setup.py x4 initialize-disk --apply --initialize-blank-disk \
  --device /dev/disk/by-id/REPLACE_NEW_EMPTY_DISK --serial REPLACE_EXACT_SERIAL
```

该入口仅支持 x4、整块至少 320 GiB 的无分区/无签名/未挂载新盘，核对序列号并
排除 / 和 /home 的底盘后，才建立 ext4、备份并追加 fstab、挂载及准备 VM 池。
任何现有文件系统、分区或数据都导致拒绝，不提供清盘/强制擦除功能。
格式化是对新空盘的初始化，不存在恢复为未格式化状态的自动回滚。

## 无 sudo 验收

重新登录后，以 peter/psy 运行（角色各自替换）：

```bash
bash check_host.sh local
virsh -c qemu:///system list --all
```

check 仅只读，所有 checks 为 true 才能放行基础 VM 创建，退出码 2 表示仍缺前置。
它检查 KVM、程序、普通用户 libvirt、OS 池和 br0；x4 新盘用上面的 storage 步骤
单独核对，不能把基础检查通过当作数据盘已通过。
VM OS 池：本机 76 GiB 可用，x2/x3/x4 各 56 GiB。x3 磁盘由用户处理；脚本不清理。
完整四节点 renderer、普通用户 VM 创建和 Kubernetes 验收还需接着适配，当前不启动 VM。

后续管理员边界：内核/包更新、宿主机网络、扩容盘、宿主机防火墙仍需人执行管理员
脚本；正常 VM 生命周期、实验 kubectl/Helm 操作走已授权的普通用户权限。
VM 内 cloud-init/系统服务也会执行已审阅的安装脚本，但不会借此修改宿主机权限。

依据：[libvirt 身份认证](https://libvirt.org/auth.html)、
[libvirt daemon 架构](https://libvirt.org/daemons.html)。
