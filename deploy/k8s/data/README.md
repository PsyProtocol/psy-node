# 四节点实验数据库

只为 `psy-k8s-local` 新实验部署五个单实例数据服务，全部在 work-x4；不访问或迁移现网数据库。
两个 PostgreSQL 分别服务 Services 和 Envio，数据库、账户密码及 PVC 分开。

| Service（psy-data） | 端口 | 数据卷 | 内存 request / limit |
| --- | ---: | ---: | --- |
| postgres-services | 5432 | 10 GiB | 256 MiB / 1 GiB |
| postgres-envio | 5432 | 10 GiB | 256 MiB / 1 GiB |
| scylla | 9042 | 50 GiB | 4 GiB / 6 GiB |
| valkey | 6379 | 5 GiB | 256 MiB / 1 GiB |
| nats | 4222 | 5 GiB | 128 MiB / 512 MiB |

业务入口如 `postgres-services.psy-data.svc.cluster.local:5432`，全部为 ClusterIP。
数据库镜像复用 `../build/versions.json` 的四个固定 digest；已核实 PG 16.15、Scylla
2026.1.5、Valkey 9.1.2。客户端 Python 3.12.15 也固定 digest。无 latest/tag 漂移。
不增加数据库 exporter，现有 Prometheus 仍采集 Pod/节点资源；数据库语义指标是后续接入项。

## 生成与施工

源码提交并独立审查、推送后，从干净源码根目录调用：

```bash
python3 deploy/k8s/data/databases.py plan
python3 deploy/k8s/data/databases.py render \
  --inventory /absolute/private/inventory.json \
  --platform /absolute/existing-platform-bundle/platform \
  --output /absolute/new-private-data-bundle \
  --secrets-file /absolute/private/data-credentials.json \
  --virtual-fs-uuid <x4新VM数据盘的文件系统UUID>
```

输出目录 700、文件 600，包含敏感 Secret manifest，不能进 Git。凭据只生成一次，
重复读取不轮换；各服务 admin/app 密码独立，生成 hex，使用文件/Secret 传递。
操作者本机须设置明确的 `KUBECONFIG`（600）、kubectl PATH、独立 K3S_DATA_DIR。

把 `prepare-data.sh` 只传到新 work-x4 VM，在该 VM 内以 ubuntu 执行
`sudo bash prepare-data.sh`。脚本核对 KVM/VM名/实验 marker/已知 vdb 文件系统 UUID
和空闲容量，再新建五个独立目录；任何已有目录都会拒绝覆盖。它不格式化、不改宿主机，
不递归修改旧目录。所有物理宿主机 sudo 步骤仍由用户执行，本步骤不需要物理宿主机 sudo。

```bash
python3 /absolute/new-private-data-bundle/databases.py install \
  --bundle /absolute/new-private-data-bundle
python3 /absolute/new-private-data-bundle/acceptance.py \
  --bundle /absolute/new-private-data-bundle \
  --evidence /absolute/new-private-evidence-directory
```

安装首先核对 API/全部节点/控制面零 Pod、数据 namespace 所有权与输入校验和。
只 create 预检不存在的资源；同一 bundle 中断可跳过已有且同 bundle ID 的对象继续，
遇到其他来源同名资源拒绝接管。失败保留数据库、PVC 与凭据，不自动重建/删除数据。
Kubernetes local PV Retain + PVC 预绑定，guest 目录为 `/srv/psy-lab/db-<Service名>`。

## 身份与网络

PostgreSQL 初始超级用户只用于引导；应用 psy_app 是非超级用户且无建库/建角色权限，
拥有自己的实验库。Scylla 启用 PasswordAuthenticator/CassandraAuthorizer，新建独立
lab_admin 和仅有 psy_lab keyspace 权限的 psy_app，关闭默认 cassandra 登录。
Valkey 关闭无密码 default 用户，应用只操作 `psy:*` key/`psy:*` channel，拒绝管理与
危险命令。NATS 使用认证及 `psy.>` / JetStream API / inbox 主题权限；业务接入时需
按真实角色、key/subject 范围进一步拆账户。本轮不做现网 schema/migration。

psy-data 默认拒绝入站/出站，只放 DNS 以及每个服务的来源 namespace AND access label：
- 两个 PG：psy-app；label 分别为 `psy.local/access-postgres-services=true`、`...postgres-envio=true`。
- Scylla/Valkey/NATS：psy-chain 或 psy-compute，label 为 `psy.local/access-<Service名>=true`。
- 专用测试 namespace 还需 lab + data-probe 标签及对应 Pod access 标签。

Namespace 标签本身不提供隔离；实际由 NetworkPolicy 执行。后续业务出站策略另按依赖
开放，不给 DB 开 NodePort/LoadBalancer，也不把认证或集群 IP 当作宿主机隔离边界。
本轮为受控局域网实验，尚未配置数据库协议 TLS 或生产 HA。

## 真实验收

验收只在两个新随机 namespace 创建客户端，三个正向 Pod 各固定一个 worker，另外两个
无凭据对照客户端分别使用错误 Pod label、错误 namespace。无 API token、非 root、
只读根文件系统、资源限制及最长一小时生命周期；测试账户不含 admin 凭据。

三 worker 分别做 SQL/CQL CRUD、Valkey SET/GET/DEL、JetStream file stream 发布并读取，
验证错误密码、PG 跨实例凭据不通、PG/Scylla/Valkey 应用权限限制。随后逐一正常删除
五个专属数据库 Pod，由 StatefulSet 重建，核对 Pod UID 变化、PVC UID 不变，再从三个
worker 读取原记录与消息。此为正常重建持久性测试，不代表断电、损坏或异机恢复已验证。

两个对照客户端访问五个端口均须拒绝；临时授予精确访问标签必须恢复、撤销后再次拒绝，
最后三个正向客户端必须仍成功。DNS/exec 错误不算拒绝成功。成功后只清理本轮客户端
namespace，数据库测试记录/stream 留作证据；失败保留客户端现场，result.json 如实失败。

Valkey AOF everysec；Scylla batch commitlog；NATS file store。PVC capacity 为调度声明，
同一 ext4 上的目录没有磁盘硬配额。监控卷 54 GiB 加本轮 80 GiB 共声明 134 GiB，
仍需留出 K3s 镜像、日志、WAL 和压缩空间。当前均为单数据节点，备份/异机恢复需单独验证。

Scylla 2026.1.5 原生外层参数解析器转交 Seastar 参数时需 `--smp=2`、`--memory=4G`
等单参数形式。旧包遇到该启动错误时，使用已审查新源码的
`databases.py repair-scylla-args --bundle /absolute/original-bundle --evidence /absolute/new-repair.json`，
只对原 bundle 所有且参数未被他人改变的 StatefulSet 做 UID/resourceVersion 条件 patch，
不修改旧包、PVC 或凭据；再从原包继续 install。失败的旧 Pod 若阻止 StatefulSet 更新，
核对 owner/旧 controller revision 后仅删除该实验 Pod，让控制器重建。
