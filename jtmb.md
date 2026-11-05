# JTMB 修复与实测交接

更新日期：2026-11-04

## 当前结论

修复了新注册账户的 ZK 公钥详情索引，并已在隔离 JTMB 节点上端到端验证：注册 3 个账户后，按真实 Strategy5 user ID 都能查回公钥；其中 user ID `1114112` 部署合约 6 并成功更新。合约更新在 checkpoint 228 确认，代码根从 `30f06e6c5c897af41c08f0f86677c66096e533ce490c9817b5ddf7b5812a3ea6` 变为 `f07cf0976c936ecd25927671dfc987596e18c6e4ff94f6a8bbab930c62363d5f`；部署者、状态树高度、布局根、字段数和槽位数保持一致。七个 RPC 在该 checkpoint 的状态根一致。

## 根因和修复

注册序号和协议 user ID 是两种编号。例如注册序号 17 映射成 user ID 1114112。注册树使用注册序号作为叶子位置；公钥详情表必须以映射后的 user ID 为键。旧的 FFS 批量存储接口假定所有 object ID 连续递增，忽略每行显式 ID，导致详情写在键 17，而更新鉴权按 1114112 查找失败。公钥反查表原先已经使用映射后的 user ID，因此会出现“按公钥能查到用户，按 user ID 查不到公钥”的现象。

当前实现：

- `psy_node_common/src/coordinator/processor/gatherers/register_user_gatherer.rs` 新增 `append_zk_public_key_ffs`，把注册序号映射为 user ID。在线注册和备份恢复两条路径都用它构造包含显式 ID 的 FFS 行。
- `psy_node_core/src/psy_core_db/v3_implementation/full.rs` 在 `set_zk_public_keys_ffs` 解析每条行记录，转成显式 ID 的 checkpoint 行，再用通用批量 writer 存储。公钥值仍是原有 64 字节格式；行 ID 不会进入公钥值。
- 回归测试覆盖 user ID 17 与 1114112 的非连续行解析、公钥值保持不变、截断 FFS 行拒绝，以及 Strategy5 注册序号映射。

## 验证结果

- `PSY_NETWORK=localhost cargo test --release -p psy_node_core --lib zk_public_key_ffs_tests --locked`：2 通过。
- `PSY_NETWORK=localhost cargo test --release -p psy_node_common --lib zk_public_key_ffs_uses_strategy_mapped_user_id --locked`：1 通过。
- SSH `test` 隔离 JTMB 栈重新注册 3 个账户，checkpoint 18 纳入；`get_public_key_for_user_id` 对 `1114112`、`589824`、`1638400` 均成功。
- 使用 user ID `1114112` 部署合约 6，checkpoint 174 纳入。
- 通过真实 layout-aware update command 和原部署者 ZK 签名提交更新，Coordinator 返回 content hash `2f007fc44870f385ebdf38f2662737df6ac1059153eefb3bb546ec19e3053171`。
- checkpoint 228 确认新代码定义和新代码根；布局字段保持与更新前完全相同。确认结果在远端 `local_checkpoints/jtmb_tests/1793791766611-update-contract-final/results.json`。
- 修复前的失败证据记录了 deployer key 查询错误。测试新链/重置前，证据备份位于远端 `/tmp/psy-jtmb-evidence-before-final-update-fix-20261104`。

## 隔离测试环境

- SSH checkout：`/home/psy/Projects/psy-node-jtmb-a350109fe`，独立 namespace：`jtmb-a350109fe`。
- 最终启动日志：`/tmp/psy-jtmb-final-update-start.log`。
- 当前 foreground supervisor 仍在运行，RPC 为 Coordinator `1337`，Realm `13380–13382` 和 `13390–13392`。
- 本次更新结果证据：`local_checkpoints/jtmb_tests/1793791766611-update-contract-final/`。
- 临时测试入口仍在隔离 checkout 的 `client_prover/psy_cli/psy_user_cli/examples/jtmb_update_contract.rs`。它只用于 JTMB 测试，后续可清理；没有加入本地提交。
- 该栈只验证 JTMB 测试后端的核心 L2 RPC，不包含 psy-services ABI 上传和 L1 部署。

## Git 工作区交接

- 当前本地 HEAD：`8588ef29e`（未推送）。提交历史：
  - `8588ef29e` Fix zk public key detail index to use strategy-mapped user id（公钥索引修复，两个文件）
  - `a06638194` Add stage progress logging to reward claim proving（`reward_client.rs` 埋点，此前他人工作，单独提交）
  - `659a085c7` fix(jtmb): bind core proof chains and add confirmed batch tests（JTMB 支持基底）
- 公钥修复与 reward_client 埋点已拆分为两个提交；`psy-genesis` gitlink 既存改动保持未提交。
- 注意：2026-11-04 晚提交过程中工作区曾被外部进程改动（reward_client.rs 工作区内容一度丢失），已从 dangling blob `2a9a8d8b8` 恢复并验证一致。提交后立即核对过 log 与 status。
- `git diff --check` 已通过。过程中发现的更新队列误判已撤销；Coordinator 的 deploy/update consumers 设计为共用队列接口，不要再改那两行。

## 跨 epoch 丢批问题（已修复，待部署验证）

根因已确认并修复（2026-11-04，本地提交见 `git log`，未推送）：finalize 实时重读共享 `gathering_checkpoint_id`，而 `sync_with_coordinator`（sync.rs:256-259）会在周期中途覆写它，导致 RealmFinalizeGUTA header 经 checkpoint-upgrade 分支被升到 sync 后的 checkpoint，目标跨入下一 epoch 的 proposer 排程，在 gatherer 树提交之后于 process_block.rs 的 scheduled-proposer 检查 fatal（现场：`base=575 end_caps=5`，generation 1064，5 个 EndCap 本以 base 574/epoch 17 认证 start root，sync 到 575 后 finalize 盲升 base 至 575、目标 576 进入 epoch 18；日志备份在远端 `/tmp/psy-jtmb-logs-before-final-20261104/`，本地副本同路径）。修复：`finalize_with_tree` 的 proof base 改用 seal 时快照 `self.status.gathering_checkpoint_id`；合法 proof base/owned generation 保留，proposer 检查未删除。回归测试 `finalize_pins_proof_base_against_midcycle_head_sync`（pre-fix 失败 / post-fix 通过）；全量 `psy_node_common --release` 回归对 HEAD baseline 零新增失败。注意：该修复是 Plonky2 共用流程，且尚未在隔离 JTMB 栈上做跨 epoch 实弹压测（上一轮 100/100 通过未跨 epoch 边界，不能作为证据）。
