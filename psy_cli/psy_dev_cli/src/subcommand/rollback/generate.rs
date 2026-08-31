use std::collections::HashSet;

use anyhow::{Context, ensure};
use async_trait::async_trait;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::QFieldHashable},
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    felt::ToU64Value,
    protocol::core_types::{Q256BitHash, QNetworkTreeConstants, QNetworkTypesConfigHelper},
};
use psy_core::{
    job::job_id::QProvingJobDataID,
    network_config::PsyNetworkLocalDevnetConstants,
};
use psy_io::tokio::TokioStdFileSystem;
use psy_plonky2_circuits::protocol_types::ZKTypesPlonky2GoldilocksPoseidon;
use psy_node_common::{
    backup::{
        coordinator::load_coordinator_memory_trees_from_db,
        realm::load_realm_memory_trees_from_db,
    },
    rollback::{
        CoordinatorCheckpointInfo, RollbackBackupDirectories,
        RollbackCheckpointInfoReader, RollbackPlan, RollbackPlanFromBackupPathsInput,
        RollbackSnapshot, RollbackStateReader, RollbackTempEnumerator, UserTransformParams,
        generate_rollback_plan_from_backup_paths,
    },
};
use psy_node_core::psy_core_db::traits::full::{
    PsyNodeCheckpointObjectDatabaseReader, PsyNodeCheckpointRealmSpecificDatabaseReader,
    PsyNodeCheckpointTransitionZKProofDatabaseReader, PsyNodeCheckpointTreeDatabaseReader,
};
use psy_node_core::store::traits::{
    core_db::{
        CoreDatabaseBidirectionalMappingReader,
        CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseIMTLeafReader,
        CoreDatabaseIMTNextAppendIndexReader, CoreDatabaseKivReader, CoreDatabaseU64Reader,
    },
    temp_db::{QTempDatabaseRawKVEnumeratorBase, QTempDatabaseRawKVReaderBase},
};
use psy_node_redis::store::{StandardFredRedisStore, new_redis_async_pool};
use psy_node_scylla::psy_setup::{
    ScyllaUnifiedPsyStore, setup_psy_scylla_database_store_from_connection_string,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use super::{GenerateArgs, ProcessorConfig, ProcessorRole};

type Network = QNetworkTypesConfigHelper<
    QProvingJobDataID,
    ZKTypesPlonky2GoldilocksPoseidon,
    PsyNetworkLocalDevnetConstants,
>;
type Hash = <Network as parth_core::protocol::core_types::QNetworkHashTypes>::QHash;
type Hasher = <Network as parth_core::protocol::core_types::QNetworkHashTypes>::HasherBase;
type ScyllaStore = ScyllaUnifiedPsyStore<Network, Hash, Hasher>;
type BoundaryTree = SimpleMemoryMerkleRecorderStore<Hasher, Hash>;

enum TargetTrees {
    Coordinator {
        global_user_tree: BoundaryTree,
        global_contract_tree: BoundaryTree,
        user_registration_tree: BoundaryTree,
    },
    Realm {
        global_user_tree: BoundaryTree,
        global_contract_tree: BoundaryTree,
        user_registration_tree: BoundaryTree,
    },
}

impl TargetTrees {
    fn into_tuple(self) -> (BoundaryTree, BoundaryTree, BoundaryTree) {
        match self {
            Self::Coordinator { global_user_tree, global_contract_tree, user_registration_tree }
            | Self::Realm { global_user_tree, global_contract_tree, user_registration_tree } => {
                (global_user_tree, global_contract_tree, user_registration_tree)
            }
        }
    }
}

struct ScyllaRollbackStateReader {
    db: ScyllaStore,
    role: ProcessorRole,
}

#[async_trait]
impl RollbackStateReader for ScyllaRollbackStateReader {
    async fn pending_id_for_checkpoint(&self, checkpoint_id: u64) -> anyhow::Result<Option<u64>> {
        self.db
            .store
            .db_select_u64_value(&self.db.checkpoint_id_to_pending_id_table, checkpoint_id)
            .await
    }

    async fn checkpoint_id_for_pending(&self, pending_id: u64) -> anyhow::Result<Option<u64>> {
        self.db
            .store
            .db_select_u64_value(&self.db.pending_id_to_checkpoint_id_table, pending_id)
            .await
    }

    async fn proc_id_for_pending(&self, pending_id: u64) -> anyhow::Result<Option<u128>> {
        self.db
            .store
            .db_select_one_u128_value_by_u64(&self.db.pending_id_to_pending_proc_id_table, pending_id)
            .await
    }

    async fn root_for_checkpoint(&self, checkpoint_id: u64) -> anyhow::Result<Option<[u8; 32]>> {
        self.db
            .store
            .db_select_one_by_k2::<Hash, u64>(
                &self.db.checkpoint_root_to_checkpoint_id_table,
                &checkpoint_id,
            )
            .await
            .map(|root| root.map(Q256BitHash::into_owned_32bytes))
    }

    async fn imt_leaf_at_target(
        &self,
        tree_id: i64,
        tree_sub_id: i64,
        leaf_index: i64,
        target_checkpoint_id: i64,
    ) -> anyhow::Result<bool> {
        Ok(self
            .db
            .store
            .db_select_imt_leaf(
                &self.db.imt_leaf_table,
                tree_id,
                tree_sub_id,
                leaf_index,
                target_checkpoint_id,
            )
            .await?
            .is_some())
    }
    async fn imt_next_append_index(
        &self,
        tree_id: i64,
        tree_sub_id: i64,
    ) -> anyhow::Result<Option<i64>> {
        self.db
            .store
            .db_select_imt_next_append_index(
                &self.db.imt_next_append_index_table,
                tree_id,
                tree_sub_id,
            )
            .await
    }
    async fn global_checkpoint_tree_delete_path_keys(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<psy_node_common::rollback::MerkleNodeKey>> {
        let proof = self
            .db
            .checkpoint_tree_get_merkle_proof(checkpoint_id, checkpoint_id)
            .await
            .with_context(|| format!("failed to read checkpoint-tree proof for checkpoint {}", checkpoint_id))?;
        let coordinator_transition = if self.role == ProcessorRole::Coordinator {
            let transition = self
                .db
                .get_verifiable_checkpoint_state_transition_and_zkp(checkpoint_id)
                .await
                .with_context(|| format!("failed to read checkpoint transition proof for checkpoint {}", checkpoint_id))?;
            Some((
                transition.info.state_transition.checkpoint_transition.new_checkpoint_tree_root,
                transition.info.state_transition.checkpoint_transition.new_checkpoint_leaf_hash,
            ))
        } else {
            None
        };
        derive_checkpoint_tree_delete_path_keys(self.role, checkpoint_id, &proof, coordinator_transition)
    }
}

fn derive_checkpoint_tree_delete_path_keys(
    role: ProcessorRole,
    checkpoint_id: u64,
    proof: &MerkleProofCore<Hash>,
    coordinator_transition: Option<(Hash, Hash)>,
) -> anyhow::Result<Vec<psy_node_common::rollback::MerkleNodeKey>> {
    ensure!(
        proof.index == checkpoint_id,
        "checkpoint-tree proof index {} does not match checkpoint {}",
        proof.index,
        checkpoint_id
    );
    ensure!(
        proof.siblings.len() == usize::from(Network::CHECKPOINT_TREE_HEIGHT),
        "checkpoint-tree proof for checkpoint {} has {} siblings, expected {}",
        checkpoint_id,
        proof.siblings.len(),
        Network::CHECKPOINT_TREE_HEIGHT
    );
    match (role, coordinator_transition) {
        (ProcessorRole::Coordinator, Some((root, leaf))) => {
            ensure!(proof.root == root, "checkpoint-tree proof root does not match persisted checkpoint transition at checkpoint {}", checkpoint_id);
            ensure!(proof.value == leaf, "checkpoint-tree proof leaf does not match persisted checkpoint transition at checkpoint {}", checkpoint_id);
        }
        (ProcessorRole::Coordinator, None) => anyhow::bail!(
            "Coordinator checkpoint {} requires its persisted checkpoint transition",
            checkpoint_id
        ),
        (ProcessorRole::Realm, None) => {}
        (ProcessorRole::Realm, Some(_)) => anyhow::bail!("Realm checkpoint-tree key derivation must not use a Coordinator transition"),
    }

    let mut key = SimpleMerkleNodeKey::new(Network::CHECKPOINT_TREE_HEIGHT, checkpoint_id);
    let mut keys = Vec::with_capacity(usize::from(Network::CHECKPOINT_TREE_HEIGHT) + 1);
    loop {
        keys.push(psy_node_common::rollback::MerkleNodeKey {
            level: key.level,
            index: key.index,
            checkpoint_id,
        });
        if key.level == 0 {
            break;
        }
        key = key.parent();
    }
    Ok(keys)
}

#[async_trait]
impl RollbackCheckpointInfoReader for ScyllaRollbackStateReader {
    async fn coordinator_checkpoint_info(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<CoordinatorCheckpointInfo> {
        let leaf = self
            .db
            .store
            .db_select_one_kiv_value::<psy_data::v1::qdata::checkpoint::PQEDCheckpointLeaf<
                <Network as parth_core::protocol::core_types::QNetworkHashTypes>::F,
                Hash,
            >>(self.db.checkpoint_leaf_table.as_ref(), checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("checkpoint leaf {checkpoint_id} is missing while deriving checkpoint info"))?;
        let roots = self
            .db
            .store
            .db_select_one_kiv_value::<psy_data::v1::qdata::checkpoint::PQEDCheckpointGlobalStateRoots<Hash>>(
                self.db.checkpoint_state_roots_table.as_ref(), checkpoint_id,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("checkpoint state roots {checkpoint_id} are missing while deriving checkpoint info"))?;
        let previous_roots = self
            .db
            .store
            .db_select_one_kiv_value::<psy_data::v1::qdata::checkpoint::PQEDCheckpointGlobalStateRoots<Hash>>(
                self.db.checkpoint_state_roots_table.as_ref(), checkpoint_id - 1,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("previous checkpoint state roots {} are missing while deriving checkpoint info", checkpoint_id - 1))?;
        ensure!(
            roots.qfhash::<Hasher>() == leaf.global_chain_root,
            "checkpoint {checkpoint_id} state roots do not match checkpoint leaf"
        );
        Ok(CoordinatorCheckpointInfo {
            has_register_users: leaf.stats.pm_jobs_completed.register_users_completed.to_u64_value() > 0,
            has_deploy_contracts: leaf.stats.pm_jobs_completed.deploy_contracts_completed.to_u64_value() > 0,
            contract_root_changed: previous_roots.contract_tree_root != roots.contract_tree_root,
            has_guta_updates: leaf.stats.pm_jobs_completed.gutas_completed.to_u64_value() > 0,
            contract_root: roots.contract_tree_root.into_owned_32bytes(),
        })
    }
}

struct TempEnumerator {
    store: StandardFredRedisStore,
}

#[async_trait]
impl RollbackTempEnumerator for TempEnumerator {
    async fn scan_fields(&self, cursor: u64, count: u32) -> anyhow::Result<(u64, Vec<Vec<u8>>)> {
        let page = self.store.qtdb_raw_kv_scan_fields(cursor, count).await?;
        Ok((page.next_cursor, page.fields))
    }

    async fn get_value(&self, field: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        self.store.qtdb_raw_kv_get_value(field).await
    }
}

struct StoreConfig<'a> {
    scylla_url: &'a str,
    redis_url: &'a str,
    namespace: &'a str,
    realm_id: u64,
    realm_sub_id: u64,
    backups: RollbackBackupDirectories,
}

pub async fn generate(
    args: &GenerateArgs,
    config: &ProcessorConfig,
) -> anyhow::Result<RollbackPlan> {
    let store = store_config(config);
    let (state_reader, temp_enumerator, latest_checkpoint_id, latest_pending_id) =
        open_rollback_stores(&store, args.common.role, args.common.target).await?;
    let snapshot = derive_snapshot(args.common.target, &state_reader.db).await?;
    let (mut global_user_tree, mut global_contract_tree, mut user_registration_tree) =
        derive_target_trees(args.common.role, store.realm_id, args.common.target, &state_reader.db)
            .await?
            .into_tuple();
    let file_system = TokioStdFileSystem {};
    let mut input = RollbackPlanFromBackupPathsInput::<Network, _> {
        role: args.common.role.into(),
        realm_id: store.realm_id,
        realm_sub_id: store.realm_sub_id,
        target_checkpoint_id: args.common.target,
        latest_checkpoint_id,
        latest_pending_id,
        state_reader: &state_reader,
        temp_enumerator: &temp_enumerator,
        checkpoint_info_reader: &state_reader,
        file_system: &file_system,
        backup_directories: &store.backups,
        global_user_tree: &mut global_user_tree,
        global_contract_tree: &mut global_contract_tree,
        user_registration_tree: &mut user_registration_tree,
        reward_realm_ids: reward_realm_ids_for_role(args.common.role, store.realm_id, &args.reward_realm_ids)?,
        user_transform: UserTransformParams {
            coordinator_global_user_tree_height: Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            realm_global_user_tree_height: Network::REALM_GLOBAL_USER_TREE_HEIGHT,
            group_realm_height: Network::GROUP_REALM_HEIGHT,
        },
        snapshot,
        target_contract_state: args.target_contract_state.clone(),
    };
    generate_rollback_plan_from_backup_paths(&mut input)
        .await
        .context("failed to generate rollback plan from authoritative Scylla, Redis, and backups")
}

async fn open_rollback_stores(
    store: &StoreConfig<'_>,
    role: ProcessorRole,
    target: u64,
) -> anyhow::Result<(ScyllaRollbackStateReader, TempEnumerator, u64, u64)> {
    let db = setup_psy_scylla_database_store_from_connection_string::<Network>(
        store.namespace,
        store.scylla_url,
        false,
    )
    .await
    .context("failed to open existing Scylla rollback store")?;
    let latest_checkpoint_id = db
        .get_latest_checkpoint_id()
        .await
        .context("failed to read latest checkpoint marker")?;
    let latest_pending_id = db
        .get_latest_pending_id()
        .await
        .context("failed to read pending counter high-water")?;
    ensure!(
        target <= latest_checkpoint_id,
        "target checkpoint {} is newer than local latest checkpoint {}",
        target,
        latest_checkpoint_id
    );
    let redis_pool = new_redis_async_pool(store.redis_url, 2)
        .await
        .context("failed to open Fred Redis rollback store")?;
    Ok((
        ScyllaRollbackStateReader { db, role },
        TempEnumerator {
            store: StandardFredRedisStore::new(
                redis_pool,
                store.namespace.to_owned(),
                store.realm_id,
                store.realm_sub_id,
            ),
        },
        latest_checkpoint_id,
        latest_pending_id,
    ))
}

async fn derive_snapshot(
    target: u64,
    db: &ScyllaStore,
) -> anyhow::Result<RollbackSnapshot> {
    let target_l2_state = db
        .get_l2_block_state(target)
        .await
        .context("failed to read target L2 block state")?;
    ensure!(
        target_l2_state.checkpoint_id == target,
        "target L2 block state checkpoint {} does not match target {}",
        target_l2_state.checkpoint_id,
        target
    );
    Ok(RollbackSnapshot {
        target_info: hex::encode(PsyCanonicalDatabaseSerializeBaseSingle::psy_ser_to_bytes_vec(&target_l2_state)?),
        worker_reputation_fields: Vec::new(),
    })
}


async fn derive_target_trees(
    role: ProcessorRole,
    realm_id: u64,
    target: u64,
    db: &ScyllaStore,
) -> anyhow::Result<TargetTrees> {
    let roots = db
        .get_checkpoint_global_state_roots(target)
        .await
        .context("failed to read target checkpoint state roots")?;
    match role {
        ProcessorRole::Coordinator => {
            let trees = load_coordinator_memory_trees_from_db::<Network, _>(db, target)
                .await
                .context("failed to reconstruct complete Coordinator target trees from checkpoint-bounded Scylla reads")?;
            ensure!(trees.global_user_tree.get_root() == roots.user_tree_root, "derived Coordinator global user tree root does not match target state roots");
            ensure!(trees.global_contract_tree.get_root() == roots.contract_tree_root, "derived Coordinator global contract tree root does not match target state roots");
            ensure!(trees.user_registration_tree.get_root() == roots.user_registration_tree_root, "derived Coordinator user registration tree root does not match target state roots");
            Ok(TargetTrees::Coordinator {
                global_user_tree: trees.global_user_tree,
                global_contract_tree: trees.global_contract_tree,
                user_registration_tree: trees.user_registration_tree,
            })
        }
        ProcessorRole::Realm => {
            let tree = load_realm_memory_trees_from_db::<Network, _>(db, target, realm_id)
                .await
                .context("failed to reconstruct Realm target subtree from checkpoint-bounded Scylla reads")?
                .global_user_tree;
            let expected_realm_root = db
                .get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(target)
                .await
                .context("failed to read target realm-root proof")?
                .value;
            ensure!(tree.get_root() == expected_realm_root, "derived Realm global user subtree root does not match target processor state");
            Ok(TargetTrees::Realm {
                global_user_tree: tree,
                global_contract_tree: BoundaryTree::new(Network::GLOBAL_CONTRACT_TREE_HEIGHT),
                user_registration_tree: BoundaryTree::new(Network::GLOBAL_USER_TREE_HEIGHT),
            })
        }
    }
}

fn store_config(config: &ProcessorConfig) -> StoreConfig<'_> {
    match config {
        ProcessorConfig::Coordinator(config) => StoreConfig {
            scylla_url: &config.scylla_db_url,
            redis_url: &config.redis_url,
            namespace: &config.db_namespace,
            realm_id: config.coordinator_id,
            realm_sub_id: u64::from(config.coordinator_sub_id),
            backups: RollbackBackupDirectories {
                register_user: config.get_register_users_backup_path(),
                deploy_contract: config.get_deploy_contracts_backup_path(),
                update_contract: config.get_update_contracts_backup_path(),
                coordinator_guta: config.get_guta_updates_backup_path(),
                realm_end_cap: String::new(),
            },
        },
        ProcessorConfig::Realm(config) => StoreConfig {
            scylla_url: &config.scylla_db_url,
            redis_url: &config.redis_url,
            namespace: &config.db_namespace,
            realm_id: config.realm_id,
            realm_sub_id: u64::from(config.realm_sub_id),
            backups: RollbackBackupDirectories {
                register_user: String::new(),
                deploy_contract: String::new(),
                update_contract: String::new(),
                coordinator_guta: String::new(),
                realm_end_cap: config.get_guta_updates_backup_path(),
            },
        },
    }
}

fn reward_realm_ids_for_role(
    role: ProcessorRole,
    own_realm_id: u64,
    cli_ids: &[u64],
) -> anyhow::Result<Vec<u64>> {
    match role {
        ProcessorRole::Realm => {
            if let Some(&foreign) = cli_ids.iter().find(|id| **id != own_realm_id) {
                anyhow::bail!(
                    "Realm generation uses only its own realm id {own_realm_id}; got foreign --reward-realm-id {foreign}"
                );
            }
            Ok(vec![own_realm_id])
        }
        ProcessorRole::Coordinator => {
            ensure!(
                !cli_ids.is_empty(),
                "Coordinator generation requires a nonempty --reward-realm-id set; local config has no realm registry"
            );
            let mut seen = HashSet::with_capacity(cli_ids.len());
            let mut ids = Vec::with_capacity(cli_ids.len());
            for &id in cli_ids {
                ensure!(
                    id < u64::from(Network::MAX_REALMS),
                    "reward realm id {id} is outside the local-devnet realm index space [0, {})",
                    Network::MAX_REALMS
                );
                if seen.insert(id) {
                    ids.push(id);
                }
            }
            Ok(ids)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_contract_state_selection_is_deferred_to_plan_generation() {
        let args = GenerateArgs {
            common: super::super::tests::common(ProcessorRole::Coordinator),
            reward_realm_ids: vec![1],
            target_contract_state: None,
        };
        assert!(args.target_contract_state.is_none());
    }
    #[test]
    fn realm_checkpoint_delete_path_does_not_require_coordinator_transition() {
        let target = 42;
        let latest = 43;
        assert!(target < latest);
        let checkpoint_id = target + 1;
        let proof = MerkleProofCore {
            root: Hash::default(),
            value: Hash::default(),
            index: checkpoint_id,
            siblings: vec![Hash::default(); usize::from(Network::CHECKPOINT_TREE_HEIGHT)],
        };

        let keys = derive_checkpoint_tree_delete_path_keys(ProcessorRole::Realm, checkpoint_id, &proof, None).unwrap();
        assert_eq!(keys.first().unwrap().checkpoint_id, checkpoint_id);
        assert_eq!(keys.len(), usize::from(Network::CHECKPOINT_TREE_HEIGHT) + 1);
        assert!(derive_checkpoint_tree_delete_path_keys(ProcessorRole::Coordinator, checkpoint_id, &proof, None).is_err());
    }



    #[test]
    fn realm_reward_ids_always_own_realm() {
        assert_eq!(
            reward_realm_ids_for_role(ProcessorRole::Realm, 7, &[]).unwrap(),
            vec![7]
        );
        assert_eq!(
            reward_realm_ids_for_role(ProcessorRole::Realm, 7, &[7, 7]).unwrap(),
            vec![7]
        );
    }

    #[test]
    fn realm_rejects_foreign_reward_ids() {
        let err = reward_realm_ids_for_role(ProcessorRole::Realm, 7, &[7, 8])
            .unwrap_err()
            .to_string();
        assert!(err.contains("foreign --reward-realm-id 8"), "{err}");
    }

    #[test]
    fn coordinator_requires_nonempty_deduped_reward_ids() {
        assert!(reward_realm_ids_for_role(ProcessorRole::Coordinator, 0, &[]).is_err());
        assert_eq!(
            reward_realm_ids_for_role(ProcessorRole::Coordinator, 0, &[1, 2, 1]).unwrap(),
            vec![1, 2]
        );
    }

    #[test]
    fn coordinator_rejects_reward_id_outside_realm_index_space() {
        let too_large = u64::from(Network::MAX_REALMS);
        let err = reward_realm_ids_for_role(ProcessorRole::Coordinator, 0, &[too_large])
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside the local-devnet realm index space"), "{err}");
    }
}
