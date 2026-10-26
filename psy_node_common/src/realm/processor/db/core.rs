use std::sync::Arc;

use crate::utils::processor_status::ProcessorStatus;

use anyhow::Ok;
use parth_core::{
    crypto::hash::
        traits::ZeroableHash
    ,
    data::{
        hash::merkle_node_key::SimpleMerkleNodeKey,
        queue::queue_key::QPBaseQueueType,
    },
    protocol::core_types::QNetworkTypesConfig,
};
use psy_core::
    job::job_id::QProvingJobDataID
;
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    node::realm_processor::{RealmProcessorCoreState, RealmProcessorCoreStateWrapper},
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::checkpoint_tree::CheckpointTreeBackupManager,
    constants::queue::
        PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID
    ,
    queue::gatherer::QueueKeyStatusManager,
    realm::
        queue_key::RealmProvingWorkQueueKey
    ,
};
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum DatabaseCheckState {
    NeedsGenesis = 0,
    NeedsRecovery = 1,
    Ready = 2,
}

pub struct PsyRealmDatabaseProcessor<
    N: QNetworkTypesConfig,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
    ProofWorkQueue: QStandardWorkerQueuePublisher,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
    FileSystem: TokioLikeFileSystem,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
> {
    // stores
    pub db: Arc<S>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,

    //queues
    pub guta_update_queue: Arc<GUTAUpdateQueue>,
    pub proof_work_queue: Arc<ProofWorkQueue>,

    //checkpoint tree
    pub checkpoint_tree_backup_manager: CheckpointTreeBackupManager<N::HasherBase, N::QHash, FileSystem>,

    // coordinator connection
    pub coordinator_client: Arc<CoordinatorClient>,
    // status
    pub status: ProcessorStatus,
    pub guta_queue_key_status_manager: QueueKeyStatusManager<PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID, PsyRealmUserUpdateQueueItem<N::F, N::QHash>>,
    pub shared_state: RealmProcessorCoreStateWrapper<N::QHash>,
    pub needs_revert: bool,

    // state
    pub state: RealmProcessorCoreState<N::QHash>,

    pub realm_root_node: SimpleMerkleNodeKey,

    // config
    pub circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
}

impl<
        N: QNetworkTypesConfig,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        ProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmDatabaseProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    N::HasherBase: 'static + Send + Sync,
{
    pub async fn print_last_10_checkpoint_roots_and_leaves(&self, location: &str) -> anyhow::Result<()> {
        let latest_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        let start_checkpoint_id = if latest_checkpoint_id >= 10 {
            latest_checkpoint_id - 9
        } else {
            0
        };
        tracing::info!("[{}] Printing last 10 checkpoint roots and leaves from ID {} to {}", start_checkpoint_id, latest_checkpoint_id, location);
        for checkpoint_id in start_checkpoint_id..=latest_checkpoint_id {
            let root_hash = self.db.checkpoint_tree_get_root_hash(checkpoint_id).await?;
            let leaf_hash = self.db.checkpoint_tree_get_leaf_hash(checkpoint_id, checkpoint_id).await?;
            println!(
                "Checkpoint ID: {}, Root Hash: {:?}, Leaf Hash: {:?}",
                checkpoint_id, root_hash, leaf_hash
            );
        }
        Ok(())
    }
    pub async fn get_next_checkpoint_id(&self) -> anyhow::Result<u64> {
        let latest_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        Ok(latest_checkpoint_id + 1)
    }
    pub fn get_proof_worker_queue_key(&self) -> RealmProvingWorkQueueKey<N::QHash, N::JobId> {
        println!(
            "get_proof_worker_queue_key: self.state.processing_proc_checkpoint_unique_id: {:?}",
            self.state.processing_proc_checkpoint_unique_id
        );

        RealmProvingWorkQueueKey {
            realm_id: self.state.realm_id_u64,
            realm_sub_id: self.state.realm_sub_id_u64,
            unique_id: self.state.processing_proc_checkpoint_unique_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        }
    }
    pub async fn get_realm_root_from_db(&self) -> anyhow::Result<N::QHash> {
        let realm_root_hash = self
            .db
            .global_user_tree_get_node(u64::MAX-0xffff, self.realm_root_node)
            .await?;
        Ok(realm_root_hash)
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        ProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmDatabaseProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    N::HasherBase: 'static + Send + Sync,
{
    pub async fn get_reward_tree_root_or_none(
        &self,
        _checkpoint_id: u64,
        unique_pending_id: u64,
        job_id: N::JobId,
    ) -> anyhow::Result<Option<N::QHash>> {
        let temp_store_reward_tree_root: Option<N::QHash> = self
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(
                &self.state.realm_identifier,
                unique_pending_id,
                job_id,
            )
            .await?;
        if temp_store_reward_tree_root.is_some() {
            let root = temp_store_reward_tree_root.unwrap();
            if root != N::QHash::get_zero_value() || unique_pending_id == 0 {
                return Ok(Some(root));
            } else {
                tracing::warn!(
                    "Temporary store returned zero value for reward tree root at unique pending ID: {}. Falling back to permanent store.",
                    unique_pending_id
                );
            }
        }
        let reward_tree_root = self
            .tag_tree_rewards_store
            .rewards_tag_tree_get_root_at_unique_pending_id(unique_pending_id)
            .await?;
        if reward_tree_root == N::QHash::get_zero_value() && unique_pending_id != 0 {
            return Ok(None);
        }
        Ok(Some(reward_tree_root))
    }

    pub async fn get_reward_tree_root(&self, checkpoint_id: u64, unique_pending_id: u64, job_id: N::JobId) -> anyhow::Result<N::QHash> {
        self.get_reward_tree_root_or_none(checkpoint_id, unique_pending_id, job_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Permanent store returned zero value for reward tree root at unique pending ID: {}. This indicates an inconsistency in the database state.",
                    unique_pending_id,
                )
            })
    }

    pub fn print_coordinator_processor_state(&self) {
        tracing::info!(
            r#"======== Realm Processor State ========
[STATE]
{:#?}
[/STATE]
============================================="#,
            self.state,
        );
    }

}

#[cfg(test)]
mod core_tests {
    use parth_core::{
        crypto::hash::traits::ZeroableHash,
        protocol::core_types::QNetworkTreeConstants,
        data::hash::merkle_node_key::SimpleMerkleNodeKey,
        felt::FromPrimitiveValuesFelt,
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_node_core::psy_core_db::traits::full::{
        PsyNodeCoreDatabaseUserStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyNodeGlobalUserTreeDatabaseReader,
    };
    use psy_node_core::psy_temp_db::QTempDBRewardsTreeWriter;

    use crate::realm::processor::db::realm_db_test_env::*;

    #[tokio::test]
    async fn get_next_checkpoint_id_and_proof_queue_key_track_state() -> anyhow::Result<()> {
        let env = RealmDbTestEnv::create().await?;

        // fresh database: next checkpoint after genesis marker 0 is 1
        assert_eq!(env.processor.get_next_checkpoint_id().await?, 1);

        let proof_key = env.processor.get_proof_worker_queue_key();
        assert_eq!(proof_key.realm_id, TEST_REALM_ID);
        assert_eq!(proof_key.realm_sub_id, TEST_REALM_SUB_ID);
        assert_eq!(proof_key.unique_id, 0);
        assert_eq!(proof_key.task_group, 0);
        assert_eq!(proof_key.unique_id, env.processor.state.processing_proc_checkpoint_unique_id);

        env.processor.print_coordinator_processor_state();
        Ok(())
    }

    #[tokio::test]
    async fn get_realm_root_from_db_reads_realm_subtree_root() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;

        let realm_root = env.processor.get_realm_root_from_db().await?;
        // matches the direct db read of the (coordinator height, realm id) node
        let direct = env
            .db
            .global_user_tree_get_node(
                0,
                SimpleMerkleNodeKey { level: N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, index: TEST_REALM_ID },
            )
            .await?;
        assert_eq!(realm_root, direct);
        // genesis users make the realm root a non-zero root
        assert_ne!(realm_root, PHash::default());
        Ok(())
    }

    #[tokio::test]
    async fn print_last_checkpoint_roots_and_leaves_covers_genesis() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.processor.print_last_10_checkpoint_roots_and_leaves("core_tests").await?;
        Ok(())
    }

    #[tokio::test]
    async fn reward_tree_root_reads_temp_store_then_tag_tree() -> anyhow::Result<()> {
        let env = RealmDbTestEnv::create().await?;
        let rid = test_realm_identifier();
        let job_id = QProvingJobDataID::qp_rand_gen();

        // pending id with no data anywhere: the tag-tree store errors, so the
        // strict getter fails
        assert!(env.processor.get_reward_tree_root(0, 5, job_id).await.is_err());

        // seed the permanent tag tree at pending id 0: root comes from there
        let root_key = SimpleMerkleNodeKey::new_root();
        let tag_value = zh(41);
        env.db.rewards_tag_tree_set_node_tag(0, root_key, zh(40), tag_value).await?;
        assert_eq!(env.processor.get_reward_tree_root(0, 0, job_id).await?, tag_value);

        // temp store wins when it has a non-zero value for the pending id
        let temp_value = zh(42);
        env.temp_db.set_proof_miner_rewards_tree_value(&rid, 7, job_id, temp_value).await?;
        assert_eq!(env.processor.get_reward_tree_root(0, 7, job_id).await?, temp_value);

        // a zero temp value at a non-zero pending id falls back to the tag
        // tree, which is zero there => None
        env.db.rewards_tag_tree_set_node_tag(9, root_key, zh(43), PHash::get_zero_value()).await?;
        env.temp_db.set_proof_miner_rewards_tree_value(&rid, 9, job_id, PHash::get_zero_value()).await?;
        assert_eq!(env.processor.get_reward_tree_root_or_none(0, 9, job_id).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn committed_genesis_writes_in_realm_user_leaves() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;

        // genesis has four users, two of which (registration ids 1 and 3) are
        // placed inside realm 1 via the user-id bit strategy
        let user_one = env.db.get_user_leaf(0, 1 << N::REALM_GLOBAL_USER_TREE_HEIGHT).await?;
        assert_eq!(user_one.balance, PF::from_u64_value(2_000));
        let user_three = env
            .db
            .get_user_leaf(0, (1 << N::REALM_GLOBAL_USER_TREE_HEIGHT) | (1 << (N::REALM_GLOBAL_USER_TREE_HEIGHT - 1)))
            .await?;
        assert_eq!(user_three.balance, PF::from_u64_value(4_000));
        Ok(())
    }
}
