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
