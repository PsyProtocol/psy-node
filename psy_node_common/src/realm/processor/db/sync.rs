use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Ok;
use parth_common::memory_stores::{mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        tag_tree::TagTreeMerkleProof,
        traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
    },
    data::{
        hash::{checkpointed_merkle_node::CheckpointedMerkleHash, merkle_node_key::SimpleMerkleNodeKey},
        queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey},
    },
    generic_traits::psy_debug_printable::PsyDebugPrintable,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
    QCoreProcCheckpointUniqueId,
};
use psy_core::{
    constants::stale_checkpoint::{STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF, STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF},
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    node::realm_processor::{RealmProcessorCoreState, RealmProcessorCoreStateWrapper},
    prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate, PsyRealmCoordinatorUpdate},
    protocol::{
        checkpoint_transition_hash::CheckpointStateHashTransition,
        verifiable_checkpoint_transition::{self, PsyVerifiableCheckpointTransition, PsyVerifiableCheckpointTransitionWithProof},
    },
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    v1::qdata::{
        checkpoint::QEDL2BlockState, checkpoint_sync::PQEDCheckpointSyncInfoCompact, contract::PsyDeployContractQueueItem,
        public_key::PZKPublicKeyInfo,
    },
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::{checkpoint_tree::CheckpointTreeBackupManager, coordinator::generate_coordinator_output_from_backups},
    constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID, PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
    },
    queue::gatherer::QueueKeyStatusManager,
    realm::{
        processor::{db::PsyRealmDatabaseProcessor, processor_shared_status::{PsyRealmProcessorSharedStatus, PsyRealmProcessorSharedStatusWrapper}},
        queue_key::RealmProvingWorkQueueKey,
    },
};
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
    pub async fn sync_to_coordinator_set_checkpoint_id(&mut self) -> anyhow::Result<()> {
        self.checkpoint_tree_backup_manager
            .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
            .await?;
        let latest_db_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        let latest_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        let latest_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        let db_root = self.db.checkpoint_tree_get_root_hash(latest_db_checkpoint_id).await?;
        if latest_checkpoint_id == latest_db_checkpoint_id && latest_checkpoint_root == db_root {
            tracing::info!("Coordinator processor database is already synced to latest checkpoint ID: {} and root: {:?}", latest_checkpoint_id, latest_checkpoint_root);
            return Ok(());
        }
        let latest_db_l2_info: QEDL2BlockState = self.db.get_l2_block_state(latest_db_checkpoint_id).await?;

        tracing::info!("Syncing checkpoint metadata from checkpoint ID {} to {}.", latest_db_checkpoint_id, latest_checkpoint_id);
        for checkpoint_id in latest_db_checkpoint_id..=latest_checkpoint_id {
            let sync_info: PsyRealmCoordinatorUpdate<N::F, N::QHash> = self
                .coordinator_client
                .rc_get_realm_sync_info(checkpoint_id)
                .await?;

            self.db
                .set_l2_block_state(checkpoint_id, &sync_info.checkpoint_sync_info.block_state)
                .await?;
            self.db
                .set_checkpoint_global_state_roots(checkpoint_id, &sync_info.checkpoint_sync_info.state_roots)
                .await?;
            self.db
                .set_checkpoint_leaf_data(checkpoint_id, &sync_info.checkpoint_sync_info.checkpoint_leaf)
                .await?;
            self.db
                .checkpoint_tree_set_leaf_hash(checkpoint_id, sync_info.checkpoint_sync_info.checkpoint_leaf_hash)
                .await?;
            self.db
                .set_checkpoint_root_hash_to_id_mapping(sync_info.checkpoint_sync_info.checkpoint_tree_root, sync_info.checkpoint_sync_info.checkpoint_id)
                .await?;

            tracing::debug!("Synced metadata for checkpoint ID: {}", checkpoint_id);
        }

        // Update the latest block state to the newest checkpoint
        let latest_sync_info: PsyRealmCoordinatorUpdate<N::F, N::QHash> = self
            .coordinator_client
            .rc_get_realm_sync_info(latest_checkpoint_id)
            .await?;
        self.db
            .set_l2_latest_block_state(&latest_sync_info.checkpoint_sync_info.block_state)
            .await?;
        if latest_db_l2_info.next_contract_id != latest_sync_info.checkpoint_sync_info.block_state.next_contract_id {
            tracing::warn!("Next contract ID mismatch when syncing to coordinator. Latest DB L2 info next contract ID: {}, New sync info next contract ID: {}. Updating to new sync info value.",
                latest_db_l2_info.next_contract_id, latest_sync_info.checkpoint_sync_info.block_state.next_contract_id);
            let batch_size = 1000u64;
            let full_batches = (latest_sync_info.checkpoint_sync_info.block_state.next_contract_id - latest_db_l2_info.next_contract_id) / (batch_size as u32);
            let remainder = (latest_sync_info.checkpoint_sync_info.block_state.next_contract_id - latest_db_l2_info.next_contract_id) % (batch_size as u32);
            for i in 0..(full_batches as u64) {
                let start_id = latest_db_l2_info.next_contract_id as u64 + i * batch_size;
                let end_id = start_id + batch_size;
                let heights:Vec<(u64, u8)> = self.coordinator_client.rc_get_contract_tree_state_heights(latest_checkpoint_id, (start_id..end_id).collect()).await?.into_iter().enumerate().map(|(i,b)| (i as u64 + start_id, b)).collect();
                println!("Fetched contract tree heights for contract IDs {} to {} during sync to coordinator {:?}.", start_id, end_id, heights);

                self.db
                    .set_contract_tree_heights(latest_checkpoint_id, &heights)
                    .await?;
                tracing::info!("Initialized contract state tree leaves for contract IDs {} to {} during sync to coordinator.", start_id, end_id);
            }

            if remainder != 0 {
                let start_id = latest_db_l2_info.next_contract_id as u64 + full_batches as u64 * batch_size;
                let end_id = start_id + remainder as u64;
                let heights:Vec<(u64, u8)> = self.coordinator_client.rc_get_contract_tree_state_heights(latest_checkpoint_id, (start_id..end_id).collect()).await?.into_iter().enumerate().map(|(i,b)| (i as u64 + start_id, b)).collect();
                println!("Fetched contract tree heights for contract IDs {} to {} during sync to coordinator {:?}.", start_id, end_id, heights);
                self.db
                    .set_contract_tree_heights(latest_checkpoint_id, &heights)
                    .await?;
            }
        }

        self.db
            .set_unique_pending_id_checkpoint_id_mapping(self.state.processing_unique_pending_id, latest_checkpoint_id)
            .await?;
        self.db.set_checkpoint_id_to_unique_pending_id_mapping(latest_checkpoint_id, self.state.processing_unique_pending_id, &self.state.processing_proc_checkpoint_unique_id).await?;
        self.db.set_latest_checkpoint_id(latest_checkpoint_id).await?;

        self.state.coordinator_head_synced_checkpoint_id = latest_checkpoint_id;
        self.state.coordinator_head_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.processing_checkpoint_root = latest_checkpoint_root;
        self.state.gathering_checkpoint_root = latest_checkpoint_root;
        self.state.processing_checkpoint_id = latest_checkpoint_id;
        self.state.gathering_checkpoint_id = latest_checkpoint_id;
        tracing::info!("Synchronized coordinator processor database to checkpoint ID: {}", latest_checkpoint_id);
        Ok(())
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
    pub async fn sync_with_coordinator(&mut self) -> anyhow::Result<()> {
        let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
        let last_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        if coordinator_latest_checkpoint_id < last_synced_checkpoint_id {
            anyhow::bail!("Local checkpoint ID ({}) is ahead of coordinator's latest checkpoint ID ({}). This indicates an inconsistency between the local database and the coordinator.",
                last_synced_checkpoint_id, coordinator_latest_checkpoint_id);
        }
        self.checkpoint_tree_backup_manager.sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000).await?;
        self.state.coordinator_head_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        self.state.coordinator_head_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        self.state.processing_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.gathering_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.processing_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;
        self.state.gathering_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;

        Ok(())
    }

    pub async fn wait_for_realm_update_sync_with_coordinator(&mut self, new_realm_root: N::QHash) -> anyhow::Result<PsyRealmCoordinatorUpdate<N::F, N::QHash>> {
        loop {
            tracing::info!("Checking for realm root update to new value: {:?}...", new_realm_root);
            let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
            let last_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
            if coordinator_latest_checkpoint_id < last_synced_checkpoint_id {
            anyhow::bail!("Local checkpoint ID ({}) is ahead of coordinator's latest checkpoint ID ({}). This indicates an inconsistency between the local database and the coordinator.",
                last_synced_checkpoint_id, coordinator_latest_checkpoint_id);
            }
            self.checkpoint_tree_backup_manager.sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000).await?;
            self.state.coordinator_head_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
            self.state.coordinator_head_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

            let latest_realm_root: CheckpointedMerkleHash<N::QHash> = self
                .coordinator_client
                .rc_get_realm_root_and_last_modified_checkpoint(self.state.coordinator_head_synced_checkpoint_id, self.state.realm_id_u64)
                .await?;
            if latest_realm_root.value == new_realm_root {
                tracing::info!("Realm root has been updated to the new value: {:?} at checkpoint ID: {}", new_realm_root, latest_realm_root.checkpoint_id);
                self.state.last_committed_checkpoint_id = latest_realm_root.checkpoint_id;
                self.state.last_committed_realm_end_root = latest_realm_root.value;
                self.state.last_committed_proc_checkpoint_unique_id = self.state.processing_proc_checkpoint_unique_id;
                self.state.last_committed_unique_pending_id = self.state.processing_unique_pending_id;
                let sync_info : PsyRealmCoordinatorUpdate<N::F, N::QHash> = self.coordinator_client.rc_get_realm_sync_info(latest_realm_root.checkpoint_id).await?;
                self.db.set_realm_rewards_tag_tree_top_proof_at_checkpoint_id(latest_realm_root.checkpoint_id, &sync_info.reward_tree_top_proof).await?;
                self.db.global_user_tree_set_top_tree_merkle_proof(latest_realm_root.checkpoint_id, &sync_info.merkle_proof_to_realm_root).await?;
                self.db.set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(self.state.last_committed_unique_pending_id, &sync_info.reward_tree_top_proof).await?;
                self.db.set_l2_block_state(latest_realm_root.checkpoint_id, &sync_info.checkpoint_sync_info.block_state).await?;
                self.db.set_l2_latest_block_state(&sync_info.checkpoint_sync_info.block_state).await?;
                self.db.set_checkpoint_global_state_roots(latest_realm_root.checkpoint_id, &sync_info.checkpoint_sync_info.state_roots).await?;
                self.db.set_checkpoint_leaf_data(latest_realm_root.checkpoint_id, &sync_info.checkpoint_sync_info.checkpoint_leaf).await?;
                return Ok(sync_info);
            }else{
                tracing::info!("Waiting for realm root to be updated to the new value: {:?}. Current realm root at checkpoint ID {} is {:?}. Retrying...", new_realm_root, latest_realm_root.checkpoint_id, latest_realm_root.value);
                self.coordinator_client.rc_wait_for_next_checkpoint().await?;
            }
        }

    }
}
