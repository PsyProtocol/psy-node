use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::realm::processor::db::PsyRealmDatabaseProcessor;

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
    pub async fn run_sanity_check(&self, _location: &str) -> anyhow::Result<()> {
        /*
        let latest_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        let start_checkpoint_id = if latest_checkpoint_id >= 5 { latest_checkpoint_id - 4 } else { 0 };
        tracing::info!(
            "[SANITY_CHECK: {}] Printing last 5 checkpoint roots and leaves from ID {} to {}",
            start_checkpoint_id,
            latest_checkpoint_id,
            location
        );
        for checkpoint_id in start_checkpoint_id..=latest_checkpoint_id {
            let local_checkpoint_tree_merkle_proof: MerkleProofCore<N::QHash> = self
                .checkpoint_tree_backup_manager
                .checkpoint_tree
                .get_merkle_proof_for_leaf(checkpoint_id)
                .to_append_proof::<N::HasherBase>();
            let local_db_merkle_proof: MerkleProofCore<N::QHash> = self.db.checkpoint_tree_get_merkle_proof(checkpoint_id, checkpoint_id).await?;
            let coordinator_merkle_proof: MerkleProofCore<N::QHash> =
                self.coordinator_client.rc_get_checkpoint_tree_merkle_proof(checkpoint_id).await?;
            let local_checkpoint_tree_merkle_proof_valid = local_checkpoint_tree_merkle_proof.verify::<N::HasherBase>();
            let local_db_merkle_proof_valid = local_db_merkle_proof.verify::<N::HasherBase>();
            let coordinator_merkle_proof_valid = coordinator_merkle_proof.verify::<N::HasherBase>();
            println!("CHECKPONT ID: {}: [local_checkpoint_tree_merkle_proof(valid = {}).root: {:?} | local_db_merkle_proof(valid = {}).root: {:?} | coordinator_merkle_proof(valid = {}).root: {:?}]", checkpoint_id, local_checkpoint_tree_merkle_proof_valid, local_checkpoint_tree_merkle_proof.root, local_db_merkle_proof_valid, local_db_merkle_proof.root, coordinator_merkle_proof_valid, coordinator_merkle_proof.root);
            println!("CHECKPONT ID: {}: [local_checkpoint_tree_merkle_proof.value: {:?} | local_db_merkle_proof.value: {:?} | coordinator_merkle_proof.value: {:?}]", checkpoint_id, local_checkpoint_tree_merkle_proof.value, local_db_merkle_proof.value, coordinator_merkle_proof.value);

            if local_db_merkle_proof.root != coordinator_merkle_proof.root {
                tracing::error!("[SANITY_CHECK: {}] CRITICAL: Checkpoint Tree Root Mismatch at checkpoint ID {}: local_db_merkle_proof.root: {:?} vs coordinator_merkle_proof.root: {:?}", location, checkpoint_id, local_db_merkle_proof.root, coordinator_merkle_proof.root);
            }
            if local_checkpoint_tree_merkle_proof.root != coordinator_merkle_proof.root {
                tracing::error!("[SANITY_CHECK: {}] CRITICAL: Checkpoint Tree Root Mismatch at checkpoint ID {}: local_checkpoint_tree_merkle_proof.root: {:?} vs coordinator_merkle_proof.root: {:?}", location, checkpoint_id, local_checkpoint_tree_merkle_proof.root, coordinator_merkle_proof.root);
            }
        }
        */
        Ok(())
    }
}
