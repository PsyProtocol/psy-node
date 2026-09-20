//! Write-side adoption of a verified history candidate.

use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;
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
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher},
    protocol::core_types::QNetworkTypesConfig,
};

use crate::realm::processor::db::PsyRealmDatabaseProcessor;

use super::{CheckpointIdentity, VerifiedHistoryCandidate};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
            + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
            + Send
            + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    >
    PsyRealmDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
        CoordinatorClient,
    >
where
    N::HasherBase: 'static + Send + Sync + MerkleZeroHasher<N::QHash> + FieldQHasher<N::F, N::QHash>,
{
    pub async fn ensure_uncommitted_processing_ids(&mut self, checkpoint_id: u64) -> anyhow::Result<()> {
        let pending_id = self.state.processing_unique_pending_id;
        let mapped_checkpoint = self.db.get_checkpoint_id_for_unique_pending_id(pending_id).await?;
        if pending_id != 0 && mapped_checkpoint == Some(checkpoint_id) {
            return Ok(());
        }
        let (pending_id, proc_checkpoint_unique_id) =
            if let Some(ids) = self.db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await? {
                ids
            } else if pending_id != 0 && mapped_checkpoint.is_none() {
                return Ok(());
            } else {
                self.db.inc_unique_pending_id(1).await?
            };
        self.state.processing_unique_pending_id = pending_id;
        self.state.processing_proc_checkpoint_unique_id = proc_checkpoint_unique_id;
        self.temp_db
            .set_unique_pending_ids(&self.state.realm_identifier, pending_id, proc_checkpoint_unique_id)
            .await?;
        Ok(())
    }

    pub async fn apply_history_proposal(
        &mut self,
        included: &CheckpointIdentity,
        verified: VerifiedHistoryCandidate<N::F, N::QHash>,
    ) -> anyhow::Result<(PsyPreparedRealmBlockStateUpdates<N::QHash>, Vec<u8>)> {
        let VerifiedHistoryCandidate {
            updates,
            state_updates,
            coordinator_update,
        } = verified;
        self.ensure_uncommitted_processing_ids(included.checkpoint_id).await?;
        self.state.processing_checkpoint_id = included.checkpoint_id;
        self.state.processing_checkpoint_root = coordinator_update.checkpoint_sync_info.checkpoint_tree_root;
        self.state.processing_realm_start_root = updates.old_realm_root;
        self.state.processing_realm_end_root = updates.new_realm_root;
        if self.state.last_committed_checkpoint_id >= included.checkpoint_id {
            anyhow::ensure!(
                self.state.last_committed_realm_end_root == updates.new_realm_root,
                "InvalidStateUpdates at C={}: committed realm root does not match candidate; refusing second FFS",
                included.checkpoint_id
            );
        } else {
            self.commit_state(
                &coordinator_update,
                &updates,
                ProvingJobCircuitType::GUTANoChange,
                vec![],
            )
            .await?;
        }
        Ok((updates, state_updates))
    }
}
