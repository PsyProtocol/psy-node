use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::coordinator::processor::{db::DatabaseCheckState, PsyCoordinatorProcessor};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >
    PsyCoordinatorProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    >
{
    pub async fn ensure_backup_restored_if_necessary(&mut self) -> anyhow::Result<()> {
        let database_check_state = self.db.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsRecovery {
            tracing::info!("Restoring coordinator processor state from backup...");
        }

        Ok(())
    }
}
