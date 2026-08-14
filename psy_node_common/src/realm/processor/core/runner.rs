
use cf_utils::log_indicator::print_cf_log_indicator;
use parth_core::{
    crypto::hash::traits::HashTo4Felts,
    felt::ToU64Value,
    protocol::core_types::QNetworkTypesConfig,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore}, psy_temp_db::StandardProcessorTempDBStoreBase, queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    }, store::traits::proof_store::QParthProofStore
};
use tokio::time::sleep;

use crate::realm::processor::core::PsyRealmProcessor;

pub async fn run_realm_processor_loop<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync + 'static,
>(
    mut processor: PsyRealmProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
        CoordinatorClient,
    >,
) -> anyhow::Result<()>
where
    N: 'static, FileSystem::File: Send + Sync + 'static,
{
    let realm_id = processor.db.state.realm_id_u64;
    let realm_sub_id = processor.db.state.realm_sub_id_u64;
    processor.db.status.mark_running();
    print_cf_log_indicator("PSY_REALM_PROCESSOR_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    let mut last_slot: u128 = 0;

    loop {
        if processor.db.status.should_run() {
            // tracing::debug!("[REALM] Sync and verify starting...");
            let sync_result = processor.sync_and_verify().await;
            match sync_result {
                Ok(_) => {
                    // tracing::debug!("[REALM] Sync and verify completed.");
                }
                Err(e) => {
                    tracing::error!("[REALM] Sync and verify failed: {:?}, skipping block processing", e);
                    sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            }

            let now = std::time::SystemTime::now();
            let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
            let current_slot = since_epoch.as_millis() / 100;

            if current_slot != last_slot && current_slot % 30 == 0 {
                last_slot = current_slot;
                if !processor.is_scheduled_proposer().await? {
                    tracing::info!(
                        "realm P2P non-proposer skip produce sub_id={} target={}",
                        processor.db.state.realm_sub_id_u64,
                        processor.db.state.processing_checkpoint_id
                    );
                    continue;
                }
                let start_processing_at = std::time::Instant::now();

                tracing::debug!("[REALM] Process block starting...");
                let result = processor.process_block().await;
                let elapsed = start_processing_at.elapsed();
                let duration_ms = elapsed.as_millis();

                match result {
                    Ok(_) => {
                        tracing::debug!("[REALM] Process block finished.");
                        tracing::info!("Generated GUTA Realm update in {}ms at slot {}", duration_ms, current_slot);
                    }
                    Err(e) => {
                        let error = format!("realm process_block failed at slot {}: {:#}", current_slot, e);
                        processor.db.status.set_error(error.clone());
                        tracing::error!("[REALM] Fatal error processing block: {:?}, took {}ms at slot {}; processor parked in Error state until manually restarted", e, duration_ms, current_slot);
                        print_cf_log_indicator("PSY_REALM_PROCESSOR_ERROR", &format!("R{}_{}", realm_id, realm_sub_id));
                    }
                }
            } else {
                sleep(std::time::Duration::from_millis(50)).await;
            }
        } else if processor.db.status.state() == crate::utils::processor_status::ProcessorState::Error {
            sleep(std::time::Duration::from_secs(1)).await;
        } else {
            tracing::info!("Realm Processor is shutting down gracefully.");
            break;
        }
    }
    processor.db.status.mark_stopped();
    print_cf_log_indicator("PSY_REALM_PROCESSOR_STOPPED", &format!("R{}_{}", realm_id, realm_sub_id));

    Ok(())
}
pub async fn run_realm_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync + 'static,
>(
    processor: PsyRealmProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
        CoordinatorClient,
    >,
    guta_gatherer_join_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
) -> anyhow::Result<()>
where
    N: 'static,
    FileSystem::File: Send + Sync + 'static,
{
    let status = processor.db.status.clone();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Ctrl-C signal received, cleaning up...");
            status.begin_shutdown();
            sleep(std::time::Duration::from_secs(5)).await;
            Ok(())
        }
        result = async {
            let (processor_result, gatherer_result) = tokio::try_join!(
                tokio::spawn(run_realm_processor_loop(processor)),
                guta_gatherer_join_handle,
            )?;
            processor_result?;
            gatherer_result?;
            Ok::<(), anyhow::Error>(())
        } => {
            result?;
            tracing::info!("All realm processor threads completed");
            Ok(())
        }
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync + 'static,
    > PsyRealmProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    N: 'static,
    FileSystem::File: Send + Sync + 'static,
{
    /// True when this processor should produce a block for `processing_checkpoint_id`.
    /// Unset P2P / rotation (or disabled rotation) keeps today's single-producer path.
    pub async fn is_scheduled_proposer(&self) -> anyhow::Result<bool> {
        let Some(rotation) = self.rotation.as_ref() else {
            return Ok(true);
        };
        if self.p2p.is_none() || !rotation.is_enabled() {
            return Ok(true);
        }
        let target = self.db.state.processing_checkpoint_id;
        let epoch = parth_common::realm_rotation::epoch(target, rotation.checkpoints_per_epoch);
        let anchor_id = parth_common::realm_rotation::anchor_checkpoint_id(epoch, rotation.checkpoints_per_epoch);
        let anchor_leaf = self.db.db.get_checkpoint_leaf_data(anchor_id).await?;
        let seed_felts = anchor_leaf.stats.random_seed.to_4_felts();
        let anchor_seed = [
            seed_felts[0].to_u64_value(),
            seed_felts[1].to_u64_value(),
            seed_felts[2].to_u64_value(),
            seed_felts[3].to_u64_value(),
        ];
        let scheduled_proposer = rotation
            .proposer_sub_id(self.db.state.realm_id_u64 as u32, target, anchor_seed)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "rotation enabled but proposer_sub_id returned None for realm {} target {}",
                    self.db.state.realm_id_u64,
                    target
                )
            })?;
        Ok(scheduled_proposer == self.db.state.realm_sub_id_u64 as u16)
    }
}
