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
    QCoreProcCheckpointUniqueId,
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
    /// The local generation that sealed `updates`: its backup starts at the transition's old root,
    /// ends at its new root, has a durable pending->proc record, and no checkpoint maps it yet.
    /// Committing under it maps the checkpoint to the backup file and Edge slot updates that
    /// generation wrote.
    async fn load_unmapped_backup_generation(
        &self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        checkpoint_id: u64,
        updates: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
    ) -> anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>> {
        // An unchanged root has no sealed batch; an unsealed or discarded backup header ends at its start root.
        if updates.old_realm_root == updates.new_realm_root {
            return Ok(None);
        }
        let (latest_unique_pending_id, _) = self.db.get_latest_mapped_unique_pending_id().await?;
        let mut first_candidate = self.state.last_committed_unique_pending_id + 1;
        while let Some(generation) = self
            .load_backup_generation_ending_at(
                file_system,
                guta_gatherer_backup_directory,
                first_candidate..=latest_unique_pending_id,
                checkpoint_id,
                updates.new_realm_root,
            )
            .await?
        {
            first_candidate = generation.unique_pending_id + 1;
            if generation.start_root != updates.old_realm_root {
                tracing::debug!(
                    "Backup pending_id {} ends at checkpoint {} realm root but starts at {:?}, not {:?}.",
                    generation.unique_pending_id, checkpoint_id, generation.start_root, updates.old_realm_root
                );
                continue;
            }
            if let Some(mapped_checkpoint_id) = self
                .db
                .get_checkpoint_id_for_unique_pending_id(generation.unique_pending_id)
                .await?
            {
                tracing::debug!(
                    "Backup pending_id {} matches checkpoint {} but already maps to checkpoint {}.",
                    generation.unique_pending_id, checkpoint_id, mapped_checkpoint_id
                );
                continue;
            }
            tracing::info!(
                "Applying history proposal at checkpoint {} under local backup pending_id={}.",
                checkpoint_id, generation.unique_pending_id
            );
            return Ok(Some((generation.unique_pending_id, generation.proc_checkpoint_unique_id)));
        }
        Ok(None)
    }

    pub async fn ensure_uncommitted_processing_ids(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        checkpoint_id: u64,
        updates: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
    ) -> anyhow::Result<()> {
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
            } else if let Some(ids) = self
                .load_unmapped_backup_generation(file_system, guta_gatherer_backup_directory, checkpoint_id, updates)
                .await?
            {
                ids
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
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
    ) -> anyhow::Result<(PsyPreparedRealmBlockStateUpdates<N::QHash>, Vec<u8>)> {
        let VerifiedHistoryCandidate {
            updates,
            state_updates,
            coordinator_update,
        } = verified;
        self.ensure_uncommitted_processing_ids(
            file_system,
            guta_gatherer_backup_directory,
            included.checkpoint_id,
            &updates,
        )
        .await?;
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

#[cfg(test)]
mod tests {
    use parth_core::{protocol::core_types::Q256BitHash, PHash};
    use psy_data::prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate};
    use psy_node_core::psy_core_db::traits::full::{
        PsyNodeCheckpointObjectDatabaseReader, PsyNodeCheckpointObjectDatabaseWriter,
    };
    use psy_node_core::psy_temp_db::QTempDBPendingIdReader;

    use crate::realm::processor::db::realm_db_test_env::*;
    use crate::realm::processor::ffs::{CheckpointIdentity, VerifiedHistoryCandidate};
    use crate::realm::processor::gatherers::realm_end_cap_gatherer::{
        get_new_realm_end_cap_gatherer_backup_file_path, REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32,
    };

    /// Writes the backup header the EndCap gatherer leaves for `unique_pending_id`.
    fn save_backup_header(env: &RealmDbTestEnv, unique_pending_id: u64, start_root: PHash, end_root: PHash) {
        let path = get_new_realm_end_cap_gatherer_backup_file_path(
            TEST_GUTA_BACKUP_DIR, TEST_REALM_ID, TEST_REALM_SUB_ID, unique_pending_id,
        );
        let mut bytes = REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&start_root.into_owned_32bytes());
        bytes.extend_from_slice(&end_root.into_owned_32bytes());
        bytes.extend_from_slice(&2u64.to_le_bytes());
        env.file_system.files.insert(path.to_string_lossy().to_string(), bytes);
    }

    fn history_candidate(
        update: &PsyRealmCoordinatorUpdate<parth_core::PF, PHash>,
        old_realm_root: PHash,
        new_realm_root: PHash,
    ) -> (CheckpointIdentity, VerifiedHistoryCandidate<parth_core::PF, PHash>) {
        let included = CheckpointIdentity {
            checkpoint_id: update.checkpoint_sync_info.checkpoint_id,
            checkpoint_leaf_hash: update.checkpoint_sync_info.checkpoint_leaf_hash.into_owned_32bytes(),
        };
        let updates = PsyPreparedRealmBlockStateUpdates::<PHash> {
            realm_id: TEST_REALM_ID,
            realm_sub_id: TEST_REALM_SUB_ID,
            unique_pending_id: 0,
            proc_checkpoint_unique_id: 0,
            old_realm_root,
            new_realm_root,
            update_global_user_tree_nodes_ffs: vec![],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            update_contract_state_imt_leaves_ffs: vec![],
        };
        (included, VerifiedHistoryCandidate { updates, state_updates: vec![], coordinator_update: update.clone() })
    }

    /// Genesis committed, the coordinator one checkpoint ahead with a changed realm root,
    /// and no local pending mapping for checkpoint 1 (the processor restarted after sealing).
    async fn restarted_after_seal() -> anyhow::Result<(RealmDbTestEnv, PsyRealmCoordinatorUpdate<parth_core::PF, PHash>, PHash, PHash)> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        let old_realm_root = env.seed_consistent_coordinator_head().await?;
        let new_realm_root = zh(71);
        assert_ne!(old_realm_root, new_realm_root);
        let update = env.make_checkpoint_one_update();
        env.seed_checkpoint_one(update.clone(), new_realm_root);
        assert_eq!(env.processor.state.last_committed_checkpoint_id, 0);
        assert_eq!(env.db.get_unique_pending_id_for_checkpoint_id(1).await?, None);
        Ok((env, update, old_realm_root, new_realm_root))
    }

    #[tokio::test]
    async fn backup_generation_scan_skips_mismatched_and_unrecorded_generations() -> anyhow::Result<()> {
        let env = RealmDbTestEnv::create().await?;
        let target_root = zh(71);
        let (mismatched, _) = env.db.inc_unique_pending_id(1).await?;
        // Advancing by two leaves the skipped pending id without a pending->proc record.
        let (recorded_after_gap, _) = env.db.inc_unique_pending_id(2).await?;
        let unrecorded = recorded_after_gap - 1;
        let (missing_file, _) = env.db.inc_unique_pending_id(1).await?;
        let (matching, matching_proc_id) = env.db.inc_unique_pending_id(1).await?;
        assert_eq!(env.db.get_proc_checkpoint_unique_id_for_pending_id(unrecorded).await?, None);
        save_backup_header(&env, mismatched, zh(70), zh(72));
        save_backup_header(&env, unrecorded, zh(70), target_root);
        save_backup_header(&env, recorded_after_gap, zh(70), zh(73));
        assert!(missing_file > recorded_after_gap);
        save_backup_header(&env, matching, zh(70), target_root);

        let found = env.processor.load_backup_generation_ending_at(
            env.file_system.as_ref(), TEST_GUTA_BACKUP_DIR, mismatched..=matching, 1, target_root,
        ).await?.expect("the recorded generation ending at the target root");
        assert_eq!(found.unique_pending_id, matching);
        assert_eq!(found.proc_checkpoint_unique_id, matching_proc_id);
        assert_eq!(found.start_root, zh(70));

        let none = env.processor.load_backup_generation_ending_at(
            env.file_system.as_ref(), TEST_GUTA_BACKUP_DIR, mismatched..=missing_file, 1, target_root,
        ).await?;
        assert_eq!(none, None, "an end-root match without a pending->proc record is never selected");
        Ok(())
    }

    /// Live 2026-11-09: the sealed generation (145669) was committed by the coordinator, the next
    /// generation's seed (145670) was written, the processor restarted, and history adoption mapped
    /// the checkpoint to a fresh pending id that has no backup file or Edge slot updates.
    #[tokio::test]
    async fn history_adopt_commits_under_sealed_local_generation() -> anyhow::Result<()> {
        let (mut env, update, old_realm_root, new_realm_root) = restarted_after_seal().await?;
        let (sealed_pending_id, sealed_proc_id) = env.db.inc_unique_pending_id(1).await?;
        let (seed_pending_id, _) = env.db.inc_unique_pending_id(1).await?;
        save_backup_header(&env, sealed_pending_id, old_realm_root, new_realm_root);
        // The next generation starts on the sealed end root; its header ends there too.
        save_backup_header(&env, seed_pending_id, new_realm_root, new_realm_root);

        let (included, verified) = history_candidate(&update, old_realm_root, new_realm_root);
        env.processor
            .apply_history_proposal(&included, verified, env.file_system.as_ref(), TEST_GUTA_BACKUP_DIR)
            .await?;

        assert_eq!(env.db.get_unique_pending_id_for_checkpoint_id(1).await?, Some((sealed_pending_id, sealed_proc_id)));
        assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(sealed_pending_id).await?, Some(1));
        assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(seed_pending_id).await?, None);
        assert_eq!(env.processor.state.last_committed_checkpoint_id, 1);
        assert_eq!(env.processor.state.last_committed_unique_pending_id, sealed_pending_id);
        assert_eq!(env.processor.state.last_committed_proc_checkpoint_unique_id, sealed_proc_id);
        assert_eq!(env.temp_db.get_unique_pending_ids(&test_realm_identifier()).await?, (sealed_pending_id, sealed_proc_id));
        assert_eq!(env.db.get_current_unique_pending_id().await?.0, seed_pending_id, "no fresh pending id is allocated");
        Ok(())
    }

    #[tokio::test]
    async fn history_adopt_without_sealed_local_generation_allocates_fresh_pending_id() -> anyhow::Result<()> {
        let (mut env, update, old_realm_root, new_realm_root) = restarted_after_seal().await?;
        let (other_pending_id, _) = env.db.inc_unique_pending_id(1).await?;
        let (seed_pending_id, _) = env.db.inc_unique_pending_id(1).await?;
        // Neither header is the sealed transition: one ends elsewhere, the other starts at the new root.
        save_backup_header(&env, other_pending_id, old_realm_root, zh(72));
        save_backup_header(&env, seed_pending_id, new_realm_root, new_realm_root);

        let (included, verified) = history_candidate(&update, old_realm_root, new_realm_root);
        env.processor
            .apply_history_proposal(&included, verified, env.file_system.as_ref(), TEST_GUTA_BACKUP_DIR)
            .await?;

        let (fresh_pending_id, fresh_proc_id) = env.db.get_current_unique_pending_id().await?;
        assert_eq!(fresh_pending_id, seed_pending_id + 1);
        assert_eq!(env.db.get_unique_pending_id_for_checkpoint_id(1).await?, Some((fresh_pending_id, fresh_proc_id)));
        assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(other_pending_id).await?, None);
        assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(seed_pending_id).await?, None);
        assert_eq!(env.processor.state.last_committed_unique_pending_id, fresh_pending_id);
        Ok(())
    }
}
