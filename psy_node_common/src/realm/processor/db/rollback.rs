use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::{
    constants::stale_checkpoint::STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF,
    job::job_id::QProvingJobDataID,
};
use psy_data::{
    node::realm_processor::RealmProcessorCoreState,
    protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    },
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
        PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::QStandardWorkerQueuePublisher,
    },
    store::{
        pending_generation_identity::PendingGenerationContext,
        rollback_runtime_rebuild::{
            RollbackRuntimeRebuildDirective, RollbackRuntimeRebuildReport,
        },
        traits::proof_store::QParthProofStore,
    },
};

use crate::realm::processor::db::PsyRealmDatabaseProcessor;

#[allow(clippy::too_many_arguments)]
fn rebuilt_realm_processor_state<Hash: Copy>(
    previous: &RealmProcessorCoreState<Hash>,
    target_checkpoint: u64,
    target_pending: u64,
    target_proc: u128,
    checkpoint_root: Hash,
    realm_root: Hash,
    processing: PendingGenerationContext,
    gathering: PendingGenerationContext,
) -> RealmProcessorCoreState<Hash> {
    let mut rebuilt = RealmProcessorCoreState::new_basic(
        previous.chain_id,
        previous.realm_identifier,
        target_checkpoint,
        target_pending,
        target_proc,
        checkpoint_root,
        realm_root,
    );
    rebuilt.processing_unique_pending_id = processing.pending_id().get();
    rebuilt.processing_proc_checkpoint_unique_id =
        processing.proc_checkpoint_id().as_u128();
    rebuilt.gathering_unique_pending_id = gathering.pending_id().get();
    rebuilt.gathering_proc_checkpoint_unique_id = gathering.proc_checkpoint_id().as_u128();
    rebuilt.coordinator_head_synced_checkpoint_id = target_checkpoint;
    rebuilt.coordinator_head_synced_checkpoint_root = checkpoint_root;
    rebuilt
}

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
    N::HasherBase: 'static + Send + Sync,
{
    /// Rebuild only Realm process-local state after the global restore owner
    /// has restored and verified the target rows.
    ///
    /// The caller must obtain `directive` from the Coordinator control plane;
    /// this method deliberately does not guess a task from the Realm keyspace.
    /// It does not publish an authority head, resume the actor, or write a
    /// completion row. Those operations remain owned by the all-participant
    /// barrier and its transport boundary.
    pub(in crate::realm::processor) async fn rebuild_realm_runtime_after_rollback(
        &mut self,
        directive: RollbackRuntimeRebuildDirective<N::QHash>,
    ) -> anyhow::Result<RollbackRuntimeRebuildReport<N::QHash>> {
        let authority = AuthorityScope::Realm {
            realm_id: self.state.realm_identifier.realm_id,
            realm_sub_id: self.state.realm_identifier.realm_sub_id,
        };
        let network = NetworkId::try_from_chain_id(self.state.chain_id)?;
        if directive.authority() != authority || directive.target().network_id() != network {
            anyhow::bail!("Realm rollback runtime directive identity mismatch")
        }
        let processing = directive.processing().ok_or_else(|| {
            anyhow::anyhow!("Realm rollback runtime directive is missing processing")
        })?;
        let gathering = directive.gathering().ok_or_else(|| {
            anyhow::anyhow!("Realm rollback runtime directive is missing gathering")
        })?;
        let target_checkpoint = directive.target().checkpoint().checkpoint_id().get();

        // All durable target rows are validated before the backup file or
        // process-local state is touched. Physical restore must already have
        // made T the latest visible checkpoint.
        let latest_checkpoint = self.db.get_latest_checkpoint_id().await?;
        if latest_checkpoint != target_checkpoint {
            anyhow::bail!(
                "Realm rollback target is not the latest restored checkpoint: target={}, latest={}",
                target_checkpoint,
                latest_checkpoint,
            )
        }
        let (target_pending, target_proc) = match self
            .db
            .get_unique_pending_id_for_checkpoint_id(target_checkpoint)
            .await?
        {
            Some(mapping) => mapping,
            None if target_checkpoint == 0 => (0, 0u128),
            None => anyhow::bail!(
                "Realm rollback target checkpoint {} has no pending mapping",
                target_checkpoint,
            ),
        };
        let checkpoint_root = self
            .db
            .checkpoint_tree_get_root_hash(target_checkpoint)
            .await?;
        let realm_root = self
            .db
            .global_user_tree_get_node(target_checkpoint, self.realm_root_node)
            .await?;

        let required_history_start = target_checkpoint
            .saturating_sub(STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF)
            .max(if target_checkpoint
                >= self.checkpoint_tree_backup_manager.max_checkpoints_to_keep
            {
                target_checkpoint
                    - self.checkpoint_tree_backup_manager.max_checkpoints_to_keep
                    + 1
            } else {
                0
            });
        self.checkpoint_tree_backup_manager
            .hard_reset_and_truncate(required_history_start)
            .await?;
        self.checkpoint_tree_backup_manager
            .sync_from_database::<S>(&self.db, 1000, target_checkpoint)
            .await?;
        if self
            .checkpoint_tree_backup_manager
            .get_current_checkpoint_tree_root_head()
            != checkpoint_root
        {
            anyhow::bail!("Realm checkpoint backup root mismatch after rollback rebuild")
        }

        let rebuilt = rebuilt_realm_processor_state(
            &self.state,
            target_checkpoint,
            target_pending,
            target_proc,
            checkpoint_root,
            realm_root,
            processing,
            gathering,
        );
        self.state = rebuilt;
        self.needs_revert = false;

        self.temp_db
            .set_unique_pending_ids(
                &self.state.realm_identifier,
                processing.pending_id().get(),
                processing.proc_checkpoint_id().as_u128(),
            )
            .await?;
        self.temp_db
            .set_gathering_unique_pending_ids(
                &self.state.realm_identifier,
                gathering.pending_id().get(),
                gathering.proc_checkpoint_id().as_u128(),
            )
            .await?;
        self.temp_db
            .clear_current_pending_context(&self.state.realm_identifier)
            .await?;
        self.guta_queue_key_status_manager
            .set_unique_id(gathering.proc_checkpoint_id().as_u128())?;
        self.shared_state.update_from_core_state(&self.state).await?;

        // Fresh reads bracket the local mutation. A report is produced only
        // if T and its identity rows remained exact throughout reconstruction.
        if self.db.get_latest_checkpoint_id().await? != target_checkpoint
            || self
                .db
                .get_unique_pending_id_for_checkpoint_id(target_checkpoint)
                .await?
                .unwrap_or((0, 0u128))
                != (target_pending, target_proc)
            || self
                .db
                .checkpoint_tree_get_root_hash(target_checkpoint)
                .await?
                != checkpoint_root
            || self
                .db
                .global_user_tree_get_node(target_checkpoint, self.realm_root_node)
                .await?
                != realm_root
        {
            anyhow::bail!("Realm restored target changed during runtime rebuild")
        }

        let report = RollbackRuntimeRebuildReport::try_after_exact_rebuild(
            &directive,
            self.checkpoint_tree_backup_manager.min_backed_up_checkpoint_id,
            self.checkpoint_tree_backup_manager.next_backup_checkpoint_id,
            self.checkpoint_tree_backup_manager
                .get_current_checkpoint_tree_root_head(),
            self.state.last_committed_checkpoint_id,
            target_checkpoint,
            realm_root,
            Some(processing),
            Some(gathering),
        )?;
        tracing::warn!(
            "Realm rollback runtime rebuilt at checkpoint {} with processing {} and gathering {}; awaiting global report persistence and publish",
            target_checkpoint,
            processing.pending_id().get(),
            gathering.pending_id().get(),
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{data::hash::hash256::Hash256, node::realm_identifier::QRealmIdentifier};
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };
    use psy_data::node::realm_processor::RealmProcessorCoreState;
    use psy_node_core::store::{
        pending_generation::ProcNamespacePrefix,
        pending_generation_identity::PendingGenerationContext,
        typed::UniquePendingId,
    };

    use super::rebuilt_realm_processor_state;

    #[test]
    fn state_rebuild_keeps_target_history_and_installs_fresh_work_contexts() {
        let realm_identifier = QRealmIdentifier {
            realm_id: 7,
            realm_sub_id: 2,
        };
        let old = RealmProcessorCoreState::new_basic(
            1337,
            realm_identifier,
            50,
            90,
            91,
            Hash256([1; 32]),
            Hash256([2; 32]),
        );
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let prefix = ProcNamespacePrefix::for_authority(
            network,
            AuthorityScope::Realm {
                realm_id: 7,
                realm_sub_id: 2,
            },
        );
        let processing_pending = UniquePendingId::try_new(101).unwrap();
        let gathering_pending = UniquePendingId::try_new(102).unwrap();
        let processing = PendingGenerationContext::try_from_legacy(
            processing_pending.get(),
            prefix.derive_proc_id(processing_pending).as_u128(),
        )
        .unwrap();
        let gathering = PendingGenerationContext::try_from_legacy(
            gathering_pending.get(),
            prefix.derive_proc_id(gathering_pending).as_u128(),
        )
        .unwrap();
        let checkpoint_root = Hash256([3; 32]);
        let realm_root = Hash256([4; 32]);
        let rebuilt = rebuilt_realm_processor_state(
            &old,
            40,
            70,
            71,
            checkpoint_root,
            realm_root,
            processing,
            gathering,
        );

        assert_eq!(rebuilt.chain_id, 1337);
        assert_eq!(rebuilt.realm_identifier, realm_identifier);
        assert_eq!(rebuilt.last_committed_checkpoint_id, 40);
        assert_eq!(rebuilt.last_committed_unique_pending_id, 70);
        assert_eq!(rebuilt.last_committed_proc_checkpoint_unique_id, 71);
        assert_eq!(rebuilt.last_committed_checkpoint_root, checkpoint_root);
        assert_eq!(rebuilt.last_committed_realm_start_root, realm_root);
        assert_eq!(rebuilt.last_committed_realm_end_root, realm_root);
        assert_eq!(rebuilt.processing_checkpoint_id, 40);
        assert_eq!(rebuilt.processing_unique_pending_id, 101);
        assert_eq!(
            rebuilt.processing_proc_checkpoint_unique_id,
            processing.proc_checkpoint_id().as_u128(),
        );
        assert_eq!(rebuilt.processing_checkpoint_root, checkpoint_root);
        assert_eq!(rebuilt.processing_realm_start_root, realm_root);
        assert_eq!(rebuilt.processing_realm_end_root, realm_root);
        assert_eq!(rebuilt.gathering_checkpoint_id, 40);
        assert_eq!(rebuilt.gathering_unique_pending_id, 102);
        assert_eq!(
            rebuilt.gathering_proc_checkpoint_unique_id,
            gathering.proc_checkpoint_id().as_u128(),
        );
        assert_eq!(rebuilt.gathering_checkpoint_root, checkpoint_root);
        assert_eq!(rebuilt.gathering_realm_start_root, realm_root);
        assert_eq!(rebuilt.coordinator_head_synced_checkpoint_id, 40);
        assert_eq!(rebuilt.coordinator_head_synced_checkpoint_root, checkpoint_root);
        assert!(!rebuilt.should_revert_processing_changes);
    }

    #[test]
    fn realm_runtime_rebuild_is_local_and_cannot_publish() {
        let source = include_str!("rollback.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for required in [
            "get_latest_checkpoint_id",
            "get_unique_pending_id_for_checkpoint_id",
            "checkpoint_tree_get_root_hash",
            "global_user_tree_get_node",
            "hard_reset_and_truncate",
            "sync_from_database",
            "clear_current_pending_context",
            "RollbackRuntimeRebuildReport::try_after_exact_rebuild",
        ] {
            assert!(source.contains(required), "missing {required}");
        }
        for forbidden in [
            "complete_rollback_realm_barrier",
            "complete_rollback(",
            "publish_current_pending_context",
            "set_latest_checkpoint_id",
            "inc_unique_pending_id",
        ] {
            assert!(!source.contains(forbidden), "forbidden {forbidden}");
        }
    }

    #[test]
    fn realm_runtime_rebuild_does_not_guess_a_local_control_keyspace() {
        let source = include_str!("rollback.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(source.contains("directive: RollbackRuntimeRebuildDirective"));
        assert!(!source.contains("read_selected_directive"));
        assert!(!source.contains("rollback_runtime_rebuild_store"));
    }
}
