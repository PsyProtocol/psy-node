use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
use parth_core::{
    QCoreProcCheckpointUniqueId,
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, MerkleZeroHasher, ZeroableHash},
    },
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};
use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::psy_core_db::traits::full::PsyRealmProcessorStore;

use crate::{
    backup::checkpoint_tree::CheckpointTreeBackupManager,
    realm::processor::db::{commit::apply_prepared_realm_checkpoint, DatabaseCheckState},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisBootstrapPlan {
    pub write_checkpoint_zero: bool,
    pub seed_backup_checkpoint_zero: bool,
    pub write_validators: bool,
    pub write_complete: bool,
}

impl GenesisBootstrapPlan {
    pub const SKIP: Self = Self {
        write_checkpoint_zero: false,
        seed_backup_checkpoint_zero: false,
        write_validators: false,
        write_complete: false,
    };
}

pub fn plan_genesis_bootstrap(
    latest_checkpoint_id: u64,
    next_backup_checkpoint_id: u64,
    checkpoint_zero_mapping_missing: bool,
    checkpoint_zero_l2_incomplete: bool,
) -> GenesisBootstrapPlan {
    if latest_checkpoint_id > 0 {
        return GenesisBootstrapPlan::SKIP;
    }
    GenesisBootstrapPlan {
        write_checkpoint_zero: checkpoint_zero_mapping_missing || checkpoint_zero_l2_incomplete,
        seed_backup_checkpoint_zero: next_backup_checkpoint_id == 0,
        write_validators: true,
        write_complete: true,
    }
}

pub fn should_recover_cleared_backup(local_tip: u64, next_backup_checkpoint_id: u64) -> bool {
    next_backup_checkpoint_id == 0 && local_tip > 0
}

pub fn should_hard_reset_ahead_backup(coordinator_tip: u64, next_backup_checkpoint_id: u64) -> bool {
    coordinator_tip == 0 && next_backup_checkpoint_id > 0
}

pub async fn seed_or_check_genesis_backup<Hasher, Hash, FileSystem>(
    manager: &mut CheckpointTreeBackupManager<Hasher, Hash, FileSystem>,
    trusted_leaf: Hash,
) -> anyhow::Result<bool>
where
    Hasher: MerkleZeroHasher<Hash> + Send + Sync + 'static,
    Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Q256BitHash,
    FileSystem: TokioLikeFileSystem,
{
    if manager.next_backup_checkpoint_id == 0 {
        manager.append_checkpoint_leaf_hash(0, trusted_leaf).await?;
        return Ok(true);
    }
    if manager.min_backed_up_checkpoint_id == 0 {
        let existing = manager.checkpoint_tree.get_leaf_value(0);
        anyhow::ensure!(
            existing == trusted_leaf,
            "backup checkpoint 0 leaf does not match trusted genesis hash"
        );
    }
    Ok(false)
}

pub fn classify_genesis_mapping(
    local_latest_checkpoint_id: u64,
    checkpoint_zero_pending: anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>,
) -> anyhow::Result<Option<DatabaseCheckState>> {
    if local_latest_checkpoint_id == 0 && checkpoint_zero_pending?.is_none() {
        return Ok(Some(DatabaseCheckState::NeedsGenesis));
    }
    Ok(None)
}

pub fn classify_genesis_complete_gate(
    genesis_complete: bool,
    local_latest_checkpoint_id: u64,
    checkpoint_zero_pending: anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>,
) -> anyhow::Result<Option<DatabaseCheckState>> {
    if genesis_complete {
        if classify_genesis_mapping(local_latest_checkpoint_id, checkpoint_zero_pending)?.is_some() {
            anyhow::bail!("genesis complete record exists but checkpoint 0 mapping is missing");
        }
        return Ok(None);
    }
    Ok(Some(DatabaseCheckState::NeedsGenesis))
}

pub async fn apply_genesis_checkpoint_records<N, S>(
    db: &S,
    genesis: &PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
    unique_pending_id: u64,
    proc_id: QCoreProcCheckpointUniqueId,
) -> anyhow::Result<()>
where
    N: QNetworkTypesConfig,
    N::HasherBase: MerkleZeroHasher<N::QHash> + FieldQHasher<N::F, N::QHash>,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
{
    let checkpoint_id = genesis.coordinator_update.checkpoint_sync_info.checkpoint_id;
    anyhow::ensure!(
        checkpoint_id == 0,
        "genesis checkpoint write requires checkpoint 0, got {checkpoint_id}"
    );
    let leaf_hash = genesis.coordinator_update.checkpoint_sync_info.checkpoint_leaf_hash;
    let tree_root = genesis.coordinator_update.checkpoint_sync_info.checkpoint_tree_root;
    let siblings = (0..N::CHECKPOINT_TREE_HEIGHT as usize)
        .map(|level| N::HasherBase::get_zero_hash(level))
        .collect();
    let membership = MerkleProofCore::new_from_params::<N::HasherBase>(0, leaf_hash, siblings);
    anyhow::ensure!(
        membership.verify::<N::HasherBase>(),
        "genesis checkpoint 0 membership does not verify"
    );
    anyhow::ensure!(
        membership.value == leaf_hash && membership.root == tree_root,
        "genesis checkpoint 0 membership does not match the trusted bundle"
    );
    anyhow::ensure!(
        membership.compute_root_with_value::<N::HasherBase>(N::QHash::get_zero_value())
            == N::HasherBase::get_zero_hash(N::CHECKPOINT_TREE_HEIGHT as usize),
        "genesis checkpoint 0 empty-leaf root is not the empty checkpoint tree"
    );
    genesis
        .coordinator_update
        .checkpoint_sync_info
        .ensure_valid::<N::HasherBase>(&membership.siblings)?;
    apply_prepared_realm_checkpoint::<N, S>(
        db,
        &genesis.coordinator_update,
        &genesis.prepared_updates,
        unique_pending_id,
        &proc_id,
        &membership,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        classify_genesis_complete_gate, classify_genesis_mapping, plan_genesis_bootstrap, GenesisBootstrapPlan,
    };
    use crate::realm::processor::db::DatabaseCheckState;

    #[derive(Default)]
    struct GenesisApplyLog {
        checkpoint_zero_writes: u32,
        backup_zero_appends: u32,
        validator_writes: u32,
        complete_writes: u32,
    }

    fn apply_plan(log: &mut GenesisApplyLog, plan: GenesisBootstrapPlan) {
        if plan.write_checkpoint_zero {
            log.checkpoint_zero_writes += 1;
        }
        if plan.seed_backup_checkpoint_zero {
            log.backup_zero_appends += 1;
        }
        if plan.write_validators {
            log.validator_writes += 1;
        }
        if plan.write_complete {
            log.complete_writes += 1;
        }
    }

    #[test]
    fn fresh_genesis_bootstraps_complete_db_and_backup_once() {
        let first = plan_genesis_bootstrap(0, 0, true, true);
        assert_eq!(
            first,
            GenesisBootstrapPlan {
                write_checkpoint_zero: true,
                seed_backup_checkpoint_zero: true,
                write_validators: true,
                write_complete: true,
            }
        );
        let mut log = GenesisApplyLog::default();
        apply_plan(&mut log, first);
        apply_plan(&mut log, plan_genesis_bootstrap(0, 1, false, false));
        assert_eq!(log.checkpoint_zero_writes, 1);
        assert_eq!(log.backup_zero_appends, 1);
        assert_eq!(log.validator_writes, 2);
        assert_eq!(log.complete_writes, 2);
    }

    #[test]
    fn restart_after_complete_genesis_does_not_reapply_zero_pending_id() {
        assert_eq!(
            classify_genesis_complete_gate(true, 0, Ok(Some((0, 0)))).expect("complete genesis"),
            None
        );
        assert_eq!(plan_genesis_bootstrap(0, 1, false, false).write_checkpoint_zero, false);
        assert_eq!(
            classify_genesis_mapping(0, Ok(Some((0, 0)))).expect("applied mapping"),
            None
        );
        assert_eq!(plan_genesis_bootstrap(1, 2, true, true), GenesisBootstrapPlan::SKIP);
    }

    #[test]
    fn crash_mid_genesis_restart_finishes_before_recovery() {
        assert_eq!(
            classify_genesis_complete_gate(false, 0, Ok(Some((0, 0)))).expect("mapping is not complete"),
            Some(DatabaseCheckState::NeedsGenesis)
        );
        let after_mapping_before_l2 = plan_genesis_bootstrap(0, 1, false, true);
        assert!(after_mapping_before_l2.write_checkpoint_zero);
        assert!(!after_mapping_before_l2.seed_backup_checkpoint_zero);
        assert!(after_mapping_before_l2.write_validators);
        assert!(after_mapping_before_l2.write_complete);
    }

    #[test]
    fn backup_ahead_of_zero_tip_restart_preserves_history_and_skips_genesis_append() {
        let plan = plan_genesis_bootstrap(0, 8, false, false);
        assert!(!plan.write_checkpoint_zero);
        assert!(!plan.seed_backup_checkpoint_zero);
        assert!(plan.write_validators);
        assert!(plan.write_complete);
    }

    #[test]
    fn mapping_only_or_incomplete_l2_replays_c0_without_append() {
        let mapping_only = plan_genesis_bootstrap(0, 1, false, true);
        assert!(mapping_only.write_checkpoint_zero);
        assert!(!mapping_only.seed_backup_checkpoint_zero);
        let mapping_missing = plan_genesis_bootstrap(0, 1, true, false);
        assert!(mapping_missing.write_checkpoint_zero);
        assert!(!mapping_missing.seed_backup_checkpoint_zero);
    }

    #[test]
    fn cleared_backup_with_positive_tip_triggers_recovery() {
        assert!(super::should_recover_cleared_backup(8, 0));
        assert!(!super::should_recover_cleared_backup(0, 0));
        assert!(!super::should_recover_cleared_backup(8, 8));
    }

    #[test]
    fn coordinator_at_zero_hard_resets_ahead_backup() {
        assert!(super::should_hard_reset_ahead_backup(0, 8));
        assert!(!super::should_hard_reset_ahead_backup(0, 0));
        assert!(!super::should_hard_reset_ahead_backup(8, 8));
    }

    struct EmptyCheckpointReader;

    #[async_trait::async_trait]
    impl psy_node_core::psy_core_db::traits::full::PsyNodeCheckpointTreeDatabaseReader<parth_core::PHash>
        for EmptyCheckpointReader
    {
        async fn checkpoint_tree_get_leaf_hash(
            &self,
            _checkpoint_id: u64,
            _leaf_index: u64,
        ) -> anyhow::Result<parth_core::PHash> {
            anyhow::bail!("empty checkpoint reader has no leaves")
        }
        async fn checkpoint_tree_get_root_hash(&self, _checkpoint_id: u64) -> anyhow::Result<parth_core::PHash> {
            anyhow::bail!("empty checkpoint reader has no roots")
        }
        async fn checkpoint_tree_get_merkle_proof(
            &self,
            _checkpoint_id: u64,
            _leaf_index: u64,
        ) -> anyhow::Result<parth_core::crypto::hash::merkle_proof::MerkleProofCore<parth_core::PHash>> {
            anyhow::bail!("empty checkpoint reader has no proofs")
        }
        async fn checkpoint_tree_get_nodes(
            &self,
            _checkpoint_id: u64,
            _keys: &[parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey],
        ) -> anyhow::Result<Vec<parth_core::PHash>> {
            anyhow::bail!("empty checkpoint reader has no nodes")
        }
    }

    async fn empty_backup_manager() -> anyhow::Result<
        crate::backup::checkpoint_tree::CheckpointTreeBackupManager<
            parth_core::pgoldilocks::PoseidonHasher,
            parth_core::PHash,
            psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem,
        >,
    > {
        let file_system = std::sync::Arc::new(psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem::new());
        crate::backup::checkpoint_tree::CheckpointTreeBackupManager::new_from_file_path(
            file_system,
            16,
            8,
            &EmptyCheckpointReader,
            "local_checkpoints/genesis_test.bin",
            true,
        )
        .await
    }

    #[tokio::test]
    async fn applied_genesis_and_backup_zero_to_eight_does_not_reappend() -> anyhow::Result<()> {
        use parth_core::crypto::hash::traits::FromU64x4;
        let mut manager = empty_backup_manager().await?;
        let leaf0 = parth_core::PHash::from_u64x4([1, 0, 0, 0]);
        assert!(super::seed_or_check_genesis_backup(&mut manager, leaf0).await?);
        for checkpoint_id in 1..8 {
            manager
                .append_checkpoint_leaf_hash(checkpoint_id, parth_core::PHash::from_u64x4([checkpoint_id + 1, 0, 0, 0]))
                .await?;
        }
        assert_eq!(manager.next_backup_checkpoint_id, 8);
        assert!(!super::seed_or_check_genesis_backup(&mut manager, leaf0).await?);
        assert_eq!(manager.next_backup_checkpoint_id, 8);
        let mismatch = super::seed_or_check_genesis_backup(&mut manager, parth_core::PHash::from_u64x4([9, 0, 0, 0]))
            .await
            .expect_err("mismatched genesis leaf must fail closed");
        assert!(mismatch.to_string().contains("trusted genesis hash"), "{mismatch}");
        Ok(())
    }

    #[tokio::test]
    async fn coordinator_at_zero_hard_reset_reseeds_checkpoint_zero() -> anyhow::Result<()> {
        use parth_core::crypto::hash::traits::FromU64x4;
        let mut manager = empty_backup_manager().await?;
        let leaf0 = parth_core::PHash::from_u64x4([1, 0, 0, 0]);
        super::seed_or_check_genesis_backup(&mut manager, leaf0).await?;
        for checkpoint_id in 1..8 {
            manager
                .append_checkpoint_leaf_hash(checkpoint_id, parth_core::PHash::from_u64x4([checkpoint_id + 1, 0, 0, 0]))
                .await?;
        }
        assert!(super::should_hard_reset_ahead_backup(0, manager.next_backup_checkpoint_id));
        manager.hard_reset_and_truncate(0).await?;
        assert_eq!(manager.next_backup_checkpoint_id, 0);
        assert!(super::seed_or_check_genesis_backup(&mut manager, leaf0).await?);
        assert_eq!(manager.next_backup_checkpoint_id, 1);
        Ok(())
    }
}
