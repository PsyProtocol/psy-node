use std::sync::Arc;

use parth_core::{crypto::hash::traits::MerkleZeroHasher, felt::QFelt};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::PsyCoordinatorProcessorStore};

use crate::backup::checkpoint_tree::CheckpointTreeBackupManager;

pub struct CoordinatorDBSync<
    S: PsyCoordinatorProcessorStore<F, Hash> + Send + Sync,
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Eq + Copy + PartialEq + Default + std::hash::Hash,
    F: QFelt,
    FileSystem: TokioLikeFileSystem,
    CoordinatorClient: RealmCoordinatorClient<F, Hash>,
>{
    pub checkpoint_tree_manager: CheckpointTreeBackupManager<Hasher, Hash, FileSystem>,
    pub client: Arc<CoordinatorClient>,
    pub db: Arc<S>,
    pub _phantom_f: std::marker::PhantomData<F>,
}
#[cfg(test)]
mod coordinator_sync_tests {
    use std::sync::Arc;

    use parth_core::{pgoldilocks::PoseidonHasher, protocol::core_types::QNetworkTreeConstants, PHash};
    use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;

    use super::*;
    use crate::backup::checkpoint_tree::CheckpointTreeBackupManager;
    use crate::realm::processor::db::realm_db_test_env::*;

    #[tokio::test]
    async fn coordinator_db_sync_constructs_around_backup_manager_and_client() -> anyhow::Result<()> {
        let env = RealmDbTestEnv::create().await?;

        let manager = CheckpointTreeBackupManager::<PoseidonHasher, PHash, SimpleMockMemoryFileSystem>::new_from_file_path(
            Arc::clone(&env.file_system),
            10,
            N::CHECKPOINT_TREE_HEIGHT,
            &env.db,
            "coordinator_sync_backup.bin",
            true,
        )
        .await?;

        let sync = CoordinatorDBSync {
            checkpoint_tree_manager: manager,
            client: Arc::clone(&env.coordinator),
            db: Arc::clone(&env.db),
            _phantom_f: std::marker::PhantomData,
        };

        // fresh construction: empty backup manager, coordinator parked at 0
        assert_eq!(sync.checkpoint_tree_manager.get_current_checkpoint_id_head(), 0);
        assert_eq!(*sync.client.latest_checkpoint_id.lock().unwrap(), 0);
        assert_eq!(sync.db.get_latest_checkpoint_id().await?, 0);
        Ok(())
    }
}
