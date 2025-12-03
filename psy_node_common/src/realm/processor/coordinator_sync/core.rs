use std::sync::Arc;

use parth_core::{crypto::hash::traits::MerkleZeroHasher, felt::{QFelt, QFelt64}};
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