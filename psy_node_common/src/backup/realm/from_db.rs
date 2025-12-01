use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::SimpleMerkleNodeKey, protocol::core_types::{QDBHashBase, QNetworkTypesConfig}};
use psy_node_core::psy_core_db::traits::full::PsyNodeGlobalUserTreeDatabaseReader;

use crate::backup::global_user_tree::db_loader_sub_root::load_global_user_tree_from_db_with_sub_root;
pub struct CoordinatorMemoryTrees<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase> {
    pub global_user_tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
}

impl<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase> CoordinatorMemoryTrees<Hasher, Hash> {
    pub fn into_tuple(
        self,
    ) -> (
        SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    ) {
        (
            self.global_user_tree,
        )
    }
}
pub async fn load_realm_memory_trees_from_db<
    N: QNetworkTypesConfig,
    Store: PsyNodeGlobalUserTreeDatabaseReader<N::QHash>,
>(
    db_reader: &Store,
    checkpoint_id: u64,
    realm_id: u64,
) -> anyhow::Result<CoordinatorMemoryTrees<N::HasherBase, N::QHash>> {
    let global_user_tree=
        load_global_user_tree_from_db_with_sub_root::<N::HasherBase, Store, N::QHash>(
            db_reader,
            N::GLOBAL_USER_TREE_HEIGHT,
            SimpleMerkleNodeKey{
                level: N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                index: realm_id,
            },
            checkpoint_id,
            1000,
        )
        .await?;
    Ok(CoordinatorMemoryTrees {
        global_user_tree,
    })
}