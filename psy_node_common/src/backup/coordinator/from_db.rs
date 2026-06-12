use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, protocol::core_types::{QDBHashBase, QNetworkTypesConfig}};
use psy_node_core::psy_core_db::traits::full::{PsyNodeGlobalContractTreeDatabaseReader, PsyNodeGlobalUserTreeDatabaseReader, PsyNodeUserRegistrationTreeDatabaseReader};

use crate::backup::{global_contract_tree::db_loader::load_global_contract_tree_append_only_pivot_from_db, global_user_tree::db_loader::load_global_user_tree_from_db, user_registration_tree::db_loader::load_global_user_registration_tree_append_only_pivot_from_db};
pub struct CoordinatorMemoryTrees<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase> {
    pub next_user_registration_id: u64,
    pub next_contract_id: u64,
    pub user_registration_tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    pub global_user_tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    pub global_contract_tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
}

impl<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase> CoordinatorMemoryTrees<Hasher, Hash> {
    pub fn into_tuple(
        self,
    ) -> (
        u64,
        u64,
        SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    ) {
        (
            self.next_user_registration_id,
            self.next_contract_id,
            self.user_registration_tree,
            self.global_user_tree,
            self.global_contract_tree,
        )
    }
}
pub async fn load_coordinator_memory_trees_from_db<
    N: QNetworkTypesConfig,
    Store: PsyNodeUserRegistrationTreeDatabaseReader<N::QHash>
    + PsyNodeGlobalUserTreeDatabaseReader<N::QHash>
    + PsyNodeGlobalContractTreeDatabaseReader<N::QHash>,
>(
    db_reader: &Store,
    checkpoint_id: u64,
) -> anyhow::Result<CoordinatorMemoryTrees<N::HasherBase, N::QHash>> {
    let (next_user_registration_id, user_registration_tree) =
        load_global_user_registration_tree_append_only_pivot_from_db::<N::HasherBase, Store, N::QHash>(
            db_reader,
            N::GLOBAL_USER_TREE_HEIGHT,
            checkpoint_id,
            (1u64<<N::BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT) as usize,
        )
        .await?;
    let global_user_tree = load_global_user_tree_from_db::<N::HasherBase, Store, N::QHash>(
        db_reader,
        N::GLOBAL_USER_TREE_HEIGHT,
        N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
        checkpoint_id,
        1000,
    )
    .await?;
    let (next_contract_id, global_contract_tree) =
        load_global_contract_tree_append_only_pivot_from_db::<N::HasherBase, Store, N::QHash>(
            db_reader,
            N::GLOBAL_CONTRACT_TREE_HEIGHT,
            checkpoint_id,
            (1u64<<N::BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT) as usize,
        )
        .await?;
    Ok(CoordinatorMemoryTrees {
        user_registration_tree,
        global_user_tree,
        global_contract_tree,
        next_user_registration_id,
        next_contract_id,
    })
}
