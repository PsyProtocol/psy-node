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

#[cfg(test)]
mod tests {
    use parth_core::{pgoldilocks::PoseidonHasher, protocol::core_types::QNetworkTreeConstants, PHash};
    use psy_node_core::psy_core_db::traits::full::{
        PsyNodeGlobalContractTreeDatabaseReader,
        PsyNodeGlobalContractTreeDatabaseWriter,
        PsyNodeGlobalUserTreeDatabaseReader,
        PsyNodeGlobalUserTreeDatabaseWriter,
        PsyNodeUserRegistrationTreeDatabaseReader,
        PsyNodeUserRegistrationTreeDatabaseWriter,
    };

    use crate::test_common::{create_test_unified_db, TestNetworkConfig, TestUnifiedDatabaseStore};

    use super::*;

    type Hash = PHash;

    const CP: u64 = 4;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    fn leaf(i: u64) -> Hash {
        PHash::from_values(i * 16 + 7, 0x0F0E_0D0C_0B0A_0908, i + 31, 0x0807_0605_0403_0201)
    }

    #[tokio::test]
    async fn load_from_empty_db_returns_empty_trees_and_zero_counters() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        let trees = load_coordinator_memory_trees_from_db::<TestNetworkConfig, TestUnifiedDatabaseStore>(&db, 0).await?;

        assert_eq!(trees.next_user_registration_id, 0);
        assert_eq!(trees.next_contract_id, 0);
        assert_eq!(
            trees.user_registration_tree.get_root(),
            zh(TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT as usize)
        );
        assert_eq!(
            trees.global_user_tree.get_root(),
            zh(TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT as usize)
        );
        assert_eq!(
            trees.global_contract_tree.get_root(),
            zh(TestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT as usize)
        );
        // the coordinator's global user tree operates at the coordinator height
        assert_eq!(trees.global_user_tree.get_effective_height(), TestNetworkConfig::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);

        let (next_user_registration_id, next_contract_id, user_registration_tree, global_user_tree, global_contract_tree) =
            trees.into_tuple();
        assert_eq!(next_user_registration_id, 0);
        assert_eq!(next_contract_id, 0);
        assert_eq!(user_registration_tree.get_root(), zh(TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT as usize));
        assert_eq!(global_user_tree.get_root(), zh(TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT as usize));
        assert_eq!(global_contract_tree.get_root(), zh(TestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT as usize));
        Ok(())
    }

    #[tokio::test]
    async fn load_from_seeded_db_rebuilds_all_three_trees() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;

        // registration tree: 5 users
        for i in 0..5u64 {
            db.user_registration_tree_set_leaf_hash(CP, i, leaf(i)).await?;
        }
        // global user tree: two coordinator-level slots
        let sub_leaves = 1u64 << (TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT - TestNetworkConfig::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);
        db.global_user_tree_set_leaf_hash(CP, 0, leaf(100)).await?;
        db.global_user_tree_set_leaf_hash(CP, sub_leaves + 3, leaf(101)).await?;
        // contract tree: 3 contracts
        for i in 0..3u64 {
            db.global_contract_tree_set_leaf_hash(CP, i, leaf(i + 200)).await?;
        }

        let trees = load_coordinator_memory_trees_from_db::<TestNetworkConfig, TestUnifiedDatabaseStore>(&db, CP).await?;

        assert_eq!(trees.next_user_registration_id, 5);
        assert_eq!(trees.next_contract_id, 3);
        assert_eq!(trees.user_registration_tree.get_root(), db.user_registration_tree_get_root_hash(CP).await?);
        assert_eq!(trees.user_registration_tree.get_leaf_value(4), leaf(4));
        assert_eq!(trees.global_user_tree.get_root(), db.global_user_tree_get_root_hash(CP).await?);
        assert_eq!(
            trees.global_user_tree.get_e_leaf_value(1),
            db.global_user_tree_get_node(
                CP,
                parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey::new(TestNetworkConfig::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, 1)
            )
            .await?
        );
        assert_eq!(trees.global_contract_tree.get_root(), db.global_contract_tree_get_root_hash(CP).await?);
        assert_eq!(trees.global_contract_tree.get_leaf_value(2), leaf(202));
        Ok(())
    }
}
