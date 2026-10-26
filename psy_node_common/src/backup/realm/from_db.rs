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

#[cfg(test)]
mod tests {
    use parth_core::{
        data::hash::merkle_node_key::SimpleMerkleNodeKey,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::QNetworkTreeConstants,
        PHash,
    };
    use psy_node_core::psy_core_db::traits::full::{PsyNodeGlobalUserTreeDatabaseReader, PsyNodeGlobalUserTreeDatabaseWriter};

    use crate::test_common::{create_test_unified_db, TestNetworkConfig, TestUnifiedDatabaseStore};

    use super::*;

    type Hash = PHash;

    const CP: u64 = 4;
    const REALM_ID: u64 = 1;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    fn leaf(i: u64) -> Hash {
        PHash::from_values(i * 16 + 9, 0x1357_9BDF_0246_8ACE, i + 37, 0xECA8_6420_DBF9_7531)
    }

    #[tokio::test]
    async fn load_realm_sub_tree_from_empty_realm_returns_empty_tree() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        let trees = load_realm_memory_trees_from_db::<TestNetworkConfig, TestUnifiedDatabaseStore>(&db, CP, REALM_ID).await?;

        assert_eq!(
            trees.global_user_tree.get_root(),
            zh((TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT - TestNetworkConfig::COORDINATOR_GLOBAL_USER_TREE_HEIGHT) as usize)
        );
        let (global_user_tree,) = trees.into_tuple();
        assert_eq!(global_user_tree.get_leaf_value(0), zh(0));
        Ok(())
    }

    #[tokio::test]
    async fn load_realm_sub_tree_rebuilds_realm_scoped_leaves_and_root() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        // realm 1 covers full-tree leaves [1<<20, 2<<20)
        let min_user_id = REALM_ID << (TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT - TestNetworkConfig::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);
        for i in 0..4u64 {
            db.global_user_tree_set_leaf_hash(CP, min_user_id + i, leaf(i)).await?;
        }
        // a leaf in realm 2 must not leak into the loaded sub-tree
        db.global_user_tree_set_leaf_hash(
            CP,
            (REALM_ID + 1) << (TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT - TestNetworkConfig::COORDINATOR_GLOBAL_USER_TREE_HEIGHT),
            leaf(99),
        )
        .await?;

        let trees = load_realm_memory_trees_from_db::<TestNetworkConfig, TestUnifiedDatabaseStore>(&db, CP, REALM_ID).await?;

        let sub_root_key = SimpleMerkleNodeKey::new(TestNetworkConfig::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, REALM_ID);
        assert_eq!(
            trees.global_user_tree.get_root(),
            db.global_user_tree_get_node(CP, sub_root_key).await?
        );
        // leaves are re-indexed relative to the realm's sub-root
        assert_eq!(trees.global_user_tree.get_leaf_value(0), leaf(0));
        assert_eq!(trees.global_user_tree.get_leaf_value(3), leaf(3));
        assert_eq!(trees.global_user_tree.get_leaf_value(4), zh(0));
        Ok(())
    }
}