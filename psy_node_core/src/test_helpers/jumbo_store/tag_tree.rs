use std::collections::HashMap;

use parth_common::memory_stores::simple_memory_tag_tree_store::SimpleMemoryTagTreeStore;
use parth_core::{
    crypto::hash::tag_tree::{compute_tag_tree_root_for_proof, hash_tag_tree_node, TagTreeMerkleProof},
    data::{
        db::{
            data_types::QDatabasePrimitiveKey,
            hash_id_u64::{get_data_buffer_for_hash256_and_u64s, read_hash256_refs_and_i64s_from_buffer, QHash256AndU64},
        },
        hash::merkle_node_key::{generate_nca_tree_groups_v1, SimpleMerkleNodeKey},
    },
    protocol::core_types::QDBHashBase,
    utils::{signed_helpers::i64_to_u64_exact, QPGenRandom},
};

use super::{
    core::QJumboStore,
    utils::{random_nodes_in_tree, PsyDBSer, THHasher, THStandardTableIdentifier},
};
use crate::store::traits::core_db::CoreDatabaseStore;

impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey,
        KivTableAValue: PsyDBSer,
        KivTableBValue: PsyDBSer,
        ObjSingleIdTableAValue: PsyDBSer,
        ObjDoubleIdTableBValue: PsyDBSer,
        Hash: QDBHashBase + QPGenRandom + std::fmt::Debug + Default + Clone + Send + Sync,
        Hasher: THHasher<Hash>,
        BiDirectionalMappingTableIdentifier: THStandardTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier: THStandardTableIdentifier,
        U64TableIdentifier: THStandardTableIdentifier,
        SingleIdTableIdentifier: THStandardTableIdentifier,
        DoubleIdTableIdentifier: THStandardTableIdentifier,
        KivTableIdentifier: THStandardTableIdentifier,
        SingleIdMerkleTableIdentifier: THStandardTableIdentifier,
        DoubleIdMerkleTableIdentifier: THStandardTableIdentifier,
        ZeroIdMerkleTableIdentifier: THStandardTableIdentifier,
        RewardTreeTableIdentifier: THStandardTableIdentifier,
        HashToManyIdsTableIdentifier: THStandardTableIdentifier,
        S: CoreDatabaseStore<
                Hash,
                Hasher,
                BiDirectionalMappingTableIdentifier,
                BiDirectionalU64U128MappingTableIdentifier,
                U64TableIdentifier,
                SingleIdTableIdentifier,
                DoubleIdTableIdentifier,
                KivTableIdentifier,
                SingleIdMerkleTableIdentifier,
                DoubleIdMerkleTableIdentifier,
                ZeroIdMerkleTableIdentifier,
                RewardTreeTableIdentifier,
                HashToManyIdsTableIdentifier,
            > + Send
            + Sync,
    >
    QJumboStore<
        ZERO_ID_TREE_A_HEIGHT,
        ZERO_ID_TREE_B_HEIGHT,
        SINGLE_ID_TREE_A_HEIGHT,
        SINGLE_ID_TREE_B_HEIGHT,
        DOUBLE_ID_TREE_A_HEIGHT,
        DOUBLE_ID_TREE_B_HEIGHT,
        BidirectionalMappingTableAK1,
        BidirectionalMappingTableAK2,
        BidirectionalMappingTableBK1,
        BidirectionalMappingTableBK2,
        KivTableAValue,
        KivTableBValue,
        ObjSingleIdTableAValue,
        ObjDoubleIdTableBValue,
        Hash,
        Hasher,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        RewardTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        S,
    >
{
    pub async fn th_util_get_tag_tree_merkle_proof(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<TagTreeMerkleProof<Hash>> {
        let result = self.store.db_get_tag_tree_merkle_proof(table, unique_pending_id, key).await?;
        assert!(result.verify::<Hasher>(), "Retrieved proof does not verify");
        let computed_root = compute_tag_tree_root_for_proof::<Hash, Hasher>(result.index, &result.leaf, &result.siblings);
        assert_eq!(computed_root, result.root, "Computed root does not match proof root");
        let stored_root = self.th_util_get_tag_tree_root(table, unique_pending_id).await?.unwrap_or_default();
        assert_eq!(result.root, stored_root, "Proof root does not match stored root");
        Ok(result)
    }

    pub async fn th_util_get_tag_tree_node_value(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_node_value(table, unique_pending_id, key).await?;
        let multi_result = self
            .store
            .db_get_tag_tree_node_values(table, unique_pending_id, &[key.clone(), key.clone()])
            .await?;
        assert!(multi_result.len() == 2, "Multi get did not return correct number of results");
        assert!(multi_result[0] == result, "Multi get first result does not match single get result");
        assert!(multi_result[1] == result, "Multi get second result does not match single get result");
        Ok(result)
    }

    pub async fn th_util_get_many_tag_tree_node_values(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Option<Hash>>> {
        let result = self.store.db_get_tag_tree_node_values(table, unique_pending_id, keys).await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested keys"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
            assert!(result[i] == single_result, "Multi get result does not match single get result");
        }
        Ok(result)
    }

    pub async fn th_util_get_tag_tree_node_tag(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
    ) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        Ok(result)
    }

    pub async fn th_util_get_tag_tree_root(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<Option<Hash>> {
        let result = self.store.db_get_tag_tree_root(table, unique_pending_id).await?;
        let root_key = SimpleMerkleNodeKey::new_root();
        let value_from_node = self.th_util_get_tag_tree_node_value(table, unique_pending_id, &root_key).await?;
        assert_eq!(result, value_from_node, "Root from get_root does not match get_node_value for root key");
        Ok(result)
    }

    pub async fn th_util_set_tag_tree_tag_value(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
        value: &Hash,
    ) -> anyhow::Result<()> {
        self.store.db_set_tag_tree_tag_value(table, unique_pending_id, key, tag, value).await?;
        let retrieved_value = self.th_util_get_tag_tree_node_value(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_value, Some(*value), "Retrieved value does not match set value");
        let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_tag, Some(*tag), "Retrieved tag does not match set tag");
        Ok(())
    }

    pub async fn th_util_set_tag_tree_tag(
        &self,
        table: &RewardTreeTableIdentifier,
        unique_pending_id: u64,
        key: &SimpleMerkleNodeKey,
        tag: &Hash,
    ) -> anyhow::Result<()> {
        self.store.db_set_tag_tree_tag(table, unique_pending_id, key, tag).await?;
        let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
        assert_eq!(retrieved_tag, Some(*tag), "Retrieved tag does not match set tag");
        Ok(())
    }
    pub async fn th_test_tag_tree_v2(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {
        let guta_height = 3u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let leaf_3 = SimpleMerkleNodeKey::new(guta_height, 2);
        let leaf_5 = SimpleMerkleNodeKey::new(guta_height, 5);
        let leaf_6 = SimpleMerkleNodeKey::new(guta_height, 6);
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_5, leaf_6];
        let group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);
        let tree_height = group_levels.len() - 1;
        assert_eq!(group_levels.len(), 3);
        let mut simple_tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(tree_height as u8);
        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();
        for (level, gl) in group_levels.iter().enumerate() {
            for (index, g) in gl.iter().enumerate() {
                let hash = Hash::qp_rand_gen();
                let key = SimpleMerkleNodeKey::new((tree_height - level) as u8, index as u64);
                hash_map_dat.insert(g.nca, key);
                self.store
                    .db_set_tag_tree_tag_known_height(table, unique_pending_id, tree_height as u8, &key, &hash)
                    .await?;
                simple_tree.set_tag(key, hash);
                let retrieved_tag = self.store.db_get_tag_tree_node_tag(table, unique_pending_id, &key).await?;
                assert_eq!(retrieved_tag, Some(hash), "Retrieved tag does not match");
                let ret_combo = self.store.db_get_tag_tree_node_value(table, unique_pending_id, &key).await?;
                assert!(ret_combo.is_some(), "Retrieved value should be Some");
                let left = self
                    .store
                    .db_get_tag_tree_node_value(table, unique_pending_id, &key.left_child())
                    .await?
                    .unwrap_or_default();
                let right = self
                    .store
                    .db_get_tag_tree_node_value(table, unique_pending_id, &key.right_child())
                    .await?
                    .unwrap_or_default();
                let expected_value = hash_tag_tree_node::<Hash, Hasher>(&left, &right, &hash);
                assert_eq!(ret_combo.unwrap(), expected_value, "Retrieved value does not match expected value");
            }
        }
        for g in group_levels.iter().flatten() {
            let key = hash_map_dat[&g.nca];
            let proof = simple_tree.get_proof_full(key);
            let proof_2 = self.store.db_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert_eq!(proof, proof_2, "Proofs do not match");
            assert!(proof.verify::<Hasher>(), "proof verification failed");
        }
        Ok(())
    }
    pub async fn th_test_tag_tree_small(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {
        let guta_height = 3u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let leaf_3 = SimpleMerkleNodeKey::new(guta_height, 2);
        let leaf_5 = SimpleMerkleNodeKey::new(guta_height, 5);
        let leaf_6 = SimpleMerkleNodeKey::new(guta_height, 6);
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_5, leaf_6];
        let group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);

        let tree_height = (group_levels.len() - 1) as u8;

        let mut tags = HashMap::new();

        for (level, gl) in group_levels.iter().enumerate() {
            for (index, _g) in gl.iter().enumerate() {
                let tag = Hash::qp_rand_gen();
                let key = SimpleMerkleNodeKey::new(tree_height - level as u8, index as u64);
                tags.insert(key, tag);
                self.th_util_set_tag_tree_tag(table, unique_pending_id, &key, &tag).await?;
            }
        }

        for (key, tag) in tags.iter() {
            let retrieved_tag = self.th_util_get_tag_tree_node_tag(table, unique_pending_id, key).await?;
            assert_eq!(retrieved_tag, Some(*tag), "Retrieved tag does not match");
        }

        for g in group_levels.iter().flatten() {
            let key = g.nca.clone();
            let proof = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert!(proof.verify::<Hasher>(), "Proof verification failed");
        }

        Ok(())
    }

    pub async fn th_test_tag_tree_medium(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {
        let guta_height: u8 = 32;
        let leaves = random_nodes_in_tree(guta_height, 1337);
        let group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);

        let tree_height = group_levels.len() - 1;
        let mut simple_tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(tree_height as u8);

        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();

        for (level, gl) in group_levels.iter().enumerate() {
            for (index, g) in gl.iter().enumerate() {
                let hash = Hash::qp_rand_gen();
                let tag_tree_key = SimpleMerkleNodeKey::new((tree_height - level) as u8, index as u64);
                hash_map_dat.insert(g.nca, tag_tree_key);
                simple_tree.set_tag(tag_tree_key, hash);
                self.store
                    .db_set_tag_tree_tag_known_height(table, unique_pending_id, tree_height as u8, &tag_tree_key, &hash)
                    .await?;
                let retrieved_tag = self.store.db_get_tag_tree_node_tag(table, unique_pending_id, &tag_tree_key).await?;
                assert_eq!(retrieved_tag, Some(hash), "Retrieved tag does not match");
                let ret_combo = self.store.db_get_tag_tree_node_value(table, unique_pending_id, &tag_tree_key).await?;
                assert!(ret_combo.is_some(), "Retrieved value should be Some");
                let left = self
                    .store
                    .db_get_tag_tree_node_value(table, unique_pending_id, &tag_tree_key.left_child())
                    .await?
                    .unwrap_or_default();
                let right = self
                    .store
                    .db_get_tag_tree_node_value(table, unique_pending_id, &tag_tree_key.right_child())
                    .await?
                    .unwrap_or_default();
                let expected_value = hash_tag_tree_node::<Hash, Hasher>(&left, &right, &hash);
                assert_eq!(ret_combo.unwrap(), expected_value, "Retrieved value does not match expected value");
                assert_eq!(
                    simple_tree.get_node_value(&tag_tree_key),
                    expected_value,
                    "In-memory tree value does not match expected value"
                );
            }
        }
        for g in group_levels.iter().flatten() {
            let key = hash_map_dat[&g.nca];
            let proof = simple_tree.get_proof_full(key);
            assert!(proof.verify::<Hasher>(), "proof verification failed for in-memory tree");
            let proof_2 = self.store.db_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert_eq!(proof, proof_2, "proof from store does not match in-memory proof");
            assert!(proof_2.verify::<Hasher>(), "store proof verification failed");
            let th_proof = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &key).await?;
            assert!(th_proof.verify::<Hasher>(), "th_util proof verification failed");
        }
        Ok(())
    }

    pub async fn th_test_tag_tree_tiny(&self, table: &RewardTreeTableIdentifier, unique_pending_id: u64) -> anyhow::Result<()> {
        let guta_height = 1u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let tag_1 = Hash::qp_rand_gen();
        let tag_2 = Hash::qp_rand_gen();
        let tag_root = Hash::qp_rand_gen();
        self.th_util_set_tag_tree_tag(table, unique_pending_id, &leaf_1, &tag_1).await?;
        self.th_util_set_tag_tree_tag(table, unique_pending_id, &leaf_2, &tag_2).await?;
        self.th_util_set_tag_tree_tag(table, unique_pending_id, &SimpleMerkleNodeKey::new_root(), &tag_root)
            .await?;

        let expected_left_value = hash_tag_tree_node::<Hash, Hasher>(&Hash::default(), &Hash::default(), &tag_1);
        let expected_right_value = hash_tag_tree_node::<Hash, Hasher>(&Hash::default(), &Hash::default(), &tag_2);
        assert_eq!(self.th_util_get_tag_tree_node_tag(table, unique_pending_id, &leaf_1).await?, Some(tag_1));
        assert_eq!(self.th_util_get_tag_tree_node_tag(table, unique_pending_id, &leaf_2).await?, Some(tag_2));
        assert_eq!(
            self.th_util_get_tag_tree_node_tag(table, unique_pending_id, &SimpleMerkleNodeKey::new_root())
                .await?,
            Some(tag_root)
        );

        assert_eq!(
            self.th_util_get_tag_tree_node_value(table, unique_pending_id, &leaf_1).await?,
            Some(expected_left_value)
        );
        assert_eq!(
            self.th_util_get_tag_tree_node_value(table, unique_pending_id, &leaf_2).await?,
            Some(expected_right_value)
        );

        let expected_root_value = hash_tag_tree_node::<Hash, Hasher>(&expected_left_value, &expected_right_value, &tag_root);

        let root = self.th_util_get_tag_tree_root(table, unique_pending_id).await?;
        assert_eq!(root, Some(expected_root_value));
        let proof_1 = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &leaf_1).await?;
        let proof_2 = self.th_util_get_tag_tree_merkle_proof(table, unique_pending_id, &leaf_2).await?;
        assert!(proof_1.verify::<Hasher>(), "proof 1 verification failed");
        assert!(proof_2.verify::<Hasher>(), "proof 2 verification failed");

        Ok(())
    }

    pub async fn th_test_hash_to_u64s_basic(&self, table: &HashToManyIdsTableIdentifier) -> anyhow::Result<()> {
        for _ in 0..10 {
            let user_hash_a = Hash::qp_rand_gen();
            let mut user_ids = u64::qp_rand_gen_vec(100)
                .iter()
                .map(|x| (*x) & 0x0000_FFFF_FFFF_FFFFu64)
                .collect::<Vec<u64>>();
            let first_user_id = u64::qp_rand_gen() & 0x0000_FFFF_FFFF_FFFFu64;
            user_ids.push(first_user_id);

            user_ids.sort_unstable();
            user_ids.dedup();

            while user_ids.len() != 101 {
                user_ids.push(u64::qp_rand_gen());
                user_ids.sort_unstable();
                user_ids.dedup();
            }

            let pairs = user_ids
                .iter()
                .map(|x| QHash256AndU64 {
                    hash: user_hash_a,
                    value_u64: *x,
                })
                .collect::<Vec<_>>();
            let serialized_insert_data = get_data_buffer_for_hash256_and_u64s(&pairs);
            let read_back = read_hash256_refs_and_i64s_from_buffer(&serialized_insert_data)?
                .iter()
                .map(|x| QHash256AndU64 {
                    hash: Hash::from_slice_32bytes(x.0).unwrap(),
                    value_u64: i64_to_u64_exact(x.1),
                })
                .collect::<Vec<_>>();
            assert_eq!(read_back, pairs, "read back should match our pairs");
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 4, 0).await?;
            assert_eq!(result.len(), 0, "the store should be empty for this hash");
            self.store.db_insert_one_hash_to_u64(table, user_hash_a, first_user_id).await?;
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 4, 0).await?;
            assert_eq!(result.len(), 1, "the store should contain the first user");
            assert_eq!(result[0], first_user_id, "the store should return the first user id");

            if first_user_id > 0 {
                let result = self
                    .store
                    .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id - 1)
                    .await?;
                assert_eq!(result.len(), 1, "the store should contain the first user");
                assert_eq!(result[0], first_user_id, "the store should return the first user id");
            }
            let result = self
                .store
                .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id / 2)
                .await?;
            assert_eq!(result.len(), 1, "the store should contain the first user");
            assert_eq!(result[0], first_user_id, "the store should return the first user id");
            if first_user_id < i64::MAX as u64 {
                let result = self
                    .store
                    .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id + 1)
                    .await?;
                assert_eq!(result.len(), 0, "the store should implement pagination correctly");
            }

            self.store
                .db_set_hash_256_to_u64_pairs_from_fast_serialized_data(table, &serialized_insert_data)
                .await?;
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 15, 0).await?;
            assert_eq!(result.len(), 15, "the store should contain the first 15 users sorted by user id");
            assert_eq!(
                result,
                user_ids[0..15].to_vec(),
                "the store should contain the first 15 users sorted by user id"
            );
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 20, user_ids[15]).await?;
            assert_eq!(result.len(), 20, "the store should contain the first 15 users sorted by user id");
            assert_eq!(
                result,
                user_ids[15..35].to_vec(),
                "the store should contain the first 15 users sorted by user id"
            );
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 200, user_ids[35]).await?;
            assert_eq!(
                result.len(),
                user_ids.len() - 35,
                "the store should contain the first 15 users sorted by user id"
            );
            assert_eq!(
                result,
                user_ids[35..].to_vec(),
                "the store should contain the last users sorted by user id"
            );
            let result = self
                .store
                .db_select_value_u64_ids_for_hash(table, user_hash_a, 10, user_ids[user_ids.len() - 1] + 1)
                .await?;
            assert_eq!(result.len(), 0, "the store should not return results after the highest user id");
        }

        for _ in 0..2 {
            let user_hash_a = Hash::qp_rand_gen();
            let mut user_ids = u64::qp_rand_gen_vec(10000)
                .iter()
                .map(|x| (*x) & 0x0000_FFFF_FFFF_FFFFu64)
                .collect::<Vec<u64>>();
            let first_user_id = u64::qp_rand_gen() & 0x0000_FFFF_FFFF_FFFFu64;
            user_ids.push(first_user_id);

            user_ids.sort_unstable();
            user_ids.dedup();

            while user_ids.len() != 10001 {
                user_ids.push(u64::qp_rand_gen());
                user_ids.sort_unstable();
                user_ids.dedup();
            }

            let pairs = user_ids
                .iter()
                .map(|x| QHash256AndU64 {
                    hash: user_hash_a,
                    value_u64: *x,
                })
                .collect::<Vec<_>>();
            let serialized_insert_data = get_data_buffer_for_hash256_and_u64s(&pairs);
            let tuples = pairs.iter().map(|x| (x.hash, x.value_u64)).collect::<Vec<_>>();

            let read_back = read_hash256_refs_and_i64s_from_buffer(&serialized_insert_data)?
                .iter()
                .map(|x| QHash256AndU64 {
                    hash: Hash::from_slice_32bytes(x.0).unwrap(),
                    value_u64: i64_to_u64_exact(x.1),
                })
                .collect::<Vec<_>>();
            assert_eq!(read_back, pairs, "read back should match our pairs");
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 4, 0).await?;
            assert_eq!(result.len(), 0, "the store should be empty for this hash");
            self.store.db_insert_one_hash_to_u64(table, user_hash_a, first_user_id).await?;
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 4, 0).await?;
            assert_eq!(result.len(), 1, "the store should contain the first user");
            assert_eq!(result[0], first_user_id, "the store should return the first user id");

            if first_user_id > 0 {
                let result = self
                    .store
                    .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id - 1)
                    .await?;
                assert_eq!(result.len(), 1, "the store should contain the first user");
                assert_eq!(result[0], first_user_id, "the store should return the first user id");
            }
            let result = self
                .store
                .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id / 2)
                .await?;
            assert_eq!(result.len(), 1, "the store should contain the first user");
            assert_eq!(result[0], first_user_id, "the store should return the first user id");
            if first_user_id < i64::MAX as u64 {
                let result = self
                    .store
                    .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id + 1)
                    .await?;
                assert_eq!(result.len(), 0, "the store should implement pagination correctly");
            }

            self.store.db_insert_many_hash_to_u64s(table, &tuples[..]).await?;
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 15, 0).await?;
            assert_eq!(result.len(), 15, "the store should contain the first 15 users sorted by user id");
            assert_eq!(
                result,
                user_ids[0..15].to_vec(),
                "the store should contain the first 15 users sorted by user id"
            );
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 20, user_ids[15]).await?;
            assert_eq!(result.len(), 20, "the store should contain the first 15 users sorted by user id");
            assert_eq!(
                result,
                user_ids[15..35].to_vec(),
                "the store should contain the first 15 users sorted by user id"
            );
            let result = self
                .store
                .db_select_value_u64_ids_for_hash(table, user_hash_a, 9999, user_ids[35])
                .await?;
            assert_eq!(
                result.len(),
                user_ids.len() - 35,
                "the store should contain the first 15 users sorted by user id"
            );
            assert_eq!(
                result,
                user_ids[35..(35 + 9999).min(user_ids.len())].to_vec(),
                "the store should contain the last users sorted by user id"
            );
            let result = self
                .store
                .db_select_value_u64_ids_for_hash(table, user_hash_a, 10, user_ids[user_ids.len() - 1] + 1)
                .await?;
            assert_eq!(result.len(), 0, "the store should not return results after the highest user id");
        }

        for _ in 0..10 {
            let user_hash_a = Hash::qp_rand_gen();
            let mut user_ids = u64::qp_rand_gen_vec(100)
                .iter()
                .map(|x| (*x) & 0x0000_FFFF_FFFF_FFFFu64)
                .collect::<Vec<u64>>();
            let first_user_id = u64::qp_rand_gen() & 0x0000_FFFF_FFFF_FFFFu64;
            user_ids.push(first_user_id);

            user_ids.sort_unstable();
            user_ids.dedup();

            while user_ids.len() != 101 {
                user_ids.push(u64::qp_rand_gen());
                user_ids.sort_unstable();
                user_ids.dedup();
            }

            let pairs = user_ids
                .iter()
                .map(|x| QHash256AndU64 {
                    hash: user_hash_a,
                    value_u64: *x,
                })
                .collect::<Vec<_>>();
            let serialized_insert_data = get_data_buffer_for_hash256_and_u64s(&pairs);
            let read_back = read_hash256_refs_and_i64s_from_buffer(&serialized_insert_data)?
                .iter()
                .map(|x| QHash256AndU64 {
                    hash: Hash::from_slice_32bytes(x.0).unwrap(),
                    value_u64: i64_to_u64_exact(x.1),
                })
                .collect::<Vec<_>>();
            assert_eq!(read_back, pairs, "read back should match our pairs");
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 4, 0).await?;
            assert_eq!(result.len(), 0, "the store should be empty for this hash");
            self.store.db_insert_one_hash_to_u64(table, user_hash_a, first_user_id).await?;
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 4, 0).await?;
            assert_eq!(result.len(), 1, "the store should contain the first user");
            assert_eq!(result[0], first_user_id, "the store should return the first user id");

            if first_user_id > 0 {
                let result = self
                    .store
                    .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id - 1)
                    .await?;
                assert_eq!(result.len(), 1, "the store should contain the first user");
                assert_eq!(result[0], first_user_id, "the store should return the first user id");
            }
            let result = self
                .store
                .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id / 2)
                .await?;
            assert_eq!(result.len(), 1, "the store should contain the first user");
            assert_eq!(result[0], first_user_id, "the store should return the first user id");
            if first_user_id < i64::MAX as u64 {
                let result = self
                    .store
                    .db_select_value_u64_ids_for_hash(table, user_hash_a, 4, first_user_id + 1)
                    .await?;
                assert_eq!(result.len(), 0, "the store should implement pagination correctly");
            }

            self.store
                .db_set_hash_256_to_u64_pairs_from_fast_serialized_data(table, &serialized_insert_data)
                .await?;
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 15, 0).await?;
            assert_eq!(result.len(), 15, "the store should contain the first 15 users sorted by user id");
            assert_eq!(
                result,
                user_ids[0..15].to_vec(),
                "the store should contain the first 15 users sorted by user id"
            );
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 20, user_ids[15]).await?;
            assert_eq!(result.len(), 20, "the store should contain the first 15 users sorted by user id");
            assert_eq!(
                result,
                user_ids[15..35].to_vec(),
                "the store should contain the first 15 users sorted by user id"
            );
            let result = self.store.db_select_value_u64_ids_for_hash(table, user_hash_a, 200, user_ids[35]).await?;
            assert_eq!(
                result.len(),
                user_ids.len() - 35,
                "the store should contain the first 15 users sorted by user id"
            );
            assert_eq!(
                result,
                user_ids[35..].to_vec(),
                "the store should contain the last users sorted by user id"
            );
            let result = self
                .store
                .db_select_value_u64_ids_for_hash(table, user_hash_a, 10, user_ids[user_ids.len() - 1] + 1)
                .await?;
            assert_eq!(result.len(), 0, "the store should not return results after the highest user id");
        }

        Ok(())
    }
}
