use std::collections::HashSet;

use parth_core::{
    crypto::hash::merkle_proof::DeltaMerkleProofCore,
    data::{
        db::{
            data_types::{BiDirectionalMappingRow, QDatabasePrimitiveKey},
            row::{QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowNoCheckpointId},
        },
        hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        serializable::QPDPair,
    },
    protocol::core_types::QDBHashBase,
    utils::QPGenRandom,
};

use super::{
    core::QJumboStore,
    utils::{
        rand_children_to_height, rand_leaves_for_subtree, rand_real_u128_id, rand_real_u64_id, PsyDBSer, THHasher, THStandardTableIdentifier,
        MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS, MAX_REAL_CHECKPOINT_ID,
    },
};
use crate::store::traits::{
    core_db::CoreDatabaseStore,
    helpers::{db_helper_select_single_id_merkle_proof_max_checkpoint, db_helper_single_id_merkle_node_simple_set_leaves_fast_serialize},
};

impl<
        const ZERO_ID_TREE_A_HEIGHT: usize,
        const ZERO_ID_TREE_B_HEIGHT: usize,
        const SINGLE_ID_TREE_A_HEIGHT: usize,
        const SINGLE_ID_TREE_B_HEIGHT: usize,
        const DOUBLE_ID_TREE_A_HEIGHT: usize,
        const DOUBLE_ID_TREE_B_HEIGHT: usize,
        BidirectionalMappingTableAK1: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableAK2: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableBK1: QDatabasePrimitiveKey + QPGenRandom,
        BidirectionalMappingTableBK2: QDatabasePrimitiveKey + QPGenRandom,
        KivTableAValue: PsyDBSer + QPGenRandom,
        KivTableBValue: PsyDBSer + QPGenRandom,
        ObjSingleIdTableAValue: PsyDBSer + QPGenRandom,
        ObjDoubleIdTableBValue: PsyDBSer + QPGenRandom,
        Hash: QDBHashBase + QPGenRandom,
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
    pub async fn th_test_u128_u64_pairs_table_1(&self, table: &BiDirectionalU64U128MappingTableIdentifier) -> anyhow::Result<()> {
        let test_rows = vec![
            BiDirectionalMappingRow { k1: 1u64, k2: 100u128 },
            BiDirectionalMappingRow { k1: 2u64, k2: 200u128 },
            BiDirectionalMappingRow { k1: 3u64, k2: 300u128 },
            BiDirectionalMappingRow { k1: 4u64, k2: 400u128 },
            BiDirectionalMappingRow { k1: 5u64, k2: 500u128 },
        ];
        self.th_util_insert_u64_u128_mapping_pairs(table, &test_rows).await?;

        for row in test_rows.iter() {
            let selected = self.th_util_select_u64_u128_bi_directional_mapping(table, row.k1).await?;
            assert!(selected.is_some(), "Value not found after insert");
            let selected_unwrapped = selected.unwrap();
            assert!(selected_unwrapped == row.k2, "Inserted value does not match retrieved value");

            let reverse_selected = self.th_util_select_u64_u128_bi_directional_mapping_by_u128(table, row.k2).await?;
            assert!(reverse_selected.is_some(), "Reverse value not found after insert");
            let reverse_selected_unwrapped = reverse_selected.unwrap();
            assert!(
                reverse_selected_unwrapped == row.k1,
                "Inserted reverse value does not match retrieved reverse value"
            );
        }

        let random_pairs = (0..100)
            .map(|_| BiDirectionalMappingRow {
                k1: rand_real_u64_id(),
                k2: rand_real_u128_id(),
            })
            .collect::<Vec<_>>();
        self.th_util_insert_u64_u128_mapping_pairs(table, &random_pairs).await?;

        let random_pairs = (0..100)
            .map(|_| BiDirectionalMappingRow {
                k1: rand_real_u64_id(),
                k2: rand_real_u128_id(),
            })
            .collect::<Vec<_>>();

        for rp in random_pairs.into_iter() {
            self.th_util_insert_u64_u128_mapping_pair(table, rp.k1, rp.k2).await?;
        }

        Ok(())
    }

    pub async fn th_test_u64_table_1(&self, table: &U64TableIdentifier) -> anyhow::Result<()> {
        let test_ids = vec![1u64, 2u64, 3u64, 4u64, 5u64];
        for id in test_ids.iter() {
            let selected = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected.is_none(), "Value should not be found before insert");
        }

        for id in test_ids.iter() {
            self.th_util_set_u64_value(table, *id, *id as u64 * 10).await?;
            let selected_value = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected_value.is_some(), "Value not found after insert");
            let selected_value_unwrapped = selected_value.unwrap();
            assert!(
                selected_value_unwrapped == *id as u64 * 10,
                "Inserted value does not match retrieved value"
            );
        }

        for id in test_ids.iter() {
            let selected = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected.is_some(), "Value not found after insert");
            let selected_unwrapped = selected.unwrap();
            assert!(selected_unwrapped == *id as u64 * 10, "Inserted value does not match retrieved value");
        }

        for id in test_ids.iter() {
            let incremented_value = self.th_util_inc_counter(table, *id, 5).await?;
            assert!(
                incremented_value == (*id as u64 * 10) + 5,
                "Incremented value does not match expected value"
            );
            let selected = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected.is_some(), "Value not found after increment");
            let selected_unwrapped = selected.unwrap();
            assert!(
                selected_unwrapped == incremented_value,
                "Incremented value does not match retrieved value"
            );
        }

        for id in test_ids.iter() {
            let current_value = self.store.db_select_u64_value(table, *id).await?;
            if current_value.is_none() || current_value.unwrap() < 3 {
                continue;
            }
            let incremented_value = self.th_util_inc_counter(table, *id, -3).await?;
            assert!(
                incremented_value == ((*id as u64 * 10) + 5).saturating_sub(3),
                "Decremented value does not match expected value"
            );
            let selected = self.th_util_select_u64_value(table, *id).await?;
            assert!(selected.is_some(), "Value not found after decrement");
            let selected_unwrapped = selected.unwrap();
            assert!(
                selected_unwrapped == incremented_value,
                "Decremented value does not match retrieved value"
            );
        }

        // test incrementing a non-existing value
        let non_existing_id = 999u64;
        let incremented_value = self.th_util_inc_counter(table, non_existing_id, 7).await?;
        assert!(
            incremented_value == 7,
            "Incremented value of non-existing id does not match expected value"
        );
        let selected = self.th_util_select_u64_value(table, non_existing_id).await?;
        assert!(selected.is_some(), "Value not found after incrementing non-existing id");
        let selected_unwrapped = selected.unwrap();
        assert!(
            selected_unwrapped == incremented_value,
            "Incremented value of non-existing id does not match retrieved value"
        );

        // test batches
        let batch_ids = vec![10u64, 20u64, 30u64, 40u64, 50u64];
        let batch_values = vec![100u64, 200u64, 300u64, 400u64, 500u64];
        let batch_rows = batch_ids
            .iter()
            .zip(batch_values.iter())
            .map(|(&id, &value)| QPDPair { key: id, value })
            .collect::<Vec<_>>();
        self.th_util_set_many_u64_values(table, &batch_rows).await?;
        Ok(())
    }

    pub async fn get_many_non_existent_ids_in_single_object_single_try<V: PsyDBSer>(
        &self,
        table: &SingleIdTableIdentifier,
        max_count: usize,
    ) -> anyhow::Result<Vec<u64>> {
        let ids = (0..(max_count + 16)).map(|_| rand_real_u64_id()).collect::<Vec<u64>>();
        let results = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &ids, MAX_REAL_CHECKPOINT_ID)
            .await?;
        let non_existent_ids = ids
            .iter()
            .zip(results.iter())
            .filter_map(|(&id, res)| if res.is_none() { Some(id) } else { None })
            .collect::<Vec<u64>>();

        if non_existent_ids.len() > max_count {
            Ok(non_existent_ids.into_iter().take(max_count).collect())
        } else {
            Ok(non_existent_ids)
        }
    }
    pub async fn get_many_non_existent_ids_in_single_object<V: PsyDBSer>(
        &self,
        table: &SingleIdTableIdentifier,
        count: usize,
    ) -> anyhow::Result<Vec<u64>> {
        let mut non_existent_ids = self.get_many_non_existent_ids_in_single_object_single_try::<V>(table, count).await?;
        let mut retry_counter = 0;
        while non_existent_ids.len() < count {
            if retry_counter > MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS {
                return Err(anyhow::anyhow!("Too many retries to find non-existent ids"));
            }
            let needed = count - non_existent_ids.len();
            let mut new_ids = self.get_many_non_existent_ids_in_single_object_single_try::<V>(table, needed).await?;
            non_existent_ids.append(&mut new_ids);
            retry_counter += 1;
        }
        Ok(non_existent_ids.into_iter().take(count).collect())
    }

    pub async fn get_non_existent_id_in_single_object<V: PsyDBSer>(&self, table: &SingleIdTableIdentifier) -> anyhow::Result<u64> {
        let mut id = rand_real_u64_id();
        let mut result = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, id, MAX_REAL_CHECKPOINT_ID)
            .await?;
        let mut retry_counter = 0;
        while result.is_some() {
            if retry_counter > MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS {
                return Err(anyhow::anyhow!("Too many retries to find a non-existent id"));
            }
            id = rand_real_u64_id();
            result = self
                .store
                .db_select_one_single_checkpointed_object_value::<V>(table, id, MAX_REAL_CHECKPOINT_ID)
                .await?;
            retry_counter += 1;
        }
        Ok(id)
    }
    pub async fn get_non_existent_id_in_double_object<V: PsyDBSer>(&self, table: &DoubleIdTableIdentifier) -> anyhow::Result<(u64, u64)> {
        let mut id = rand_real_u64_id();
        let mut secondary_id = rand_real_u64_id();
        let mut result = self
            .store
            .db_select_one_double_checkpointed_object_value::<V>(table, id, secondary_id, MAX_REAL_CHECKPOINT_ID)
            .await?;
        let mut retry_counter = 0;

        while result.is_some() {
            if retry_counter > MAX_GET_UNIQUE_ID_RETRY_ATTEMPTS {
                return Err(anyhow::anyhow!("Too many retries to find a non-existent id"));
            }
            id = rand_real_u64_id();
            secondary_id = rand_real_u64_id();
            result = self
                .store
                .db_select_one_double_checkpointed_object_value::<V>(table, id, secondary_id, MAX_REAL_CHECKPOINT_ID)
                .await?;
            retry_counter += 1;
        }
        Ok((id, secondary_id))
    }

    pub async fn th_test_single_checkpointed_object_1_full_history_1<V: PsyDBSer + QPGenRandom>(
        &self,
        table: &SingleIdTableIdentifier,
    ) -> anyhow::Result<()> {
        let obj_id = self.get_non_existent_id_in_single_object::<V>(table).await?;
        // ensure the id is really non-existent
        let check = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, MAX_REAL_CHECKPOINT_ID)
            .await?;
        assert!(check.is_none(), "Expected non-existent id to not be found");

        let value_c_1337 = V::qp_rand_gen();
        let start_checkpoint_id = 1337u64;
        self.store
            .db_insert_one_single_checkpointed_object(table, obj_id, start_checkpoint_id, &value_c_1337)
            .await?;

        let result = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id)
            .await?;
        assert!(result.is_some(), "Value not found after insert at checkpoint 1337");
        let result_unwrapped = result.unwrap();
        assert!(result_unwrapped == value_c_1337, "Inserted value does not match");
        let result_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id)
            .await?;
        assert!(result_with_ids.is_some(), "Value with ids not found after insert at checkpoint 1337");
        let result_with_ids_unwrapped = result_with_ids.unwrap();
        assert!(result_with_ids_unwrapped.obj_id == obj_id, "Object id does not match");
        assert!(
            result_with_ids_unwrapped.checkpoint_id == start_checkpoint_id,
            "Checkpoint id does not match"
        );
        assert!(result_with_ids_unwrapped.value == value_c_1337, "Value does not match");
        // checking at a higher checkpoint should return the same value
        let result_higher = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id + 100)
            .await?;
        assert!(
            result_higher.is_some(),
            "Value not found at higher checkpoint after insert at checkpoint 1337"
        );
        let result_higher_unwrapped = result_higher.unwrap();
        assert!(result_higher_unwrapped == value_c_1337, "Value does not match at higher checkpoint");
        let result_higher_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id + 100)
            .await?;
        assert!(
            result_higher_with_ids.is_some(),
            "Value with ids not found at higher checkpoint after insert at checkpoint 1337"
        );
        let result_higher_with_ids_unwrapped = result_higher_with_ids.unwrap();
        assert!(
            result_higher_with_ids_unwrapped.obj_id == obj_id,
            "Object id does not match at higher checkpoint"
        );
        assert_eq!(
            result_higher_with_ids_unwrapped.checkpoint_id, start_checkpoint_id,
            "Checkpoint id does not match at higher checkpoint"
        );
        assert!(
            result_higher_with_ids_unwrapped.value == value_c_1337,
            "Value does not match at higher checkpoint"
        );

        // checking at a lower checkpoint should return None
        let result_lower = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id - 1)
            .await?;
        assert!(
            result_lower.is_none(),
            "Value should not be found at lower checkpoint after insert at checkpoint 1337"
        );
        let result_lower_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id - 1)
            .await?;
        assert!(
            result_lower_with_ids.is_none(),
            "Value with ids should not be found at lower checkpoint after insert at checkpoint 1337"
        );
        // inserting at a lower checkpoint should work
        let value_c_1000 = V::qp_rand_gen();
        let lower_checkpoint_id = 1000u64;
        self.store
            .db_insert_one_single_checkpointed_object(table, obj_id, lower_checkpoint_id, &value_c_1000)
            .await?;
        let result_after_lower_insert = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, lower_checkpoint_id)
            .await?;
        assert!(
            result_after_lower_insert.is_some(),
            "Value not found after insert at lower checkpoint 1000"
        );
        let result_after_lower_insert_unwrapped = result_after_lower_insert.unwrap();
        assert!(
            result_after_lower_insert_unwrapped == value_c_1000,
            "Inserted value at lower checkpoint does not match"
        );
        let result_after_lower_insert_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, lower_checkpoint_id)
            .await?;
        assert!(
            result_after_lower_insert_with_ids.is_some(),
            "Value with ids not found after insert at lower checkpoint 1000"
        );
        let result_after_lower_insert_with_ids_unwrapped = result_after_lower_insert_with_ids.unwrap();
        assert!(
            result_after_lower_insert_with_ids_unwrapped.obj_id == obj_id,
            "Object id does not match after lower checkpoint insert"
        );
        assert!(
            result_after_lower_insert_with_ids_unwrapped.checkpoint_id == lower_checkpoint_id,
            "Checkpoint id does not match after lower checkpoint insert"
        );
        assert!(
            result_after_lower_insert_with_ids_unwrapped.value == value_c_1000,
            "Value does not match after lower checkpoint insert"
        );
        // checking at a higher checkpoint should still return the original value
        let result_higher_after_lower_insert = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id)
            .await?;
        assert!(
            result_higher_after_lower_insert.is_some(),
            "Value not found at original checkpoint after lower checkpoint insert"
        );
        let result_higher_after_lower_insert_unwrapped = result_higher_after_lower_insert.unwrap();
        assert!(
            result_higher_after_lower_insert_unwrapped == value_c_1337,
            "Value at original checkpoint does not match after lower checkpoint insert"
        );
        let result_higher_after_lower_insert_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id)
            .await?;
        assert!(
            result_higher_after_lower_insert_with_ids.is_some(),
            "Value with ids not found at original checkpoint after lower checkpoint insert"
        );
        let result_higher_after_lower_insert_with_ids_unwrapped = result_higher_after_lower_insert_with_ids.unwrap();
        assert!(
            result_higher_after_lower_insert_with_ids_unwrapped.obj_id == obj_id,
            "Object id does not match at original checkpoint after lower checkpoint insert"
        );
        assert!(
            result_higher_after_lower_insert_with_ids_unwrapped.checkpoint_id == start_checkpoint_id,
            "Checkpoint id does not match at original checkpoint after lower checkpoint insert"
        );
        assert!(
            result_higher_after_lower_insert_with_ids_unwrapped.value == value_c_1337,
            "Value does not match at original checkpoint after lower checkpoint insert"
        );

        // 0-100 full history test
        let first_100_checkpoints = (0..100u64).map(|_| V::qp_rand_gen()).collect::<Vec<_>>();

        let should_be_empty_pre_insert_0 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 0).await?;
        assert!(
            should_be_empty_pre_insert_0.is_none(),
            "Value should not be found at checkpoint 0 before insert"
        );
        let should_be_empty_pre_insert_50 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 50).await?;
        assert!(
            should_be_empty_pre_insert_50.is_none(),
            "Value should not be found at checkpoint 50 before insert"
        );
        let should_be_empty_pre_insert_99 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 99).await?;
        assert!(
            should_be_empty_pre_insert_99.is_none(),
            "Value should not be found at checkpoint 99 before insert"
        );

        for (checkpoint_id, value) in first_100_checkpoints.iter().enumerate() {
            self.store
                .db_insert_one_single_checkpointed_object(table, obj_id, checkpoint_id as u64, value)
                .await?;
            let should_be_value_post_insert = self
                .store
                .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id as u64)
                .await?;
            assert!(
                should_be_value_post_insert.is_some(),
                "Value should be found at checkpoint {} after insert",
                checkpoint_id
            );
            let should_be_value_post_insert_unwrapped = should_be_value_post_insert.unwrap();
            assert!(
                should_be_value_post_insert_unwrapped == *value,
                "Value at checkpoint {} does not match inserted value",
                checkpoint_id
            );
            // check all future checkpoints to 100 are also the same as this value
            for future_checkpoint in (checkpoint_id + 1)..100 {
                let should_be_value_future = self
                    .store
                    .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, future_checkpoint as u64)
                    .await?;
                assert!(
                    should_be_value_future.is_some(),
                    "Value should be found at future checkpoint {} after insert at checkpoint {}",
                    future_checkpoint,
                    checkpoint_id
                );
                let should_be_value_future_unwrapped = should_be_value_future.unwrap();
                assert!(
                    should_be_value_future_unwrapped == *value,
                    "Value at future checkpoint {} does not match value at checkpoint {} after insert",
                    future_checkpoint,
                    checkpoint_id
                );
            }
        }

        // 5000-5600 full history test with batches
        let checkpoints_5000_5600 = (5000..5600u64)
            .map(|i| QDatabaseSingleIdTableRow::new(obj_id, i, V::qp_rand_gen()))
            .collect::<Vec<_>>();

        // insert the first 300 in a batch
        self.store
            .db_insert_many_single_checkpointed_object_rows_t(table, &checkpoints_5000_5600[0..300])
            .await?;

        for chk in checkpoints_5000_5600[0..300].iter() {
            let actual_value = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, chk.checkpoint_id)
                .await?;
            assert!(
                actual_value.is_some(),
                "Value should be found at checkpoint {} after batch insert",
                chk.checkpoint_id
            );
            let actual_value_unwrapped = actual_value.unwrap();
            assert!(
                actual_value_unwrapped == chk.value,
                "Value at checkpoint {} does not match inserted value after batch insert",
                chk.checkpoint_id
            );
        }
        let actual_value_max_real = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, MAX_REAL_CHECKPOINT_ID)
            .await?;
        assert!(
            actual_value_max_real.is_some(),
            "Value should be found at MAX_REAL_CHECKPOINT_ID after batch insert"
        );
        let actual_value_max_real_unwrapped = actual_value_max_real.unwrap();
        assert!(
            actual_value_max_real_unwrapped == checkpoints_5000_5600[299].value,
            "Value at MAX_REAL_CHECKPOINT_ID does not match last inserted value after batch insert"
        );

        let actual_value_u64_max = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, u64::MAX)
            .await?;
        assert!(actual_value_u64_max.is_some(), "Value should be found at u64::MAX after batch insert");
        let actual_value_u64_max_unwrapped = actual_value_u64_max.unwrap();
        assert!(
            actual_value_u64_max_unwrapped == checkpoints_5000_5600[299].value,
            "Value at u64::MAX does not match last inserted value after batch insert"
        );
        assert!(
            actual_value_u64_max_unwrapped == actual_value_max_real_unwrapped,
            "Value at u64::MAX does not match value at MAX_REAL_CHECKPOINT_ID after batch insert"
        );

        // insert the next 300 in a batch
        self.store
            .db_insert_many_single_checkpointed_object_rows_t(table, &checkpoints_5000_5600[300..600])
            .await?;
        for chk in checkpoints_5000_5600[0..600].iter() {
            let actual_value = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, chk.checkpoint_id)
                .await?;
            assert!(
                actual_value.is_some(),
                "Value should be found at checkpoint {} after second batch insert",
                chk.checkpoint_id
            );
            let actual_value_unwrapped = actual_value.unwrap();
            assert!(
                actual_value_unwrapped == chk.value,
                "Value at checkpoint {} does not match inserted value after second batch insert",
                chk.checkpoint_id
            );
        }
        let actual_value_max_real = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, MAX_REAL_CHECKPOINT_ID)
            .await?;
        assert!(
            actual_value_max_real.is_some(),
            "Value should be found at MAX_REAL_CHECKPOINT_ID after second batch insert"
        );
        let actual_value_max_real_unwrapped = actual_value_max_real.unwrap();
        assert!(
            actual_value_max_real_unwrapped == checkpoints_5000_5600[599].value,
            "Value at MAX_REAL_CHECKPOINT_ID does not match last inserted value after second batch insert"
        );
        let actual_value_u64_max = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, u64::MAX)
            .await?;
        assert!(
            actual_value_u64_max.is_some(),
            "Value should be found at u64::MAX after second batch insert"
        );

        let actual_value_u64_max_unwrapped = actual_value_u64_max.unwrap();
        assert!(
            actual_value_u64_max_unwrapped == checkpoints_5000_5600[599].value,
            "Value at u64::MAX does not match last inserted value after second batch insert"
        );
        assert!(
            actual_value_u64_max_unwrapped == actual_value_max_real_unwrapped,
            "Value at u64::MAX does not match value at MAX_REAL_CHECKPOINT_ID after second batch insert"
        );
        Ok(())
    }

    pub async fn th_test_single_checkpointed_object_1_full_history_2<V: PsyDBSer + QPGenRandom>(
        &self,
        table: &SingleIdTableIdentifier,
    ) -> anyhow::Result<()> {
        // ensure the id is really non-existent
        let obj_id = self.get_non_existent_id_in_single_object::<V>(table).await?;
        let check = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, MAX_REAL_CHECKPOINT_ID)
            .await?;
        assert!(check.is_none(), "Expected non-existent id to not be found");

        let value_c_1337 = V::qp_rand_gen();
        let start_checkpoint_id = 1337u64;
        self.store
            .db_insert_one_single_checkpointed_object(table, obj_id, start_checkpoint_id, &value_c_1337)
            .await?;

        let result = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id)
            .await?;
        assert!(result.is_some(), "Value not found after insert at checkpoint 1337");
        let result_unwrapped = result.unwrap();
        assert!(result_unwrapped == value_c_1337, "Inserted value does not match");
        let result_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id)
            .await?;
        assert!(result_with_ids.is_some(), "Value with ids not found after insert at checkpoint 1337");
        let result_with_ids_unwrapped = result_with_ids.unwrap();
        assert!(result_with_ids_unwrapped.obj_id == obj_id, "Object id does not match");
        assert!(
            result_with_ids_unwrapped.checkpoint_id == start_checkpoint_id,
            "Checkpoint id does not match"
        );
        assert!(result_with_ids_unwrapped.value == value_c_1337, "Value does not match");
        // checking at a higher checkpoint should return the same value
        let result_higher = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id + 100)
            .await?;
        assert!(
            result_higher.is_some(),
            "Value not found at higher checkpoint after insert at checkpoint 1337"
        );
        let result_higher_unwrapped = result_higher.unwrap();
        assert!(result_higher_unwrapped == value_c_1337, "Value does not match at higher checkpoint");
        let result_higher_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id + 100)
            .await?;
        assert!(
            result_higher_with_ids.is_some(),
            "Value with ids not found at higher checkpoint after insert at checkpoint 1337"
        );
        let result_higher_with_ids_unwrapped = result_higher_with_ids.unwrap();
        assert!(
            result_higher_with_ids_unwrapped.obj_id == obj_id,
            "Object id does not match at higher checkpoint"
        );
        assert!(
            result_higher_with_ids_unwrapped.checkpoint_id == start_checkpoint_id,
            "Checkpoint id does not match at higher checkpoint"
        );
        assert!(
            result_higher_with_ids_unwrapped.value == value_c_1337,
            "Value does not match at higher checkpoint"
        );

        // checking at a lower checkpoint should return None
        let result_lower = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id - 1)
            .await?;
        assert!(
            result_lower.is_none(),
            "Value should not be found at lower checkpoint after insert at checkpoint 1337"
        );
        let result_lower_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id - 1)
            .await?;
        assert!(
            result_lower_with_ids.is_none(),
            "Value with ids should not be found at lower checkpoint after insert at checkpoint 1337"
        );
        // inserting at a lower checkpoint should work
        let value_c_1000 = V::qp_rand_gen();
        let lower_checkpoint_id = 1000u64;
        self.store
            .db_insert_one_single_checkpointed_object(table, obj_id, lower_checkpoint_id, &value_c_1000)
            .await?;
        let result_after_lower_insert = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, lower_checkpoint_id)
            .await?;
        assert!(
            result_after_lower_insert.is_some(),
            "Value not found after insert at lower checkpoint 1000"
        );
        let result_after_lower_insert_unwrapped = result_after_lower_insert.unwrap();
        assert!(
            result_after_lower_insert_unwrapped == value_c_1000,
            "Inserted value at lower checkpoint does not match"
        );
        let result_after_lower_insert_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, lower_checkpoint_id)
            .await?;
        assert!(
            result_after_lower_insert_with_ids.is_some(),
            "Value with ids not found after insert at lower checkpoint 1000"
        );
        let result_after_lower_insert_with_ids_unwrapped = result_after_lower_insert_with_ids.unwrap();
        assert!(
            result_after_lower_insert_with_ids_unwrapped.obj_id == obj_id,
            "Object id does not match after lower checkpoint insert"
        );
        assert!(
            result_after_lower_insert_with_ids_unwrapped.checkpoint_id == lower_checkpoint_id,
            "Checkpoint id does not match after lower checkpoint insert"
        );
        assert!(
            result_after_lower_insert_with_ids_unwrapped.value == value_c_1000,
            "Value does not match after lower checkpoint insert"
        );
        // checking at a higher checkpoint should still return the original value
        let result_higher_after_lower_insert = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, start_checkpoint_id)
            .await?;
        assert!(
            result_higher_after_lower_insert.is_some(),
            "Value not found at original checkpoint after lower checkpoint insert"
        );
        let result_higher_after_lower_insert_unwrapped = result_higher_after_lower_insert.unwrap();
        assert!(
            result_higher_after_lower_insert_unwrapped == value_c_1337,
            "Value at original checkpoint does not match after lower checkpoint insert"
        );
        let result_higher_after_lower_insert_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, start_checkpoint_id)
            .await?;
        assert!(
            result_higher_after_lower_insert_with_ids.is_some(),
            "Value with ids not found at original checkpoint after lower checkpoint insert"
        );
        let result_higher_after_lower_insert_with_ids_unwrapped = result_higher_after_lower_insert_with_ids.unwrap();
        assert!(
            result_higher_after_lower_insert_with_ids_unwrapped.obj_id == obj_id,
            "Object id does not match at original checkpoint after lower checkpoint insert"
        );
        assert!(
            result_higher_after_lower_insert_with_ids_unwrapped.checkpoint_id == start_checkpoint_id,
            "Checkpoint id does not match at original checkpoint after lower checkpoint insert"
        );
        assert!(
            result_higher_after_lower_insert_with_ids_unwrapped.value == value_c_1337,
            "Value does not match at original checkpoint after lower checkpoint insert"
        );

        // 0-10 full history test
        let first_10_checkpoints = (0..10u64).map(|_| V::qp_rand_gen()).collect::<Vec<_>>();

        let should_be_empty_pre_insert_0 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 0).await?;
        assert!(
            should_be_empty_pre_insert_0.is_none(),
            "Value should not be found at checkpoint 0 before insert"
        );
        let should_be_empty_pre_insert_5 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 5).await?;
        assert!(
            should_be_empty_pre_insert_5.is_none(),
            "Value should not be found at checkpoint 5 before insert"
        );
        let should_be_empty_pre_insert_9 = self.store.db_select_one_single_checkpointed_object_value::<V>(table, obj_id, 9).await?;
        assert!(
            should_be_empty_pre_insert_9.is_none(),
            "Value should not be found at checkpoint 9 before insert"
        );

        for (checkpoint_id, value) in first_10_checkpoints.iter().enumerate() {
            self.store
                .db_insert_one_single_checkpointed_object(table, obj_id, checkpoint_id as u64, value)
                .await?;
            let should_be_value_post_insert = self
                .store
                .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id as u64)
                .await?;
            assert!(
                should_be_value_post_insert.is_some(),
                "Value should be found at checkpoint {} after insert",
                checkpoint_id
            );
            let should_be_value_post_insert_unwrapped = should_be_value_post_insert.unwrap();
            assert!(
                should_be_value_post_insert_unwrapped == *value,
                "Value at checkpoint {} does not match inserted value",
                checkpoint_id
            );
            // check all future checkpoints to 10 are also the same as this value
            for future_checkpoint in (checkpoint_id + 1)..10 {
                let should_be_value_future = self
                    .store
                    .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, future_checkpoint as u64)
                    .await?;
                assert!(
                    should_be_value_future.is_some(),
                    "Value should be found at future checkpoint {} after insert at checkpoint {}",
                    future_checkpoint,
                    checkpoint_id
                );
                let should_be_value_future_unwrapped = should_be_value_future.unwrap();
                assert!(
                    should_be_value_future_unwrapped == *value,
                    "Value at future checkpoint {} does not match value at checkpoint {} after insert",
                    future_checkpoint,
                    checkpoint_id
                );
            }
        }

        // test if we can get many non-existent ids and this id

        let non_existent_obj_id_a = self.get_non_existent_id_in_single_object::<V>(table).await?;

        let non_existent_obj_id_b = self.get_non_existent_id_in_single_object::<V>(table).await?;

        let result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(
                table,
                &[non_existent_obj_id_a, obj_id, non_existent_obj_id_b],
                MAX_REAL_CHECKPOINT_ID,
            )
            .await?;
        assert!(result.len() == 3, "Expected 3 results from multi-select");
        assert!(result[0].is_none(), "Expected first result to be None for non-existent id");
        assert!(result[1].is_some(), "Expected second result to be Some for existing id");
        assert!(
            result[1].as_ref().unwrap() == &value_c_1337,
            "Expected second result to match inserted value"
        );
        assert!(result[2].is_none(), "Expected third result to be None for non-existent id");

        // check an intermediate checkpoint id 1336
        let result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &[non_existent_obj_id_a, obj_id, non_existent_obj_id_b], 500)
            .await?;
        assert!(result.len() == 3, "Expected 3 results from multi-select at intermediate checkpoint");
        assert!(
            result[0].is_none(),
            "Expected first result to be None for non-existent id at intermediate checkpoint"
        );
        assert!(
            result[1].is_some(),
            "Expected second result to be Some for existing id at intermediate checkpoint"
        );
        assert!(
            result[1].as_ref().unwrap() == &first_10_checkpoints[9],
            "Expected second result to match inserted value at intermediate first_10_checkpoints[9]"
        );
        assert!(
            result[2].is_none(),
            "Expected third result to be None for non-existent id at intermediate checkpoint"
        );

        // test multiple occurrences of the same id
        let result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(
                table,
                &[obj_id, non_existent_obj_id_a, obj_id, non_existent_obj_id_b, obj_id],
                MAX_REAL_CHECKPOINT_ID,
            )
            .await?;
        assert!(result.len() == 5, "Expected 5 results from multi-select with duplicates");
        assert!(result[0].is_some(), "Expected first result to be Some for existing id");
        assert!(
            result[0].as_ref().unwrap() == &value_c_1337,
            "Expected first result to match inserted value"
        );
        assert!(result[1].is_none(), "Expected second result to be None for non-existent id");
        assert!(result[2].is_some(), "Expected third result to be Some for existing id");
        assert!(
            result[2].as_ref().unwrap() == &value_c_1337,
            "Expected third result to match inserted value"
        );
        assert!(result[3].is_none(), "Expected fourth result to be None for non-existent id");
        assert!(result[4].is_some(), "Expected fifth result to be Some for existing id");
        assert!(
            result[4].as_ref().unwrap() == &value_c_1337,
            "Expected fifth result to match inserted value"
        );

        Ok(())
    }

    pub async fn th_test_single_checkpointed_object_1_full_history_3<V: PsyDBSer + QPGenRandom>(
        &self,
        table: &SingleIdTableIdentifier,
    ) -> anyhow::Result<()> {
        let first_checkpoint = 0u64;
        let second_checkpoint = 1u64;
        let last_checkpoint = 100_000u64;

        let obj_ids_batch_a = self.get_many_non_existent_ids_in_single_object::<V>(table, 2000).await?;
        assert!(obj_ids_batch_a.len() == 2000, "Expected to get 2000 non-existent ids");

        let obj_rows_batch_a = obj_ids_batch_a
            .iter()
            .map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen()))
            .collect::<Vec<_>>();

        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint(table, first_checkpoint, &obj_rows_batch_a)
            .await?;
        let objs_a_at_first = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_a, first_checkpoint)
            .await?;
        let objs_a_at_first = objs_a_at_first
            .into_iter()
            .collect::<Option<Vec<V>>>()
            .ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at first checkpoint"))?;
        assert!(
            objs_a_at_first.len() == obj_ids_batch_a.len(),
            "Expected all objects to be found at first checkpoint"
        );
        for (i, obj) in objs_a_at_first.iter().enumerate() {
            assert!(obj == &obj_rows_batch_a[i].value, "Expected object value to match at first checkpoint");
        }
        let objs_a_at_second = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_a, second_checkpoint)
            .await?;
        let objs_a_at_second = objs_a_at_second
            .into_iter()
            .collect::<Option<Vec<V>>>()
            .ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at second checkpoint"))?;
        assert!(
            objs_a_at_second.len() == obj_ids_batch_a.len(),
            "Expected all objects to be found at second checkpoint"
        );
        for (i, obj) in objs_a_at_second.iter().enumerate() {
            assert!(obj == &obj_rows_batch_a[i].value, "Expected object value to match at second checkpoint");
        }
        let objs_a_at_high = self
            .store
            .db_select_many_single_checkpointed_object_keys_and_values::<V, QDatabaseSingleIdTableRow<V>>(table, &obj_ids_batch_a, 12312732)
            .await?;
        for (i, row) in objs_a_at_high.iter().enumerate() {
            assert!(row.obj_id == obj_ids_batch_a[i], "Expected object id to match at high checkpoint");
            assert!(
                row.checkpoint_id == first_checkpoint,
                "Expected checkpoint id to match at high checkpoint"
            );
            assert!(
                row.value == obj_rows_batch_a[i].value,
                "Expected object value to match at high checkpoint"
            );
        }

        // insert at second_checkpoint
        let obj_rows_batch_a_second = obj_ids_batch_a
            .iter()
            .map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen()))
            .collect::<Vec<_>>();
        let obj_ids_batch_b = self.get_many_non_existent_ids_in_single_object::<V>(table, 1500).await?;
        assert!(obj_ids_batch_b.len() == 1500, "Expected to get 1500 non-existent ids for batch b");
        let obj_rows_batch_b = obj_ids_batch_b
            .iter()
            .map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen()))
            .collect::<Vec<_>>();
        let combined_rows: Vec<QDatabaseSingleIdTableRowNoCheckpointId<V>> =
            obj_rows_batch_a_second.iter().chain(obj_rows_batch_b.iter()).cloned().collect();
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint(table, second_checkpoint, &combined_rows)
            .await?;

        let combined_ids = obj_ids_batch_a.iter().chain(obj_ids_batch_b.iter()).cloned().collect::<Vec<_>>();
        let objs_combined_at_second = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, second_checkpoint)
            .await?;
        let objs_combined_at_second = objs_combined_at_second
            .into_iter()
            .collect::<Option<Vec<V>>>()
            .ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at second checkpoint after second insert"))?;
        assert!(
            objs_combined_at_second.len() == combined_ids.len(),
            "Expected all objects to be found at second checkpoint after second insert"
        );
        for i in 0..obj_ids_batch_a.len() {
            assert!(
                objs_combined_at_second[i] == obj_rows_batch_a_second[i].value,
                "Expected object value to match for batch a at second checkpoint after second insert"
            );
        }
        for i in 0..obj_ids_batch_b.len() {
            assert!(
                objs_combined_at_second[i + obj_ids_batch_a.len()] == obj_rows_batch_b[i].value,
                "Expected object value to match for batch b at second checkpoint after second insert"
            );
        }
        // check that batch a ids at first checkpoint are still the same, and batch b
        // ids are not found
        let objs_a_at_first_post_second = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, first_checkpoint)
            .await?;
        let objs_a_at_first_post_second = objs_a_at_first_post_second[0..obj_ids_batch_a.len()]
            .to_vec()
            .into_iter()
            .collect::<Option<Vec<V>>>()
            .ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at first checkpoint after second insert"))?;
        assert!(
            objs_a_at_first_post_second.len() == obj_ids_batch_a.len(),
            "Expected all batch a objects to be found at first checkpoint after second insert"
        );
        for (i, obj) in objs_a_at_first_post_second.iter().enumerate() {
            assert!(
                obj == &obj_rows_batch_a[i].value,
                "Expected batch a object value to match at first checkpoint after second insert"
            );
        }
        let objs_b_at_first_post_second = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_b, first_checkpoint)
            .await?;
        for obj in objs_b_at_first_post_second.iter() {
            assert!(
                obj.is_none(),
                "Expected batch b object to not be found at first checkpoint after second insert"
            );
        }
        // insert at last_checkpoint
        let obj_rows_batch_a_last = obj_ids_batch_a
            .iter()
            .map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen()))
            .collect::<Vec<_>>();
        let obj_rows_batch_b_last = obj_ids_batch_b
            .iter()
            .map(|&id| QDatabaseSingleIdTableRowNoCheckpointId::new(id, V::qp_rand_gen()))
            .collect::<Vec<_>>();
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint(table, last_checkpoint, &obj_rows_batch_a_last)
            .await?;
        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_t(table, last_checkpoint, &obj_rows_batch_b_last)
            .await?;
        let combined_ids = obj_ids_batch_a.iter().chain(obj_ids_batch_b.iter()).cloned().collect::<Vec<_>>();
        let objs_combined_at_last = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, last_checkpoint)
            .await?;
        let objs_combined_at_last = objs_combined_at_last
            .into_iter()
            .collect::<Option<Vec<V>>>()
            .ok_or_else(|| anyhow::anyhow!("Expected all objects to be found at last checkpoint after last insert"))?;
        assert!(
            objs_combined_at_last.len() == combined_ids.len(),
            "Expected all objects to be found at last checkpoint after last insert"
        );
        for i in 0..obj_ids_batch_a.len() {
            assert!(
                objs_combined_at_last[i] == obj_rows_batch_a_last[i].value,
                "Expected object value to match for batch a at last checkpoint after last insert"
            );
        }
        for i in 0..obj_ids_batch_b.len() {
            assert!(
                objs_combined_at_last[i + obj_ids_batch_a.len()] == obj_rows_batch_b_last[i].value,
                "Expected object value to match for batch b at last checkpoint after last insert"
            );
        }
        // check that batch a ids at second checkpoint are still the same, and batch b
        // ids are not found
        let objs_a_at_second_post_last = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, second_checkpoint)
            .await?;
        let objs_a_at_second_post_last = objs_a_at_second_post_last[0..obj_ids_batch_a.len()]
            .to_vec()
            .into_iter()
            .collect::<Option<Vec<V>>>()
            .ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at second checkpoint after last insert"))?;
        assert!(
            objs_a_at_second_post_last.len() == obj_ids_batch_a.len(),
            "Expected all batch a objects to be found at second checkpoint after last insert"
        );
        for (i, obj) in objs_a_at_second_post_last.iter().enumerate() {
            assert!(
                obj == &obj_rows_batch_a_second[i].value,
                "Expected batch a object value to match at second checkpoint after last insert"
            );
        }
        let objs_b_at_second_post_last = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_b, second_checkpoint)
            .await?;
        for obj in objs_b_at_second_post_last.iter() {
            assert!(
                obj.is_some(),
                "Expected batch b object to be found at second checkpoint after last insert"
            );
            assert!(
                obj.as_ref().unwrap() == &obj_rows_batch_b[objs_b_at_second_post_last.iter().position(|x| x == obj).unwrap()].value,
                "Expected batch b object value to match at second checkpoint after last insert"
            );
        }
        // check that batch a ids at first checkpoint are still the same, and batch b
        // ids are not found
        let objs_a_at_first_post_last = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &combined_ids, first_checkpoint)
            .await?;
        let objs_a_at_first_post_last = objs_a_at_first_post_last[0..obj_ids_batch_a.len()]
            .to_vec()
            .into_iter()
            .collect::<Option<Vec<V>>>()
            .ok_or_else(|| anyhow::anyhow!("Expected all batch a objects to be found at first checkpoint after last insert"))?;
        assert!(
            objs_a_at_first_post_last.len() == obj_ids_batch_a.len(),
            "Expected all batch a objects to be found at first checkpoint after last insert"
        );
        for (i, obj) in objs_a_at_first_post_last.iter().enumerate() {
            assert!(
                obj == &obj_rows_batch_a[i].value,
                "Expected batch a object value to match at first checkpoint after last insert"
            );
        }
        let objs_b_at_first_post_last = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &obj_ids_batch_b, first_checkpoint)
            .await?;
        for obj in objs_b_at_first_post_last.iter() {
            assert!(
                obj.is_none(),
                "Expected batch b object to not be found at first checkpoint after last insert"
            );
        }

        // batch set obj_ids_batch_a to first_checkpoint

        Ok(())
    }

    async fn th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_id: u64,
        checkpoint_id: u64,
        tree_height: u8,
        root: SimpleMerkleNodeKey,
    ) -> anyhow::Result<()> {
        assert!(tree_height >= root.level, "Tree height must be greater than or equal to root level");
        let root_value = self
            .store
            .db_select_single_id_merkle_node_max_checkpoint(table, checkpoint_id, tree_id, tree_height, root)
            .await?;
        assert!(
            root_value == Hasher::get_zero_hash((tree_height - root.level) as usize),
            "Root value must be zero hash at root level"
        );
        if root.level == tree_height {
            return Ok(());
        }

        let child_keys = rand_children_to_height(&root, tree_height);
        let node_values = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &child_keys)
            .await?;
        let expected_values = child_keys
            .iter()
            .map(|key| Hasher::get_zero_hash((tree_height - key.level) as usize))
            .collect::<Vec<_>>();
        assert!(
            node_values.len() == expected_values.len(),
            "Node values and expected values lengths must match"
        );
        for (i, value) in node_values.iter().enumerate() {
            assert!(value == &expected_values[i], "Node value must match expected zero hash");
        }

        Ok(())
    }
    pub async fn th_test_insert_single_id_merkle_leaves_sub_tree_dmp(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        checkpoint_id: u64,
        tree_id: u64,
        tree_height: u8,
        sub_root_key: &SimpleMerkleNodeKey,
        leaves: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
        if leaves.is_empty() {
            return Ok(vec![]);
        }
        assert!(
            sub_root_key.level <= tree_height,
            "Sub root level must be at or below the tree height level"
        );

        let first_leaf_level = leaves[0].key.level;
        assert!(first_leaf_level <= tree_height, "Leaf keys must be at or below the tree height level");
        assert!(first_leaf_level >= sub_root_key.level, "Leaf keys must be at or below the sub root level");

        for leaf in leaves.iter() {
            assert!(leaf.key.level == first_leaf_level, "All leaf keys must be at the same level");
        }
        let leaf_values = leaves.iter().map(|node| node.value).collect::<Vec<_>>();
        let leaf_keys = leaves.iter().map(|node| node.key).collect::<Vec<_>>();
        let dmps = db_helper_single_id_merkle_node_simple_set_leaves_fast_serialize::<Hash, Hasher, SingleIdMerkleTableIdentifier, _>(
            &self.store,
            table,
            checkpoint_id,
            tree_id,
            tree_height,
            0,
            9999,
            leaves,
        )
        .await?;
        assert!(
            dmps.len() == leaves.len(),
            "Number of DeltaMerkleProofs must match number of inserted leaves"
        );
        let selected_leaf_values = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &leaf_keys)
            .await?;
        assert!(
            selected_leaf_values.len() == leaf_values.len(),
            "Selected leaf values length must match inserted leaf values length"
        );
        for (i, value) in selected_leaf_values.iter().enumerate() {
            assert!(value == &leaf_values[i], "Selected leaf value must match inserted leaf value");
        }
        for dmp in dmps.iter() {
            assert!(dmp.verify::<Hasher>(), "DeltaMerkleProof must verify correctly");
        }

        for i in 1..dmps.len() {
            assert!(
                dmps[i - 1].new_root == dmps[i].old_root,
                "Consecutive DeltaMerkleProofs must be connected back to back, ie. new_root of previous must equal old_root of next"
            );
        }

        Ok(dmps)
    }
    pub async fn th_test_single_id_merkle_nodes_basic(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_id: u64,
        tree_height: u8,
    ) -> anyhow::Result<()> {
        let first_checkpoint_id = 1u64;
        let second_checkpoint_id = 2u64;
        let third_checkpoint_id = 3u64;
        let fourth_checkpoint_id = 999u64;
        let last_checkpoint_id = 12874892u64;
        self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(
            table,
            tree_id,
            first_checkpoint_id,
            tree_height,
            SimpleMerkleNodeKey::new_root(),
        )
        .await?;
        self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(
            table,
            tree_id,
            second_checkpoint_id,
            tree_height,
            SimpleMerkleNodeKey::new_root(),
        )
        .await?;
        self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(
            table,
            tree_id,
            third_checkpoint_id,
            tree_height,
            SimpleMerkleNodeKey::new_root(),
        )
        .await?;
        self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(
            table,
            tree_id,
            fourth_checkpoint_id,
            tree_height,
            SimpleMerkleNodeKey::new_root(),
        )
        .await?;
        self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(
            table,
            tree_id,
            last_checkpoint_id,
            tree_height,
            SimpleMerkleNodeKey::new_root(),
        )
        .await?;

        let max_leaves_in_tree = 1u64 << tree_height;
        let num_leaves_to_insert = 16u64.min(max_leaves_in_tree);
        let num_leaves_to_insert_usize = num_leaves_to_insert as usize;
        let root_key = SimpleMerkleNodeKey::new_root();
        let first_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);

        let dmps_0 = self
            .th_test_insert_single_id_merkle_leaves_sub_tree_dmp(
                table,
                first_checkpoint_id,
                tree_id,
                tree_height,
                &SimpleMerkleNodeKey::new_root(),
                &first_batch,
            )
            .await?;
        assert!(
            dmps_0.len() == first_batch.len(),
            "Number of DeltaMerkleProofs must match number of inserted leaves at first checkpoint"
        );

        self.th_ensure_single_id_merkle_zero_hashes_at_checkpoint_for_sub_tree_a(table, tree_id, 0, tree_height, SimpleMerkleNodeKey::new_root())
            .await?;
        let second_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_1 = self
            .th_test_insert_single_id_merkle_leaves_sub_tree_dmp(
                table,
                second_checkpoint_id,
                tree_id,
                tree_height,
                &SimpleMerkleNodeKey::new_root(),
                &second_batch,
            )
            .await?;
        assert!(
            dmps_1.len() == second_batch.len(),
            "Number of DeltaMerkleProofs must match number of inserted leaves at second checkpoint"
        );

        let first_second_batch_combined_halves = [
            first_batch[0..(num_leaves_to_insert_usize / 2)].to_vec(),
            second_batch[(num_leaves_to_insert_usize / 2)..num_leaves_to_insert_usize].to_vec(),
        ]
        .concat();
        let third_batch_unmodified = [
            first_batch[(num_leaves_to_insert_usize / 2)..num_leaves_to_insert_usize].to_vec(),
            second_batch[0..(num_leaves_to_insert_usize / 2)].to_vec(),
        ]
        .concat();
        let third_batch_new_leaves = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let first_second_batch_leaves_at_third_checkpoint = first_second_batch_combined_halves
            .iter()
            .map(|x| SimpleMerkleNode {
                key: x.key,
                value: Hash::qp_rand_gen(),
            })
            .collect::<Vec<_>>();
        let third_batch = [first_second_batch_leaves_at_third_checkpoint, third_batch_new_leaves.clone()].concat();
        let dmps_2 = self
            .th_test_insert_single_id_merkle_leaves_sub_tree_dmp(
                table,
                third_checkpoint_id,
                tree_id,
                tree_height,
                &SimpleMerkleNodeKey::new_root(),
                &third_batch,
            )
            .await?;
        assert!(
            dmps_2.len() == third_batch.len(),
            "Number of DeltaMerkleProofs must match number of inserted leaves at third checkpoint"
        );
        // ensure that the unmodified leaves are still the same at third checkpoint
        let b12_unmodified_keys = third_batch_unmodified.iter().map(|x| x.key).collect::<Vec<_>>();
        let b12_unmodified_values = third_batch_unmodified.iter().map(|x| x.value).collect::<Vec<_>>();
        let selected_unmodified_values = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, third_checkpoint_id, tree_id, tree_height, &b12_unmodified_keys)
            .await?;
        assert!(
            selected_unmodified_values.len() == b12_unmodified_values.len(),
            "Selected unmodified values length must match unmodified values length at third checkpoint"
        );
        for (i, value) in selected_unmodified_values.iter().enumerate() {
            assert!(
                value == &b12_unmodified_values[i],
                "Selected unmodified value must match unmodified value at third checkpoint"
            );
        }
        // ensure that the modified leaves are different at third checkpoint
        let b3_modified_keys = third_batch_new_leaves.iter().map(|x| x.key).collect::<Vec<_>>();
        let b3_modified_values = third_batch_new_leaves.iter().map(|x| x.value).collect::<Vec<_>>();
        let selected_modified_values = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, third_checkpoint_id, tree_id, tree_height, &b3_modified_keys)
            .await?;
        assert!(
            selected_modified_values.len() == b3_modified_values.len(),
            "Selected modified values length must match modified values length at third checkpoint"
        );
        for (i, value) in selected_modified_values.iter().enumerate() {
            assert!(
                value == &b3_modified_values[i],
                "Selected modified value must match modified value at third checkpoint"
            );
        }

        let fourth_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_3 = self
            .th_test_insert_single_id_merkle_leaves_sub_tree_dmp(
                table,
                fourth_checkpoint_id,
                tree_id,
                tree_height,
                &SimpleMerkleNodeKey::new_root(),
                &fourth_batch,
            )
            .await?;
        assert!(
            dmps_3.len() == fourth_batch.len(),
            "Number of DeltaMerkleProofs must match number of inserted leaves at fourth checkpoint"
        );

        let last_batch = rand_leaves_for_subtree::<Hash>(&root_key, tree_height, num_leaves_to_insert_usize);
        let dmps_4 = self
            .th_test_insert_single_id_merkle_leaves_sub_tree_dmp(
                table,
                last_checkpoint_id,
                tree_id,
                tree_height,
                &SimpleMerkleNodeKey::new_root(),
                &last_batch,
            )
            .await?;
        assert!(
            dmps_4.len() == last_batch.len(),
            "Number of DeltaMerkleProofs must match number of inserted leaves at last checkpoint"
        );

        let keys_to_check: Vec<_> = first_batch
            .iter()
            .chain(second_batch.iter())
            .chain(third_batch.iter())
            .chain(fourth_batch.iter())
            .chain(last_batch.iter())
            .map(|x| x.key)
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        for k in keys_to_check {
            let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(
                &self.store,
                table,
                first_checkpoint_id + 1,
                tree_id,
                tree_height,
                k,
            )
            .await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(
                &self.store,
                table,
                second_checkpoint_id,
                tree_id,
                tree_height,
                k,
            )
            .await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(
                &self.store,
                table,
                third_checkpoint_id,
                tree_id,
                tree_height,
                k,
            )
            .await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(
                &self.store,
                table,
                fourth_checkpoint_id,
                tree_id,
                tree_height,
                k,
            )
            .await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(
                &self.store,
                table,
                last_checkpoint_id,
                tree_id,
                tree_height,
                k,
            )
            .await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
            let mp = db_helper_select_single_id_merkle_proof_max_checkpoint::<Hash, Hasher, _, _>(
                &self.store,
                table,
                last_checkpoint_id + 100,
                tree_id,
                tree_height,
                k,
            )
            .await?;
            assert!(mp.verify::<Hasher>(), "MerkleProof must verify correctly for key {:?}", k);
        }
        Ok(())
    }
}
