// this is test only helper code, so we allow dead code
// for tests/examples only, we allow dead code
#![allow(dead_code)]

use parth_core::{
    data::{
        db::{
            data_types::{BiDirectionalMappingRow, QDatabasePrimitiveKey},
            row::{
                QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRowNoCheckpointIdLike,
            },
        },
        hash::
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}
        ,
        serializable::QPDPair,
    },
    protocol::core_types::QDBHashBase,
};

use super::{
    core::QJumboStore,
    utils::{PsyDBSer, THHasher, THStandardTableIdentifier, DEFINITELY_MISSING_U128_ID_VALUE,
        DEFINITELY_MISSING_U64_VALUE,
    },
};
use crate::
    store::traits::
        core_db::{CoreDatabaseSingleIdMerkleReader, CoreDatabaseStore}
    
;
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
        Hash: QDBHashBase,
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
    pub async fn th_util_insert_one_kiv<V: PsyDBSer>(&self, table: &KivTableIdentifier, obj_id: u64, value: &V) -> anyhow::Result<()> {
        self.store.db_insert_one_kiv(table, obj_id, value).await?;
        let result = self.store.db_select_one_kiv_value::<V>(table, obj_id).await?;
        assert!(result.is_some(), "Value not found after insert");
        let result_value = result.unwrap();
        assert!(result_value == value.clone(), "Inserted value does not match retrieved value");
        Ok(())
    }

    async fn th_util_insert_many_kivs_t<V: PsyDBSer, R: QDatabaseKeyIdValueTableRowLike<V> + Send + Sync>(
        &self,
        table: &KivTableIdentifier,
        rows: &[R],
    ) -> anyhow::Result<()> {
        self.store.db_insert_many_kivs_t(table, rows).await?;
        let keys: Vec<u64> = rows.iter().map(|r| r.get_row_obj_id()).collect();
        let results = self.store.db_select_many_kiv_values::<V>(table, &keys).await?;
        assert!(
            results.len() == rows.len(),
            "Number of retrieved values does not match number of inserted values"
        );
        for (i, row) in rows.iter().enumerate() {
            let result_value = results[i].as_ref().ok_or_else(|| anyhow::anyhow!("Value not found after insert"))?;
            assert!(result_value == row.get_row_value_ref(), "Inserted value does not match retrieved value");
        }
        Ok(())
    }

    async fn th_util_insert_one_bidirectional_mapping<K1: QDatabasePrimitiveKey, K2: QDatabasePrimitiveKey>(
        &self,
        table: &BiDirectionalMappingTableIdentifier,
        key1: &K1,
        key2: &K2,
    ) -> anyhow::Result<()> {
        self.store.db_insert_pair_ref(table, key1, key2).await?;

        let result_key2 = self.store.db_select_one_by_k1::<K1, K2>(table, key1).await?;
        assert!(result_key2.is_some(), "Key2 not found after insert");
        let result_key2_value = result_key2.unwrap();
        assert!(result_key2_value == key2.clone(), "Inserted key2 does not match retrieved key2");
        let result_key1 = self.store.db_select_one_by_k2::<K1, K2>(table, key2).await?;
        assert!(result_key1.is_some(), "Key1 not found after insert");
        let result_key1_value = result_key1.unwrap();
        assert!(result_key1_value == key1.clone(), "Inserted key1 does not match retrieved key1");

        // test many as well
        let result_key2_multi = self.store.db_select_many_by_k1::<K1, K2>(table, &[key1.clone()]).await?;
        assert!(
            result_key2_multi.len() == 1,
            "Number of retrieved key2 values does not match number of inserted values"
        );
        let result_key2_multi_value = result_key2_multi[0]
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Key2 not found after insert in multi"))?;
        assert!(
            *result_key2_multi_value == key2.clone(),
            "Inserted key2 does not match retrieved key2 in multi"
        );
        let result_key1_multi = self.store.db_select_many_by_k2::<K1, K2>(table, &[key2.clone()]).await?;
        assert!(
            result_key1_multi.len() == 1,
            "Number of retrieved key1 values does not match number of inserted values"
        );
        let result_key1_multi_value = result_key1_multi[0]
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Key1 not found after insert in multi"))?;
        assert!(
            *result_key1_multi_value == key1.clone(),
            "Inserted key1 does not match retrieved key1 in multi"
        );

        Ok(())
    }

    async fn th_util_insert_many_bidirectional_mappings<
        K1: QDatabasePrimitiveKey,
        K2: QDatabasePrimitiveKey,
        R: QDatabaseKeyIdValueTableRowLike<K2> + Send + Sync,
    >(
        &self,
        table: &BiDirectionalMappingTableIdentifier,
        rows: &[BiDirectionalMappingRow<K1, K2>],
    ) -> anyhow::Result<()> {
        let expected_k1s = rows.iter().map(|r| r.k1.clone()).collect::<Vec<K1>>();
        let expected_k2s = rows.iter().map(|r| r.k2.clone()).collect::<Vec<K2>>();

        self.store.db_insert_pairs(table, rows).await?;

        // ensure multi select works

        let actual_rows = self.store.db_select_many_pairs_by_k1::<K1, K2>(table, &expected_k1s).await?;
        assert!(
            actual_rows.len() == rows.len(),
            "Number of retrieved rows does not match number of inserted rows"
        );
        for row in rows.iter() {
            let actual_row = actual_rows
                .iter()
                .find(|r| r.k1 == row.k1)
                .ok_or_else(|| anyhow::anyhow!("Row not found after insert"))?;
            assert!(actual_row.k2 == row.k2, "Inserted row does not match retrieved row");
        }
        assert!(&actual_rows == rows, "Inserted rows order do not match retrieved rows order");
        let actual_k2s = self
            .store
            .db_select_many_by_k1::<K1, K2>(table, &expected_k1s)
            .await?
            .into_iter()
            .map(|r| r.unwrap())
            .collect::<Vec<K2>>();
        assert!(
            actual_k2s.len() == rows.len(),
            "Number of retrieved key2 values does not match number of inserted values"
        );
        assert!(&actual_k2s == &expected_k2s, "Inserted key2 values do not match retrieved key2 values");
        let actual_k1s = self
            .store
            .db_select_many_by_k2::<K1, K2>(table, &expected_k2s)
            .await?
            .into_iter()
            .map(|r| r.unwrap())
            .collect::<Vec<K1>>();
        assert!(
            actual_k1s.len() == rows.len(),
            "Number of retrieved key1 values does not match number of inserted values"
        );
        assert!(&actual_k1s == &expected_k1s, "Inserted key1 values do not match retrieved key1 values");

        // ensure single select works
        for (i, k1) in expected_k1s.iter().enumerate() {
            let actual_k2 = self.store.db_select_one_by_k1::<K1, K2>(table, k1).await?;
            assert!(actual_k2.is_some(), "Key2 not found after insert");
            let actual_k2_value = actual_k2.unwrap();
            assert!(actual_k2_value == expected_k2s[i], "Inserted key2 does not match retrieved key2");
        }

        for (i, k2) in expected_k2s.iter().enumerate() {
            let actual_k1 = self.store.db_select_one_by_k2::<K1, K2>(table, k2).await?;
            assert!(actual_k1.is_some(), "Key1 not found after insert");
            let actual_k1_value = actual_k1.unwrap();
            assert!(actual_k1_value == expected_k1s[i], "Inserted key1 does not match retrieved key1");
        }

        let actual_rows_by_k2 = self.store.db_select_many_pairs_by_k2::<K1, K2>(table, &expected_k2s).await?;
        assert!(
            actual_rows_by_k2.len() == rows.len(),
            "Number of retrieved rows does not match number of inserted rows"
        );
        assert!(&actual_rows_by_k2 == rows, "Inserted rows order do not match retrieved rows order");
        Ok(())
    }
}

// END: TH Helpers

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
        Hash: QDBHashBase,
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
    pub async fn th_util_select_u64_value(&self, table: &U64TableIdentifier, obj_id: u64) -> anyhow::Result<Option<u64>> {
        let result = self.store.db_select_u64_value(table, obj_id).await?;
        let multi_result = self
            .store
            .db_select_u64_values(table, &[obj_id, DEFINITELY_MISSING_U64_VALUE, obj_id])
            .await?;
        assert!(multi_result.len() == 3, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(multi_result[1].is_none(), "Multi select second result should be None");
        assert!(multi_result[2] == result, "Multi select third result does not match single select result");

        Ok(result)
    }
    pub async fn th_util_set_u64_value(&self, table: &U64TableIdentifier, obj_id: u64, value: u64) -> anyhow::Result<()> {
        self.store.db_set_u64_value(table, obj_id, value).await?;
        let result = self.th_util_select_u64_value(table, obj_id).await?;
        assert!(result.is_some(), "Value not found after insert");
        let result_value = result.unwrap();
        assert!(result_value == value, "Inserted value does not match retrieved value");
        Ok(())
    }
    pub async fn th_util_set_many_u64_values(&self, table: &U64TableIdentifier, rows: &[QPDPair<u64, u64>]) -> anyhow::Result<()> {
        self.store.db_set_many_u64_values(table, rows).await?;
        let keys: Vec<u64> = rows.iter().map(|r| r.key).collect();
        let results = self.store.db_select_u64_values(table, &keys).await?;
        assert!(
            results.len() == rows.len(),
            "Number of retrieved values does not match number of inserted values"
        );
        for (i, row) in rows.iter().enumerate() {
            let result_value = results[i].as_ref().ok_or_else(|| anyhow::anyhow!("Value not found after insert"))?;
            assert!(*result_value == row.value, "Inserted value does not match retrieved value");
            let result_single_value = self.th_util_select_u64_value(table, row.key).await?;
            assert!(result_single_value.is_some(), "Value not found after insert in single select");
            let result_single_value_unwrapped = result_single_value.unwrap();
            assert!(
                result_single_value_unwrapped == row.value,
                "Inserted value does not match retrieved value in single select"
            );
        }

        Ok(())
    }

    pub async fn th_util_inc_counter(&self, table: &U64TableIdentifier, obj_id: u64, inc_amount: i64) -> anyhow::Result<u64> {
        let before = self.th_util_select_u64_value(table, obj_id).await?;
        let result = self.store.db_inc_counter(table, obj_id, inc_amount).await?;
        let after = self.th_util_select_u64_value(table, obj_id).await?;
        if before.is_none() {
            assert!(result == inc_amount as u64, "Increment result does not match expected value");
            assert!(after.is_some(), "Value not found after increment");
            let after_unwrapped = after.unwrap();
            assert!(
                after_unwrapped == inc_amount as u64,
                "Value after increment does not match expected value"
            );
        } else {
            let before_unwrapped = before.unwrap();
            let expected = if inc_amount.is_negative() {
                before_unwrapped.saturating_sub(inc_amount.wrapping_abs() as u64)
            } else {
                before_unwrapped.saturating_add(inc_amount as u64)
            };
            assert!(result == expected, "Increment result does not match expected value");
            assert!(after.is_some(), "Value not found after increment");
            let after_unwrapped = after.unwrap();
            assert!(after_unwrapped == expected, "Value after increment does not match expected value");
        }
        Ok(result)
    }
    pub async fn th_util_select_u64_u128_bi_directional_mapping(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        key: u64,
    ) -> anyhow::Result<Option<u128>> {
        let result = self.store.db_select_one_u128_value_by_u64(table, key).await?;
        let result_multi = self
            .store
            .db_select_many_u128_values_by_u64s(table, &[key, DEFINITELY_MISSING_U64_VALUE, key])
            .await?;
        assert!(result_multi.len() == 3, "Multi select did not return correct number of results");
        assert!(result_multi[0] == result, "Multi select first result does not match single select result");
        assert!(result_multi[1].is_none(), "Multi select second result should be None");
        assert!(result_multi[2] == result, "Multi select third result does not match single select result");

        // check the reverse

        if result.is_some() {
            let r_result = result.unwrap();
            let reverse_lookup = self.store.db_select_one_u64_key_by_u128(table, r_result).await?;
            assert!(reverse_lookup.is_some(), "Reverse lookup failed, value not found");
            let reverse_lookup_unwrapped = reverse_lookup.unwrap();
            assert!(reverse_lookup_unwrapped == key, "Reverse lookup failed, value does not match");

            let reverse_lookup_multi = self
                .store
                .db_select_many_u64_keys_by_u128s(table, &[r_result, (DEFINITELY_MISSING_U128_ID_VALUE), r_result])
                .await?;
            assert!(
                reverse_lookup_multi.len() == 3,
                "Reverse lookup multi did not return correct number of results"
            );
            assert!(reverse_lookup_multi[0].is_some(), "Reverse lookup multi first result should be Some");
            assert!(
                reverse_lookup_multi[0].unwrap() == key,
                "Reverse lookup multi first result does not match key"
            );
            assert!(reverse_lookup_multi[1].is_none(), "Reverse lookup multi second result should be None");
            assert!(reverse_lookup_multi[2].is_some(), "Reverse lookup multi third result should be Some");
            assert!(
                reverse_lookup_multi[2].unwrap() == key,
                "Reverse lookup multi third result does not match key"
            );
        }
        Ok(result)
    }

    pub async fn th_util_select_many_u128_values_by_u64s(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        keys: &[u64],
    ) -> anyhow::Result<Vec<Option<u128>>> {
        let result = self.store.db_select_many_u128_values_by_u64s(table, keys).await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self.th_util_select_u64_u128_bi_directional_mapping(table, *key).await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }

    pub async fn th_util_select_u64_u128_bi_directional_mapping_by_u128(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        key: u128,
    ) -> anyhow::Result<Option<u64>> {
        let result = self.store.db_select_one_u64_key_by_u128(table, key).await?;
        let result_multi = self
            .store
            .db_select_many_u64_keys_by_u128s(table, &[key, DEFINITELY_MISSING_U128_ID_VALUE, key])
            .await?;
        assert!(result_multi.len() == 3, "Multi select did not return correct number of results");
        assert!(result_multi[0] == result, "Multi select first result does not match single select result");
        assert!(result_multi[1].is_none(), "Multi select second result should be None");
        assert!(result_multi[2] == result, "Multi select third result does not match single select result");

        // check the reverse

        if result.is_some() {
            let r_result = result.unwrap();
            let reverse_lookup = self.store.db_select_one_u128_value_by_u64(table, r_result).await?;
            assert!(reverse_lookup.is_some(), "Reverse lookup failed, value not found");
            let reverse_lookup_unwrapped = reverse_lookup.unwrap();
            assert!(reverse_lookup_unwrapped == key, "Reverse lookup failed, value does not match");

            let reverse_lookup_multi = self
                .store
                .db_select_many_u128_values_by_u64s(table, &[r_result, DEFINITELY_MISSING_U64_VALUE, r_result])
                .await?;
            assert!(
                reverse_lookup_multi.len() == 3,
                "Reverse lookup multi did not return correct number of results"
            );
            assert!(reverse_lookup_multi[0].is_some(), "Reverse lookup multi first result should be Some");
            assert!(
                reverse_lookup_multi[0].unwrap() == key,
                "Reverse lookup multi first result does not match key"
            );
            assert!(reverse_lookup_multi[1].is_none(), "Reverse lookup multi second result should be None");
            assert!(reverse_lookup_multi[2].is_some(), "Reverse lookup multi third result should be Some");
            assert!(
                reverse_lookup_multi[2].unwrap() == key,
                "Reverse lookup multi third result does not match key"
            );
        }
        Ok(result)
    }

    pub async fn th_util_select_many_u64_keys_by_u128s(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        keys: &[u128],
    ) -> anyhow::Result<Vec<Option<u64>>> {
        let result = self.store.db_select_many_u64_keys_by_u128s(table, keys).await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self.th_util_select_u64_u128_bi_directional_mapping_by_u128(table, *key).await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }
    pub async fn th_util_insert_u64_u128_mapping_pair(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        key: u64,
        value: u128,
    ) -> anyhow::Result<()> {
        self.store.db_insert_u64_u128_mapping_pair(table, key, value).await?;
        let result = self.th_util_select_u64_u128_bi_directional_mapping(table, key).await?;
        assert!(result.is_some(), "Value not found after insert");
        let result_value = result.unwrap();
        assert!(result_value == value, "Inserted value does not match retrieved value");

        let reverse_result = self.th_util_select_u64_u128_bi_directional_mapping_by_u128(table, value).await?;
        assert!(reverse_result.is_some(), "Reverse value not found after insert");
        let reverse_result_value = reverse_result.unwrap();
        assert!(
            reverse_result_value == key,
            "Inserted reverse value does not match retrieved reverse value"
        );
        Ok(())
    }
    pub async fn th_util_insert_u64_u128_mapping_pairs(
        &self,
        table: &BiDirectionalU64U128MappingTableIdentifier,
        rows: &[BiDirectionalMappingRow<u64, u128>],
    ) -> anyhow::Result<()> {
        let expected_k1s = rows.iter().map(|r| r.k1).collect::<Vec<u64>>();
        let expected_k2s = rows.iter().map(|r| r.k2).collect::<Vec<u128>>();

        self.store.db_insert_u64_u128_mapping_pairs(table, &rows).await?;

        // ensure multi select works

        let actual_k1s = self
            .th_util_select_many_u64_keys_by_u128s(table, &expected_k2s)
            .await?
            .iter()
            .map(|r| r.unwrap())
            .collect::<Vec<u64>>();
        assert!(
            actual_k1s.len() == rows.len(),
            "Number of retrieved key1 values does not match number of inserted values"
        );
        assert!(&actual_k1s == &expected_k1s, "Inserted key1 values do not match retrieved key1 values");

        let actual_k2s = self
            .th_util_select_many_u128_values_by_u64s(table, &expected_k1s)
            .await?
            .iter()
            .map(|r| r.unwrap())
            .collect::<Vec<u128>>();
        assert!(
            actual_k2s.len() == rows.len(),
            "Number of retrieved key2 values does not match number of inserted values"
        );
        assert!(&actual_k2s == &expected_k2s, "Inserted key2 values do not match retrieved key2 values");
        Ok(())
    }

    pub async fn th_util_select_one_single_checkpointed_object_value<V: PsyDBSer>(
        &self,
        table: &SingleIdTableIdentifier,
        obj_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<V>> {
        let result = self
            .store
            .db_select_one_single_checkpointed_object_value::<V>(table, obj_id, max_checkpoint_id)
            .await?;
        let result_with_ids = self
            .store
            .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, max_checkpoint_id)
            .await?;
        if result.is_some() {
            let r = result.clone().unwrap();
            let row = result_with_ids.ok_or_else(|| anyhow::anyhow!("Value with ids not found after select"))?;
            assert!(row.obj_id == obj_id, "Object id does not match");
            assert!(row.checkpoint_id <= max_checkpoint_id, "Checkpoint id is greater than max_checkpoint_id");
            assert!(row.value == r, "Value with ids does not match value without ids");

            let above_checkpoint_id = row.checkpoint_id + 1;
            let result_above = self
                .store
                .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, above_checkpoint_id)
                .await?;
            assert!(
                result_above.is_some(),
                "Value not found when selecting with checkpoint_id above the one returned in value with ids"
            );
            let result_above_unwrapped = result_above.unwrap();
            assert!(
                result_above_unwrapped.obj_id == obj_id,
                "Object id does not match when selecting with checkpoint_id above the one returned in value with ids"
            );
            if result_above_unwrapped.checkpoint_id != row.checkpoint_id {
                assert!(result_above_unwrapped.checkpoint_id > row.checkpoint_id, "Checkpoint id is not greater than the one returned in value with ids when selecting with checkpoint_id above the one returned in value with ids");
            }
            if row.checkpoint_id > 0 {
                let result_below = self
                    .store
                    .db_select_one_single_checkpointed_object_value_and_ids::<V>(table, obj_id, row.checkpoint_id - 1)
                    .await?;
                if result_below.is_some() {
                    let result_below_unwrapped = result_below.unwrap();
                    assert!(
                        result_below_unwrapped.obj_id == obj_id,
                        "Object id does not match when selecting with checkpoint_id equal to the one returned in value with ids"
                    );
                    assert!(result_below_unwrapped.checkpoint_id < row.checkpoint_id);
                }
            }
        } else {
            assert!(result_with_ids.is_none(), "Value with ids should be None when value without ids is None");
        }
        let multi_result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &[obj_id, DEFINITELY_MISSING_U64_VALUE, obj_id], max_checkpoint_id)
            .await?;
        assert!(multi_result.len() == 3, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(multi_result[1].is_none(), "Multi select second result should be None");
        assert!(multi_result[2] == result, "Multi select third result does not match single select result");

        Ok(result)
    }

    pub async fn th_util_select_many_single_checkpointed_object_values<V: PsyDBSer>(
        &self,
        table: &SingleIdTableIdentifier,
        obj_id: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<V>>> {
        let result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, obj_id, max_checkpoint_id)
            .await?;
        assert!(
            result.len() == obj_id.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, id) in obj_id.iter().enumerate() {
            let single_result = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, *id, max_checkpoint_id)
                .await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }
    pub async fn th_util_insert_single_checkpointed_object<V: PsyDBSer>(
        &self,
        table: &SingleIdTableIdentifier,
        obj_id: u64,
        checkpoint_id: u64,
        value: &V,
    ) -> anyhow::Result<()> {
        let prev_lower = if checkpoint_id > 0 {
            self.th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id - 1)
                .await?
        } else {
            None
        };

        let higher = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id + 1)
            .await?;

        self.store
            .db_insert_one_single_checkpointed_object(table, obj_id, checkpoint_id, value)
            .await?;

        let after = self
            .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id)
            .await?;

        assert!(after.is_some(), "Value not found after insert");
        let after_unwrapped = after.clone().unwrap();
        assert!(after_unwrapped == *value, "Inserted value does not match retrieved value after insert");
        if higher.is_none() {
            let higher_new = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id + 1)
                .await?;
            assert!(higher_new.is_some(), "Higher value should be found after insert");
            let higher_new_unwrapped = higher_new.unwrap();
            assert!(higher_new_unwrapped == after_unwrapped, "Higher value should match inserted value");
        }

        if prev_lower.is_some() {
            let prev_lower_unwrapped = prev_lower.unwrap();
            let prev_lower_again = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, obj_id, checkpoint_id - 1)
                .await?;
            assert!(prev_lower_again.is_some(), "Previous lower value should still be found after insert");
            let prev_lower_again_unwrapped = prev_lower_again.unwrap();
            assert!(
                prev_lower_again_unwrapped == prev_lower_unwrapped,
                "Previous lower value should not change after insert"
            );
        }

        // check multi
        let multi_result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &[obj_id, DEFINITELY_MISSING_U64_VALUE, obj_id], checkpoint_id)
            .await?;
        assert!(multi_result.len() == 3, "Multi select did not return correct number of results");
        assert!(multi_result[0] == after, "Multi select first result does not match single select result");
        assert!(multi_result[1].is_none(), "Multi select second result should be None");
        assert!(multi_result[2] == after, "Multi select third result does not match single select result");

        Ok(())
    }

    pub async fn th_util_insert_many_single_checkpointed_objects<V: PsyDBSer, R: QDatabaseSingleIdTableRowNoCheckpointIdLike<V> + Send + Sync>(
        &self,
        table: &SingleIdTableIdentifier,
        rows: &[R],
        checkpoint_id: u64,
    ) -> anyhow::Result<()> {
        let mut prev_lowers = Vec::with_capacity(rows.len());
        let mut highers = Vec::with_capacity(rows.len());
        for row in rows.iter() {
            let prev_lower = if checkpoint_id > 0 {
                self.th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id - 1)
                    .await?
            } else {
                None
            };
            prev_lowers.push(prev_lower);
            let higher = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id + 1)
                .await?;
            highers.push(higher);
        }

        self.store
            .db_insert_many_single_checkpointed_objects_at_checkpoint_t::<V, R>(table, checkpoint_id, rows)
            .await?;

        for (i, row) in rows.iter().enumerate() {
            let after = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id)
                .await?;
            assert!(after.is_some(), "Value not found after insert");
            let after_unwrapped = after.clone().unwrap();
            assert!(
                after_unwrapped == *row.get_row_value_ref(),
                "Inserted value does not match retrieved value after insert"
            );

            if highers[i].is_none() {
                let higher_new = self
                    .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id + 1)
                    .await?;
                assert!(higher_new.is_some(), "Higher value should be found after insert");
                let higher_new_unwrapped = higher_new.unwrap();
                assert!(higher_new_unwrapped == after_unwrapped, "Higher value should match inserted value");
            }

            if prev_lowers[i].is_some() {
                let prev_lower_unwrapped = prev_lowers[i].as_ref().unwrap();
                let prev_lower_again = self
                    .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id - 1)
                    .await?;
                assert!(prev_lower_again.is_some(), "Previous lower value should still be found after insert");
                let prev_lower_again_unwrapped = prev_lower_again.unwrap();
                assert!(
                    prev_lower_again_unwrapped == *prev_lower_unwrapped,
                    "Previous lower value should not change after insert"
                );
            }
        }
        // check multi
        let keys: Vec<u64> = rows.iter().map(|r| r.get_row_obj_id()).collect();
        let multi_result = self
            .store
            .db_select_many_single_checkpointed_object_values::<V>(table, &keys, checkpoint_id)
            .await?;
        assert!(multi_result.len() == rows.len(), "Multi select did not return correct number of results");
        for (i, row) in rows.iter().enumerate() {
            let after = self
                .th_util_select_one_single_checkpointed_object_value::<V>(table, row.get_row_obj_id(), checkpoint_id)
                .await?;
            assert!(multi_result[i] == after, "Multi select result does not match single select result");
        }
        Ok(())
    }

    pub async fn th_util_select_single_id_merkle_node_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_height: u8,
        max_checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
    ) -> anyhow::Result<Hash> {
        let result = self
            .store
            .db_select_single_id_merkle_node_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, key)
            .await?;
        let zero_hash_at_level = Hasher::get_zero_hash((tree_height - key.level) as usize);
        if result == zero_hash_at_level {
            if max_checkpoint_id > 0 {
                // if it is a zero hash, then checking at another lower checkpoint should also
                // return the same zero hash
                let lower_checkpoint = max_checkpoint_id - 1;
                let lower_result = self
                    .store
                    .db_select_single_id_merkle_node_max_checkpoint(table, lower_checkpoint, tree_id, tree_height, key)
                    .await?;
                assert!(lower_result == result, "Lower checkpoint result does not match when result is zero hash");
            }
        }

        let multi_result = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, &[key, key])
            .await?;

        assert!(multi_result.len() == 2, "Multi select did not return correct number of results");
        assert!(multi_result[0] == result, "Multi select first result does not match single select result");
        assert!(
            multi_result[1] == result,
            "Multi select second result does not match single select result"
        );

        Ok(result)
    }
    pub async fn th_util_select_many_single_id_merkle_nodes_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_height: u8,
        max_checkpoint_id: u64,
        tree_id: u64,
        keys: &[SimpleMerkleNodeKey],
    ) -> anyhow::Result<Vec<Hash>> {
        let result = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, keys)
            .await?;
        assert!(
            result.len() == keys.len(),
            "Number of retrieved values does not match number of requested values"
        );
        for (i, key) in keys.iter().enumerate() {
            let single_result = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, max_checkpoint_id, tree_id, *key)
                .await?;
            assert!(result[i] == single_result, "Multi select result does not match single select result");
        }
        Ok(result)
    }
    pub async fn th_util_insert_single_id_merkle_node_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        tree_id: u64,
        key: SimpleMerkleNodeKey,
        hash: &Hash,
    ) -> anyhow::Result<()> {
        let prev_lower = if checkpoint_id > 0 {
            self.th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, tree_id, key)
                .await?
        } else {
            Hasher::get_zero_hash((tree_height - key.level) as usize)
        };

        let higher = self
            .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, key)
            .await?;

        self.store
            .db_insert_single_id_merkle_node(table, checkpoint_id, tree_id, key, hash)
            .await?;

        let after = self
            .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, key)
            .await?;

        assert!(after == *hash, "Inserted hash does not match retrieved hash after insert");
        if higher == Hasher::get_zero_hash((tree_height - key.level) as usize) {
            let higher_new = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, key)
                .await?;
            assert!(higher_new == after, "Higher hash should match inserted hash");
        }

        if prev_lower != Hasher::get_zero_hash((tree_height - key.level) as usize) {
            let prev_lower_again = self
                .th_util_select_single_id_merkle_node_max_checkpoint(
                    table,
                    tree_height,
                    if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                    tree_id,
                    key,
                )
                .await?;
            assert!(prev_lower_again == prev_lower, "Previous lower hash should not change after insert");
        }

        // check multi
        let multi_result = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &[key, key])
            .await?;
        assert!(multi_result.len() == 2, "Multi select did not return correct number of results");
        assert!(multi_result[0] == after, "Multi select first result does not match single select result");
        assert!(multi_result[1] == after, "Multi select second result does not match single select result");

        Ok(())
    }

    pub async fn th_util_insert_many_single_id_merkle_node_max_checkpoint(
        &self,
        table: &SingleIdMerkleTableIdentifier,
        tree_height: u8,
        checkpoint_id: u64,
        tree_id: u64,
        nodes: &[SimpleMerkleNode<Hash>],
    ) -> anyhow::Result<()> {
        let keys = nodes.iter().map(|n| n.key).collect::<Vec<SimpleMerkleNodeKey>>();
        let mut prev_lowers = Vec::with_capacity(nodes.len());
        let mut highers = Vec::with_capacity(nodes.len());
        for key in keys.iter() {
            let prev_lower = if checkpoint_id > 0 {
                self.th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id - 1, tree_id, *key)
                    .await?
            } else {
                Hasher::get_zero_hash((tree_height - key.level) as usize)
            };
            prev_lowers.push(prev_lower);
            let higher = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, *key)
                .await?;
            highers.push(higher);
        }

        self.store
            .db_set_single_id_merkle_nodes_batch(table, checkpoint_id, tree_id, nodes)
            .await?;
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, node.key)
                .await?;
            assert!(after == node.value, "Inserted hash does not match retrieved hash after insert");

            if highers[i] == Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let higher_new = self
                    .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id + 1, tree_id, node.key)
                    .await?;
                assert!(higher_new == after, "Higher hash should match inserted hash");
            }

            if prev_lowers[i] != Hasher::get_zero_hash((tree_height - node.key.level) as usize) {
                let prev_lower_again = self
                    .th_util_select_single_id_merkle_node_max_checkpoint(
                        table,
                        tree_height,
                        if checkpoint_id > 0 { checkpoint_id - 1 } else { 0 },
                        tree_id,
                        node.key,
                    )
                    .await?;
                assert!(prev_lower_again == prev_lowers[i], "Previous lower hash should not change after insert");
            }
        }
        // check multi
        let multi_result = self
            .store
            .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &keys)
            .await?;
        assert!(multi_result.len() == nodes.len(), "Multi select did not return correct number of results");
        for (i, node) in nodes.iter().enumerate() {
            let after = self
                .th_util_select_single_id_merkle_node_max_checkpoint(table, tree_height, checkpoint_id, tree_id, node.key)
                .await?;
            assert!(multi_result[i] == after, "Multi select result does not match single select result");
        }
        Ok(())
    }
}
