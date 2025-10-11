use anyhow::Result;
use async_trait::async_trait;
use parth_core::{
    crypto::hash::{tag_tree::TagTreeMerkleProof, traits::{MerkleZeroHasher, RandomHash}},
    data::{
        db::{
            data_types::{BiDirectionalMappingRow, CoreDatabaseValueDeserialize, QDatabasePrimitiveKey},
            row::{
                QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowCreatable, QDatabaseDoubleIdTableRowLike,
                QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseDoubleIdTableRowNoCheckpointIdLike, QDatabaseKeyIdValueTableRow,
                QDatabaseKeyIdValueTableRowCreatable, QDatabaseKeyIdValueTableRowLike, QDatabaseSingleIdTableRow, QDatabaseSingleIdTableRowCreatable,
                QDatabaseSingleIdTableRowLike, QDatabaseSingleIdTableRowNoCheckpointId, QDatabaseSingleIdTableRowNoCheckpointIdLike, QDoubleIdKey,
            },
        },
        hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}},
        serializable::QPDPair,
    },
    protocol::core_types::QHashBase,
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use rand::{Rng, seq::SliceRandom, thread_rng};
use serde::{Deserialize, Serialize};

use crate::store::traits::core_db::{CoreDatabaseBidirectionalMappingStore, CoreDatabaseBidirectionalU64U128MappingStore, CoreDatabaseDoubleIdCheckpointedStore, CoreDatabaseDoubleIdMerkleStore, CoreDatabaseKivStore, CoreDatabaseSingleIdCheckpointedStore, CoreDatabaseSingleIdMerkleStore, CoreDatabaseU64Store, CoreDatabaseZeroIdMerkleStore};

// Constants from old test suite
const GOLDILOCKS_PRIME: u64 = 18446744069414584321;
const MAX_CHECKPOINT_ID: u64 = (i64::MAX - 1) as u64;
const NEVER_EXIST_IDS_COUNT: u64 = 0xfffffff;
const START_NEVER_EXIST_IDS: u64 = GOLDILOCKS_PRIME - NEVER_EXIST_IDS_COUNT - 2;

fn rand_non_existent_id() -> u64 {
    1 + START_NEVER_EXIST_IDS + (rand::random::<u64>() % NEVER_EXIST_IDS_COUNT)
}

// Test value struct
#[pderive::serialize_clone]
struct TestValue {
    pub num: u64,
    pub string: String,
    pub vec: Vec<u8>,
}

impl TestValue {
    pub fn random() -> Self {
        let mut rng = thread_rng();
        Self {
            num: rng.gen(),
            string: (0..rng.gen_range(5..20)).map(|_| rng.gen::<char>()).collect(),
            vec: (0..rng.gen_range(10..50)).map(|_| rng.gen()).collect(),
        }
    }

    pub fn mutate(&self) -> Self {
        let mut new = self.clone();
        let mut rng = thread_rng();
        if rng.gen_bool(0.5) {
            new.num = rng.gen();
        }
        if rng.gen_bool(0.5) {
            new.string = (0..rng.gen_range(5..20)).map(|_| rng.gen::<char>()).collect();
        }
        if rng.gen_bool(0.5) {
            new.vec = (0..rng.gen_range(10..50)).map(|_| rng.gen()).collect();
        }
        new
    }
}

// Helper to generate random checkpoint id less than max
fn random_checkpoint(max: u64) -> u64 {
    thread_rng().gen_range(0..max)
}

// Test for CoreDatabaseBidirectionalMappingStore
pub async fn test_bidirectional_mapping_store<
    S: CoreDatabaseBidirectionalMappingStore<T>,
    T: Clone + Send + Sync,
    K1: QDatabasePrimitiveKey + Clone + PartialEq + std::fmt::Debug,
    K2: QDatabasePrimitiveKey + Clone + PartialEq + std::fmt::Debug,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    // Use u64 and u128 for K1 and K2
    type TestK1 = u64;
    type TestK2 = Hash256;

    // Insert single pair
    let k1 = thread_rng().gen::<TestK1>();
    let k2 = Hash256::rand();
    store.db_insert_pair(table, k1.clone(), k2.clone()).await?;
    assert_eq!(store.db_select_one_by_k1(table, &k1).await?, Some(k2.clone()));
    assert_eq!(store.db_select_one_by_k2(table, &k2).await?, Some(k1.clone()));

    // Insert many pairs
    let num_pairs = 50;
    let mut pairs: Vec<BiDirectionalMappingRow<TestK1, TestK2>> = (0..num_pairs)
        .map(|_| BiDirectionalMappingRow {
            k1: thread_rng().gen(),
            k2: Hash256::rand(),
        })
        .collect();
    store.db_insert_pairs(table, &pairs).await?;

    // Select many by k1
    let k1s: Vec<TestK1> = pairs.iter().map(|p| p.k1.clone()).collect();
    let selected_k2s = store.db_select_many_by_k1(table, &k1s).await?;
    for (i, sel) in selected_k2s.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&pairs[i].k2));
    }

    // Select many by k2
    let k2s: Vec<TestK2> = pairs.iter().map(|p| p.k2.clone()).collect();
    let selected_k1s = store.db_select_many_by_k2(table, &k2s).await?;
    for (i, sel) in selected_k1s.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&pairs[i].k1));
    }

    // Select many pairs by k1
    let selected_pairs = store.db_select_many_pairs_by_k1::<TestK1, TestK2>(table, &k1s).await?;
    assert_eq!(selected_pairs.len(), pairs.len());
    for sel in selected_pairs {
        assert!(pairs.iter().any(|p| p.k1 == sel.k1 && p.k2 == sel.k2));
    }

    // Select many pairs by k2
    let selected_pairs_k2 = store.db_select_many_pairs_by_k2::<TestK1, TestK2>(table, &k2s).await?;
    assert_eq!(selected_pairs_k2.len(), pairs.len());
    for sel in selected_pairs_k2 {
        assert!(pairs.iter().any(|p| p.k1 == sel.k1 && p.k2 == sel.k2));
    }

    // Non-existent
    let non_k1 = rand_non_existent_id();
    assert_eq!(store.db_select_one_by_k1::<TestK1, TestK2>(table, &non_k1).await?, None);

    // All pairs (if supported, but in trait it's from start_k1, max_count)
    //let all_pairs = store.db_select_all_pairs_from_k1::<TestK1, TestK2>(table, None::<TestK1>, 100).await?;
    //assert!(all_pairs.len() >= num_pairs + 1); // +1 for the single insert

    Ok(())
}

// Test for CoreDatabaseBidirectionalU64U128MappingStore
pub async fn test_bidirectional_u64_u128_mapping_store<
    S: CoreDatabaseBidirectionalU64U128MappingStore<T>,
    T: Clone + Send + Sync,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    // Insert single
    let k1 = thread_rng().gen::<u64>();
    let k2 = thread_rng().gen::<u128>();
    store.db_insert_u64_u128_mapping_pair(table, k1, k2).await?;
    assert_eq!(store.db_select_one_u128_value_by_u64(table, k1).await?, Some(k2));
    assert_eq!(store.db_select_one_u64_key_by_u128(table, k2).await?, Some(k1));

    // Insert many
    let num = 50;
    let pairs: Vec<BiDirectionalMappingRow<u64, u128>> = (0..num)
        .map(|_| BiDirectionalMappingRow {
            k1: thread_rng().gen(),
            k2: thread_rng().gen(),
        })
        .collect();
    store.db_insert_u64_u128_mapping_pairs(table, &pairs).await?;

    // Select many u128 by u64s
    let u64s: Vec<u64> = pairs.iter().map(|p| p.k1).collect();
    let selected_u128s = store.db_select_many_u128_values_by_u64s(table, &u64s).await?;
    for (i, sel) in selected_u128s.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&pairs[i].k2));
    }

    // Select many u64 by u128s
    let u128s: Vec<u128> = pairs.iter().map(|p| p.k2).collect();
    let selected_u64s = store.db_select_many_u64_keys_by_u128s(table, &u128s).await?;
    for (i, sel) in selected_u64s.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&pairs[i].k1));
    }

    // Non-existent
    assert_eq!(store.db_select_one_u128_value_by_u64(table, rand_non_existent_id()).await?, None);

    Ok(())
}

// Test for CoreDatabaseU64Store
pub async fn test_u64_store<
    S: CoreDatabaseU64Store<T>,
    T: Clone + Send + Sync,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    // Set single
    let id1 = thread_rng().gen::<u64>();
    let val1 = thread_rng().gen::<u64>();
    store.db_set_u64_value(table, id1, val1).await?;
    assert_eq!(store.db_select_u64_value(table, id1).await?, Some(val1));

    // Increment
    let inc_amount = 5i64;
    let new_val = store.db_inc_counter(table, id1, inc_amount).await?;
    assert_eq!(new_val, val1 + inc_amount as u64);
    assert_eq!(store.db_select_u64_value(table, id1).await?, Some(new_val));

    // Set many
    let num = 50;
    let pairs: Vec<QPDPair<u64, u64>> = (0..num)
        .map(|_| QPDPair {
            key: thread_rng().gen(),
            value: thread_rng().gen(),
        })
        .collect();
    store.db_set_many_u64_values(table, &pairs).await?;

    // Select many
    let ids: Vec<u64> = pairs.iter().map(|p| p.key).collect();
    let selected = store.db_select_u64_values(table, &ids).await?;
    for (i, sel) in selected.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&pairs[i].value));
    }

    // Mix existent and non-existent
    let non_ids: Vec<u64> = (0..20).map(|_| rand_non_existent_id()).collect();
    let mut mixed_ids = [ids[0..20].to_vec(), non_ids].concat();
    mixed_ids.shuffle(&mut thread_rng());
    let mixed_selected = store.db_select_u64_values(table, &mixed_ids).await?;
    for (i, id) in mixed_ids.iter().enumerate() {
        if let Some(p) = pairs.iter().find(|p| p.key == *id) {
            assert_eq!(mixed_selected[i], Some(p.value));
        } else {
            assert_eq!(mixed_selected[i], None);
        }
    }

    Ok(())
}

// Test for CoreDatabaseSingleIdCheckpointedStore
pub async fn test_single_id_checkpointed_store<
    S: CoreDatabaseSingleIdCheckpointedStore<T>,
    T: Clone + Send + Sync,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    // Single insert and queries
    let obj_id = thread_rng().gen::<u64>();
    let val1 = TestValue::random();
    let cp1 = random_checkpoint(MAX_CHECKPOINT_ID / 2);
    store.db_insert_one_single_checkpointed_object(table, obj_id, cp1, &val1).await?;

    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, cp1).await?,
        Some(val1.clone())
    );
    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, cp1 + 100).await?,
        Some(val1.clone())
    );
    assert_eq!(
        store.db_select_one_single_checkpointed_object_value::<TestValue>(table, obj_id, cp1 - 1).await?,
        None
    );

    let fetched_with_ids: QDatabaseSingleIdTableRow<TestValue> = store
        .db_select_one_single_checkpointed_object_value_and_ids(table, obj_id, cp1)
        .await?
        .unwrap();
    assert_eq!(fetched_with_ids.obj_id, obj_id);
    assert_eq!(fetched_with_ids.checkpoint_id, cp1);
    assert_eq!(fetched_with_ids.value, val1);

    // Insert at higher checkpoint
    let val2 = val1.mutate();
    let cp2 = cp1 + random_checkpoint(MAX_CHECKPOINT_ID / 2);
    store.db_insert_one_single_checkpointed_object(table, obj_id, cp2, &val2).await?;

    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, cp1).await?,
        Some(val1.clone())
    );
    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, cp2).await?,
        Some(val2.clone())
    );
    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, MAX_CHECKPOINT_ID).await?,
        Some(val2.clone())
    );

    // Insert at lower checkpoint (should not affect latest)
    let val3 = val2.mutate();
    let cp3 = cp1 + (cp2 - cp1) / 2;
    store.db_insert_one_single_checkpointed_object(table, obj_id, cp3, &val3).await?;

    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, cp1).await?,
        Some(val1.clone())
    );
    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, cp3).await?,
        Some(val3.clone())
    );
    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, cp2).await?,
        Some(val2.clone())
    );
    assert_eq!(
        store.db_select_one_single_checkpointed_object_value(table, obj_id, MAX_CHECKPOINT_ID).await?,
        Some(val2.clone())
    );

    // Many inserts at same checkpoint
    let num_many = 20;
    let mut rows_no_cp: Vec<QDatabaseSingleIdTableRowNoCheckpointId<TestValue>> = (0..num_many)
        .map(|_| QDatabaseSingleIdTableRowNoCheckpointId {
            obj_id: thread_rng().gen(),
            value: TestValue::random(),
        })
        .collect();
    let cp_many = random_checkpoint(MAX_CHECKPOINT_ID);
    store.db_insert_many_single_checkpointed_objects_at_checkpoint(table, cp_many, &rows_no_cp).await?;

    let obj_ids: Vec<u64> = rows_no_cp.iter().map(|r| r.obj_id).collect();
    let selected_values = store.db_select_many_single_checkpointed_object_values(table, &obj_ids, cp_many).await?;
    for (i, sel) in selected_values.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&rows_no_cp[i].value));
    }

    // Update some with higher cp
    for i in 0..num_many / 2 {
        let new_val = rows_no_cp[i].value.mutate();
        let new_cp = cp_many + random_checkpoint(1000);
        store.db_insert_one_single_checkpointed_object(table, rows_no_cp[i].obj_id, new_cp, &new_val).await?;
        rows_no_cp[i].value = new_val; // Update local for later check
    }

    let selected_latest = store.db_select_many_single_checkpointed_object_values(table, &obj_ids, MAX_CHECKPOINT_ID).await?;
    for (i, sel) in selected_latest.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&rows_no_cp[i].value));
    }

    // Non-existent
    let non_id = rand_non_existent_id();
    assert_eq!(
        store.db_select_one_single_checkpointed_object_value::<TestValue>(table, non_id, MAX_CHECKPOINT_ID).await?,
        None
    );

    // All (if needed, but trait has select_all)
    //let all = store.db_select_all_single_checkpointed_object::<TestValue>(table).await?;
    //assert!(all.len() >= num_many + 1); // +1 for the single obj_id

    Ok(())
}

// Similar for CoreDatabaseDoubleIdCheckpointedStore
pub async fn test_double_id_checkpointed_store<
    S: CoreDatabaseDoubleIdCheckpointedStore<T>,
    T: Clone + Send + Sync,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    // Single insert and queries
    let obj_id = thread_rng().gen::<u64>();
    let sec_id = thread_rng().gen::<u64>();
    let val1 = TestValue::random();
    let cp1 = random_checkpoint(MAX_CHECKPOINT_ID / 2);
    store.db_insert_one_double_checkpointed_object(table, obj_id, sec_id, cp1, &val1).await?;

    assert_eq!(
        store.db_select_one_double_checkpointed_object_value(table, obj_id, sec_id, cp1).await?,
        Some(val1.clone())
    );
    assert_eq!(
        store.db_select_one_double_checkpointed_object_value(table, obj_id, sec_id, cp1 + 100).await?,
        Some(val1.clone())
    );
    assert_eq!(
        store.db_select_one_double_checkpointed_object_value::<TestValue>(table, obj_id, sec_id, cp1 - 1).await?,
        None
    );

    let fetched_with_ids: QDatabaseDoubleIdTableRow<TestValue> = store
        .db_select_one_double_checkpointed_object_value_and_ids(table, obj_id, sec_id, cp1)
        .await?
        .unwrap();
    assert_eq!(fetched_with_ids.obj_id, obj_id);
    assert_eq!(fetched_with_ids.secondary_id, sec_id);
    assert_eq!(fetched_with_ids.checkpoint_id, cp1);
    assert_eq!(fetched_with_ids.value, val1);

    // Insert at higher checkpoint
    let val2 = val1.mutate();
    let cp2 = cp1 + random_checkpoint(MAX_CHECKPOINT_ID / 2);
    store.db_insert_one_double_checkpointed_object(table, obj_id, sec_id, cp2, &val2).await?;

    assert_eq!(
        store.db_select_one_double_checkpointed_object_value(table, obj_id, sec_id, cp1).await?,
        Some(val1.clone())
    );
    assert_eq!(
        store.db_select_one_double_checkpointed_object_value(table, obj_id, sec_id, cp2).await?,
        Some(val2.clone())
    );
    assert_eq!(
        store.db_select_one_double_checkpointed_object_value(table, obj_id, sec_id, MAX_CHECKPOINT_ID).await?,
        Some(val2.clone())
    );

    // Many at same cp
    let num_many = 20;
    let mut rows_no_cp: Vec<QDatabaseDoubleIdTableRowNoCheckpointId<TestValue>> = (0..num_many)
        .map(|_| QDatabaseDoubleIdTableRowNoCheckpointId {
            obj_id: thread_rng().gen(),
            secondary_id: thread_rng().gen(),
            value: TestValue::random(),
        })
        .collect();
    let cp_many = random_checkpoint(MAX_CHECKPOINT_ID);
    store.db_insert_many_double_checkpointed_objects_at_checkpoint(table, cp_many, &rows_no_cp).await?;

    let keys: Vec<QDoubleIdKey> = rows_no_cp.iter().map(|r| QDoubleIdKey { obj_id: r.obj_id, secondary_id: r.secondary_id }).collect();
    let selected_values = store.db_select_many_double_checkpointed_object_values(table, &keys, cp_many).await?;
    for (i, sel) in selected_values.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&rows_no_cp[i].value));
    }

    // Non-existent
    let non_key = QDoubleIdKey { obj_id: rand_non_existent_id(), secondary_id: rand_non_existent_id() };
    assert_eq!(
        store.db_select_one_double_checkpointed_object_value::<TestValue>(table, non_key.obj_id, non_key.secondary_id, MAX_CHECKPOINT_ID).await?,
        None
    );

    Ok(())
}

// Test for CoreDatabaseKivStore
pub async fn test_kiv_store<
    S: CoreDatabaseKivStore<T>,
    T: Clone + Send + Sync,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    // Single insert
    let obj_id = thread_rng().gen::<u64>();
    let val = TestValue::random();
    store.db_insert_one_kiv(table, obj_id, &val).await?;
    assert_eq!(store.db_select_one_kiv_value(table, obj_id).await?, Some(val.clone()));

    let fetched_with_id: QDatabaseKeyIdValueTableRow<TestValue> = store.db_select_one_kiv_value_and_ids(table, obj_id).await?.unwrap();
    assert_eq!(fetched_with_id.obj_id, obj_id);
    assert_eq!(fetched_with_id.value, val);

    // Many inserts
    let num = 50;
    let mut rows: Vec<QDatabaseKeyIdValueTableRow<TestValue>> = (0..num)
        .map(|_| QDatabaseKeyIdValueTableRow {
            obj_id: thread_rng().gen(),
            value: TestValue::random(),
        })
        .collect();
    store.db_insert_many_kivs(table, &rows).await?;

    let obj_ids: Vec<u64> = rows.iter().map(|r| r.obj_id).collect();
    let selected_values = store.db_select_many_kiv_values(table, &obj_ids).await?;
    for (i, sel) in selected_values.iter().enumerate() {
        assert_eq!(sel.as_ref(), Some(&rows[i].value));
    }

    let selected_with_ids = store.db_select_many_kiv_keys_and_values::<TestValue, QDatabaseKeyIdValueTableRow<TestValue>>(table, &obj_ids).await?;
    assert_eq!(selected_with_ids.len(), num as usize);
    for sel in selected_with_ids {
        assert!(rows.iter().any(|r| r.obj_id == sel.obj_id && r.value == sel.value));
    }

    // Non-existent
    assert_eq!(store.db_select_one_kiv_value::<TestValue>(table, rand_non_existent_id()).await?, None);


    Ok(())
}

// Test for CoreDatabaseSingleIdMerkleStore
pub async fn test_single_id_merkle_store<
    S: CoreDatabaseSingleIdMerkleStore<Hash256, CoreSha256Hasher, T>,
    T: Clone + Send + Sync,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    let tree_id = thread_rng().gen::<u64>();
    let tree_height = 4u8; // Small tree for testing
    let checkpoint_id = random_checkpoint(MAX_CHECKPOINT_ID);

    // Insert some nodes
    let mut nodes: Vec<SimpleMerkleNode<Hash256>> = (0..5)
        .map(|_| SimpleMerkleNode {
            key: SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height),
            value: Hash256::rand_hash(),
        })
        .collect();
    store.db_set_single_id_merkle_nodes_batch(table, checkpoint_id, tree_id, &nodes).await?;

    // Query existing
    for node in &nodes {
        let fetched = store.db_select_single_id_merkle_node_max_checkpoint(table, checkpoint_id, tree_id, tree_height, node.key).await?;
        assert_eq!(fetched, node.value);
    }

    // Query non-existent, should get zero hash
    let non_key = SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height);
    let fetched_non = store.db_select_single_id_merkle_node_max_checkpoint(table, checkpoint_id, tree_id, tree_height, non_key).await?;
    let expected_zero = CoreSha256Hasher::get_zero_hash((tree_height - non_key.level) as usize);
    assert_eq!(fetched_non, expected_zero);

    // Many queries
    let mut many_keys: Vec<SimpleMerkleNodeKey> = nodes.iter().map(|n| n.key).collect();
    many_keys.push(SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height)); // non-existent
    let fetched_many = store.db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &many_keys).await?;
    for (i, key) in many_keys.iter().enumerate() {
        if let Some(node) = nodes.iter().find(|n| n.key == *key) {
            assert_eq!(fetched_many[i], node.value);
        } else {
            assert_eq!(fetched_many[i], CoreSha256Hasher::get_zero_hash((tree_height - key.level) as usize));
        }
    }

    // Insert single
    let single_key = SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height);
    let single_value = Hash256::rand_hash();
    store.db_insert_single_id_merkle_node(table, checkpoint_id, tree_id, single_key, &single_value).await?;
    let fetched_single = store.db_select_single_id_merkle_node_max_checkpoint(table, checkpoint_id, tree_id, tree_height, single_key).await?;
    assert_eq!(fetched_single, single_value);

    Ok(())
}

// Similar for CoreDatabaseDoubleIdMerkleStore
pub async fn test_double_id_merkle_store<
    S: CoreDatabaseDoubleIdMerkleStore<Hash256, CoreSha256Hasher, T>,
    T: Clone + Send + Sync,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    let tree_id = thread_rng().gen::<u64>();
    let tree_sub_id = thread_rng().gen::<u64>();
    let tree_height = 4u8;
    let checkpoint_id = random_checkpoint(MAX_CHECKPOINT_ID);

    // Insert batch
    let mut nodes: Vec<SimpleMerkleNode<Hash256>> = (0..5)
        .map(|_| SimpleMerkleNode {
            key: SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height),
            value: Hash256::rand_hash(),
        })
        .collect();
    store.db_set_double_id_merkle_nodes_batch(table, checkpoint_id, tree_id, tree_sub_id, &nodes).await?;

    // Query existing
    for node in &nodes {
        let fetched = store.db_select_double_id_merkle_node_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, node.key).await?;
        assert_eq!(fetched, node.value);
    }

    // Query non-existent
    let non_key = SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height);
    let fetched_non = store.db_select_double_id_merkle_node_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, non_key).await?;
    assert_eq!(fetched_non, CoreSha256Hasher::get_zero_hash((tree_height - non_key.level) as usize));

    // Many
    let mut many_keys: Vec<SimpleMerkleNodeKey> = nodes.iter().map(|n| n.key).collect();
    many_keys.push(SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height));
    let fetched_many = store.db_select_many_double_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, &many_keys).await?;
    for (i, key) in many_keys.iter().enumerate() {
        if let Some(node) = nodes.iter().find(|n| n.key == *key) {
            assert_eq!(fetched_many[i], node.value);
        } else {
            assert_eq!(fetched_many[i], CoreSha256Hasher::get_zero_hash((tree_height - key.level) as usize));
        }
    }

    Ok(())
}

// For CoreDatabaseZeroIdMerkleStore, similar but no tree_id
// Assuming ScyllaMerkleNodesZeroPreparedStatements<TREE_HEIGHT>, but trait is without const.
// Wait, in the code, ScyllaMerkleNodesZeroPreparedStatements has const TREE_HEIGHT.
// But in trait, no.
// Perhaps assume tree_height in tests.

// Test for CoreDatabaseZeroIdMerkleStore
pub async fn test_zero_id_merkle_store<
    S: CoreDatabaseZeroIdMerkleStore<Hash256, CoreSha256Hasher, T>,
    T: Clone + Send + Sync,
>(
    store: &S,
    table: &T,
) -> Result<()> {
    let tree_height = 4u8;
    let checkpoint_id = random_checkpoint(MAX_CHECKPOINT_ID);

    // Insert batch
    let mut nodes: Vec<SimpleMerkleNode<Hash256>> = (0..5)
        .map(|_| SimpleMerkleNode {
            key: SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height),
            value: Hash256::rand_hash(),
        })
        .collect();
    store.db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, &nodes).await?;

    // Query existing
    for node in &nodes {
        let fetched = store.db_select_zero_id_merkle_node_max_checkpoint(table, checkpoint_id, &node.key).await?;
        assert_eq!(fetched, node.value);
    }

    // Query non-existent
    let non_key = SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height);
    let fetched_non = store.db_select_zero_id_merkle_node_max_checkpoint(table, checkpoint_id, &non_key).await?;
    assert_eq!(fetched_non, CoreSha256Hasher::get_zero_hash((tree_height - non_key.level) as usize));

    // Many
    let mut many_keys: Vec<SimpleMerkleNodeKey> = nodes.iter().map(|n| n.key).collect();
    many_keys.push(SimpleMerkleNodeKey::random_simple_merkle_node_in_tree(tree_height));
    let fetched_many = store.db_select_many_zero_id_merkle_nodes_max_checkpoint(table, checkpoint_id, &many_keys).await?;
    for (i, key) in many_keys.iter().enumerate() {
        if let Some(node) = nodes.iter().find(|n| n.key == *key) {
            assert_eq!(fetched_many[i], node.value);
        } else {
            assert_eq!(fetched_many[i], CoreSha256Hasher::get_zero_hash((tree_height - key.level) as usize));
        }
    }

    Ok(())
}