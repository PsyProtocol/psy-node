use parth_core::{data::hash::{hash256::Hash256, merkle_node_key::SimpleMerkleNodeKey}, data::db::data_types::BiDirectionalMappingRow};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_node_core::store::traits::core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalMappingWriter,
    CoreDatabaseBidirectionalU64U128MappingReader, CoreDatabaseBidirectionalU64U128MappingWriter,
    CoreDatabaseBlobPairDeleter, CoreDatabaseBlobPairVerifier, CoreDatabaseDoubleIdCheckpointedWriter,
    CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseHashToManyIdsWriter, CoreDatabaseHashUserPairDeleter,
    CoreDatabaseHashUserPairVerifier, CoreDatabaseIMTKeyIndexWriter, CoreDatabaseIMTLeafWriter,
    CoreDatabaseIMTNextAppendIndexWriter, CoreDatabaseImtKeyDeleter, CoreDatabaseImtKeyVerifier,
    CoreDatabaseImtLeafDeleter, CoreDatabaseImtLeafVerifier, CoreDatabaseImtNextAppendIndexDeleter,
    CoreDatabaseImtNextAppendIndexVerifier, CoreDatabaseMerkleDeleter, CoreDatabaseMerkleVerifier,
    CoreDatabaseObjectCheckpointDeleter, CoreDatabaseObjectCheckpointVerifier, CoreDatabaseObjectIdDeleter,
    CoreDatabaseObjectIdVerifier, CoreDatabasePendingIdPartitionDeleter,
    CoreDatabasePendingIdPartitionVerifier, CoreDatabaseSingleIdCheckpointedWriter,
    CoreDatabaseSingleIdMerkleWriter, CoreDatabaseTagTreeReader, CoreDatabaseTagTreeWriter,
    CoreDatabaseTreeMerkleDeleter, CoreDatabaseTreeMerkleVerifier,
    CoreDatabaseTreeSubtreeMerkleDeleter, CoreDatabaseTreeSubtreeMerkleVerifier,
    CoreDatabaseU64U128PairDeleter, CoreDatabaseU64U128PairVerifier, CoreDatabaseU64Writer,
    CoreDatabaseZeroIdMerkleWriter,
};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsySerializeCanonicalAsyncSafe};
use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};


type Store = InMemoryCoreStore<Hash256, CoreSha256Hasher>;

fn table(name: &str) -> InMemoryTableIdentifier {
    InMemoryTableIdentifier::new_with_keyspace("delete-api-test", name)
}

#[tokio::test]
async fn delete_apis_accept_empty_and_missing_keys() -> anyhow::Result<()> {
    let store = Store::new();
    let generic = table("generic");

    store.db_delete_many_object_ids(&generic, &[]).await?;
    store.db_delete_many_object_checkpoint(&generic, &[]).await?;
    store.db_delete_many_merkle_nodes(&generic, &[]).await?;
    store.db_delete_many_tree_merkle_nodes(&generic, &[]).await?;
    store.db_delete_many_tree_subtree_merkle_nodes(&generic, &[]).await?;
    store.db_delete_many_imt_leaves(&generic, &[]).await?;
    store.db_delete_many_imt_keys(&generic, &[]).await?;
    store.db_delete_many_imt_next_append_indexes(&generic, &[]).await?;
    store.db_delete_many_hash_user_pairs(&generic, &[]).await?;
    store.db_delete_many_blob_pairs(&generic, &[]).await?;
    store.db_delete_many_u64_u128_pairs(&generic, &[]).await?;
    store.db_delete_many_pending_id_partitions(&generic, &[]).await?;

    store.db_delete_many_object_ids(&generic, &[1]).await?;
    store.db_delete_many_object_checkpoint(&generic, &[(1, 2)]).await?;
    store.db_delete_many_merkle_nodes(&generic, &[(1, 2, 3)]).await?;
    store.db_delete_many_tree_merkle_nodes(&generic, &[(1, 2, 3, 4)]).await?;
    store.db_delete_many_tree_subtree_merkle_nodes(&generic, &[(1, 2, 3, 4, 5)]).await?;
    store.db_delete_many_imt_leaves(&generic, &[(1, 2, 3, 4)]).await?;
    store.db_delete_many_imt_keys(&generic, &[(1, 2, 3, vec![4])]).await?;
    store.db_delete_many_imt_next_append_indexes(&generic, &[(1, 2)]).await?;
    store.db_delete_many_hash_user_pairs(&generic, &[(Hash256::default(), 1)]).await?;
    store.db_delete_many_blob_pairs(&generic, &[(vec![1], vec![2])]).await?;
    store.db_delete_many_u64_u128_pairs(&generic, &[(1, 2)]).await?;
    store.db_delete_many_pending_id_partitions(&generic, &[1]).await?;

    assert!(store.db_get_existing_object_ids(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_object_checkpoints(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_merkle_nodes(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_tree_merkle_nodes(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_tree_subtree_merkle_nodes(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_imt_leaves(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_imt_keys(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_imt_next_append_indexes(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_hash_user_pairs(&generic, &[]).await?.is_empty());
    assert!(store.db_get_blob_pair_presence(&generic, &[]).await?.is_empty());
    assert!(store.db_get_u64_u128_pair_presence(&generic, &[]).await?.is_empty());
    assert!(store.db_get_existing_pending_id_partitions(&generic, &[]).await?.is_empty());

    assert!(store.db_get_existing_object_ids(&generic, &[1]).await?.is_empty());
    assert!(store.db_get_existing_object_checkpoints(&generic, &[(1, 2)]).await?.is_empty());
    assert!(store.db_get_existing_merkle_nodes(&generic, &[(1, 2, 3)]).await?.is_empty());
    assert!(store.db_get_existing_tree_merkle_nodes(&generic, &[(1, 2, 3, 4)]).await?.is_empty());
    assert!(store.db_get_existing_tree_subtree_merkle_nodes(&generic, &[(1, 2, 3, 4, 5)]).await?.is_empty());
    assert!(store.db_get_existing_imt_leaves(&generic, &[(1, 2, 3, 4)]).await?.is_empty());
    assert!(store.db_get_existing_imt_keys(&generic, &[(1, 2, 3, vec![4])]).await?.is_empty());
    assert!(store.db_get_existing_imt_next_append_indexes(&generic, &[(1, 2)]).await?.is_empty());
    assert!(store.db_get_existing_hash_user_pairs(&generic, &[(Hash256::default(), 1)]).await?.is_empty());
    assert!(store.db_get_blob_pair_presence(&generic, &[(vec![1], vec![2])]).await?.is_empty());
    assert!(store.db_get_u64_u128_pair_presence(&generic, &[(1, 2)]).await?.is_empty());
    assert!(store.db_get_existing_pending_id_partitions(&generic, &[1]).await?.is_empty());

    Ok(())
}

#[tokio::test]
async fn bidirectional_deletes_remove_both_physical_directions() -> anyhow::Result<()> {
    let store = Store::new();
    let blob_table = table("blob");
    let pending_table = table("pending");
    let blob_pair = (17_u64, Hash256::default());
    let pending_pair = (17_u64, 29_u128);

    store.db_insert_pair(&blob_table, blob_pair.0, blob_pair.1).await?;
    store
        .db_insert_u64_u128_mapping_pairs(&pending_table, &[BiDirectionalMappingRow::new(pending_pair.0, pending_pair.1)])
        .await?;

    store
        .db_delete_many_blob_pairs(
            &blob_table,
            &[(blob_pair.0.psy_ser_to_bytes_vec()?, blob_pair.1.psy_ser_to_bytes_vec()?)],
        )
        .await?;
    store.db_delete_many_u64_u128_pairs(&pending_table, &[pending_pair]).await?;

    assert_eq!(store.db_select_one_by_k1::<u64, Hash256>(&blob_table, &blob_pair.0).await?, None);
    assert_eq!(store.db_select_one_by_k2::<u64, Hash256>(&blob_table, &blob_pair.1).await?, None);
    assert_eq!(store.db_select_one_u128_value_by_u64(&pending_table, pending_pair.0).await?, None);
    assert_eq!(store.db_select_one_u64_key_by_u128(&pending_table, pending_pair.1).await?, None);

    Ok(())
}


#[tokio::test]
async fn pending_partition_delete_removes_only_the_selected_partition() -> anyhow::Result<()> {
    let store = Store::new();
    let tag_table = table("tag-tree");
    let selected_pending_id = 41;
    let retained_pending_id = 42;
    let root = SimpleMerkleNodeKey::new_root();
    let child = SimpleMerkleNodeKey { level: 1, index: 1 };
    let tag = Hash256::default();
    let value = Hash256::default();

    store.db_set_tag_tree_tag_value(&tag_table, selected_pending_id, &root, &tag, &value).await?;
    store.db_set_tag_tree_tag_value(&tag_table, selected_pending_id, &child, &tag, &value).await?;
    store.db_set_tag_tree_tag_value(&tag_table, retained_pending_id, &root, &tag, &value).await?;

    store.db_delete_many_pending_id_partitions(&tag_table, &[selected_pending_id]).await?;

    assert_eq!(store.db_get_tag_tree_node_value(&tag_table, selected_pending_id, &root).await?, None);
    assert_eq!(store.db_get_tag_tree_node_value(&tag_table, selected_pending_id, &child).await?, None);
    assert!(store.db_get_tag_tree_node_value(&tag_table, retained_pending_id, &root).await?.is_some());

    Ok(())
}

#[tokio::test]
async fn exact_verifiers_report_present_then_absent_for_frozen_keys() -> anyhow::Result<()> {
    let store = Store::new();
    let u64_table = table("u64");
    let object_table = table("object");
    let merkle_table = table("merkle");
    let hash_table = table("hash-user");
    let imt_leaf_table = table("imt-leaf");
    let imt_key_table = table("imt-key");
    let imt_index_table = table("imt-index");
    let hash = Hash256::default();
    let node = SimpleMerkleNodeKey { level: 3, index: 9 };

    store.db_set_u64_value(&u64_table, 7, 11).await?;
    store.db_insert_one_single_checkpointed_object(&object_table, 5, 13, &17_u64).await?;
    store.db_insert_zero_id_merkle_node(&merkle_table, 13, &node, &hash).await?;
    store.db_insert_one_hash_to_u64(&hash_table, hash, 23).await?;
    store.db_insert_imt_leaf(&imt_leaf_table, 1, 2, 3, 13, &[0; 32], &[1; 32], &[2; 32], &[3; 32], 4).await?;
    store.db_insert_imt_key_index(&imt_key_table, 1, 2, 3, &[4; 32], &[5; 32], 13, 6).await?;
    store.db_insert_imt_next_append_index(&imt_index_table, 1, 2, 7).await?;

    assert_eq!(store.db_get_existing_object_ids(&u64_table, &[]).await?, Vec::<u64>::new());
    store.db_insert_one_double_checkpointed_object(&object_table, 5, 6, 13, &19_u64).await?;
    store.db_insert_single_id_merkle_node(&merkle_table, 13, 2, node, &hash).await?;
    store.db_insert_double_id_merkle_node(&merkle_table, 13, 2, 4, node, &hash).await?;
    assert_eq!(store.db_get_existing_object_ids(&u64_table, &[999]).await?, Vec::<u64>::new());
    assert_eq!(store.db_get_existing_object_ids(&u64_table, &[7]).await?, vec![7]);
    assert_eq!(store.db_get_existing_object_checkpoints(&object_table, &[(5, 13)]).await?, vec![(5, 13)]);
    assert_eq!(store.db_get_existing_merkle_nodes(&merkle_table, &[(3, 9, 13)]).await?, vec![(3, 9, 13)]);
    assert_eq!(store.db_get_existing_hash_user_pairs(&hash_table, &[(hash, 23)]).await?, vec![(hash, 23)]);
    assert_eq!(store.db_get_existing_imt_leaves(&imt_leaf_table, &[(1, 2, 3, 13)]).await?, vec![(1, 2, 3, 13)]);
    assert_eq!(store.db_get_existing_imt_keys(&imt_key_table, &[(1, 2, 3, vec![4; 32])]).await?, vec![(1, 2, 3, vec![4; 32])]);
    assert_eq!(store.db_get_existing_imt_next_append_indexes(&imt_index_table, &[(1, 2)]).await?, vec![(1, 2)]);

    store.db_delete_many_object_ids(&u64_table, &[7]).await?;
    assert_eq!(store.db_get_existing_tree_merkle_nodes(&merkle_table, &[(2, 3, 9, 13)]).await?, vec![(2, 3, 9, 13)]);
    assert_eq!(store.db_get_existing_tree_subtree_merkle_nodes(&merkle_table, &[(2, 4, 3, 9, 13)]).await?, vec![(2, 4, 3, 9, 13)]);
    store.db_delete_many_object_checkpoint(&object_table, &[(5, 13)]).await?;
    store.db_delete_many_merkle_nodes(&merkle_table, &[(3, 9, 13)]).await?;
    store.db_delete_many_hash_user_pairs(&hash_table, &[(hash, 23)]).await?;
    store.db_delete_many_imt_leaves(&imt_leaf_table, &[(1, 2, 3, 13)]).await?;
    store.db_delete_many_imt_keys(&imt_key_table, &[(1, 2, 3, vec![4; 32])]).await?;
    store.db_delete_many_imt_next_append_indexes(&imt_index_table, &[(1, 2)]).await?;

    assert!(store.db_get_existing_object_ids(&u64_table, &[7]).await?.is_empty());
    assert!(store.db_get_existing_object_checkpoints(&object_table, &[(5, 13)]).await?.is_empty());
    store.db_delete_many_tree_merkle_nodes(&merkle_table, &[(2, 3, 9, 13)]).await?;
    store.db_delete_many_tree_subtree_merkle_nodes(&merkle_table, &[(2, 4, 3, 9, 13)]).await?;
    assert!(store.db_get_existing_tree_merkle_nodes(&merkle_table, &[(2, 3, 9, 13)]).await?.is_empty());
    assert!(store.db_get_existing_tree_subtree_merkle_nodes(&merkle_table, &[(2, 4, 3, 9, 13)]).await?.is_empty());
    assert!(store.db_get_existing_merkle_nodes(&merkle_table, &[(3, 9, 13)]).await?.is_empty());
    assert!(store.db_get_existing_hash_user_pairs(&hash_table, &[(hash, 23)]).await?.is_empty());
    assert!(store.db_get_existing_imt_leaves(&imt_leaf_table, &[(1, 2, 3, 13)]).await?.is_empty());
    assert!(store.db_get_existing_imt_keys(&imt_key_table, &[(1, 2, 3, vec![4; 32])]).await?.is_empty());
    assert!(store.db_get_existing_imt_next_append_indexes(&imt_index_table, &[(1, 2)]).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn exact_verifiers_cover_bidirectional_and_pending_partition_presence() -> anyhow::Result<()> {
    let store = Store::new();
    let blob_table = table("blob-presence");
    let numeric_table = table("numeric-presence");
    let tag_table = table("tag-presence");
    let blob_pair = (41_u64, Hash256::default());
    let blob_keys = (blob_pair.0.psy_ser_to_bytes_vec()?, blob_pair.1.psy_ser_to_bytes_vec()?);
    let numeric_pair = (43_u64, 47_u128);
    let root = SimpleMerkleNodeKey::new_root();

    store.db_insert_pair(&blob_table, blob_pair.0, blob_pair.1).await?;
    store.db_insert_u64_u128_mapping_pair(&numeric_table, numeric_pair.0, numeric_pair.1).await?;
    store.db_set_tag_tree_tag_value(&tag_table, 53, &root, &Hash256::default(), &Hash256::default()).await?;

    let blob_presence = store.db_get_blob_pair_presence(&blob_table, &[blob_keys.clone()]).await?;
    let wrong_blob_reverse = vec![99];
    let half_blob = store.db_get_blob_pair_presence(&blob_table, &[(blob_keys.0.clone(), wrong_blob_reverse)]).await?;
    assert_eq!((half_blob[0].forward_present, half_blob[0].reverse_present), (true, false));
    assert_eq!((blob_presence[0].forward_present, blob_presence[0].reverse_present), (true, true));
    let numeric_presence = store.db_get_u64_u128_pair_presence(&numeric_table, &[numeric_pair]).await?;
    assert_eq!((numeric_presence[0].forward_present, numeric_presence[0].reverse_present), (true, true));
    let half_numeric = store.db_get_u64_u128_pair_presence(&numeric_table, &[(numeric_pair.0, numeric_pair.1 + 1)]).await?;
    assert_eq!((half_numeric[0].forward_present, half_numeric[0].reverse_present), (true, false));
    assert_eq!(store.db_get_existing_pending_id_partitions(&tag_table, &[53, 54]).await?, vec![53]);

    store.db_delete_many_blob_pairs(&blob_table, &[blob_keys.clone()]).await?;
    store.db_delete_many_u64_u128_pairs(&numeric_table, &[numeric_pair]).await?;
    store.db_delete_many_pending_id_partitions(&tag_table, &[53]).await?;

    assert!(store.db_get_blob_pair_presence(&blob_table, &[blob_keys]).await?.is_empty());
    assert!(store.db_get_u64_u128_pair_presence(&numeric_table, &[numeric_pair]).await?.is_empty());
    assert!(store.db_get_existing_pending_id_partitions(&tag_table, &[53]).await?.is_empty());
    Ok(())
}
#[tokio::test]
async fn mixed_missing_and_duplicate_keys_delete_once() -> anyhow::Result<()> {
    let store = Store::new();
    let u64_table = table("mixed-u64");
    let object_table = table("mixed-object");

    store.db_set_u64_value(&u64_table, 7, 11).await?;
    store.db_set_u64_value(&u64_table, 8, 12).await?;
    store.db_insert_one_single_checkpointed_object(&object_table, 5, 13, &17_u64).await?;
    store.db_insert_one_single_checkpointed_object(&object_table, 6, 13, &18_u64).await?;

    for _ in 0..2 {
        store.db_delete_many_object_ids(&u64_table, &[7, 7, 999]).await?;
        store.db_delete_many_object_checkpoint(&object_table, &[(5, 13), (5, 13), (5, 14)]).await?;
    }

    assert!(store.db_get_existing_object_ids(&u64_table, &[7, 999]).await?.is_empty());
    assert_eq!(store.db_get_existing_object_ids(&u64_table, &[8]).await?, vec![8]);
    assert!(store.db_get_existing_object_checkpoints(&object_table, &[(5, 13), (5, 14)]).await?.is_empty());
    assert_eq!(store.db_get_existing_object_checkpoints(&object_table, &[(6, 13)]).await?, vec![(6, 13)]);
    Ok(())
}

#[tokio::test]
async fn deletes_are_scoped_to_selected_keys() -> anyhow::Result<()> {
    let store = Store::new();
    let u64_table = table("scoped-u64");
    let object_table = table("scoped-object");
    let merkle_table = table("scoped-merkle");
    let hash_table = table("scoped-hash");
    let imt_leaf_table = table("scoped-imt-leaf");
    let imt_key_table = table("scoped-imt-key");
    let imt_index_table = table("scoped-imt-index");
    let hash = Hash256::default();
    let node = SimpleMerkleNodeKey { level: 3, index: 9 };

    store.db_set_u64_value(&u64_table, 7, 11).await?;
    store.db_set_u64_value(&u64_table, 8, 12).await?;
    store.db_insert_one_single_checkpointed_object(&object_table, 5, 13, &17_u64).await?;
    store.db_insert_one_single_checkpointed_object(&object_table, 5, 14, &18_u64).await?;
    store.db_insert_zero_id_merkle_node(&merkle_table, 13, &node, &hash).await?;
    store.db_insert_zero_id_merkle_node(&merkle_table, 14, &node, &hash).await?;
    store.db_insert_single_id_merkle_node(&merkle_table, 13, 2, node, &hash).await?;
    store.db_insert_single_id_merkle_node(&merkle_table, 14, 2, node, &hash).await?;
    store.db_insert_double_id_merkle_node(&merkle_table, 13, 2, 4, node, &hash).await?;
    store.db_insert_double_id_merkle_node(&merkle_table, 14, 2, 4, node, &hash).await?;
    store.db_insert_one_hash_to_u64(&hash_table, hash, 23).await?;
    store.db_insert_one_hash_to_u64(&hash_table, hash, 24).await?;
    store.db_insert_imt_leaf(&imt_leaf_table, 1, 2, 3, 13, &[0; 32], &[1; 32], &[2; 32], &[3; 32], 4).await?;
    store.db_insert_imt_leaf(&imt_leaf_table, 1, 2, 4, 13, &[0; 32], &[1; 32], &[2; 32], &[3; 32], 4).await?;
    store.db_insert_imt_key_index(&imt_key_table, 1, 2, 3, &[4; 32], &[5; 32], 13, 6).await?;
    store.db_insert_imt_key_index(&imt_key_table, 1, 2, 3, &[6; 32], &[7; 32], 13, 6).await?;
    store.db_insert_imt_next_append_index(&imt_index_table, 1, 2, 7).await?;
    store.db_insert_imt_next_append_index(&imt_index_table, 1, 3, 8).await?;

    store.db_delete_many_object_ids(&u64_table, &[7]).await?;
    store.db_delete_many_object_checkpoint(&object_table, &[(5, 13)]).await?;
    store.db_delete_many_merkle_nodes(&merkle_table, &[(3, 9, 13)]).await?;
    store.db_delete_many_tree_merkle_nodes(&merkle_table, &[(2, 3, 9, 13)]).await?;
    store.db_delete_many_tree_subtree_merkle_nodes(&merkle_table, &[(2, 4, 3, 9, 13)]).await?;
    store.db_delete_many_hash_user_pairs(&hash_table, &[(hash, 23)]).await?;
    store.db_delete_many_imt_leaves(&imt_leaf_table, &[(1, 2, 3, 13)]).await?;
    store.db_delete_many_imt_keys(&imt_key_table, &[(1, 2, 3, vec![4; 32])]).await?;
    store.db_delete_many_imt_next_append_indexes(&imt_index_table, &[(1, 2)]).await?;

    assert_eq!(store.db_get_existing_object_ids(&u64_table, &[7, 8]).await?, vec![8]);
    assert_eq!(store.db_get_existing_object_checkpoints(&object_table, &[(5, 13), (5, 14)]).await?, vec![(5, 14)]);
    assert_eq!(store.db_get_existing_merkle_nodes(&merkle_table, &[(3, 9, 13), (3, 9, 14)]).await?, vec![(3, 9, 14)]);
    assert_eq!(store.db_get_existing_tree_merkle_nodes(&merkle_table, &[(2, 3, 9, 13), (2, 3, 9, 14)]).await?, vec![(2, 3, 9, 14)]);
    assert_eq!(store.db_get_existing_tree_subtree_merkle_nodes(&merkle_table, &[(2, 4, 3, 9, 13), (2, 4, 3, 9, 14)]).await?, vec![(2, 4, 3, 9, 14)]);
    assert_eq!(store.db_get_existing_hash_user_pairs(&hash_table, &[(hash, 23), (hash, 24)]).await?, vec![(hash, 24)]);
    assert_eq!(store.db_get_existing_imt_leaves(&imt_leaf_table, &[(1, 2, 3, 13), (1, 2, 4, 13)]).await?, vec![(1, 2, 4, 13)]);
    assert_eq!(store.db_get_existing_imt_keys(&imt_key_table, &[(1, 2, 3, vec![4; 32]), (1, 2, 3, vec![6; 32])]).await?, vec![(1, 2, 3, vec![6; 32])]);
    assert_eq!(store.db_get_existing_imt_next_append_indexes(&imt_index_table, &[(1, 2), (1, 3)]).await?, vec![(1, 3)]);
    Ok(())
}

#[tokio::test]
async fn deletes_do_not_cross_contaminate_tables() -> anyhow::Result<()> {
    let store = Store::new();
    let first_u64 = table("first-u64");
    let second_u64 = table("second-u64");
    let first_blob = table("first-blob");
    let second_blob = table("second-blob");
    let blob_pair = (17_u64, Hash256::default());
    let blob_keys = (blob_pair.0.psy_ser_to_bytes_vec()?, blob_pair.1.psy_ser_to_bytes_vec()?);

    store.db_set_u64_value(&first_u64, 7, 11).await?;
    store.db_set_u64_value(&second_u64, 7, 12).await?;
    store.db_insert_pair(&first_blob, blob_pair.0, blob_pair.1).await?;
    store.db_insert_pair(&second_blob, blob_pair.0, blob_pair.1).await?;

    store.db_delete_many_object_ids(&first_u64, &[7]).await?;
    store.db_delete_many_blob_pairs(&first_blob, &[blob_keys.clone()]).await?;

    assert!(store.db_get_existing_object_ids(&first_u64, &[7]).await?.is_empty());
    assert_eq!(store.db_get_existing_object_ids(&second_u64, &[7]).await?, vec![7]);
    assert!(store.db_get_blob_pair_presence(&first_blob, &[blob_keys.clone()]).await?.is_empty());
    let second_presence = store.db_get_blob_pair_presence(&second_blob, &[blob_keys]).await?;
    assert_eq!((second_presence[0].forward_present, second_presence[0].reverse_present), (true, true));
    Ok(())
}
