use parth_core::data::{db::table::QDatabaseTableRoutingKey, hash::hash256::Hash256};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_node_core::store::traits::core_db::*;
use psy_node_scylla::{core::ScyllaCoreStore, tables::{
    bridge::{deposit_leaf::ScyllaBridgeDepositLeafPreparedStatements, next_index::ScyllaBridgeDepositNextIndexPreparedStatements},
    counter::u64_counter::ScyllaU64ToU64CounterTablePreparedStatements,
    imt::{ScyllaIMTKeyIndexPreparedStatements, ScyllaIMTLeafPreparedStatements, ScyllaIMTNextAppendIndexPreparedStatements},
}};

type Store = ScyllaCoreStore<Hash256, CoreSha256Hasher>;
fn routing() -> QDatabaseTableRoutingKey {
    QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(1, 0)
}
async fn store() -> anyhow::Result<Store> {
    let addr = std::env::var("PSY_TEST_SCYLLA").expect("PSY_TEST_SCYLLA must identify an isolated test database");
    Store::new(0, 0, format!("contract_{}", rand::random::<u64>()), &[addr]).await
}
async fn cleanup(s: &Store) -> anyhow::Result<()> {
    for ks in [&s.keyspace, &s.no_tablet_keyspace] {
        s.session.query_unpaged(format!("DROP KEYSPACE {ks}"), &[]).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn signed_counter_saturates_and_rejects_overflow_without_mutation() -> anyhow::Result<()> {
    let s = store().await?;
    let t = s.init_no_tablet_table::<ScyllaU64ToU64CounterTablePreparedStatements>("counters", routing()).await?;
    assert_eq!(s.db_select_u64_counter_value(&t, 1).await?, None);
    assert_eq!(s.db_inc_u64_counter(&t, 1, 15).await?, 15);
    assert_eq!(s.db_inc_u64_counter(&t, 1, -3).await?, 12);
    assert_eq!(s.db_inc_u64_counter(&t, 1, i64::MIN).await?, 0);
    assert_eq!(s.db_inc_u64_counter(&t, 2, -1).await?, 0);
    assert_eq!(s.db_inc_u64_counter(&t, 1, i64::MAX).await?, i64::MAX as u64);
    assert!(s.db_inc_u64_counter(&t, 1, 1).await.is_err());
    assert!(t.atomic_increment(&s.session, 3, u64::MAX).await.is_err());
    assert_eq!(t.atomic_increment(&s.session, 4, 7).await?, 7);
    assert_eq!(s.db_select_u64_counter_values(&t, &[2, 1, 3, 4]).await?, vec![Some(0), Some(i64::MAX as u64), None, Some(7)]);
    // Corrupt stored counters must be surfaced, not silently reinterpreted.
    s.session.query_unpaged(format!("INSERT INTO {}.counters (obj_id,value) VALUES (5,-1)", s.no_tablet_keyspace), &[]).await?;
    assert!(s.db_select_u64_counter_value(&t, 5).await.is_err());
    assert!(s.db_select_u64_counter_values(&t, &[5]).await.is_err());
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn bridge_checkpoint_history_and_chain_isolation() -> anyhow::Result<()> {
    let s = store().await?;
    let t = s.init_std_table::<ScyllaBridgeDepositLeafPreparedStatements>("deposits", routing()).await?;
    let next = s.init_std_table::<ScyllaBridgeDepositNextIndexPreparedStatements>("next_index", routing()).await?;
    assert_eq!(next.get_next_index(&s.session, 1).await?, None);
    for (chain, value) in [(1, 4), (56, 9)] {
        next.set_next_index(&s.session, chain, value).await?;
        assert_eq!(next.get_next_index(&s.session, chain).await?, Some(value));
    }
    t.insert_leaf(&s.session, 1, 0, 5, &[5; 32]).await?;
    t.insert_leaf(&s.session, 1, 0, 9, &[9; 32]).await?;
    t.insert_leaf(&s.session, 56, 0, 5, &[56; 32]).await?;
    assert_eq!(t.select_leaf_at_or_before_checkpoint(&s.session, 1, 0, 4).await?, None);
    assert_eq!(t.select_leaf_at_or_before_checkpoint(&s.session, 1, 0, 8).await?, Some(vec![5; 32]));
    assert_eq!(t.select_leaf_at_or_before_checkpoint(&s.session, 1, 0, 9).await?, Some(vec![9; 32]));
    assert_eq!(t.select_leaf_at_or_before_checkpoint(&s.session, 56, 0, 99).await?, Some(vec![56; 32]));
    let prepared = s.init_std_table_prepare_only::<ScyllaBridgeDepositLeafPreparedStatements>("deposits", routing()).await?;
    assert_eq!(prepared.select_leaf_at_or_before_checkpoint(&s.session, 1, 0, 99).await?, Some(vec![9; 32]));
    let prepared_next = s.init_std_table_prepare_only::<ScyllaBridgeDepositNextIndexPreparedStatements>("next_index", routing()).await?;
    assert_eq!(prepared_next.get_next_index(&s.session, 1).await?, Some(4));
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn imt_preimages_history_predecessor_order_and_tree_isolation() -> anyhow::Result<()> {
    let s = store().await?;
    let leaf = s.init_std_table::<ScyllaIMTLeafPreparedStatements>("leaves", routing()).await?;
    let index = s.init_std_table::<ScyllaIMTKeyIndexPreparedStatements>("keys", routing()).await?;
    let next = s.init_std_table::<ScyllaIMTNextAppendIndexPreparedStatements>("next_index", routing()).await?;
    assert!(s.db_select_imt_leaf(&leaf, 1, 2, 0, 10).await?.is_none());
    for checkpoint in [5, 9] {
        s.db_insert_imt_leaf(&leaf, 1, 2, 0, checkpoint, &[checkpoint as u8; 32], &[1; 32], &[2; 32], &[3; 32], 4).await?;
    }
    assert_eq!(s.db_select_imt_leaf(&leaf, 1, 2, 0, 8).await?, Some((vec![5; 32], vec![1; 32], vec![2; 32], vec![3; 32], 4)));
    assert_eq!(s.db_select_imt_leaf(&leaf, 1, 2, 0, 10).await?.unwrap().0, vec![9; 32]);
    assert!(s.db_select_imt_leaf(&leaf, 1, 3, 0, 10).await?.is_none());
    assert!(s.db_select_imt_key_index_exact(&index, 1, 2, 0, &[2]).await?.is_none());
    assert!(s.db_select_imt_key_index_predecessor(&index, 1, 2, 0, &[9]).await?.is_empty());
    for key in 1..=8 {
        s.db_insert_imt_key_index(&index, 1, 2, 0, &[key], &[key; 32], 5, key as i64).await?;
    }
    assert_eq!(s.db_select_imt_key_index_exact(&index, 1, 2, 0, &[2]).await?, Some((2, 5)));
    let candidates = s.db_select_imt_key_index_predecessor(&index, 1, 2, 0, &[8]).await?;
    assert_eq!(candidates.iter().map(|v| v.2).collect::<Vec<_>>(), vec![7, 6, 5, 4, 3]);
    assert_eq!(candidates[0].1, vec![7; 32]);
    let bucket = s.db_select_imt_key_index_predecessor_full_bucket(&index, 1, 2, 0).await?;
    assert_eq!(bucket.iter().map(|v| v.2).collect::<Vec<_>>(), vec![8, 7, 6, 5, 4]);
    assert!(s.db_select_imt_key_index_predecessor_full_bucket(&index, 1, 2, 1).await?.is_empty());
    assert_eq!(s.db_select_imt_next_append_index(&next, 1, 2).await?, None);
    s.db_insert_imt_next_append_index(&next, 1, 2, 9).await?;
    assert_eq!(s.db_select_imt_next_append_index(&next, 1, 2).await?, Some(9));
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn merkle_batch_variants_preserve_every_node_at_batch_boundaries() -> anyhow::Result<()> {
    use parth_core::data::hash::{
        fast_node_serializer::QMerkleStoreFastDoubleNodeSerializer,
        merkle_node_key::SimpleMerkleNodeKey,
        merkle_store_key::{QMerkleStoreDoubleIdKey, QMerkleStoreDoubleIdNode},
    };
    use psy_node_scylla::tables::merkle::ScyllaDoubleMerkleNodesPreparedStatements;
    let s = store().await?;
    let t = s.init_std_table::<ScyllaDoubleMerkleNodesPreparedStatements>("merkle", routing()).await?;
    let mut checkpoint = 0;
    macro_rules! check_writer {
        ($method:ident) => {{
            assert!(t.$method::<Hash256>(&s.session, 1, &[0]).await.is_err(), stringify!($method));
            for count in [0, 63, 64, 128, 256, 257] {
                checkpoint += 1;
                let nodes: Vec<_> = (0..count).map(|i| QMerkleStoreDoubleIdNode {
                    key: QMerkleStoreDoubleIdKey { tree_id: checkpoint, tree_sub_id: 2, level: 16, index: i },
                    value: Hash256([((i % 251) + 1) as u8; 32]),
                }).collect();
                let bytes = QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_many_nodes(&nodes);
                t.$method::<Hash256>(&s.session, checkpoint, &bytes).await?;
                let keys: Vec<_> = nodes.iter().map(|n| SimpleMerkleNodeKey::new(n.key.level, n.key.index)).collect();
                let actual = t.select_many_double_id_merkle_nodes_max_checkpoint_internal::<Hash256, CoreSha256Hasher>(
                    &s.session, checkpoint, checkpoint, 2, 16, &keys).await?;
                assert_eq!(actual, nodes.iter().map(|n| n.value).collect::<Vec<_>>(), "{} count={count}", stringify!($method));
                if count != 0 {
                    assert_eq!(t.select_double_id_merkle_node_max_checkpoint_internal::<Hash256, CoreSha256Hasher>(
                        &s.session, checkpoint - 1, checkpoint, 16, 2, keys[0]).await?, Hash256([0; 32]));
                }
            }
        }};
    }
    check_writer!(set_double_id_merkle_nodes_batch_from_fast_serialized_data_simple);
    check_writer!(set_double_id_merkle_nodes_batch_256_from_fast_serialized_data);
    check_writer!(set_double_id_merkle_nodes_batch_g_internal_fast_v2);
    check_writer!(set_double_id_merkle_nodes_batch_g_internal_fast_v3);
    check_writer!(set_double_id_merkle_nodes_batch_fast_serialize);
    check_writer!(set_double_id_merkle_nodes_batch_g_internal_fast_v5_grok_3);
    check_writer!(set_double_id_merkle_nodes_batch_g_internal_fast_v5_grok_2);
    check_writer!(set_double_id_merkle_nodes_batch_g_internal_fast_v5_gemini_1);
    check_writer!(set_double_id_merkle_nodes_batch_fast_v7_g);
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn kiv_batch_variants_return_values_in_requested_order() -> anyhow::Result<()> {
    use parth_core::data::db::row::QDatabaseKeyIdValueTableRow;
    use psy_node_scylla::tables::object::ScyllaGenericKeyIdValueTablePreparedStatements;
    let s = store().await?;
    let t = s.init_std_table::<ScyllaGenericKeyIdValueTablePreparedStatements>("objects", routing()).await?;
    assert!(t.select_one_kiv_value_and_ids::<u64>(&s.session, 1).await?.is_none());
    assert!(t.select_one_kiv_value_and_ids_t::<u64, QDatabaseKeyIdValueTableRow<u64>>(&s.session, 1).await?.is_none());
    let rows: Vec<_> = (1..=129).map(|i| QDatabaseKeyIdValueTableRow { obj_id: i, value: i * 10 }).collect();
    t.insert_many_kivs(&s.session, &rows).await?;
    t.insert_many_kivs_t::<u64, _>(&s.session, &rows).await?;
    t.insert_many_kiv_rows_t::<u64, _>(&s.session, &rows).await?;
    t.insert_one_kiv(&s.session, 130, &1300u64).await?;
    assert_eq!(t.select_one_kiv_value_and_ids::<u64>(&s.session, 1).await?.unwrap().value, 10);
    assert_eq!(t.select_one_kiv_value_and_ids_t::<u64, QDatabaseKeyIdValueTableRow<u64>>(&s.session, 129).await?.unwrap().obj_id, 129);
    assert_eq!(t.select_many_kiv_values::<u64>(&s.session, &[129, 999, 1]).await?, vec![Some(1290), None, Some(10)]);
    let selected = t.select_many_kiv_keys_and_values::<u64, QDatabaseKeyIdValueTableRow<u64>>(&s.session, &[129, 999, 1]).await?;
    assert_eq!(selected.iter().map(|v| (v.obj_id, v.value)).collect::<Vec<_>>(), vec![(129, 1290), (1, 10)]);
    let mut all = t.select_all_kiv::<u64>(&s.session).await?;
    all.sort_by_key(|v| v.obj_id);
    assert_eq!(all.iter().map(|v| v.value).collect::<Vec<_>>(), (1..=130).map(|i| i * 10).collect::<Vec<_>>());
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn blob_mapping_batches_support_typed_and_binary_keys() -> anyhow::Result<()> {
    use parth_core::data::db::data_types::BiDirectionalMappingRow;
    use psy_node_scylla::tables::blob::{ScyllaBlobToBlobTablePreparedStatements, ScyllaBiDirectionalBlobToBlobTablePreparedStatements};
    let s = store().await?;
    let t = s.init_std_table::<ScyllaBlobToBlobTablePreparedStatements>("blobs", routing()).await?;
    assert!(t.select_one_single(s.session.clone(), &[1]).await?.is_none());
    t.set_or_insert_one(s.session.clone(), &[1], &[11, 12]).await?;
    t.set_or_insert_many(s.session.clone(), vec![(vec![2], vec![21, 22]), (vec![3], vec![31, 32])]).await?;
    assert_eq!(t.select_one_single(s.session.clone(), &[1]).await?, Some(vec![11, 12]));
    let expected = vec![Some(vec![21, 22]), None, Some(vec![11, 12])];
    assert_eq!(t.select_many_values_ref(s.session.clone(), &[&[2], &[9], &[1]]).await?, expected);
    assert_eq!(t.select_many_values_sized(s.session.clone(), &[[2], [9], [1]]).await?, expected);
    assert_eq!(t.select_many_values_dual_sized::<1, 2>(s.session.clone(), &[[2], [9], [1]]).await?, vec![Some([21, 22]), None, Some([11, 12])]);
    assert!(t.select_many_values_dual_sized::<1, 3>(s.session.clone(), &[[2]]).await.is_err());
    let bi = s.init_std_table::<ScyllaBiDirectionalBlobToBlobTablePreparedStatements>("bidirectional", routing()).await?;
    let rows: Vec<_> = (1u64..=129).map(|i| BiDirectionalMappingRow { k1: i, k2: i + 1000 }).collect();
    bi.set_or_insert_many_qpk(s.session.clone(), &rows).await?;
    bi.set_or_insert_one_qpk(s.session.clone(), &130u64, &1130u64).await?;
    assert_eq!(bi.select_one_by_k1::<u64, u64>(s.session.clone(), &1).await?, Some(1001));
    assert_eq!(bi.select_one_by_k2::<u64, u64>(s.session.clone(), &1130).await?, Some(130));
    assert_eq!(bi.select_many_by_k1::<u64, u64>(s.session.clone(), &[129, 999, 1]).await?, vec![Some(1129), None, Some(1001)]);
    assert_eq!(bi.select_many_by_k2::<u64, u64>(s.session.clone(), &[1129, 999, 1001]).await?, vec![Some(129), None, Some(1)]);
    let forward = bi.select_many_key_values_by_k1::<u64, u64>(s.session.clone(), &[129, 999, 1]).await?;
    let backward = bi.select_many_key_values_by_k2::<u64, u64>(s.session.clone(), &[1129, 999, 1001]).await?;
    assert_eq!(forward.iter().map(|r| (r.k1, r.k2)).collect::<Vec<_>>(), vec![(129, 1129), (1, 1001)]);
    assert_eq!(backward.iter().map(|r| (r.k1, r.k2)).collect::<Vec<_>>(), vec![(129, 1129), (1, 1001)]);
    bi.set_or_insert_many(s.session.clone(), vec![(vec![1, 2], vec![3, 4])]).await?;
    assert_eq!(bi.k1.select_one_single(s.session.clone(), &[1, 2]).await?, Some(vec![3, 4]));
    assert_eq!(bi.k2.select_one_single(s.session.clone(), &[3, 4]).await?, Some(vec![1, 2]));
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn tag_tree_optional_bulk_reads_and_both_proof_readers_agree() -> anyhow::Result<()> {
    use parth_core::{crypto::hash::tag_tree::hash_tag_tree_node, data::hash::merkle_node_key::SimpleMerkleNodeKey};
    use psy_node_scylla::tables::tag_tree::ScyllaTagTreeNodesPreparedStatements;
    let s = store().await?;
    let t = s.init_std_table::<ScyllaTagTreeNodesPreparedStatements>("tags", routing()).await?;
    let root = SimpleMerkleNodeKey::new_root();
    let left = SimpleMerkleNodeKey::new(1, 0);
    let right = SimpleMerkleNodeKey::new(1, 1);
    let missing = SimpleMerkleNodeKey::new(2, 3);
    let zero = Hash256([0; 32]);
    let tag = Hash256([7; 32]);
    let value = hash_tag_tree_node::<Hash256, CoreSha256Hasher>(&zero, &zero, &tag);
    assert!(t.select_tag_tree_proof_old::<Hash256>(&s.session, 1, left).await.is_err());
    t.set_or_insert_one(&s.session, 1, &left, &tag.0, &value.0).await?;
    t.set_or_insert_one(&s.session, 1, &right, &tag.0, &value.0).await?;
    t.set_tag_only_computed::<Hash256, CoreSha256Hasher>(&s.session, 1, root, Some(1), &tag).await?;
    for proof in [t.select_tag_tree_proof::<Hash256>(&s.session, 1, left).await?, t.select_tag_tree_proof_old::<Hash256>(&s.session, 1, left).await?] {
        assert!(proof.verify::<CoreSha256Hasher>());
        assert_eq!(proof.root, hash_tag_tree_node::<Hash256, CoreSha256Hasher>(&value, &value, &tag));
    }
    let keys = [right, missing, left];
    assert_eq!(t.select_many_tag_tree_values::<Hash256>(&s.session, 1, &keys).await?, vec![Some(value), None, Some(value)]);
    assert_eq!(t.select_many_tag_tree_tags::<Hash256>(&s.session, 1, &keys).await?, vec![Some(tag), None, Some(tag)]);
    assert_eq!(t.select_many_tag_tree_values_or_zero::<Hash256>(&s.session, 1, &keys).await?, vec![value, zero, value]);
    assert_eq!(t.select_many_tag_tree_tags_or_zero::<Hash256>(&s.session, 1, &keys).await?, vec![tag, zero, tag]);
    let values = t.select_many_tag_tree_tags_and_values::<Hash256>(&s.session, 1, &keys).await?;
    assert_eq!(values[0].as_ref().unwrap().tag, tag);
    assert!(values[1].is_none());
    let values = t.select_many_tag_tree_tags_and_values_or_zero::<Hash256>(&s.session, 1, &keys).await?;
    assert_eq!((values[1].tag, values[1].value), (zero, zero));
    assert_eq!((values[2].tag, values[2].value), (tag, value));
    // A value-only row is not a complete tag/value node.
    t.update_value_only(&s.session, 1, &missing, &value.0).await?;
    assert!(t.select_one_tag_tree_tag_and_value::<Hash256>(&s.session, 1, &missing).await?.is_none());
    assert!(t.select_many_tag_tree_tags_and_values::<Hash256>(&s.session, 1, &[missing]).await?[0].is_none());
    assert_eq!(t.select_many_tag_tree_tags_and_values_or_zero::<Hash256>(&s.session, 1, &[missing]).await?[0].value, zero);
    assert!(t.get_tag_tree_node_preimage::<Hash256>(&s.session, 1, Some(1), &missing).await.is_err());
    assert!(t.get_tag_tree_node_children::<Hash256>(&s.session, 1, &missing, Some(1)).await.is_err());
    assert_eq!(t.get_tag_tree_node_children::<Hash256>(&s.session, 1, &left, Some(1)).await?, (zero, zero));
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn packed_object_writers_preserve_ids_values_and_checkpoint_history() -> anyhow::Result<()> {
    use parth_core::data::db::row::QDatabaseSingleIdTableRowNoCheckpointId;
    use psy_node_scylla::tables::object::ScyllaGenericObjectSingleIdTablePreparedStatements;
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
    let s = store().await?;
    let t = s.init_std_table::<ScyllaGenericObjectSingleIdTablePreparedStatements>("packed", routing()).await?;
    for count in [0, 63, 128, 257] {
        let rows: Vec<_> = (0..count).map(|i| QDatabaseSingleIdTableRowNoCheckpointId { obj_id: i, value: i + 100u64 }).collect();
        let packed: Vec<u8> = rows.iter().flat_map(|r| [r.obj_id.to_le_bytes().to_vec(), r.value.psy_ser_to_bytes_vec().unwrap()].concat()).collect();
        t.insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(&s.session, 8, 5, &packed).await?;
        for r in &rows {
            assert_eq!(t.select_one_single_checkpointed_object_value::<u64>(&s.session, r.obj_id, 5).await?, Some(r.value));
        }
        // with_id_at_index stores the complete record, including the ID.
        t.insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index(&s.session, 16, 0, 6, &packed).await?;
        for r in &rows {
            let record = t.select_one_single_checkpointed_object_value::<u128>(&s.session, r.obj_id, 6).await?.unwrap();
            assert_eq!(record, u128::from(r.obj_id) | (u128::from(r.value) << 64));
        }
        t.insert_many_single_checkpointed_objects_at_checkpoint_t_single_insert_chunks::<u64, _>(&s.session, 7, &rows).await?;
        t.insert_many_single_checkpointed_objects_at_checkpoint_t_with_batch_size::<u64, _>(&s.session, 8, 64, &rows).await?;
        let keys: Vec<_> = rows.iter().map(|r| r.obj_id).collect();
        assert_eq!(t.select_many_single_checkpointed_object_values::<u64>(&s.session, &keys, 8).await?, rows.iter().map(|r| Some(r.value)).collect::<Vec<_>>());
        assert!(t.select_one_single_checkpointed_object_value::<u64>(&s.session, 0, 4).await?.is_none());
    }
    assert!(t.insert_many_single_checkpointed_objects_at_checkpoint_ffs_clip_id_at_start(&s.session, 8, 9, &[0]).await.is_err());
    assert!(t.insert_many_single_checkpointed_objects_at_checkpoint_ffs_with_id_at_index(&s.session, 16, 0, 9, &[0]).await.is_err());
    cleanup(&s).await
}
