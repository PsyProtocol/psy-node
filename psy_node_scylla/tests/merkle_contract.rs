use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{db::table::QDatabaseTableRoutingKey, hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}},
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_node_core::store::traits::core_db::*;
use psy_node_scylla::{core::ScyllaCoreStore, tables::merkle::ScyllaMerkleNodesPreparedStatements};
use std::collections::HashMap;

type Store = ScyllaCoreStore<Hash256, CoreSha256Hasher>;
fn routing() -> QDatabaseTableRoutingKey { QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(1, 0) }
async fn store() -> anyhow::Result<Store> {
    let endpoint = std::env::var("PSY_TEST_SCYLLA").expect("PSY_TEST_SCYLLA must identify an isolated database");
    Store::new(0, 0, format!("merkle_contract_{}", rand::random::<u64>()), &[endpoint]).await
}
async fn cleanup(s: &Store) -> anyhow::Result<()> {
    for keyspace in [&s.keyspace, &s.no_tablet_keyspace] { s.session.query_unpaged(format!("DROP KEYSPACE {keyspace}"), &[]).await?; }
    Ok(())
}
fn leaf(height: u8, index: u64, value: u8) -> SimpleMerkleNode<Hash256> {
    SimpleMerkleNode { key: SimpleMerkleNodeKey::new(height, index), value: Hash256([value; 32]) }
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn zero_id_dump_selects_history_before_future_overwrites() -> anyhow::Result<()> {
    let s = store().await?;
    let t = s.init_zero_id_merkle_table("history", routing(), 4).await?;
    assert!(s.db_dump_all_zero_id_merkle_node_leaves_vec(&t, 4, MerkleTreeDumpStrategy::DumpAllStrategy).await?.is_empty());
    s.db_set_zero_id_merkle_nodes_batch(&t, 5, &[leaf(4, 0, 10), leaf(4, 1, 11), leaf(4, 7, 17)]).await?;
    s.db_set_zero_id_merkle_nodes_batch(&t, 9, &[leaf(4, 0, 90), leaf(4, 2, 92), leaf(4, 7, 97)]).await?;
    let expected = HashMap::from([(0, Hash256([10; 32])), (1, Hash256([11; 32])), (7, Hash256([17; 32]))]);
    assert_eq!(s.db_dump_all_zero_id_merkle_node_leaves_chunked(&t, 8).await?, expected);
    let dumped = s.db_dump_all_zero_id_merkle_node_leaves_vec(&t, 8, MerkleTreeDumpStrategy::DumpAllStrategy).await?;
    assert_eq!(dumped.iter().map(|n| (n.key.index, n.value)).collect::<Vec<_>>(), vec![(0, Hash256([10; 32])), (1, Hash256([11; 32])), (7, Hash256([17; 32]))]);
    let previous = s.db_select_zero_id_merkle_node_and_checkpoint_max_checkpoint(&t, 8, &SimpleMerkleNodeKey::new(4, 0)).await?;
    assert_eq!((previous.checkpoint_id, previous.value), (5, Hash256([10; 32])));
    let missing = s.db_select_zero_id_merkle_node_and_checkpoint_max_checkpoint(&t, 8, &SimpleMerkleNodeKey::new(4, 2)).await?;
    assert_eq!((missing.checkpoint_id, missing.value), (8, Hash256([0; 32])));
    assert_eq!(s.db_select_zero_id_merkle_node_max_checkpoint(&t, u64::MAX, &SimpleMerkleNodeKey::new(4, 0)).await?, Hash256([90; 32]));
    assert!(t.select_optional_zero_id_merkle_node_internal::<Hash256>(&s.session, 8, SimpleMerkleNodeKey::new(4, 2)).await?.is_none());
    assert_eq!(t.select_optional_zero_id_merkle_node_internal::<Hash256>(&s.session, 9, SimpleMerkleNodeKey::new(4, 2)).await?, Some(Hash256([92; 32])));
    s.db_insert_zero_id_merkle_node(&t, 10, &SimpleMerkleNodeKey::new(4, 1), &Hash256([0; 32])).await?;
    assert_eq!(s.db_dump_all_zero_id_merkle_node_leaves_chunked(&t, 10).await?.get(&1), Some(&Hash256([0; 32])));
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn append_only_dump_respects_snapshot_and_full_tree_boundary() -> anyhow::Result<()> {
    let s = store().await?;
    let t = s.init_zero_id_merkle_table("append_history", routing(), 2).await?;
    assert!(s.db_dump_all_zero_id_merkle_node_leaves_vec(&t, 4, MerkleTreeDumpStrategy::AppendOnlyTreeStrategy).await?.is_empty());
    s.db_set_zero_id_merkle_nodes_batch(&t, 5, &[leaf(2, 0, 10), leaf(2, 1, 11)]).await?;
    s.db_set_zero_id_merkle_nodes_batch(&t, 9, &[leaf(2, 0, 90), leaf(2, 2, 92), leaf(2, 3, 93)]).await?;
    for strategy in [MerkleTreeDumpStrategy::DumpAllStrategy, MerkleTreeDumpStrategy::AppendOnlyTreeStrategy] {
        let old = s.db_dump_all_zero_id_merkle_node_leaves_vec(&t, 8, strategy).await?;
        assert_eq!(old.iter().map(|n| (n.key.index, n.value)).collect::<Vec<_>>(), vec![(0, Hash256([10; 32])), (1, Hash256([11; 32]))]);
        let full = s.db_dump_all_zero_id_merkle_node_leaves_vec(&t, 9, strategy).await?;
        assert_eq!(full.iter().map(|n| (n.key.index, n.value)).collect::<Vec<_>>(), vec![(0, Hash256([90; 32])), (1, Hash256([11; 32])), (2, Hash256([92; 32])), (3, Hash256([93; 32]))]);
    }
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn zero_id_writers_preserve_every_node_across_batch_boundaries() -> anyhow::Result<()> {
    use parth_core::data::hash::fast_node_serializer::QMerkleStoreFastZeroNodeSerializer;
    let s = store().await?;
    let t = s.init_zero_id_merkle_table("batches", routing(), 24).await?;
    for (variant, checkpoint) in [(0, 5), (1, 9)] {
        for count in [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257, 513] {
            let base = variant * 1_000_000 + count * 1000;
            let nodes: Vec<_> = (0..count).map(|i| leaf(24, base + i, (i % 251 + 1) as u8)).collect();
            if variant == 0 {
                s.db_set_zero_id_merkle_nodes_batch(&t, checkpoint, &nodes).await?;
            } else {
                let bytes: Vec<_> = nodes.iter().flat_map(QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_node_to_fixed).collect();
                s.db_set_zero_id_merkle_nodes_from_fast_serialized(&t, checkpoint, &bytes).await?;
            }
            let mut keys: Vec<_> = nodes.iter().rev().map(|n| n.key).collect();
            keys.push(SimpleMerkleNodeKey::new(23, base));
            let mut expected: Vec<_> = nodes.iter().rev().map(|n| n.value).collect();
            expected.push(<CoreSha256Hasher as MerkleZeroHasher<Hash256>>::get_zero_hash(1));
            assert_eq!(s.db_select_many_zero_id_merkle_nodes_max_checkpoint(&t, checkpoint, &keys).await?, expected, "writer {variant}, count {count}");
            assert_eq!(s.db_select_zero_id_merkle_node_max_checkpoint(&t, checkpoint - 1, &SimpleMerkleNodeKey::new(24, base)).await?, Hash256([0; 32]));
        }
    }
    assert!(s.db_set_zero_id_merkle_nodes_from_fast_serialized(&t, 10, &[0]).await.is_err());
    let index_table = s.init_zero_id_merkle_table("index_checkpoints", routing(), 10).await?;
    let nodes: Vec<_> = (0..513).map(|i| leaf(10, i, (i % 251 + 1) as u8)).collect();
    s.db_set_zero_id_merkle_nodes_batch_checkpoint_is_index(&index_table, &nodes).await?;
    for i in [0, 255, 256, 511, 512] {
        let actual = s.db_select_zero_id_merkle_node_and_checkpoint_max_checkpoint(&index_table, u64::MAX, &nodes[i as usize].key).await?;
        assert_eq!((actual.checkpoint_id, actual.value), (i, nodes[i as usize].value));
        if i > 0 { assert_eq!(s.db_select_zero_id_merkle_node_max_checkpoint(&index_table, i-1, &nodes[i as usize].key).await?, Hash256([0; 32])); }
    }
    let bad_key = SimpleMerkleNodeKey::new(24, 9_000_000);
    t.insert_zero_id_merkle_node_internal(&s.session, 20, bad_key, &[1]).await?;
    assert!(t.select_optional_zero_id_merkle_node_internal::<Hash256>(&s.session, 20, bad_key).await.is_err());
    assert!(s.db_select_zero_id_merkle_node_max_checkpoint(&t, 20, &bad_key).await.is_err());
    assert!(s.db_dump_all_zero_id_merkle_node_leaves_vec(&t, 20, MerkleTreeDumpStrategy::DumpAllStrategy).await.is_err());
    cleanup(&s).await
}

#[tokio::test]
#[ignore = "Requires isolated PSY_TEST_SCYLLA"]
async fn single_id_serialized_batches_preserve_tree_and_checkpoint_isolation() -> anyhow::Result<()> {
    use parth_core::data::hash::{fast_node_serializer::QMerkleStoreFastSingleNodeSerializer, merkle_store_key::{QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode}};
    let s = store().await?;
    let t = s.init_std_table::<ScyllaMerkleNodesPreparedStatements>("single_id", routing()).await?;
    for count in [0, 1, 63, 64, 65, 128, 129, 256, 257] {
        let tree = count + 1;
        let nodes: Vec<_> = (0..count).map(|i| QMerkleStoreSingleIdNode {
            key: QMerkleStoreSingleIdKey { tree_id: tree, level: 16, index: i }, value: Hash256([(i % 251 + 1) as u8; 32]),
        }).collect();
        let bytes = QMerkleStoreFastSingleNodeSerializer::serialize_single_id_many_nodes(&nodes);
        s.db_set_single_id_merkle_nodes_from_fast_serialized(&t, 5, &bytes).await?;
        let mut keys: Vec<_> = nodes.iter().rev().map(|n| SimpleMerkleNodeKey::new(n.key.level, n.key.index)).collect();
        keys.push(SimpleMerkleNodeKey::new(15, 0));
        let mut expected: Vec<_> = nodes.iter().rev().map(|n| n.value).collect();
        expected.push(<CoreSha256Hasher as MerkleZeroHasher<Hash256>>::get_zero_hash(1));
        assert_eq!(s.db_select_many_single_id_merkle_nodes_max_checkpoint(&t, 5, tree, 16, &keys).await?, expected);
        assert_eq!(s.db_select_single_id_merkle_node_max_checkpoint(&t, 5, tree+10_000, 16, SimpleMerkleNodeKey::new(16, 0)).await?, Hash256([0; 32]));
        if count > 0 {
            s.db_insert_single_id_merkle_node(&t, 9, tree, SimpleMerkleNodeKey::new(16, 0), &Hash256([99; 32])).await?;
            assert_eq!(s.db_select_single_id_merkle_node_max_checkpoint(&t, 8, tree, 16, SimpleMerkleNodeKey::new(16, 0)).await?, nodes[0].value);
            assert_eq!(s.db_select_single_id_merkle_node_max_checkpoint(&t, 9, tree, 16, SimpleMerkleNodeKey::new(16, 0)).await?, Hash256([99; 32]));
        }
    }
    let normal: Vec<_> = (0..257).map(|i| leaf(16, i, (i % 251 + 1) as u8)).collect();
    s.db_set_single_id_merkle_nodes_batch(&t, 11, 20_000, &normal).await?;
    assert_eq!(s.db_select_many_single_id_merkle_nodes_max_checkpoint(&t, 11, 20_000, 16, &normal.iter().map(|n| n.key).collect::<Vec<_>>()).await?, normal.iter().map(|n| n.value).collect::<Vec<_>>());
    assert!(s.db_set_single_id_merkle_nodes_from_fast_serialized(&t, 12, &[0]).await.is_err());
    cleanup(&s).await
}
