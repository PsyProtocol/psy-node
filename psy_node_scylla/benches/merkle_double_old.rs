use criterion::Criterion;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::table::QDatabaseTableRoutingKey, hash::{hash256::Hash256, merkle_store_key::QMerkleStoreDoubleIdNode}}, protocol::core_types::QDBHashBase, utils::QPGenRandom};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_scylla::{core::ScyllaCoreStore, tables::merkle::ScyllaDoubleMerkleNodesPreparedStatements};
use psy_node_core::qblob::{data_views::double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, structs::common::{blob_metadata_header::QBlobWriterContextMetadataHeader, tree_node_batch_header::QBLOB_TREE_NODE_BATCH_HEADER_SIZE}};



async fn setup_scylla_core<Hash: QDBHashBase, Hasher: MerkleZeroHasher<Hash>>(keyspace: String) -> anyhow::Result<(ScyllaCoreStore<Hash, Hasher>, ScyllaDoubleMerkleNodesPreparedStatements)> {
    let store = ScyllaCoreStore::<Hash, Hasher>::new(
        1,
        1,
        keyspace,
        &["127.0.0.1:9042".to_string()],
    ).await?;
    let double_id_merkle_table: ScyllaDoubleMerkleNodesPreparedStatements = store.init_std_table::<ScyllaDoubleMerkleNodesPreparedStatements>("double_merkle_id_test", QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(0, 0)).await?;



    Ok((store, double_id_merkle_table))
}
fn gen_rand_double_id_nodes<Hash: QPGenRandom>(count: usize) -> Vec<QMerkleStoreDoubleIdNode<Hash>> {
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let node = QMerkleStoreDoubleIdNode::qp_rand_gen();
        nodes.push(node);
    }
    nodes
}

pub fn bench_merkle_double_id(c: &mut Criterion) {
    let realm_id = rand::random::<u64>();
    let realm_sub_id = 1;
    let keyspace_prefix = format!("bench_merkle_double_id_v1_{}_{}", realm_id, realm_sub_id);

    type Hash = Hash256;
    type Hasher = CoreSha256Hasher;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let node_count = 100000;
    let (store, double_id_merkle_table) = rt
        .block_on(setup_scylla_core::<Hash, Hasher>(keyspace_prefix))
        .unwrap();
    let double_id_merkle_nodes_a = gen_rand_double_id_nodes::<Hash>(node_count);
    let double_id_merkle_nodes_b = gen_rand_double_id_nodes::<Hash>(node_count);
    let double_id_merkle_nodes_c = gen_rand_double_id_nodes::<Hash>(node_count);
    let double_id_merkle_nodes_d = gen_rand_double_id_nodes::<Hash>(node_count);
    let double_id_merkle_nodes_e = gen_rand_double_id_nodes::<Hash>(node_count);
    let double_id_merkle_nodes_f = gen_rand_double_id_nodes::<Hash>(node_count);
    let double_id_merkle_nodes_g = gen_rand_double_id_nodes::<Hash>(node_count);
    let double_id_merkle_nodes_h = gen_rand_double_id_nodes::<Hash>(node_count);
    let double_id_merkle_nodes_i = gen_rand_double_id_nodes::<Hash>(node_count);

    let context = QBlobWriterContextMetadataHeader::new_at_now(1, 1, 1, 1, 1, 1, 1);
    let fast_serialized_a = QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref(context, &double_id_merkle_nodes_a);
    let fast_serialized_b = QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref(context, &double_id_merkle_nodes_b);
    let fast_serialized_c = QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref(context, &double_id_merkle_nodes_c);
    let fast_serialized_d = QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref(context, &double_id_merkle_nodes_d);
    
    let checkpoint_id_test_a = 12345;
    let mut group = c.benchmark_group("merkle_double_id_v1");
    group.sample_size(10);
/* 
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_fast_serialized_data_simple", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_from_fast_serialized_data_simple::<Hash>(&store.session, checkpoint_id_test_a, &fast_serialized[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });*/
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_fast_serialized_data_v2", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal_fast_v2::<Hash>(&store.session, checkpoint_id_test_a, &fast_serialized_a[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_fast_serialized_data_v5_gemini_1", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal_fast_v5_gemini_1::<Hash>(&store.session, checkpoint_id_test_a, &&fast_serialized_b[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_set_double_id_merkle_nodes_batch_fast_v7_g", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_fast_v7_g::<Hash>(&store.session, checkpoint_id_test_a, &fast_serialized_c[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_fast_serialized_data_fast_v5_grok_3", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal_fast_v5_grok_3::<Hash>(&store.session, checkpoint_id_test_a, &fast_serialized_d[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_batch_size_256", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes_e, 256)).unwrap();
        });
    });
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_batch_size_128", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes_f, 128)).unwrap();
        });
    });
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_batch_size_512", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes_g, 512)).unwrap();
        });
    });
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_batch_size_64", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes_h, 64)).unwrap();
        });
    });
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_batch_size_1024", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes_i, 1024)).unwrap();
        });
    });
}

