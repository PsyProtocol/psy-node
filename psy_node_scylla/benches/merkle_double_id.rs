use criterion::Criterion;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::table::QDatabaseTableRoutingKey, hash::{hash256::Hash256, merkle_store_key::QMerkleStoreDoubleIdNode}}, protocol::core_types::QHashBase, utils::QPGenRandom};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_scylla::{core::ScyllaCoreStore, tables::merkle::ScyllaDoubleMerkleNodesPreparedStatements};



async fn setup_scylla_core<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>>(keyspace: String) -> anyhow::Result<(ScyllaCoreStore<Hash, Hasher>, ScyllaDoubleMerkleNodesPreparedStatements)> {
    let store = ScyllaCoreStore::<Hash, Hasher>::new(
        1,
        1,
        keyspace,
        &["127.0.0.1:9042".to_string()],
    ).await?;
    let double_id_merkle_table: ScyllaDoubleMerkleNodesPreparedStatements = store.init_std_table::<ScyllaDoubleMerkleNodesPreparedStatements>("double_merkle_id_test", QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(0, 0)).await?;



    Ok((store, double_id_merkle_table))
}

pub fn bench_merkle_double_id(c: &mut Criterion) {
    let realm_id = 1;
    let realm_sub_id = 1;
    let keyspace_prefix = format!("bench_merkle_double_id_v1_{}_{}", realm_id, realm_sub_id);

    type Hash = Hash256;
    type Hasher = CoreSha256Hasher;
    let rt = tokio::runtime::Runtime::new().unwrap();

    let (store, double_id_merkle_table) = rt
        .block_on(setup_scylla_core::<Hash, Hasher>(keyspace_prefix))
        .unwrap();
    let double_id_merkle_nodes = (0..10000).map(|_| QMerkleStoreDoubleIdNode::<Hash>::qp_rand_gen()).collect::<Vec<_>>();

    let checkpoint_id_test_a = 12345;
    let mut group = c.benchmark_group("merkle_double_id_v1");
    group.bench_function("h256_insert_10000_QMerkleStoreDoubleIdNode_batch_size_256", |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes, 256)).unwrap();
        });
    });
    group.bench_function("h256_insert_10000_QMerkleStoreDoubleIdNode_batch_size_128", |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes, 128)).unwrap();
        });
    });
    group.bench_function("h256_insert_10000_QMerkleStoreDoubleIdNode_batch_size_512", |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes, 512)).unwrap();
        });
    });
    group.bench_function("h256_insert_10000_QMerkleStoreDoubleIdNode_batch_size_64", |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes, 64)).unwrap();
        });
    });
    group.bench_function("h256_insert_10000_QMerkleStoreDoubleIdNode_batch_size_1024", |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal::<Hash>(&store.session, checkpoint_id_test_a, &double_id_merkle_nodes, 1024)).unwrap();
        });
    });
}