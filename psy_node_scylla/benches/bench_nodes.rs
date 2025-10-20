use criterion::Criterion;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::{db::table::QDatabaseTableRoutingKey, hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, merkle_store_key::{QMerkleStoreDoubleIdKey, QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdKey, QMerkleStoreSingleIdNode}}}, pgoldilocks::{PGoldilocksHash, PoseidonHasher}, protocol::core_types::QDBHashBase, utils::QPGenRandom};
use parth_node_scylla::{core::ScyllaCoreStore, tables::merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements}};
use psy_node_core::{qblob::{blob_type::QBlobMerkleNodeTreeType, data_views::{double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView, zero_merkle_node_batch::QBlobZeroMerkleNodeBatchDataView}, structs::common::{blob_metadata_header::QBlobWriterContextMetadataHeader, tree_node_batch_header::QBLOB_TREE_NODE_BATCH_HEADER_SIZE}}, store::traits::core_db::{CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseSingleIdMerkleWriter, CoreDatabaseZeroIdMerkleWriter}};



async fn setup_scylla_core<Hash: QDBHashBase, Hasher: MerkleZeroHasher<Hash>>(keyspace: String) -> anyhow::Result<(ScyllaCoreStore<Hash, Hasher>, ScyllaMerkleNodesZeroPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaDoubleMerkleNodesPreparedStatements)> {
    
    let ks=keyspace.clone();
    let store = ScyllaCoreStore::<Hash, Hasher>::new(
        1,
        1,
        keyspace,
        &["127.0.0.1:9042".to_string()],
    ).await?;
    let zero_id_merkle_table = ScyllaMerkleNodesZeroPreparedStatements::new_create_from_session(store.session.clone(),&ks, "zero_id_merkle_nodes_test", QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(0, 0), 24).await?;
    
    let single_id_merkle_table = store.init_std_table::<ScyllaMerkleNodesPreparedStatements>("single_merkle_id_test", QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(0, 0)).await?;
    let double_id_merkle_table = store.init_std_table::<ScyllaDoubleMerkleNodesPreparedStatements>("double_merkle_id_test", QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(0, 0)).await?;



    Ok((store, zero_id_merkle_table, single_id_merkle_table, double_id_merkle_table))
}

trait BenchFastRand {
    fn bench_rand_gen_fast() -> Self;
}
impl BenchFastRand for Hash256 {
    fn bench_rand_gen_fast() -> Self {
        Hash256::rand()
    }
}
impl BenchFastRand for PGoldilocksHash {
    fn bench_rand_gen_fast() -> Self {
        PGoldilocksHash::from_hash256_le(Hash256::rand())
    }
}
fn gen_rand_double_id_nodes_fast_rand<Hash: BenchFastRand>(count: usize) -> Vec<QMerkleStoreDoubleIdNode<Hash>> {
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let node = QMerkleStoreDoubleIdNode{
            key: QMerkleStoreDoubleIdKey::qp_rand_gen(),
            value: Hash::bench_rand_gen_fast(),
        };
        nodes.push(node);
    }
    nodes
}
fn gen_rand_single_id_nodes_fast_rand<Hash: BenchFastRand>(count: usize) -> Vec<QMerkleStoreSingleIdNode<Hash>> {
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let node = QMerkleStoreSingleIdNode{
            key: QMerkleStoreSingleIdKey::qp_rand_gen(),
            value: Hash::bench_rand_gen_fast(),
        };
        nodes.push(node);
    }
    nodes
}
fn gen_rand_zero_id_nodes_fast_rand<Hash: BenchFastRand>(count: usize) -> Vec<SimpleMerkleNode<Hash>> {
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let node = SimpleMerkleNode{
            key: SimpleMerkleNodeKey::qp_rand_gen(),
            value: Hash::bench_rand_gen_fast(),
        };
        nodes.push(node);
    }
    nodes
}

fn bench_merkle_double_id_internal<Hash: BenchFastRand + QDBHashBase, Hasher: MerkleZeroHasher<Hash> + Send + Sync>(c: &mut Criterion, node_count: usize) {
    let realm_id = rand::random::<u64>();
    let realm_sub_id = 1;
    let keyspace_prefix = format!("bench_memory_merkle_double_id_v1_{}_{}", realm_id, realm_sub_id);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (store, zero_merkle_table, single_merkle_table, double_merkle_table) = rt
        .block_on(setup_scylla_core::<Hash, Hasher>(keyspace_prefix))
        .unwrap();
    let double_id_merkle_nodes = gen_rand_double_id_nodes_fast_rand::<Hash>(node_count);
    let single_id_merkle_nodes = gen_rand_single_id_nodes_fast_rand::<Hash>(node_count);
    let zero_id_merkle_nodes = gen_rand_zero_id_nodes_fast_rand::<Hash>(node_count);
    let context = QBlobWriterContextMetadataHeader::new_at_now(1, 1, 1, 1, 1, 1, 1);
    let fast_serialized_double = QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref(context, &double_id_merkle_nodes);
    let fast_serialized_single = QBlobSingleMerkleNodeBatchDataView::generate_single_merkle_node_batch_blob_data_from_ref(context, QBlobMerkleNodeTreeType::UserContractTree, &single_id_merkle_nodes);
    let fast_serialized_zero = QBlobZeroMerkleNodeBatchDataView::generate_zero_merkle_node_batch_blob_data_from_ref(context, QBlobMerkleNodeTreeType::GlobalUserTree, &zero_id_merkle_nodes);


    let checkpoint_id_test_a = rand::random::<u64>()&0xffff_ffff_ffffu64;
    let mut group = c.benchmark_group(format!("memory_merkle_{}_insert_id_v1", Hash::q_type_name()));
    //group.sample_size(10);
/* 
    group.bench_function(&format!("h256_insert_{}_QMerkleStoreDoubleIdNode_fast_serialized_data_simple", node_count), |b| {
        b.iter(|| {
            rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_from_fast_serialized_data_simple::<Hash>(&store.session, checkpoint_id_test_a, &fast_serialized[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });*/
    group.bench_function(&format!("insert_{}_db_set_double_id_merkle_nodes_from_fast_serialized", node_count), |b| {
        b.iter(|| {
            rt.block_on(store.db_set_double_id_merkle_nodes_from_fast_serialized(&double_merkle_table, checkpoint_id_test_a, &&fast_serialized_double[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });
    group.bench_function(&format!("insert_{}_db_set_single_id_merkle_nodes_from_fast_serialized", node_count), |b| {
        b.iter(|| {
            rt.block_on(store.db_set_single_id_merkle_nodes_from_fast_serialized(&single_merkle_table, checkpoint_id_test_a, &fast_serialized_single[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });
    group.bench_function(&format!("insert_{}_db_set_zero_id_merkle_nodes_from_fast_serialized", node_count), |b| {
        b.iter(|| {
            rt.block_on(store.db_set_zero_id_merkle_nodes_from_fast_serialized(&zero_merkle_table, checkpoint_id_test_a, &fast_serialized_zero[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])).unwrap();
        });
    });
}

pub fn bench_merkle_insertion(c: &mut Criterion) {
    //bench_merkle_double_id_internal::<Hash256, CoreSha256Hasher>(c);
    bench_merkle_double_id_internal::<PGoldilocksHash, PoseidonHasher>(c, 10_000);
    bench_merkle_double_id_internal::<PGoldilocksHash, PoseidonHasher>(c, 25_000);
    bench_merkle_double_id_internal::<PGoldilocksHash, PoseidonHasher>(c, 50_000);
    bench_merkle_double_id_internal::<PGoldilocksHash, PoseidonHasher>(c, 100_000);
    bench_merkle_double_id_internal::<PGoldilocksHash, PoseidonHasher>(c, 1_000_000);
}