#![allow(dead_code)]
use std::time::{Duration, Instant};

use criterion::Criterion;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::{
            hash256::Hash256,
            merkle_store_key::{QMerkleStoreDoubleIdKey, QMerkleStoreDoubleIdNode},
        },
    },
    pgoldilocks::{PGoldilocksHash, PoseidonHasher},
    protocol::core_types::QDBHashBase,
    utils::QPGenRandom,
};
use parth_node_scylla::{core::ScyllaCoreStore, tables::merkle::ScyllaDoubleMerkleNodesPreparedStatements};
use psy_node_core::qblob::{
    data_views::double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView,
    structs::common::{blob_metadata_header::QBlobWriterContextMetadataHeader, tree_node_batch_header::QBLOB_TREE_NODE_BATCH_HEADER_SIZE},
};

async fn setup_scylla_core<Hash: QDBHashBase, Hasher: MerkleZeroHasher<Hash>>(
    keyspace: String,
) -> anyhow::Result<(ScyllaCoreStore<Hash, Hasher>, ScyllaDoubleMerkleNodesPreparedStatements)> {
    let store = ScyllaCoreStore::<Hash, Hasher>::new(1, 1, keyspace, &["127.0.0.1:9042".to_string()]).await?;
    let double_id_merkle_table: ScyllaDoubleMerkleNodesPreparedStatements = store
        .init_std_table::<ScyllaDoubleMerkleNodesPreparedStatements>(
            "double_merkle_id_test",
            QDatabaseTableRoutingKey::new_with_connection_empty_secondary_routing_key(0, 0),
        )
        .await?;

    Ok((store, double_id_merkle_table))
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
fn _gen_rand_double_id_nodes<Hash: QPGenRandom>(count: usize) -> Vec<QMerkleStoreDoubleIdNode<Hash>> {
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let node = QMerkleStoreDoubleIdNode::qp_rand_gen();
        nodes.push(node);
    }
    nodes
}
fn gen_rand_double_id_nodes_fast_rand<Hash: BenchFastRand>(count: usize) -> Vec<QMerkleStoreDoubleIdNode<Hash>> {
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        let node = QMerkleStoreDoubleIdNode {
            key: QMerkleStoreDoubleIdKey::qp_rand_gen(),
            value: Hash::bench_rand_gen_fast(),
        };
        nodes.push(node);
    }
    nodes
}

fn bench_merkle_double_id_internal<Hash: BenchFastRand + QDBHashBase, Hasher: MerkleZeroHasher<Hash>>(c: &mut Criterion, node_count: usize, recover_time_ms: u64) {
    let realm_id = rand::random::<u64>();
    let realm_sub_id = 1;
    let keyspace_prefix = format!("bench_merkle_double_id_v1_{}_{}", realm_id, realm_sub_id);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (store, double_id_merkle_table) = rt.block_on(setup_scylla_core::<Hash, Hasher>(keyspace_prefix)).unwrap();
    let double_id_merkle_nodes_a = gen_rand_double_id_nodes_fast_rand::<Hash>(node_count);

    let context = QBlobWriterContextMetadataHeader::new_at_now(1, 1, 1, 1, 1, 1, 1);
    let fast_serialized_a =
        QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref(context, &double_id_merkle_nodes_a);

    let checkpoint_id = 12345;

    let recovery_pause: Duration = Duration::from_millis(recover_time_ms);
    let mut group = c.benchmark_group(&format!("merkle_double_id_burst_insert_{}", node_count));
    let samples = (10000/recover_time_ms).min(10) as usize;
    group.measurement_time(Duration::from_millis((recover_time_ms*(samples as u64)).min(10000)));
    group.sample_size(samples);

    group.bench_function(&format!("fast_v5"), |b| {
        b.iter_custom(|iters| {
            let mut total_duration = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_g_internal_fast_v5_grok_3::<Hash>(
                    &store.session,
                    checkpoint_id,
                    &fast_serialized_a[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..],
                ))
                .unwrap();
                total_duration += start.elapsed();
                std::thread::sleep(recovery_pause); // Pause here, untimed
            }
            total_duration
        });
    });
    

    group.bench_function(&format!("fast_v7_g"), |b| {
        b.iter_custom(|iters| {
            let mut total_duration = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                rt.block_on(double_id_merkle_table.set_double_id_merkle_nodes_batch_fast_v7_g::<Hash>(
                    &store.session,
                    checkpoint_id,
                    &fast_serialized_a[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..],
                ))
                .unwrap();
                total_duration += start.elapsed();
                std::thread::sleep(recovery_pause); // Pause here, untimed
            }
            total_duration
        });
    });
    group.finish();
}

pub fn bench_merkle_double_id_burst(c: &mut Criterion) {
    //bench_merkle_double_id_internal::<PGoldilocksHash, PoseidonHasher>(c, 1_000_000, 6000);

    bench_merkle_double_id_internal::<PGoldilocksHash, PoseidonHasher>(c, 1_000_000, 500);
}
