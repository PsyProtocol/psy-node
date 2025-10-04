use criterion::Criterion;
use parth_core::
    data::{
        db::table::QDatabaseTableRoutingKey,
        hash::{
            hash256::Hash256,
            merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        },
    }
;
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_v1::store::scylla::{
    core::ScyllaCoreStore,
    tables::merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements},
};
async fn setup_store(
    realm_id: u64,
    realm_sub_id: u64,
    keyspace_prefix: String,
) -> (
    ScyllaCoreStore<Hash256, CoreSha256Hasher>,
    ScyllaMerkleNodesPreparedStatements,
    ScyllaDoubleMerkleNodesPreparedStatements,
) {
    let store = ScyllaCoreStore::<Hash256, CoreSha256Hasher>::new(realm_id, realm_sub_id, keyspace_prefix, &["127.0.0.1:9042".to_string()])
        .await
        .unwrap();
    let single_merkle = store
        .init_single_merkle_table(
            "bench_single_merkle_nodes",
            QDatabaseTableRoutingKey::new_with_empty_secondary_routing_key(0),
        )
        .await
        .unwrap();
    let double_merkle = store
        .init_double_merkle_table(
            "bench_double_merkle_nodes",
            QDatabaseTableRoutingKey::new_with_empty_secondary_routing_key(1),
        )
        .await
        .unwrap();
    (store, single_merkle, double_merkle)
}
pub fn bench_large_ops(c: &mut Criterion) {
    let realm_id = 1;
    let realm_sub_id = 1;
    let keyspace_prefix = format!("bench_large_ops_v2_{}_{}", realm_id, realm_sub_id);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (store, single_merkle_table, double_merkle_table) = rt.block_on(setup_store(realm_id, realm_sub_id, keyspace_prefix));

    let tree_height: u8 = 32;
    let mut group = c.benchmark_group("large_ops");
    group.bench_function("set_10000_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..10000)
                .map(|i| SimpleMerkleNode {
                    key: SimpleMerkleNodeKey {
                        level: tree_height,
                        index: i,
                    },
                    value: Hash256([(i & 255) as u8; 32]),
                })
                .collect();
            rt.block_on(store.set_single_id_merkle_nodes_batch_internal(&single_merkle_table, 3, 992, nodes)).unwrap();
        });
    });

    group.bench_function("get_10000_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..10000)
                .map(|i| SimpleMerkleNodeKey {
                    level: tree_height,
                    index: i,
                })
                .collect();
            let _all = rt
                .block_on(store.select_many_single_id_merkle_nodes_max_checkpoint_internal(&single_merkle_table, u64::MAX, 992, tree_height, &keys))
                .unwrap();
        });
    });
    group.bench_function("set_10000_double_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..10000)
                .map(|i| SimpleMerkleNode {
                    key: SimpleMerkleNodeKey {
                        level: tree_height,
                        index: i,
                    },
                    value: Hash256([(i & 255) as u8; 32]),
                })
                .collect();
            rt.block_on(store.set_double_id_merkle_nodes_batch_internal(&double_merkle_table, 3, 992, 1337, nodes)).unwrap();
        });
    });

    group.bench_function("get_10000_double_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..10000)
                .map(|i| SimpleMerkleNodeKey {
                    level: tree_height,
                    index: i,
                })
                .collect();
            let _all = rt
                .block_on(store.select_many_double_id_merkle_nodes_max_checkpoint_internal(&double_merkle_table, u64::MAX, 992, 1337, tree_height, &keys))
                .unwrap();
        });
    });
}
