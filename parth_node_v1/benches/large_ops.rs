use criterion::Criterion;
use parth_core::{crypto::hash::sha256::CoreSha256Hasher, data::hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}};
use parth_node_v1::{ store::scylla::core::ScyllaCoreStore};

fn bench_large_ops(c: &mut Criterion) {
    let realm_id = 1;
    let realm_sub_id = 1;
    let keyspace_prefix = format!("bench_large_ops_v2_{}_{}", realm_id, realm_sub_id);


            let rt = tokio::runtime::Runtime::new().unwrap();
            let store = rt.block_on(ScyllaCoreStore::<Hash256, CoreSha256Hasher>::new(realm_id, realm_sub_id, keyspace_prefix, &["127.0.0.1:9042".to_string()])).unwrap();
    let tree_height: u8 = 32;
    let mut group = c.benchmark_group("large_ops");
    group.bench_function("set_10000_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..10000).map(|i| SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: tree_height, index: i },
                value: Hash256([(i & 255) as u8; 32]),
            }).collect();
            rt.block_on(store.set_single_id_merkle_nodes_batch_internal(3, 992, nodes)).unwrap();
        });
    });

    group.bench_function("get_10000_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..10000).map(|i| SimpleMerkleNodeKey { level: tree_height, index: i }).collect();
            rt.block_on(store.select_many_single_id_merkle_nodes_max_checkpoint_internal(u64::MAX, 992, tree_height, &keys)).unwrap();
        });
    });
}

criterion::criterion_group!(benches, bench_large_ops);
criterion::criterion_main!(benches);