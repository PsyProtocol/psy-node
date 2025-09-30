use criterion::Criterion;
use parth_core::{crypto::hash::sha256::CoreSha256Hasher, data::hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}};
use parth_node_v1::{data::hash::QPMerkleTreeStore, scylla::merkle_store::ScyllaMerkleTreeStore};

fn bench_large_ops(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = rt.block_on(ScyllaMerkleTreeStore::<Hash256, CoreSha256Hasher>::new(vec!["127.0.0.1:9042".to_string()])).unwrap();

    let mut group = c.benchmark_group("large_ops");
    group.bench_function("set_10000_nodes", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..10000).map(|i| SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: 0, index: i },
                value: Hash256([(i & 255) as u8; 32]),
            }).collect();
            rt.block_on(store.set_tree_nodes(3, 992, nodes)).unwrap();
        });
    });

    group.bench_function("get_10000_nodes", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..10000).map(|i| SimpleMerkleNodeKey { level: 0, index: i }).collect();
            rt.block_on(store.get_tree_nodes(u64::MAX, 992, &keys)).unwrap();
        });
    });
}

criterion::criterion_group!(benches, bench_large_ops);
criterion::criterion_main!(benches);