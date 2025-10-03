use criterion::Criterion;
use parth_core::data::hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_node_v1::{ store::scylla::core::ScyllaCoreStore};

fn bench_lops2(c: &mut Criterion) {
    let realm_id = 1;
    let realm_sub_id = 1;
    let keyspace_prefix = format!("bench_large_ops_v3_{}_{}", realm_id, realm_sub_id);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = rt
        .block_on(ScyllaCoreStore::<Hash256, CoreSha256Hasher>::new(
            realm_id,
            realm_sub_id,
            keyspace_prefix,
            &["127.0.0.1:9042".to_string()],
        ))
        .unwrap();
    let tree_height: u8 = 32;
    let mut group = c.benchmark_group("lops2");
    /*
    group.bench_function("set_10000_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..10000).map(|i| SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: tree_height, index: i },
                value: Hash256([(i & 255) as u8; 32]),
            }).collect();
            rt.block_on(store.set_single_id_merkle_nodes_batch_internal(4, 993, nodes)).unwrap();
        });
    });
    group.bench_function("get_10000_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..10000).map(|i| SimpleMerkleNodeKey { level: tree_height, index: i }).collect();
            let _all = rt.block_on(store.select_many_single_id_merkle_nodes_max_checkpoint_internal(u64::MAX, 992, tree_height, &keys)).unwrap();
        });
    });
    */
    let tree_id = 999;
    for c in 10..50 {
        /* 
        group.bench_function(format!("f_get_10000_single_id_nodes_merkle_simple_{}", c), |b| {
            b.iter(|| {
                let keys: Vec<_> = (0..10000)
                    .map(|i| SimpleMerkleNodeKey {
                        level: tree_height,
                        index: i,
                    })
                    .collect();
                let _all = rt
                    .block_on(store.select_many_single_id_merkle_nodes_max_checkpoint_internal(u64::MAX, tree_id, tree_height, &keys))
                    .unwrap();
            });
        });
        */

        group.bench_function(format!("set_10000_single_id_nodes_merkle_simple_{}", c), |b| {
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
                rt.block_on(store.set_single_id_merkle_nodes_batch_internal(c, tree_id, nodes)).unwrap();
            });
        });
        /* 
        group.bench_function(format!("get_10000_single_id_nodes_merkle_simple_{}", c), |b| {
            b.iter(|| {
                let keys: Vec<_> = (0..10000)
                    .map(|i| SimpleMerkleNodeKey {
                        level: tree_height,
                        index: i,
                    })
                    .collect();
                let _all = rt
                    .block_on(store.select_many_single_id_merkle_nodes_max_checkpoint_internal(u64::MAX, tree_id, tree_height, &keys))
                    .unwrap();
            });
        });*/
    }
    /*
    group.bench_function("set_100000_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..100000).map(|i| SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: tree_height, index: i },
                value: Hash256([(i & 255) as u8; 32]),
            }).collect();
            rt.block_on(store.set_single_id_merkle_nodes_batch_internal(5, 993, nodes)).unwrap();
        });
    });

    group.bench_function("get_100000_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..100000).map(|i| SimpleMerkleNodeKey { level: tree_height, index: i }).collect();
            let _all = rt.block_on(store.select_many_single_id_merkle_nodes_max_checkpoint_internal(u64::MAX, 992, tree_height, &keys)).unwrap();
        });
    });*/

    /*
    group.bench_function("set_1024_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..1024).map(|i| SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: tree_height, index: i },
                value: Hash256([(i & 255) as u8; 32]),
            }).collect();
            rt.block_on(store.set_single_id_merkle_nodes_batch_internal(3, 992, nodes)).unwrap();
        });
    });

    group.bench_function("get_1024_single_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..1024).map(|i| SimpleMerkleNodeKey { level: tree_height, index: i }).collect();
            let _all = rt.block_on(store.select_many_single_id_merkle_nodes_max_checkpoint_internal(u64::MAX, 992, tree_height, &keys)).unwrap();
        });
    });
    group.bench_function("set_10000_double_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..10000).map(|i| SimpleMerkleNode {
                key: SimpleMerkleNodeKey { level: tree_height, index: i },
                value: Hash256([(i & 255) as u8; 32]),
            }).collect();
            rt.block_on(store.set_double_id_merkle_nodes_batch_internal(3, 992, 1337, nodes)).unwrap();
        });
    });

    group.bench_function("get_10000_double_id_nodes_merkle_simple", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..10000).map(|i| SimpleMerkleNodeKey { level: tree_height, index: i }).collect();
            let _all = rt.block_on(store.select_many_double_id_merkle_nodes_max_checkpoint_internal(u64::MAX, 992, 1337, tree_height, &keys)).unwrap();
        });
    });
    group.bench_function("set_10000_single_id_nodes_merkle_kv_blob", |b| {
        b.iter(|| {
            let nodes: Vec<_> = (0..10000).map(|i| QPDPair {
                key: QMerkleStoreBlobKey { table_type: 0x2000, tree_id: 1337, level: tree_height, index: i },
                value: Hash256([(i & 255) as u8; 32]),
            }).collect();
            rt.block_on(store.insert_checkpoint_kv_objs(3, &nodes)).unwrap();
        });
    });

    group.bench_function("get_10000_single_id_nodes_merkle_kv_blob", |b| {
        b.iter(|| {
            let keys: Vec<_> = (0..10000).map(|i| SimpleMerkleNodeKey { level: tree_height, index: i }).collect();
            let _all = rt.block_on(store.select_many_checkpoint_kv_obj_with_checkpoint::<SimpleMerkleNodeKey, Hash256>(u64::MAX, &keys)).unwrap().into_iter().zip(keys.iter()).map(|(v, k)| {
                if v.is_some() {
                    let res = v.unwrap();
                    res
                }else{
                    CoreSha256Hasher::get_zero_hash((tree_height - k.level) as usize)
                }

            }).collect::<Vec<_>>();
        });
    });
    */
}

criterion::criterion_group!(benches, bench_lops2);
criterion::criterion_main!(benches);
