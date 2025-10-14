use criterion::{criterion_group, criterion_main};

mod nca_group_gen;
mod merkle_node_serialization;


criterion_group!(
    benches, 
    merkle_node_serialization::benchmark_group_of_groups_single_id_merkle_node_serialization_qhashout
);
criterion_main!(benches);