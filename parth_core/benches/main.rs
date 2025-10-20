use criterion::{criterion_group, criterion_main};

mod nca_group_gen;
mod merkle_node_serialization;
mod nca_2;
mod nca_3;
criterion_group!(
    benches, 
    //nca_group_gen::benchmark_nca_group_generation,
    //nca_2::benchmark_nca_group_generation,
    nca_3::benchmark_nca_group_generation,
);
criterion_main!(benches);