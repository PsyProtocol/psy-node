use criterion::{criterion_group, criterion_main};

mod core_merkle_hasher;


criterion_group!(
    benches, 
    core_merkle_hasher::benchmark_core_hashers
);
criterion_main!(benches);