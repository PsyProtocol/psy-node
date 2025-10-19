use criterion::{criterion_group, criterion_main};

mod core_merkle_hasher;
mod leaves_v2;

criterion_group!(
    benches, 
    leaves_v2::benchmark_merkle_leaf_hashers
);
criterion_main!(benches);