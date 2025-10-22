use criterion::{criterion_group, criterion_main};
mod raw;
mod r2;
mod r1;
mod r3;

criterion_group!(benches, raw::criterion_benchmark_g);
criterion_main!(benches);