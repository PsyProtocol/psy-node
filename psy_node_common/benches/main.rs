use criterion::{criterion_group, criterion_main};
mod deser_from_edge;

criterion_group!(benches, deser_from_edge::criterion_benchmark_dser_edge);
criterion_main!(benches);