use criterion::{criterion_group, criterion_main};

mod serialize_common;



criterion_group!(
    benches, 
    //serialize_common::benckmark_serialize_round_trip_contract_function,
    serialize_common::benckmark_serialization
);
criterion_main!(benches);