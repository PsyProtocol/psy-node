mod merkle_double_id;
//mod merkle_double_id_burst;

criterion::criterion_group!(
    benches, 
    /* 
    nats_bench_v1::bench_push_messages,
    nats_bench_v1::bench_end_to_end_processing,
    nats_bench_v1::bench_wait_until_complete,*/
    merkle_double_id::bench_merkle_double_id,
    //merkle_double_id_burst::bench_merkle_double_id_burst,
);
criterion::criterion_main!(benches);
