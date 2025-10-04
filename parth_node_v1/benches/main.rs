mod large_ops;
mod lops2;
mod nats_bench_v1;
mod object_ops;
mod obj_operations;
mod serialize;
mod nats_bench_v2;
/* *
criterion::criterion_group!(
    benches, 
    large_ops::bench_large_ops, 
    lops2::bench_lops2,
    object_ops::bench_object_ops,
    obj_operations::bench_obj_operations,
    nats_bench_v1::bench_push_messages,
    nats_bench_v1::bench_get_message_loop,
    nats_bench_v1::bench_report_message_completed,
    nats_bench_v1::bench_wait_until_all_complete
);
*/

criterion::criterion_group!(
    benches, 
    /* 
    nats_bench_v1::bench_push_messages,
    nats_bench_v1::bench_end_to_end_processing,
    nats_bench_v1::bench_wait_until_complete,*/
    nats_bench_v2::client_push_throughput,
    nats_bench_v2::client_ack_throughput,
    nats_bench_v2::client_poll_empty_throughput,
    nats_bench_v2::client_concurrent_poll,
    nats_bench_v2::client_wait_completion,
);
criterion::criterion_main!(benches);