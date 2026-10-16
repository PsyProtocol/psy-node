use super::*;

fn observer(capacity: usize) -> (Observer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let obs = Observer::start(
        Config {
            directory: dir.path().into(),
            capacity,
            event_capacity: 4096,
            file_bytes: 1024 * 1024,
            files: 2,
            slow_ms: 10,
        },
        "user",
        "test",
    )
    .unwrap();
    (obs, dir)
}

#[tokio::test]
async fn bounded_tracking_and_id_sanitization() {
    let (o, _dir) = observer(2);
    assert_eq!(o.request_id(Some("ABCDEF0123456789abcdef0123456789")), "abcdef0123456789abcdef0123456789");
    assert!(!o.request_id(Some("private-key\nINJECTED")).contains("private-key"));
    let a = o.activity("rpc", "one", "role", Stage::Rpc);
    let b = o.activity("rpc", "two", "role", Stage::Rpc);
    let c = o.activity("rpc", "three", "role", Stage::Rpc);
    assert_eq!(o.snapshot()["inflight"], 2);
    assert_eq!(o.snapshot()["tracker_overflow"], 1);
    drop(a);
    drop(b);
    drop(c);
    assert_eq!(o.snapshot()["inflight"], 0);
    let _d = o.activity("rpc", "four", "role", Stage::Rpc);
    assert_eq!(o.snapshot()["inflight"], 1);
    o.stop();
}

#[tokio::test]
async fn nested_stages_restore_and_build_has_owner_key() {
    let (o, _dir) = observer(10);
    let mut request = o.activity("rpc", "r", "cold", Stage::Rpc);
    request
        .context()
        .scope(async {
            let key = cache_key(1, 2);
            let _wait = stage_key(Stage::CacheWait, Some(key));
            build(key, || {
                let s = o.snapshot();
                let active = s["active"].as_array().unwrap();
                assert!(active
                    .iter()
                    .any(|v| v["kind"] == "build" && v["cache_key"] == key && v["parent_id"].is_u64()));
                assert!(active.iter().any(|v| v["kind"] == "rpc" && v["stage"] == "cache_wait"));
            });
            assert_eq!(o.snapshot()["inflight"], 1);
        })
        .await;
    assert_eq!(o.snapshot()["active"][0]["stage"], "rpc");
    request.finish("success");
    drop(request);
    assert_eq!(o.snapshot()["inflight"], 0);
    o.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_single_flight_cache_exposes_builder_and_waiter() {
    let (o, _dir) = observer(16);
    let cache = Arc::new(quick_cache::sync::Cache::<u64, u32>::new(8));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let a = o.activity("rpc", "owner", "cold", Stage::Rpc);
    let c = cache.clone();
    let first = a
        .context()
        .scope(async {
            spawn_blocking(move || {
                let _wait = stage_key(Stage::CacheWait, Some(19));
                c.get_or_insert_with(&19, || {
                    Ok::<_, std::convert::Infallible>(build(19, || {
                        started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        7
                    }))
                })
                .unwrap()
            })
        })
        .await;
    started_rx.await.unwrap();
    let b = o.activity("rpc", "waiter", "cold", Stage::Rpc);
    let c = cache.clone();
    let second = b
        .context()
        .scope(async {
            spawn_blocking(move || {
                let _wait = stage_key(Stage::CacheWait, Some(19));
                c.get_or_insert_with(&19, || Ok::<_, std::convert::Infallible>(build(19, || 99))).unwrap()
            })
        })
        .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = o.snapshot();
            let entries = snapshot["active"].as_array().unwrap();
            if entries.iter().any(|v| v["request_id"] == "waiter" && v["stage"] == "cache_wait") {
                assert!(entries
                    .iter()
                    .any(|v| v["request_id"] == "owner" && v["kind"] == "build" && v["cache_key"] == 19));
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // A different cache key remains available; do not mislabel single-flight as
    // global lock.
    assert_eq!(cache.get_or_insert_with(&20, || Ok::<_, std::convert::Infallible>(8)).unwrap(), 8);
    release_tx.send(()).unwrap();
    assert_eq!(first.await.unwrap(), 7);
    assert_eq!(second.await.unwrap(), 7);
    drop(a);
    drop(b);
    assert_eq!(o.snapshot()["inflight"], 0);
    o.stop();
}

#[test]
fn executor_queue_is_visible_before_job_starts() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (o, _dir) = observer(8);
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.await.unwrap();
        let request = o.activity("rpc", "r", "queued", Stage::Rpc);
        let job = request.context().scope(async { spawn_blocking(|| 42) }).await;
        let snapshot = o.snapshot();
        assert!(snapshot["active"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["kind"] == "job" && v["stage"] == "executor_queue"));
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        assert_eq!(job.await.unwrap(), 42);
        drop(request);
        assert_eq!(o.snapshot()["inflight"], 0);
        o.stop();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_rpc_keeps_running_job_visible() {
    let (o, _dir) = observer(10);
    let request = o.activity("rpc", "r", "proof", Stage::Rpc);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        let context = request.context();
        let _request = request;
        context
            .scope(async move {
                spawn_blocking(move || {
                    let _ = started_tx.send(());
                    release_rx.recv().unwrap();
                })
                .await
                .unwrap();
            })
            .await;
    });
    started_rx.await.unwrap();
    task.abort();
    let _ = task.await;
    let snapshot = o.snapshot();
    assert_eq!(snapshot["inflight"], 1);
    assert_eq!(snapshot["active"][0]["kind"], "job");
    assert_eq!(snapshot["active"][0]["rpc_waiter_gone"], true);
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while o.snapshot()["inflight"] != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    o.stop();
}

#[tokio::test]
async fn panic_cleans_build_and_job_and_restores_context() {
    let (o, _dir) = observer(10);
    let request = o.activity("rpc", "r", "panic", Stage::Rpc);
    request
        .context()
        .scope(async {
            let result = spawn_blocking(|| build(77, || panic!("test panic"))).await;
            assert!(result.unwrap_err().is_panic());
            assert_eq!(o.snapshot()["inflight"], 1);
            assert!(spawn_blocking(|| current().0.is_some()).await.unwrap());
        })
        .await;
    drop(request);
    assert_eq!(o.snapshot()["inflight"], 0);
    o.stop();
}

#[tokio::test]
async fn blocked_runtime_is_visible_without_application_locks() {
    let (o, _dir) = observer(10);
    tokio::time::sleep(Duration::from_millis(10)).await; // initial heartbeat
    let other = o.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1100));
        let s = other.snapshot();
        assert_eq!(s["heartbeat_seen"], true);
        assert!(s["heartbeat_age_ms"].as_u64().unwrap() >= 1000);
    });
    // Deliberate local fault injection on a current-thread runtime.
    std::thread::sleep(Duration::from_millis(1300));
    handle.join().unwrap();
    o.stop();
}

#[tokio::test]
async fn full_writer_queue_never_blocks_requests() {
    let (mut o, _dir) = observer(2);
    // No await: the current-thread runtime has not polled the heartbeat. Weak
    // background references do not prevent taking ownership of Inner for this
    // stalled-writer fixture.
    let mut inner = Arc::try_unwrap(o.0.take().unwrap()).ok().unwrap();
    let (tx, _rx) = sync_channel(1);
    inner.tx = tx;
    let o = Observer(Some(Arc::new(inner)));
    for _ in 0..100 {
        let mut request = o.activity("rpc", "r", "role", Stage::Rpc);
        request.finish("rpc_success");
    }
    assert_eq!(o.snapshot()["inflight"], 0);
    assert!(o.snapshot()["dropped_events"].as_u64().unwrap() >= 199);
    let request = o.activity("rpc", "r", "role", Stage::Rpc);
    request.context.0.as_ref().unwrap().state.version.store(1, SeqCst);
    assert_eq!(o.snapshot()["inflight"], 0);
    assert!(o.snapshot()["snapshot_skipped"].as_u64().unwrap() > 0);
    request.context.0.as_ref().unwrap().state.version.store(2, SeqCst);
    drop(request);
    o.stop();
}

async fn server(o: Observer, observe: bool) -> (String, jsonrpsee::server::ServerHandle) {
    use jsonrpsee::{
        server::{middleware::rpc::RpcServiceBuilder, ServerBuilder},
        RpcModule,
    };
    let mut module = RpcModule::new(());
    module.register_method("role", |_, _, _| "user").unwrap();
    module
        .register_async_method("work", |_, _, _| async {
            let _s = stage(Stage::Register);
            spawn_blocking(|| build(123, || 42u32)).await.unwrap()
        })
        .unwrap();
    module
        .register_method("error", |_, _, _| -> Result<(), jsonrpsee::types::ErrorObjectOwned> {
            Err(jsonrpsee::types::ErrorObjectOwned::owned(-32000, "SECRET_ERROR", Some("SECRET_DATA")))
        })
        .unwrap();
    let builder = ServerBuilder::default().set_config(jsonrpsee::server::ServerConfig::builder().max_response_body_size(1024).build());
    if observe {
        let rpc_o = o.clone();
        let server = builder
            .set_http_middleware(tower::ServiceBuilder::new().layer(HttpLayer(o)))
            .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(move |s| RpcObserver::new(s, rpc_o.clone(), 1024)))
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (url, server.start(module))
    } else {
        let server = builder.build("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", server.local_addr().unwrap());
        (url, server.start(module))
    }
}

#[tokio::test]
async fn real_http_batch_outputs_match_framework_and_no_payload_leaks() {
    let (o, dir) = observer(32);
    let (url, handle) = server(o.clone(), true).await;
    let (plain, plain_handle) = server(Observer::disabled(), false).await;
    let client = reqwest::Client::new();
    let bodies = [
        json!({"jsonrpc":"2.0","id":"SECRET_ID","method":"work","params":["SECRET_INPUT"]}),
        json!([{ "jsonrpc":"2.0","id":1,"method":"role" },{"jsonrpc":"2.0","id":2,"method":"error"},
            {"jsonrpc":"2.0","id":3,"method":"missing"},{"invalid":true},{"jsonrpc":"2.0","method":"role"}]),
        json!([]),
        json!([{ "jsonrpc":"2.0","method":"role" }]),
        json!((0..100).map(|id| json!({"jsonrpc":"2.0","id":id,"method":"role"})).collect::<Vec<_>>()),
    ];
    for body in bodies {
        let a = client
            .post(&url)
            .header("x-request-id", "abcdef0123456789abcdef0123456789")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(a.headers()["x-request-id"], "abcdef0123456789abcdef0123456789");
        let b = client.post(&plain).json(&body).send().await.unwrap();
        assert_eq!(a.status(), b.status());
        assert_eq!(a.bytes().await.unwrap(), b.bytes().await.unwrap());
    }
    handle.stop().unwrap();
    plain_handle.stop().unwrap();
    handle.stopped().await;
    plain_handle.stopped().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let logs = std::fs::read_to_string(dir.path().join("events.0.jsonl")).unwrap();
    assert!(logs.contains("abcdef0123456789abcdef0123456789"));
    assert!(logs.contains("executor_started"));
    for secret in ["SECRET_INPUT", "SECRET_ID", "SECRET_ERROR", "SECRET_DATA"] {
        assert!(!logs.contains(secret));
    }
    assert_eq!(o.snapshot()["inflight"], 0);
    o.stop();
}

#[tokio::test]
async fn watchdog_writes_before_blocked_runtime_recovers() {
    let (o, dir) = observer(16);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let a = o.activity("rpc", "blocked-runtime", "cold", Stage::Rpc);
    a.context()
        .scope(async {
            let _build = stage(Stage::CircuitBuild);
            // Not Tokio sleep: intentionally prevent this current-thread runtime
            // from polling either the heartbeat or the request completion.
            std::thread::sleep(Duration::from_millis(5600));
            let text = std::fs::read_to_string(dir.path().join("events.0.jsonl")).unwrap();
            let snapshots: Vec<Value> = text
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .filter(|v: &Value| v["event"] == "watchdog")
                .collect();
            assert!(snapshots.iter().any(|v| v["heartbeat_age_ms"].as_u64().unwrap() >= 4000
                && v["active"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a["request_id"] == "blocked-runtime" && a["stage"] == "circuit_build")));
        })
        .await;
    drop(a);
    o.stop();
}

// Diagnostic middleware microbenchmark only. This is NOT a proof-performance
// replay, and debug timings must never be advertised as production overhead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn http_overhead_probe() {
    let client = reqwest::Client::new();
    let paced = std::env::var_os("PSY_OBSERVE_BENCH_PACED").is_some();
    let per_worker = if paced { 50 } else { 250 };
    for enabled in [false, true, true, false] {
        let (o, dir) = if enabled {
            observer(512)
        } else {
            (Observer::disabled(), tempfile::tempdir().unwrap())
        };
        let (url, handle) = server(o.clone(), true).await;
        let start = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let client = client.clone();
            let url = url.clone();
            tasks.spawn(async move {
                for id in 0..per_worker {
                    let request_start = Instant::now();
                    let v: Value = client
                        .post(&url)
                        .json(&json!({"jsonrpc":"2.0","id":id,"method":"work"}))
                        .send()
                        .await
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                    assert_eq!(v["result"], 42);
                    if paced {
                        tokio::time::sleep(Duration::from_millis(200).saturating_sub(request_start.elapsed())).await;
                    }
                }
            });
        }
        while let Some(r) = tasks.join_next().await {
            r.unwrap();
        }
        let elapsed = start.elapsed();
        handle.stop().unwrap();
        handle.stopped().await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let bytes: u64 = std::fs::read_dir(dir.path()).unwrap().map(|p| p.unwrap().metadata().unwrap().len()).sum();
        eprintln!(
            "OVERHEAD {}",
            json!({"enabled":enabled,"requests":8*per_worker,"concurrency":8,"paced":paced,
            "wall_ms":elapsed.as_secs_f64()*1000.0,"retained_bytes":bytes,"snapshot":o.snapshot()})
        );
        o.stop();
    }
}

#[cfg(feature = "plonky2-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prover_hook_exposes_wait_and_restores_stage_on_panic() {
    use plonky2::util::observation::{enter, Phase};
    let (o, _dir) = observer(16);
    let rpc = o.activity("rpc", "gpu-fixture", "work", Stage::Rpc);
    let captured = o.clone();
    rpc.context()
        .scope(async {
            spawn_blocking(move || {
                let _wait = enter(Phase::GpuLaneWait);
                assert!(captured.snapshot()["active"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["kind"] == "job" && v["stage"] == "gpu_lane_wait" && v["request_id"] == "gpu-fixture"));
                let caught = std::panic::catch_unwind(|| {
                    let _device = enter(Phase::GpuDevice);
                    panic!("local observation fixture");
                });
                assert!(caught.is_err());
                assert!(captured.snapshot()["active"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v["kind"] == "job" && v["stage"] == "gpu_lane_wait"));
            })
            .await
            .unwrap();
        })
        .await;
    drop(rpc);
    assert_eq!(o.snapshot()["inflight"], 0);
    o.stop();
}

/// Real small-circuit proof compatibility gate, not a production fixture
/// replay. Run in its own process with deterministic random/PoW switches, GPU
/// disabled.
#[cfg(feature = "plonky2-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn real_proof_observation_equivalence() {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    assert_eq!(std::env::var("PLONKY2_DETERMINISTIC_RANDOM").as_deref(), Ok("1"));
    assert_eq!(std::env::var("PLONKY2_POW_DETERMINISTIC").as_deref(), Ok("1"));
    assert_eq!(std::env::var("PLONKY2_GPU").as_deref(), Ok("0"));
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
    let x = builder.add_virtual_target();
    let square = builder.mul(x, x);
    builder.register_public_input(square);
    let data = Arc::new(builder.build::<PoseidonGoldilocksConfig>());
    let mut witness = PartialWitness::new();
    witness.set_target(x, GoldilocksField::from_canonical_u64(7)).unwrap();
    let d = data.clone();
    let w = witness.clone();
    let reference = tokio::task::spawn_blocking(move || d.prove(w).unwrap()).await.unwrap();
    data.verify(reference.clone()).unwrap();
    let (o, dir) = observer(16);
    let request = o.activity("rpc", "real-proof", "fixture", Stage::Rpc);
    let d = data.clone();
    let actual = request
        .context()
        .scope(async { spawn_blocking(move || d.prove(witness).unwrap()).await.unwrap() })
        .await;
    data.verify(actual.clone()).unwrap();
    assert_eq!(reference.to_bytes(), actual.to_bytes());
    drop(request);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let log = std::fs::read_to_string(dir.path().join("events.0.jsonl")).unwrap();
    for phase in ["witness", "wires_commit", "quotient", "fri"] {
        assert!(
            log.lines().any(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                v["event"] == "stage_begin" && v["detail"]["stage"] == phase && v["request_id"] == "real-proof"
            }),
            "missing {phase}"
        );
    }
    assert_eq!(o.snapshot()["inflight"], 0);
    o.stop();
}

#[cfg(feature = "plonky2-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn real_large_proof_slot_wait_is_visible() {
    assert_eq!(std::env::var("PLONKY2_LARGE_PROOF_SLOTS").as_deref(), Ok("1"));
    let (o, _dir) = observer(16);
    let owner = o.activity("rpc", "slot-owner", "fixture", Stage::Rpc);
    let waiter = o.activity("rpc", "slot-waiter", "fixture", Stage::Rpc);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let first = owner
        .context()
        .scope(async {
            spawn_blocking(move || {
                let _slot = plonky2::util::proof_gate::acquire(20);
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        })
        .await;
    started_rx.await.unwrap();
    let second = waiter
        .context()
        .scope(async {
            spawn_blocking(|| {
                let _slot = plonky2::util::proof_gate::acquire(20);
            })
        })
        .await;
    let observed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let s = o.snapshot();
            let a = s["active"].as_array().unwrap();
            if a.iter().any(|v| v["request_id"] == "slot-waiter" && v["stage"] == "large_proof_wait") {
                assert!(a.iter().any(|v| v["request_id"] == "slot-owner" && v["stage"] == "large_proof_held"));
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    release_tx.send(()).unwrap();
    first.await.unwrap();
    second.await.unwrap();
    observed.unwrap();
    drop(owner);
    drop(waiter);
    assert_eq!(o.snapshot()["inflight"], 0);
    o.stop();
}
