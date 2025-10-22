// src/store/generic_tests.rs

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use async_trait::async_trait;
use parth_core::{
    data::{
        queue::queue_key::{PCoreQueueItemBase, QPStandardUniqueIdQueueKey},
        serializable::{QPDPair, QPDSerializable},
    },
    utils::QPGenRandom,
    QCoreProcCheckpointUniqueId,
};
use psy_core::job::job_id::QProvingJobDataID;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    queue::ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
    store::traits::{
        proof_store::{QParthProofStoreReader, QParthProofStoreWriter},
        temp_db::{
            QTempDatabaseRawCounterReaderBase, QTempDatabaseRawCounterWriterBase, QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase,
            QTempDatabaseRawStoreWriter,
        },
    },
};

//================================================================================
// Test Data Structures
//================================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestProof {
    pub data: Vec<u8>,
    pub value: u64,
}

impl QPDSerializable for TestProof {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
    fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct TestQueueItem {
    pub job_id: u64,
    pub payload: String,
}

impl PCoreQueueItemBase for TestQueueItem {
    fn is_queue_item(_data: &[u8]) -> bool {
        true
    }
    fn decode_queue_item_ref(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(Into::into)
    }
    fn encode_queue_item_vec(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }
    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.job_id.to_le_bytes().to_vec()
    }
    fn get_size_hint() -> usize {
        0
    }
    fn has_fixed_size() -> bool {
        false
    }
}

pub type TestQueueKey = QPStandardUniqueIdQueueKey<101, TestQueueItem>;

//================================================================================
// Store Factory Trait and Implementations
//================================================================================

/// Abstracts the creation of a clean store instance for each test.
#[async_trait]
pub trait StoreFactory: Send + Sync {
    type Store: Clone + Send + Sync + 'static;
    async fn new_store(&self) -> Self::Store;
    fn name(&self) -> &'static str;
}

//================================================================================
// Generic Test Functions
//================================================================================

/// Tests for `QTempDatabaseRawKVReaderBase` and `QTempDatabaseRawKVWriterBase`.
pub async fn test_raw_kv_store<S>(store: S)
where
    S: QTempDatabaseRawKVReaderBase + QTempDatabaseRawKVWriterBase,
{
    let key1 = b"key1";
    let val1 = b"value1";
    let key2 = b"key2";
    let val2 = b"value2";
    let key3 = b"key3"; // non-existent key

    // Test put and get
    store.qtdb_raw_kv_put_value(key1, val1).await.unwrap();
    let retrieved = store.qtdb_raw_kv_get_value(key1).await.unwrap();
    assert_eq!(retrieved, Some(val1.to_vec()));

    // Test get non-existent
    assert_eq!(store.qtdb_raw_kv_get_value(key3).await.unwrap(), None);

    // Test contains
    assert!(store.qtdb_raw_kv_contains_key(key1).await.unwrap());
    assert!(!store.qtdb_raw_kv_contains_key(key3).await.unwrap());

    // Test delete
    store.qtdb_raw_kv_delete_key(key1).await.unwrap();
    assert!(!store.qtdb_raw_kv_contains_key(key1).await.unwrap());
    assert_eq!(store.qtdb_raw_kv_get_value(key1).await.unwrap(), None);

    // Test put_many and get_many
    let entries = vec![
        QPDPair {
            key: key1.to_vec(),
            value: val1.to_vec(),
        },
        QPDPair {
            key: key2.to_vec(),
            value: val2.to_vec(),
        },
    ];
    store.qtdb_raw_kv_put_many_values(&entries).await.unwrap();

    let keys_to_get = vec![key1.to_vec(), key3.to_vec(), key2.to_vec()];
    let values = store.qtdb_raw_kv_get_many_values_vec(&keys_to_get).await.unwrap();
    assert_eq!(values, vec![Some(val1.to_vec()), None, Some(val2.to_vec())]);
}

/// Tests for `QTempDatabaseRawCounterReaderBase` and
/// `QTempDatabaseRawCounterWriterBase`.
pub async fn test_raw_counter_store<S>(store: S)
where
    S: QTempDatabaseRawCounterReaderBase + QTempDatabaseRawCounterWriterBase,
{
    let counter_key = b"my_counter";

    // Get initial value
    assert_eq!(store.qtdb_raw_counter_get_value(counter_key).await.unwrap(), 0);

    // Increment
    let new_val = store.qtdb_raw_counter_increment_by(counter_key, 5).await.unwrap();
    assert_eq!(new_val, 5);
    assert_eq!(store.qtdb_raw_counter_get_value(counter_key).await.unwrap(), 5);

    // Decrement
    let new_val = store.qtdb_raw_counter_increment_by(counter_key, -2).await.unwrap();
    assert_eq!(new_val, 3);
    assert_eq!(store.qtdb_raw_counter_get_value(counter_key).await.unwrap(), 3);

    // Set
    store.qtdb_raw_counter_set_value(counter_key, 100).await.unwrap();
    assert_eq!(store.qtdb_raw_counter_get_value(counter_key).await.unwrap(), 100);
}

/// Tests for `QParthProofStoreReader` and `QParthProofStoreWriter`.
pub async fn test_proof_store<S>(store: S)
where
    S: QParthProofStoreReader + QParthProofStoreWriter + Send + 'static,
{
    let job_id1 = QProvingJobDataID::qp_rand_gen();
    let proof1 = TestProof {
        data: vec![1, 2, 3],
        value: 99,
    };
    let job_id2 = QProvingJobDataID::qp_rand_gen();

    // Test contains on non-existent
    assert!(!store.contains_proof_for_job_id(job_id1).await.unwrap());

    // Test put and get (object)
    store.put_proof_for_job_id(job_id1, &proof1).await.unwrap();
    assert!(store.contains_proof_for_job_id(job_id1).await.unwrap());
    let retrieved: TestProof = store.get_proof_by_job_id(job_id1).await.unwrap().unwrap();
    assert_eq!(retrieved, proof1);

    // Test get non-existent
    let retrieved_none: Option<TestProof> = store.get_proof_by_job_id(job_id2).await.unwrap();
    assert!(retrieved_none.is_none());

    // Test put and get (bytes)
    let proof_bytes = proof1.to_bytes().unwrap();
    store.put_proof_bytes_for_job_id(job_id1, &proof_bytes).await.unwrap();
    let retrieved_bytes = store.get_proof_bytes_by_job_id(job_id1).await.unwrap().unwrap();
    assert_eq!(retrieved_bytes, proof_bytes);
}

/// Tests for `QStandardEphemeralQueuePublisher` and
/// `QStandardEphemeralQueueSubscriber`.
pub async fn test_ephemeral_queue<S: Clone>(store: S)
where
    S: QStandardEphemeralQueuePublisher + QStandardEphemeralQueueSubscriber + Send + 'static,
{
    let queue_key = TestQueueKey {
        realm_id: 1,
        realm_sub_id: 2,
        unique_id: 3,
        task_group: 4,
        queue_type: parth_core::data::queue::queue_key::QPBaseQueueType::StandardEphemeral,
        _phantom_queue_item: std::marker::PhantomData,
    };
    let (realm_id, realm_sub_id, unique_id, task_group) = (1, 2, 3, 4);

    // Test consume on empty queue
    let item: Option<TestQueueItem> = store
        .consume_ephemeral_queue_item_or_none(&queue_key, realm_id, realm_sub_id, unique_id, task_group)
        .await
        .unwrap();
    assert!(item.is_none());

    // Test publish one, consume one
    let item1 = TestQueueItem {
        job_id: 1,
        payload: "one".into(),
    };
    store
        .publish_ephemeral_queue_item_owned(&queue_key, realm_id, realm_sub_id, unique_id, task_group, item1.clone())
        .await
        .unwrap();
    let consumed = store
        .consume_ephemeral_queue_item_or_none(&queue_key, realm_id, realm_sub_id, unique_id, task_group)
        .await
        .unwrap(); // here:

    /*
    
    
---- test_redis_store_implementation stdout ----
--- Running tests for StandardRedisStore ---
  -> Testing KV Store...
  -> Testing Counter Store...
  -> Testing Proof Store...
  -> Testing Ephemeral Queue...

thread 'test_redis_store_implementation' panicked at /Users/carter/Documents/projects/psyv3/psy-v3/psy_node_core/src/test_helpers/basic_1.rs:233:10:
called `Result::unwrap()` on an `Err` value: Response was of incompatible type - TypeError: "Could not convert from string." (response was bulk-string('"\u{1}\0\0\0\0\0\0\0\u{3}\0\0\0\0\0\0\0one"'))

Stack backtrace:
   0: std::backtrace_rs::backtrace::libunwind::trace
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/../../backtrace/src/backtrace/libunwind.rs:117:9
   1: std::backtrace_rs::backtrace::trace_unsynchronized
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/../../backtrace/src/backtrace/mod.rs:66:14
   2: std::backtrace::Backtrace::create
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/backtrace.rs:331:13
   3: anyhow::error::<impl core::convert::From<E> for anyhow::Error>::from
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/anyhow-1.0.100/src/backtrace.rs:27:14
   4: <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
             at /Users/carter/.rustup/toolchains/nightly-2025-06-15-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/result.rs:2079:27
   5: <psy_node_redis::store::core::StandardRedisStore as psy_node_core::queue::ephemeral::QStandardEphemeralQueueSubscriber>::consume_ephemeral_queue_item_or_none::{{closure}}
             at ./src/store/core.rs:539:37
   6: <core::pin::Pin<P> as core::future::future::Future>::poll
             at /Users/carter/.rustup/toolchains/nightly-2025-06-15-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/future/future.rs:124:9
   7: psy_node_core::test_helpers::basic_1::test_ephemeral_queue::{{closure}}
             at /Users/carter/Documents/projects/psyv3/psy-v3/psy_node_core/src/test_helpers/basic_1.rs:232:10
   8: psy_node_core::test_helpers::basic_1::run_all_tests_for_factory::{{closure}}
             at /Users/carter/Documents/projects/psyv3/psy-v3/psy_node_core/src/test_helpers/basic_1.rs:340:39
   9: temp_v1::test_redis_store_implementation::{{closure}}
             at ./tests/temp_v1.rs:43:40
  10: <core::pin::Pin<P> as core::future::future::Future>::poll
             at /Users/carter/.rustup/toolchains/nightly-2025-06-15-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/future/future.rs:124:9
  11: <core::pin::Pin<P> as core::future::future::Future>::poll
             at /Users/carter/.rustup/toolchains/nightly-2025-06-15-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/future/future.rs:124:9
  12: tokio::runtime::scheduler::current_thread::CoreGuard::block_on::{{closure}}::{{closure}}::{{closure}}
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:742:70
  13: tokio::task::coop::with_budget
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/task/coop/mod.rs:167:5
  14: tokio::task::coop::budget
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/task/coop/mod.rs:133:5
  15: tokio::runtime::scheduler::current_thread::CoreGuard::block_on::{{closure}}::{{closure}}
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:742:25
  16: tokio::runtime::scheduler::current_thread::Context::enter
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:432:19
  17: tokio::runtime::scheduler::current_thread::CoreGuard::block_on::{{closure}}
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:741:44
  18: tokio::runtime::scheduler::current_thread::CoreGuard::enter::{{closure}}
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:829:68
  19: tokio::runtime::context::scoped::Scoped<T>::set
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/context/scoped.rs:40:9
  20: tokio::runtime::context::set_scheduler::{{closure}}
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/context.rs:176:38
  21: std::thread::local::LocalKey<T>::try_with
             at /Users/carter/.rustup/toolchains/nightly-2025-06-15-aarch64-apple-darwin/lib/rustlib/src/rust/library/std/src/thread/local.rs:315:12
  22: std::thread::local::LocalKey<T>::with
             at /Users/carter/.rustup/toolchains/nightly-2025-06-15-aarch64-apple-darwin/lib/rustlib/src/rust/library/std/src/thread/local.rs:279:20
  23: tokio::runtime::context::set_scheduler
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/context.rs:176:17
  24: tokio::runtime::scheduler::current_thread::CoreGuard::enter
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:829:27
  25: tokio::runtime::scheduler::current_thread::CoreGuard::block_on
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:729:24
  26: tokio::runtime::scheduler::current_thread::CurrentThread::block_on::{{closure}}
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:200:33
  27: tokio::runtime::context::runtime::enter_runtime
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/context/runtime.rs:65:16
  28: tokio::runtime::scheduler::current_thread::CurrentThread::block_on
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/scheduler/current_thread/mod.rs:188:9
  29: tokio::runtime::runtime::Runtime::block_on_inner
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/runtime.rs:356:52
  30: tokio::runtime::runtime::Runtime::block_on
             at /Users/carter/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.47.1/src/runtime/runtime.rs:330:18
  31: temp_v1::test_redis_store_implementation
             at ./tests/temp_v1.rs:43:45
  32: temp_v1::test_redis_store_implementation::{{closure}}
             at ./tests/temp_v1.rs:41:47
  33: core::ops::function::FnOnce::call_once
             at /Users/carter/.rustup/toolchains/nightly-2025-06-15-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/ops/function.rs:250:5
  34: core::ops::function::FnOnce::call_once
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/core/src/ops/function.rs:250:5
  35: test::__rust_begin_short_backtrace
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/test/src/lib.rs:648:18
  36: test::run_test_in_process::{{closure}}
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/test/src/lib.rs:671:74
  37: <core::panic::unwind_safe::AssertUnwindSafe<F> as core::ops::function::FnOnce<()>>::call_once
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/core/src/panic/unwind_safe.rs:272:9
  38: std::panicking::catch_unwind::do_call
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/panicking.rs:589:40
  39: std::panicking::catch_unwind
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/panicking.rs:552:19
  40: std::panic::catch_unwind
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/panic.rs:359:14
  41: test::run_test_in_process
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/test/src/lib.rs:671:27
  42: test::run_test::{{closure}}
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/test/src/lib.rs:592:43
  43: test::run_test::{{closure}}
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/test/src/lib.rs:622:41
  44: std::sys::backtrace::__rust_begin_short_backtrace
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/sys/backtrace.rs:152:18
  45: std::thread::Builder::spawn_unchecked_::{{closure}}::{{closure}}
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/thread/mod.rs:559:17
  46: <core::panic::unwind_safe::AssertUnwindSafe<F> as core::ops::function::FnOnce<()>>::call_once
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/core/src/panic/unwind_safe.rs:272:9
  47: std::panicking::catch_unwind::do_call
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/panicking.rs:589:40
  48: std::panicking::catch_unwind
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/panicking.rs:552:19
  49: std::panic::catch_unwind
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/panic.rs:359:14
  50: std::thread::Builder::spawn_unchecked_::{{closure}}
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/std/src/thread/mod.rs:557:30
  51: core::ops::function::FnOnce::call_once{{vtable.shim}}
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/core/src/ops/function.rs:250:5
  52: <alloc::boxed::Box<F,A> as core::ops::function::FnOnce<Args>>::call_once
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/alloc/src/boxed.rs:1966:9
  53: <alloc::boxed::Box<F,A> as core::ops::function::FnOnce<Args>>::call_once
             at /rustc/49a8ba06848fa8f282fe9055b4178350970bb0ce/library/alloc/src/boxed.rs:1966:9
  54: std::sys::pal::unix::thread::Thread::new::thr
     */
    assert_eq!(consumed, Some(item1));

    // Test publish many, dump all
    let mut items = vec![
        TestQueueItem {
            job_id: 2,
            payload: "two".into(),
        },
        TestQueueItem {
            job_id: 3,
            payload: "three".into(),
        },
        TestQueueItem {
            job_id: 4,
            payload: "four".into(),
        },
    ];
    store
        .publish_many_ephemeral_queue_items_owned(&queue_key, realm_id, realm_sub_id, unique_id, task_group, items.clone())
        .await
        .unwrap();

    let dumped = store
        .dump_entire_ephemeral_queue(&queue_key, realm_id, realm_sub_id, unique_id, task_group, 10)
        .await
        .unwrap();
    assert_eq!(dumped, items);

    // Queue should now be empty
    let is_empty: Option<TestQueueItem> = store
        .consume_ephemeral_queue_item_or_none(&queue_key, realm_id, realm_sub_id, unique_id, task_group)
        .await
        .unwrap();
    assert!(is_empty.is_none());

    // Test wait_for_ephemeral_queue_item
    let store_clone = store.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let item_to_wait_for = TestQueueItem {
        job_id: 5,
        payload: "five".into(),
    };

    let qk = queue_key.clone();
    tokio::spawn(async move {
        let qk = qk.clone();
        let received = store_clone
            .wait_for_ephemeral_queue_item(&qk, realm_id, realm_sub_id, unique_id, task_group, 1000)
            .await
            .unwrap();
        tx.send(received).unwrap();
    });

    // Give the waiter a moment to start polling
    tokio::time::sleep(Duration::from_millis(50)).await;
    let qk = queue_key.clone();
    store
        .publish_ephemeral_queue_item_owned(&qk, realm_id, realm_sub_id, unique_id, task_group, item_to_wait_for.clone())
        .await
        .unwrap();

    let received = rx.await.unwrap();
    assert_eq!(received, Some(item_to_wait_for));

    // Test wait_for timeout
    let timed_out = store
        .wait_for_ephemeral_queue_item::<TestQueueKey>(&queue_key, realm_id, realm_sub_id, unique_id, task_group, 50)
        .await
        .unwrap();
    assert!(timed_out.is_none());
}

//================================================================================
// Test Runners
//================================================================================

pub async fn run_all_tests_for_factory<F: StoreFactory>(factory: Arc<F>)
where
    <F as StoreFactory>::Store: QTempDatabaseRawKVWriterBase
        + QTempDatabaseRawStoreWriter
        + QTempDatabaseRawKVReaderBase
        + QTempDatabaseRawCounterReaderBase
        + QTempDatabaseRawKVReaderBase
        + QParthProofStoreWriter
        + QParthProofStoreReader
        + QStandardEphemeralQueueSubscriber
        + QStandardEphemeralQueuePublisher
        + Send
        + 'static,
{
    println!("--- Running tests for {} ---", factory.name());

    println!("  -> Testing KV Store...");
    let kv_store = factory.new_store().await;
    test_raw_kv_store(kv_store).await;

    println!("  -> Testing Counter Store...");
    let counter_store = factory.new_store().await;
    test_raw_counter_store(counter_store).await;

    println!("  -> Testing Proof Store...");
    let proof_store = factory.new_store().await;
    test_proof_store(proof_store).await;

    println!("  -> Testing Ephemeral Queue...");
    let queue_store = factory.new_store().await;
    test_ephemeral_queue(queue_store).await;

    println!("--- All tests passed for {} ---", factory.name());
}
