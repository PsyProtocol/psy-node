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
};
use psy_core::job::job_id::QProvingJobDataID;
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
    let pending_id = 42u64;
    assert!(!store.contains_proof_for_job_id(job_id1, pending_id).await.unwrap());

    // Test put and get (object)
    store.put_proof_for_job_id(job_id1, pending_id, &proof1).await.unwrap();
    assert!(store.contains_proof_for_job_id(job_id1, pending_id).await.unwrap());
    let retrieved: TestProof = store.get_proof_by_job_id(job_id1, pending_id).await.unwrap().unwrap();
    assert_eq!(retrieved, proof1);

    // Test get non-existent
    let retrieved_none: Option<TestProof> = store.get_proof_by_job_id(job_id2, pending_id).await.unwrap();
    assert!(retrieved_none.is_none());

    // Test put and get (bytes)
    let proof_bytes = proof1.to_bytes().unwrap();
    store.put_proof_bytes_for_job_id(job_id1, pending_id, &proof_bytes).await.unwrap();
    let retrieved_bytes = store.get_proof_bytes_by_job_id(job_id1, pending_id).await.unwrap().unwrap();
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
    Historical failure example for queue decoding:

    - test_redis_store_implementation
    - StandardRedisStore
    - consume_ephemeral_queue_item_or_none returned:
      Response was of incompatible type - TypeError: "Could not convert from string."

    The original pasted backtrace contained developer-local absolute paths and
    was intentionally removed.
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
    let items = vec![
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
