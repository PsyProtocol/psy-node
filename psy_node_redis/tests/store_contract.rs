use fred::interfaces::*;
use parth_core::{data::serializable::{QPDPair, QPDSerializable}, QJobIdSerialized};
use psy_node_core::{
    store::traits::proof_store::{QParthProofStoreReader, QParthProofStoreWriter},
    test_helpers::basic_1::TestProof,
};
use psy_node_redis::store::{new_redis_async_pool, StandardFredRedisStore};

async fn store() -> anyhow::Result<StandardFredRedisStore> {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must identify an isolated test database");
    let pool = new_redis_async_pool(&url, 2).await?;
    Ok(StandardFredRedisStore::new(pool, format!("contract_{}", rand::random::<u64>()), 1, 2))
}

#[tokio::test]
#[ignore = "Requires isolated Redis 7.4+ at REDIS_URL"]
async fn hash_missing_values_batch_order_and_counter_clamping() -> anyhow::Result<()> {
    let s = store().await?;
    let ns = &s.kv_store_namespace;
    assert!(s.get_bytes_generic_internal(ns, b"missing").await?.is_empty());
    s.set_many_bytes_generic_internal(ns, vec![QPDPair { key: b"a".to_vec(), value: b"A".to_vec() }]).await?;
    s.set_many_bytes_generic_internal_ref(ns, &[QPDPair { key: b"b".to_vec(), value: b"B".to_vec() }]).await?;
    s.set_many_bytes_generic_internal_tuple(ns, &[(b"c".to_vec(), b"C".to_vec())]).await?;
    let expected = vec![b"C".to_vec(), vec![], b"A".to_vec(), b"B".to_vec()];
    assert_eq!(s.get_many_bytes_generic_internal(ns, &[b"c".to_vec(), b"missing".to_vec(), b"a".to_vec(), b"b".to_vec()]).await?, expected);
    assert_eq!(s.get_many_bytes_generic_internal_ref(ns, &[b"c", b"missing", b"a", b"b"]).await?, expected);
    assert_eq!(s.get_iu64_generic_internal(ns, b"counter").await?, 0);
    s.set_iu64_generic_internal(ns, b"counter", -2).await?;
    assert_eq!(s.get_iu64_generic_internal(ns, b"counter").await?, 0);
    assert_eq!(s.inc_iu64_generic_internal(ns, b"counter", 5).await?, 3);
    assert_eq!(s.inc_iu64_generic_internal(ns, b"counter", -4).await?, 0);
    let _: i64 = s.client.del(ns).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated Redis 7.4+ at REDIS_URL"]
async fn sets_deduplicate_and_fifo_queues_preserve_binary_payloads() -> anyhow::Result<()> {
    let s = store().await?;
    let ns = &s.root_prefix;
    s.add_to_set_generic_internal(ns, b"x").await?;
    s.add_to_set_generic_internal(ns, b"x").await?;
    assert_eq!(s.get_set_generic_internal(ns).await?, vec![b"x".to_vec()]);
    s.remove_from_set_generic_internal(ns, b"x").await?;
    assert!(s.get_set_generic_internal(ns).await?.is_empty());
    s.add_to_u64_set_internal(ns, 42).await?;
    assert_eq!(s.get_u64_set_internal(ns).await?, vec![42]);
    s.remove_from_u64_set_internal(ns, 42).await?;
    assert!(s.get_u64_set_internal(ns).await?.is_empty());
    s.push_to_generic_u64_queue_internal(ns, 7).await?;
    assert_eq!(s.wait_for_generic_u64_queue_internal(ns).await?, 7);
    assert!(s.pop_from_generic_bytes_queue_or_none_internal(ns).await?.is_none());
    s.push_to_generic_bytes_queue_internal(ns, b"\0\xff").await?;
    s.push_many_to_generic_bytes_queue_internal(ns, &[b"second".to_vec(), b"third".to_vec()]).await?;
    assert_eq!(s.wait_for_generic_bytes_queue_internal(ns).await?, b"\0\xff");
    assert_eq!(s.dump_ro_generic_bytes_queue_internal(ns).await?, vec![b"second".to_vec(), b"third".to_vec()]);
    assert_eq!(s.pop_from_generic_bytes_queue_or_none_internal(ns).await?, Some(b"second".to_vec()));
    assert_eq!(s.dump_generic_bytes_queue_internal(ns).await?, vec![b"third".to_vec()]);
    assert!(s.dump_generic_bytes_queue_internal(ns).await?.is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated Redis 7.4+ at REDIS_URL"]
async fn typed_queues_round_trip_and_reject_corrupt_payloads() -> anyhow::Result<()> {
    let s = store().await?;
    let ns = &s.root_prefix;
    let a = TestProof { data: vec![0, 255], value: 42 };
    let b = TestProof { data: vec![1, 2], value: 43 };
    assert!(s.pop_from_generic_obj_queue_or_none_internal::<TestProof>(ns).await?.is_none());
    s.push_to_generic_obj_queue_internal(ns, &a).await?;
    s.push_many_to_generic_obj_queue_internal(ns, &[b.clone(), a.clone()]).await?;
    assert_eq!(s.dump_ro_generic_obj_queue_internal::<TestProof>(ns).await?, vec![a.clone(), b.clone(), a.clone()]);
    assert_eq!(s.wait_for_generic_obj_queue_internal::<TestProof>(ns).await?, a);
    assert_eq!(s.pop_from_generic_obj_queue_or_none_internal::<TestProof>(ns).await?, Some(b));
    assert_eq!(s.dump_generic_obj_queue_internal::<TestProof>(ns).await?, vec![a]);
    s.push_to_generic_bytes_queue_internal(ns, &[255]).await?;
    assert!(s.pop_from_generic_obj_queue_or_none_internal::<TestProof>(ns).await.is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated Redis 7.4+ at REDIS_URL"]
async fn proofs_have_field_ttl_and_pending_and_realm_isolation() -> anyhow::Result<()> {
    let s = store().await?;
    let other = StandardFredRedisStore::new(s.client.clone(), s.root_prefix.clone(), 1, 3);
    let job: QJobIdSerialized = [7; 24];
    let proof = TestProof { data: vec![1, 2, 3], value: 77 };
    assert!(s.get_proof_bytes_by_job_id(job, 10).await?.is_none());
    assert!(s.get_proof_by_job_id::<_, TestProof>(job, 10).await?.is_none());
    s.put_proof_for_job_id(job, 10, &proof).await?;
    s.put_proof_bytes_for_job_id(job, 11, &proof.to_bytes()?).await?;
    assert_eq!(s.get_proof_by_job_id::<_, TestProof>(job, 10).await?, Some(proof.clone()));
    assert!(!other.contains_proof_for_job_id(job, 10).await?);
    let bucket = format!("{}-10", s.proof_store_namespace);
    let ttl: Vec<i64> = s.client.httl(&bucket, &job[..]).await?;
    assert!(ttl[0] > 0 && ttl[0] <= 600, "proof must have a bounded field TTL: {ttl:?}");
    s.delete_all_proofs_for_pending_id(10).await?;
    assert!(!s.contains_proof_for_job_id(job, 10).await?);
    assert_eq!(s.get_proof_bytes_by_job_id(job, 11).await?, Some(proof.to_bytes()?));
    s.put_proof_bytes_for_job_id(job, 10, b"").await?;
    assert!(s.get_proof_bytes_by_job_id(job, 10).await?.is_none());
    assert!(s.get_proof_by_job_id::<_, TestProof>(job, 10).await?.is_none());
    s.put_proof_bytes_for_job_id(job, 10, &[255]).await?;
    assert!(s.get_proof_by_job_id::<_, TestProof>(job, 10).await.is_err());
    s.delete_all_proofs_for_pending_id(10).await?;
    s.delete_all_proofs_for_pending_id(11).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated Redis 7.4+ at REDIS_URL"]
async fn queue_server_timeout_is_empty_but_command_and_type_errors_propagate() -> anyhow::Result<()> {
    use parth_core::data::queue::queue_key::{PCoreSubjectQueueBase, QPBaseQueueType};
    use psy_node_core::{queue::ephemeral::QStandardEphemeralQueueSubscriber, test_helpers::basic_1::TestQueueKey};
    use std::{marker::PhantomData, time::Duration};
    let s = store().await?;
    let key = TestQueueKey { realm_id: 1, realm_sub_id: 2, unique_id: 3, task_group: 0, queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: PhantomData };
    assert!(s.wait_for_ephemeral_queue_item_bytes(&key, 1, 2, 3, 0, 20).await?.is_none());
    let subject = key.get_queue_subject(&s.root_prefix, 1, 2, 3, 0);
    let _: () = s.client.set(&subject, "wrong type", None, None, false).await?;
    assert!(s.wait_for_ephemeral_queue_item_bytes(&key, 1, 2, 3, 0, 20).await.is_err());
    let _: i64 = s.client.del(&subject).await?;
    s.client.update_perf_config(fred::types::config::PerformanceConfig {
        default_command_timeout: Duration::from_millis(10),
        ..Default::default()
    });
    let error = s.wait_for_ephemeral_queue_item_bytes(&key, 1, 2, 3, 0, 200).await.unwrap_err();
    assert_eq!(error.downcast_ref::<fred::error::Error>().unwrap().kind(), &fred::error::ErrorKind::Timeout);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires isolated Redis 7.4+ at REDIS_URL"]
async fn blocked_consumers_do_not_starve_producers_and_cancel_cleanly() -> anyhow::Result<()> {
    use std::time::Duration;
    use tokio::time::{sleep, timeout};
    let url = std::env::var("REDIS_URL")?;
    let observer = new_redis_async_pool(&url, 1).await?;
    async fn blocked(observer: &fred::clients::Pool) -> anyhow::Result<usize> {
        let clients: String = observer.custom(fred::types::CustomCommand::new("CLIENT", None, false), vec!["LIST"]).await?;
        Ok(clients.lines().filter(|line| line.split_whitespace().any(|field| field.strip_prefix("flags=").is_some_and(|flags| flags.contains('b')))).count())
    }
    async fn wait_blocked(observer: &fred::clients::Pool, expected: usize) -> anyhow::Result<()> {
        timeout(Duration::from_secs(3), async {
            while blocked(observer).await? != expected { sleep(Duration::from_millis(10)).await; }
            Ok::<_, anyhow::Error>(())
        }).await??;
        Ok(())
    }
    for size in [1, 2] {
        let baseline = blocked(&observer).await?;
        let s = StandardFredRedisStore::new(new_redis_async_pool(&url, size).await?, format!("blocked_{}", rand::random::<u64>()), 1, 2);
        let bytes_key = format!("{}-bytes", s.root_prefix);
        let number_key = format!("{}-number", s.root_prefix);
        let reader = s.clone();
        let key = bytes_key.clone();
        let bytes_wait = tokio::spawn(async move { reader.wait_for_generic_bytes_queue_internal(&key).await });
        let reader = s.clone();
        let key = number_key.clone();
        let number_wait = tokio::spawn(async move { reader.wait_for_generic_u64_queue_internal(&key).await });
        wait_blocked(&observer, baseline + 2).await?;
        // Perturb shared-pool selection while two consumers are confirmed blocked.
        // Even a one-connection pool must remain available to producers.
        timeout(Duration::from_secs(3), async {
            for _ in 0..4 { assert_eq!(s.get_iu64_generic_internal(&s.kv_store_namespace, b"missing").await?, 0); }
            s.push_to_generic_u64_queue_internal(&number_key, 42).await?;
            s.push_to_generic_bytes_queue_internal(&bytes_key, b"awake").await?;
            assert_eq!(number_wait.await??, 42);
            assert_eq!(bytes_wait.await??, b"awake");
            Ok::<_, anyhow::Error>(())
        }).await??;
        wait_blocked(&observer, baseline).await?;
        let reader = s.clone();
        let cancelled = tokio::spawn(async move { reader.wait_for_generic_bytes_queue_internal(&bytes_key).await });
        wait_blocked(&observer, baseline + 1).await?;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        wait_blocked(&observer, baseline).await?;
    }
    Ok(())
}
