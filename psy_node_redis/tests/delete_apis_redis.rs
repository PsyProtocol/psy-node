use std::collections::HashSet;

use parth_core::QJobIdSerialized;
use psy_node_core::psy_temp_db::{
    tt_get_contract_updates_key, tt_get_deploy_contract_code_definition_key,
    tt_get_job_claim_key_from_bytes, tt_get_job_stats_count_key, tt_get_proof_claim_tag_key,
    tt_get_proof_witness_data_key, tt_get_proving_job_metadata_key,
    tt_get_rewards_tag_tree_value_key, tt_get_submit_status_key, tt_get_unique_pending_id_key,
    tt_get_user_end_cap_slot_updates_key, tt_get_worker_reputation_key,
    TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES,
};
use psy_node_core::store::traits::{
    proof_store::{QParthProofBucketPresenceReader, QParthProofStoreReader, QParthProofStoreWriter},
    temp_db::{
        filter_temp_kv_fields_by_pending, QTempDatabaseRawKVEnumeratorBase,
        QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase, TempKvScanPage,
    },
};
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use rand::Rng;
use redis::AsyncCommands;

struct TestEnv {
    store: StandardRedisStore,
    redis_url: String,
    realm_id: u32,
    realm_sub_id: u16,
    pending_id: u64,
}

async fn new_env(ns: &str) -> TestEnv {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
    let pool = new_redis_async_pool(&redis_url, 2).await.unwrap();
    let root_prefix = format!("t-{ns}");
    let mut rng = rand::thread_rng();
    let realm_id: u32 = rng.gen();
    let realm_sub_id: u16 = rng.gen();
    let pending_id: u64 = rng.gen_range(1..u64::MAX);
    let store = StandardRedisStore::new(pool, root_prefix, realm_id as u64, realm_sub_id as u64);
    let env = TestEnv { store, redis_url, realm_id, realm_sub_id, pending_id };
    cleanup(&env).await;
    env
}

fn job_id(seed: u32) -> QJobIdSerialized {
    let mut j = [0u8; 24];
    j[0..4].copy_from_slice(&seed.to_le_bytes());
    j
}

async fn physical(env: &TestEnv) -> redis::aio::MultiplexedConnection {
    redis::Client::open(env.redis_url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

async fn cleanup(env: &TestEnv) {
    let mut conn = physical(env).await;
    let _: i64 = conn.del(env.store.kv_store_namespace.as_str()).await.unwrap();
    let _: i64 = conn.del(env.store.proof_store_namespace.as_str()).await.unwrap();
    let bucket_pattern = format!("{}*", env.store.proof_store_namespace);
    let mut iter = conn.scan_match::<String, String>(bucket_pattern).await.unwrap();
    let mut buckets = Vec::new();
    while let Some(key) = iter.next_item().await {
        buckets.push(key);
    }
    drop(iter);
    if !buckets.is_empty() {
        let _: i64 = conn.del(buckets).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
async fn raw_field_delete_is_exact_and_idempotent() {
    let env = new_env("raw_field_delete_is_exact_and_idempotent").await;
    let target = tt_get_proving_job_metadata_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(1)).to_vec();
    let sibling = tt_get_proving_job_metadata_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(2)).to_vec();
    env.store.qtdb_raw_kv_put_value(&target, b"t").await.unwrap();
    env.store.qtdb_raw_kv_put_value(&sibling, b"s").await.unwrap();
    assert!(env.store.qtdb_raw_kv_contains_key(&target).await.unwrap());
    assert!(env.store.qtdb_raw_kv_contains_key(&sibling).await.unwrap());
    env.store.qtdb_raw_kv_delete_key(&target).await.unwrap();
    assert!(!env.store.qtdb_raw_kv_contains_key(&target).await.unwrap());
    assert!(env.store.qtdb_raw_kv_contains_key(&sibling).await.unwrap());
    let mut conn = physical(&env).await;
    let target_present: bool = conn.hexists(env.store.kv_store_namespace.as_str(), &target[..]).await.unwrap();
    assert!(!target_present);
    let sibling_present: bool = conn.hexists(env.store.kv_store_namespace.as_str(), &sibling[..]).await.unwrap();
    assert!(sibling_present);
    env.store.qtdb_raw_kv_delete_key(&target).await.unwrap();
    assert!(!env.store.qtdb_raw_kv_contains_key(&target).await.unwrap());
    assert!(env.store.qtdb_raw_kv_contains_key(&sibling).await.unwrap());
    cleanup(&env).await;
}

#[tokio::test]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
async fn scan_enumerates_binary_fields_across_pages() {
    let env = new_env("scan_enumerates_binary_fields_across_pages").await;
    let mut entries = Vec::with_capacity(600);
    for i in 0..600u32 {
        let key = tt_get_proving_job_metadata_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(i)).to_vec();
        entries.push((key, vec![i as u8; 8]));
    }
    env.store.qtdb_raw_kv_put_many_values_tuple(&entries).await.unwrap();
    let mut conn = physical(&env).await;
    let len: i64 = conn.hlen(env.store.kv_store_namespace.as_str()).await.unwrap();
    assert_eq!(len, 600);
    let mut cursor = 0u64;
    let mut collected = HashSet::new();
    let mut pages = 0u32;
    loop {
        let TempKvScanPage { next_cursor, fields } = env.store.qtdb_raw_kv_scan_fields(cursor, 7).await.unwrap();
        pages += 1;
        for field in fields {
            assert!(collected.insert(field), "duplicate field across pages");
        }
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    assert!(pages > 1, "HSCAN with COUNT 7 over 600 fields must span multiple pages");
    assert_eq!(collected.len(), 600);
    for i in 0..600u32 {
        let key = tt_get_proving_job_metadata_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(i)).to_vec();
        assert!(collected.contains(&key), "field {i} missing from scan");
    }
    cleanup(&env).await;
}

#[tokio::test]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
async fn pending_prefix_filter_isolates_realm_sub_table_pending() {
    let env = new_env("pending_prefix_filter_isolates_realm_sub_table_pending").await;
    let expected: Vec<Vec<u8>> = vec![
        tt_get_proving_job_metadata_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(1)).to_vec(),
        tt_get_proving_job_metadata_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(2)).to_vec(),
        tt_get_proof_witness_data_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(3)).to_vec(),
        tt_get_submit_status_key(env.realm_id, env.realm_sub_id, env.pending_id, 777).to_vec(),
        tt_get_contract_updates_key(env.realm_id, env.realm_sub_id, env.pending_id, 11).to_vec(),
        tt_get_user_end_cap_slot_updates_key(env.realm_id, env.realm_sub_id, env.pending_id, 12).to_vec(),
        tt_get_rewards_tag_tree_value_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(4)).to_vec(),
        tt_get_deploy_contract_code_definition_key(env.realm_id, env.realm_sub_id, env.pending_id, &[7u8; 16]).to_vec(),
        tt_get_job_claim_key_from_bytes(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(5)).to_vec(),
        tt_get_job_stats_count_key(env.realm_id, env.realm_sub_id, env.pending_id).to_vec(),
        tt_get_proof_claim_tag_key(env.realm_id, env.realm_sub_id, env.pending_id, &job_id(6)).to_vec(),
    ];
    for key in &expected {
        env.store.qtdb_raw_kv_put_value(key, b"v").await.unwrap();
    }
    let other_pending = tt_get_proving_job_metadata_key(env.realm_id, env.realm_sub_id, env.pending_id + 1, &job_id(9)).to_vec();
    env.store.qtdb_raw_kv_put_value(&other_pending, b"v").await.unwrap();
    let other_realm = tt_get_submit_status_key(env.realm_id.wrapping_add(1), env.realm_sub_id, env.pending_id, 1).to_vec();
    env.store.qtdb_raw_kv_put_value(&other_realm, b"v").await.unwrap();
    let other_sub = tt_get_submit_status_key(env.realm_id, env.realm_sub_id.wrapping_add(1), env.pending_id, 1).to_vec();
    env.store.qtdb_raw_kv_put_value(&other_sub, b"v").await.unwrap();
    let pi = tt_get_unique_pending_id_key(env.realm_id, env.realm_sub_id).to_vec();
    env.store.qtdb_raw_kv_put_value(&pi, b"v").await.unwrap();
    let mut pk = [0u8; 33];
    pk[0] = 0x02;
    let wr = tt_get_worker_reputation_key(env.realm_id, env.realm_sub_id, &pk).to_vec();
    env.store.qtdb_raw_kv_put_value(&wr, b"v").await.unwrap();
    let mut short = vec![0u8; 15];
    short[0..4].copy_from_slice(&env.realm_id.to_le_bytes());
    short[4..6].copy_from_slice(&env.realm_sub_id.to_le_bytes());
    short[6..8].copy_from_slice(&TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES);
    env.store.qtdb_raw_kv_put_value(&short, b"v").await.unwrap();
    let mut cursor = 0u64;
    let mut all = Vec::new();
    loop {
        let TempKvScanPage { next_cursor, fields } = env.store.qtdb_raw_kv_scan_fields(cursor, 64).await.unwrap();
        all.extend(fields);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }
    let matched = filter_temp_kv_fields_by_pending(&all, env.realm_id, env.realm_sub_id, env.pending_id);
    let matched_set: HashSet<Vec<u8>> = matched.iter().cloned().collect();
    let expected_set: HashSet<Vec<u8>> = expected.iter().cloned().collect();
    assert_eq!(matched_set, expected_set);
    assert!(!matched_set.contains(&other_pending));
    assert!(!matched_set.contains(&other_realm));
    assert!(!matched_set.contains(&other_sub));
    assert!(!matched_set.contains(&pi));
    assert!(!matched_set.contains(&wr));
    assert!(!matched_set.contains(&short));
    for field in &matched {
        env.store.qtdb_raw_kv_delete_key(field).await.unwrap();
    }
    for field in &matched {
        assert!(!env.store.qtdb_raw_kv_contains_key(field).await.unwrap(), "filtered field must be HDELed");
    }
    assert!(env.store.qtdb_raw_kv_contains_key(&other_pending).await.unwrap(), "other-pending row survives");
    assert!(env.store.qtdb_raw_kv_contains_key(&other_realm).await.unwrap(), "other-realm row survives");
    assert!(env.store.qtdb_raw_kv_contains_key(&other_sub).await.unwrap(), "other-sub row survives");
    assert!(env.store.qtdb_raw_kv_contains_key(&pi).await.unwrap(), "PI singleton survives");
    assert!(env.store.qtdb_raw_kv_contains_key(&wr).await.unwrap(), "WR row survives");
    assert!(env.store.qtdb_raw_kv_contains_key(&short).await.unwrap(), "short field survives");
    let mut conn = physical(&env).await;
    let remaining: i64 = conn.hlen(env.store.kv_store_namespace.as_str()).await.unwrap();
    assert_eq!(remaining, 6, "hash must still exist with exactly the 6 decoys");
    cleanup(&env).await;
}

#[tokio::test]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
async fn proof_bucket_delete_is_pending_scoped_and_idempotent() {
    let env = new_env("proof_bucket_delete_is_pending_scoped_and_idempotent").await;
    let target = env.pending_id;
    let sibling = env.pending_id + 1;
    env.store.put_proof_bytes_for_job_id(job_id(1), target, b"proof-a").await.unwrap();
    env.store.put_proof_bytes_for_job_id(job_id(2), sibling, b"proof-b").await.unwrap();
    assert!(env.store.contains_proofs_for_pending_id(target).await.unwrap());
    assert!(env.store.contains_proofs_for_pending_id(sibling).await.unwrap());
    assert!(env.store.contains_proof_for_job_id(job_id(1), target).await.unwrap());
    assert!(env.store.contains_proof_for_job_id(job_id(2), sibling).await.unwrap());
    env.store.delete_all_proofs_for_pending_id(target).await.unwrap();
    assert!(!env.store.contains_proofs_for_pending_id(target).await.unwrap());
    assert!(env.store.contains_proofs_for_pending_id(sibling).await.unwrap());
    assert!(!env.store.contains_proof_for_job_id(job_id(1), target).await.unwrap());
    assert!(env.store.contains_proof_for_job_id(job_id(2), sibling).await.unwrap());
    let mut conn = physical(&env).await;
    let target_bucket = format!("{}-{}", env.store.proof_store_namespace, target);
    let sibling_bucket = format!("{}-{}", env.store.proof_store_namespace, sibling);
    let target_exists: i64 = conn.exists(target_bucket.as_str()).await.unwrap();
    assert_eq!(target_exists, 0);
    let sibling_exists: i64 = conn.exists(sibling_bucket.as_str()).await.unwrap();
    assert_eq!(sibling_exists, 1);
    env.store.delete_all_proofs_for_pending_id(target).await.unwrap();
    assert!(!env.store.contains_proofs_for_pending_id(target).await.unwrap());
    assert!(env.store.contains_proofs_for_pending_id(sibling).await.unwrap());
    cleanup(&env).await;
}

#[tokio::test]
#[ignore = "Requires a running Redis instance at REDIS_URL"]
async fn namespace_isolation() {
    let env_a = new_env("namespace_isolation_a").await;
    let env_b = new_env("namespace_isolation_b").await;
    assert_ne!(env_a.store.kv_store_namespace, env_b.store.kv_store_namespace);
    let field: Vec<u8> = vec![
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC, 0x7F, 0x80, 0x81,
        0x82, 0x11, 0x22, 0x33, 0x44,
    ];
    env_a.store.qtdb_raw_kv_put_value(&field, b"a").await.unwrap();
    env_b.store.qtdb_raw_kv_put_value(&field, b"b").await.unwrap();
    assert!(env_a.store.qtdb_raw_kv_contains_key(&field).await.unwrap());
    assert!(env_b.store.qtdb_raw_kv_contains_key(&field).await.unwrap());
    env_a.store.qtdb_raw_kv_delete_key(&field).await.unwrap();
    assert!(!env_a.store.qtdb_raw_kv_contains_key(&field).await.unwrap());
    assert!(env_b.store.qtdb_raw_kv_contains_key(&field).await.unwrap());
    assert_eq!(env_b.store.qtdb_raw_kv_get_value(&field).await.unwrap().unwrap(), b"b".to_vec());
    let mut conn = physical(&env_a).await;
    let a_present: bool = conn.hexists(env_a.store.kv_store_namespace.as_str(), &field[..]).await.unwrap();
    assert!(!a_present);
    let b_present: bool = conn.hexists(env_b.store.kv_store_namespace.as_str(), &field[..]).await.unwrap();
    assert!(b_present);
    cleanup(&env_a).await;
    cleanup(&env_b).await;
}
