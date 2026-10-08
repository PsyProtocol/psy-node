use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_node_core::psy_temp_db::QTempDBWorkerFetchReplayStore;
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use std::{sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

async fn stores() -> anyhow::Result<(StandardRedisStore, StandardRedisStore)> {
    let url = std::env::var("REDIS_URL")?;
    let prefix = format!("fetch-replay-test-{}", rand::random::<u64>());
    Ok((
        StandardRedisStore::new(new_redis_async_pool(&url, 2).await?, prefix.clone(), 1, 2),
        StandardRedisStore::new(new_redis_async_pool(&url, 2).await?, format!("{prefix}-other-realm"), 3, 4),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires an isolated Redis instance at REDIS_URL"]
async fn redis_fetch_replay_is_atomic_across_independent_edge_clients() -> anyhow::Result<()> {
    let (a, b) = stores().await?;
    let clients = [Arc::new(a), Arc::new(b)];
    let expires = now_ms() + 10_000;
    let digest = rand::random::<[u8; 32]>();
    let tasks = (0..32).map(|i| {
        let client = clients[i % 2].clone();
        tokio::spawn(async move {
            client.consume_worker_fetch(&QRealmIdentifier::new(i as u32 % 2, 2), &[1; 33], &digest, expires).await
        })
    }).collect::<Vec<_>>();
    let mut winners = 0;
    for task in tasks { winners += usize::from(task.await??); }
    assert_eq!(winners, 1);
    assert!(clients[0].consume_worker_fetch(&QRealmIdentifier::new(1, 2), &[1; 33], &rand::random(), expires).await?);
    assert!(clients[1].consume_worker_fetch(&QRealmIdentifier::new(1, 2), &[2; 33], &digest, expires).await?);
    Ok(())
}

#[tokio::test]
#[ignore = "Requires an isolated Redis instance at REDIS_URL"]
async fn redis_replay_expiry_never_reopens_an_expired_signed_request() -> anyhow::Result<()> {
    let (a, b) = stores().await?;
    let rid = QRealmIdentifier::new(1, 2);
    let expires = now_ms() + 150;
    let digest = rand::random::<[u8; 32]>();
    assert!(a.consume_worker_fetch(&rid, &[1; 33], &digest, expires).await?);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!b.consume_worker_fetch(&rid, &[1; 33], &digest, expires).await?);
    assert!(b.consume_worker_fetch(&rid, &[1; 33], &rand::random(), now_ms() + 1_000).await?);
    assert!(b.consume_worker_fetch(&rid, &[1; 33], &[4; 32], now_ms() + 600_000).await.is_err());
    Ok(())
}
