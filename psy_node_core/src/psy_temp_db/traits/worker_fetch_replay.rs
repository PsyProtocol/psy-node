use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;
use std::{collections::HashMap, sync::{Arc, Mutex, OnceLock}, time::{SystemTime, UNIX_EPOCH}};

/// Atomically consumes a signed fetch before any probation reservation or queue read.
/// An error must fail closed. Reservations survive failed/empty fetches; retries sign anew.
/// The signed request has no realm binding: all Edges must share a consumption domain.
#[async_trait]
pub trait QTempDBWorkerFetchReplayStore {
    async fn consume_worker_fetch(
        &self,
        rid: &QRealmIdentifier,
        signer: &[u8; 33],
        digest: &[u8; 32],
        expires_at_ms: u64,
    ) -> anyhow::Result<bool>;
}

pub fn worker_fetch_replay_key(_rid: &QRealmIdentifier, signer: &[u8; 33], digest: &[u8; 32]) -> String {
    format!("psy-worker-fetch-v1:{}:{}", hex::encode(signer), hex::encode(digest))
}

/// Memory-backend equivalent of Redis's atomic expiring reservation.
#[derive(Debug, Default)]
pub struct WorkerFetchReplayMemory(Mutex<HashMap<String, u64>>);

impl WorkerFetchReplayMemory {
    pub fn shared() -> Arc<Self> {
        static CACHE: OnceLock<Arc<WorkerFetchReplayMemory>> = OnceLock::new();
        CACHE.get_or_init(|| Arc::new(Self::default())).clone()
    }

    pub fn consume(&self, key: String, expires_at_ms: u64) -> anyhow::Result<bool> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let mut entries = self.0.lock().map_err(|e| anyhow::anyhow!(e.to_string()))?;
        entries.retain(|_, until| *until > now);
        if expires_at_ms <= now || entries.contains_key(&key) {
            return Ok(false);
        }
        anyhow::ensure!(expires_at_ms - now <= 300_000, "worker fetch expiry too far in future");
        entries.insert(key, expires_at_ms);
        Ok(true)
    }
}
