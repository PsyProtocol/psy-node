use std::sync::Arc;

use dashmap::DashMap;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use std::time::Duration;
use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_api_core::worker::standard_worker_rpc::NodeEdgeWorkerRpcClient;
use psy_core::constants::url_rotation::PsyAPIURLRotationStrategy;
use tokio::sync::RwLock;

use crate::utils::api_url::hash_api_url_to_32_bytes;

#[derive(Debug, Clone)]
pub struct PsyWorkerAPIURLManager {
    pub api_url_hash_to_string: DashMap<[u8; 32], String>,
    pub api_url_string_to_hash: DashMap<String, [u8; 32]>,
    pub api_url_hash_to_client: DashMap<[u8; 32], HttpClient>,
    pub api_url_failed_attempts: DashMap<[u8; 32], u32>,
    pub api_url_realm_identifiers: DashMap<[u8; 32], QRealmIdentifier>,
    pub api_url_list: Arc<RwLock<Vec<String>>>,
    pub current_api_url_index: Arc<RwLock<usize>>,
    pub last_seen_job_for_current_api_url_at: Arc<RwLock<u64>>,
    pub rotation_strategy: PsyAPIURLRotationStrategy,
}
fn get_current_unix_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    since_the_epoch.as_millis() as u64
}
impl PsyWorkerAPIURLManager {
    pub fn new(rotation_strategy: PsyAPIURLRotationStrategy) -> Self {
        Self {
            api_url_hash_to_string: DashMap::new(),
            api_url_string_to_hash: DashMap::new(),
            api_url_hash_to_client: DashMap::new(),
            api_url_failed_attempts: DashMap::new(),
            api_url_realm_identifiers: DashMap::new(),
            api_url_list: Arc::new(RwLock::new(Vec::new())),
            current_api_url_index: Arc::new(RwLock::new(0)),
            last_seen_job_for_current_api_url_at: Arc::new(RwLock::new(0)),
            rotation_strategy,
        }
    }
    pub fn get_total_api_urls(&self) -> usize {
        self.api_url_hash_to_string.len()
    }
    pub fn has_urls(&self) -> bool {
        !self.api_url_hash_to_string.is_empty()
    }
    pub async fn remove_api_url_by_hash(&self, api_url_hash: &[u8; 32]) -> anyhow::Result<()> {
        // Clone the URL string and drop the DashMap guard before any subsequent
        // remove() call on the same map — DashMap's get() acquires a per-shard
        // read lock, and remove() needs the per-shard write lock, so holding
        // the guard across remove() deadlocks.
        let api_url = match self.api_url_hash_to_string.get(api_url_hash) {
            Some(entry) => entry.value().clone(),
            None => return Ok(()),
        };
        self.api_url_hash_to_string.remove(api_url_hash);
        self.api_url_string_to_hash.remove(&api_url);
        self.api_url_hash_to_client.remove(api_url_hash);
        self.api_url_realm_identifiers.remove(api_url_hash);
        let mut api_url_list = self.api_url_list.write().await;
        if let Some(pos) = api_url_list.iter().position(|x| x == &api_url) {
            api_url_list.remove(pos);
        }
        Ok(())
    }
    pub async fn remove_api_url(&self, api_url: &str) -> anyhow::Result<()> {
        // Drop the DashMap guard before removing entries — see comment above.
        let api_url_hash = match self.api_url_string_to_hash.get(api_url) {
            Some(entry) => *entry,
            None => return Ok(()),
        };
        self.api_url_hash_to_string.remove(&api_url_hash);
        self.api_url_string_to_hash.remove(api_url);
        self.api_url_hash_to_client.remove(&api_url_hash);
        self.api_url_realm_identifiers.remove(&api_url_hash);
        let mut api_url_list = self.api_url_list.write().await;
        if let Some(pos) = api_url_list.iter().position(|x| x == api_url) {
            api_url_list.remove(pos);
        }
        Ok(())
    }
    pub async fn add_api_urls<
        Hash: Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static,
        JobId: Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static,
    >(
        &self,
        api_urls: &[impl AsRef<str>],
    ) -> anyhow::Result<()> {
        for api_url in api_urls {
            loop {
                let client = HttpClientBuilder::default().set_keep_alive(Some(Duration::from_secs(10))).build(api_url.as_ref())?;
                let realm_identifier = <HttpClient as NodeEdgeWorkerRpcClient<Hash, JobId>>::get_realm_identifier_worker_api(&client).await;

                match realm_identifier {
                    Ok(realm_identifier) => {
                        let api_url_hash = hash_api_url_to_32_bytes(api_url.as_ref());
                        self.api_url_hash_to_string.insert(api_url_hash, api_url.as_ref().to_string());
                        self.api_url_string_to_hash.insert(api_url.as_ref().to_string(), api_url_hash);
                        self.api_url_realm_identifiers.insert(api_url_hash, realm_identifier);
                        self.api_url_hash_to_client.insert(api_url_hash, client);
                        self.api_url_list.write().await.push(api_url.as_ref().to_string());
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Failed to get realm identifier from API URL: {}, retrying in 100ms: {:?}",
                            api_url.as_ref(),
                            err
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        Ok(())
    }
    pub async fn report_seen_job_for_current_api_url(&self) {
        let mut last_seen_job_time = self.last_seen_job_for_current_api_url_at.write().await;
        *last_seen_job_time = get_current_unix_timestamp_ms();
    }
    pub fn report_api_url_failure(&self, api_url_hash: &[u8; 32]) {
        let mut entry = self.api_url_failed_attempts.entry(*api_url_hash).or_insert(0);
        *entry += 1;
    }
    pub fn report_api_url_success(&self, api_url_hash: &[u8; 32]) {
        // reset the failure count on success
        self.api_url_failed_attempts.remove(api_url_hash);
    }

    /// Return true if `api_url_hash` has an active failure entry (known-failed endpoint).
    fn is_url_failed(&self, api_url_hash: &[u8; 32]) -> bool {
        self.api_url_failed_attempts.contains_key(api_url_hash)
    }

    /// Resolve `[u8; 32]` hash for the URL at `index` in the locked `api_url_list`.
    /// Returns `None` if the URL has been removed from `api_url_string_to_hash`
    /// (defensive — see issue bug 8).
    fn url_hash_at(&self, api_url_list: &[String], index: usize) -> Option<[u8; 32]> {
        let url = api_url_list.get(index)?;
        self.api_url_string_to_hash.get(url).map(|h| *h)
    }

    /// Mark the URL at `index` as the current selection: update
    /// `current_api_url_index` and reset `last_seen_job_for_current_api_url_at`.
    /// Centralizes the bookkeeping that previously was duplicated (and missed)
    /// across the rotation strategies — fixes Random bugs 1 & 2 and the
    /// RoundRobin `last_seen` reset (bug 7).
    async fn mark_current_url(&self, index: usize) {
        {
            let mut current = self.current_api_url_index.write().await;
            *current = index;
        }
        {
            let mut last_seen = self.last_seen_job_for_current_api_url_at.write().await;
            *last_seen = get_current_unix_timestamp_ms();
        }
    }

    pub async fn get_next_api_url_hash(&self) -> Option<[u8; 32]> {
        let api_url_list = self.api_url_list.read().await;
        if api_url_list.is_empty() {
            return None;
        }
        let list_len = api_url_list.len();
        match self.rotation_strategy {
            PsyAPIURLRotationStrategy::RoundRobin => {
                // Advance first, then read — consistent with ContinueUntilFailure*.
                let index_current = {
                    let mut index = self.current_api_url_index.write().await;
                    let prev = *index;
                    *index = (prev + 1) % list_len;
                    *index
                };
                // Bug 7 fix: when RoundRobin advances to a new URL, reset the
                // last_seen timestamp so a later strategy switch to
                // ContinueUntilFailureOrNoWorkFor3Seconds does not immediately
                // switch away due to a stale timestamp.
                self.mark_current_url(index_current).await;
                let api_url = &api_url_list[index_current];
                self.api_url_string_to_hash.get(api_url).map(|h| *h)
            }
            PsyAPIURLRotationStrategy::Random => {
                // Bug 3 & 5 fix: filter out URLs with active failure entries so
                // Random does not keep selecting known-dead endpoints.
                //
                // rand::thread_rng() (ThreadRng) is NOT Send, so the random
                // index is computed in a non-async block and dropped before we
                // await mark_current_url — otherwise the future would not be
                // Send (basic_job_fetcher requires Send).
                let final_index = {
                    use rand::Rng;
                    let mut rng = rand::thread_rng();
                    let candidates: Vec<usize> = (0..list_len)
                        .filter(|i| {
                            self.url_hash_at(&api_url_list, *i)
                                .map(|h| !self.is_url_failed(&h))
                                .unwrap_or(true)
                        })
                        .collect();
                    if candidates.is_empty() {
                        // All URLs are currently marked failed. Still pick one
                        // at random rather than returning None and blocking the
                        // worker forever — the failure entry may be stale and
                        // the caller will report_api_url_failure /
                        // report_api_url_success and drive recovery. This
                        // preserves liveness.
                        rng.gen_range(0..list_len)
                    } else {
                        candidates[rng.gen_range(0..candidates.len())]
                    }
                };

                // Bug 1 & 2 fix: update current_api_url_index and reset
                // last_seen so other strategies that read this state see a
                // consistent view after a Random selection.
                self.mark_current_url(final_index).await;

                // Bug 4: the read lock on api_url_list is held for the entire
                // match block, so the index cannot race with remove_api_url;
                // api_url_string_to_hash is a DashMap and safe to query under
                // the read lock. We resolve the hash while the lock is still
                // held to keep the snapshot consistent.
                self.url_hash_at(&api_url_list, final_index)
            }
            PsyAPIURLRotationStrategy::ContinueUntilFailure => {
                let current_index = *self.current_api_url_index.read().await;
                let api_url = &api_url_list[current_index % list_len];
                let api_url_hash = match self.api_url_string_to_hash.get(api_url) {
                    Some(h) => *h,
                    None => return None,
                };

                if self.is_url_failed(&api_url_hash) {
                    let index_current = {
                        let mut index = self.current_api_url_index.write().await;
                        *index = (*index + 1) % list_len;
                        *index
                    };
                    // Bug 8 fix: re-resolve the hash for the new URL instead of
                    // returning a hash that may belong to a removed URL.
                    let next_api_url = &api_url_list[index_current];
                    let mut last_seen_job_time = self.last_seen_job_for_current_api_url_at.write().await;
                    *last_seen_job_time = get_current_unix_timestamp_ms();
                    self.api_url_string_to_hash.get(next_api_url).map(|h| *h)
                } else {
                    Some(api_url_hash)
                }
            }
            PsyAPIURLRotationStrategy::ContinueUntilFailureOrNoWorkFor3Seconds => {
                let current_index = *self.current_api_url_index.read().await;
                let api_url = &api_url_list[current_index % list_len];
                let api_url_hash = match self.api_url_string_to_hash.get(api_url) {
                    Some(h) => *h,
                    None => return None,
                };
                let last_seen = {
                    self.last_seen_job_for_current_api_url_at.read().await.clone()
                };
                if self.is_url_failed(&api_url_hash) || (last_seen + 3000) < get_current_unix_timestamp_ms() {
                    let index_current = {
                        let mut index = self.current_api_url_index.write().await;
                        *index = (*index + 1) % list_len;
                        *index
                    };
                    let next_api_url = &api_url_list[index_current];
                    let mut last_seen_job_time = self.last_seen_job_for_current_api_url_at.write().await;
                    *last_seen_job_time = get_current_unix_timestamp_ms();
                    self.api_url_string_to_hash.get(next_api_url).map(|h| *h)
                } else {
                    Some(api_url_hash)
                }
            }
            PsyAPIURLRotationStrategy::SmartSwapV1 => {
                let current_index = *self.current_api_url_index.read().await;
                let api_url = &api_url_list[current_index % list_len];
                let api_url_hash = match self.api_url_string_to_hash.get(api_url) {
                    Some(h) => *h,
                    None => return None,
                };
                let last_seen = {
                    self.last_seen_job_for_current_api_url_at.read().await.clone()
                };
                if self.is_url_failed(&api_url_hash) || (last_seen + 3000) < get_current_unix_timestamp_ms() {
                    // Bug 6 fix: advance first, then read — matches
                    // ContinueUntilFailureOrNoWorkFor3Seconds. The previous
                    // code returned the OLD url while current_api_url_index
                    // already pointed at the NEW one, an internal inconsistency.
                    let index_current = {
                        let mut index = self.current_api_url_index.write().await;
                        *index = (*index + 1) % list_len;
                        *index
                    };
                    let next_api_url = &api_url_list[index_current];
                    let mut last_seen_job_time = self.last_seen_job_for_current_api_url_at.write().await;
                    *last_seen_job_time = get_current_unix_timestamp_ms();
                    self.api_url_string_to_hash.get(next_api_url).map(|h| *h)
                } else {
                    Some(api_url_hash)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_core::constants::url_rotation::PsyAPIURLRotationStrategy;

    // Helper: create a manager with N mock URLs (no real HTTP client needed).
    // Directly populates the URL maps so `get_next_api_url_hash` works without
    // hitting the network (add_api_urls requires live endpoints).
    async fn create_manager_with_urls(
        strategy: PsyAPIURLRotationStrategy,
        urls: Vec<&str>,
    ) -> PsyWorkerAPIURLManager {
        let manager = PsyWorkerAPIURLManager::new(strategy);
        for url in urls {
            let hash = hash_api_url_to_32_bytes(url);
            manager.api_url_hash_to_string.insert(hash, url.to_string());
            manager.api_url_string_to_hash.insert(url.to_string(), hash);
            manager.api_url_list.write().await.push(url.to_string());
        }
        manager
    }

    // ============================================================
    // Bug 1: Random updates current_api_url_index after selection
    // ============================================================
    #[tokio::test]
    async fn test_random_updates_current_index() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::Random,
            vec!["http://A:1337", "http://B:1337", "http://C:1337"],
        )
        .await;

        // Run several Random selections; at least one should land on a non-zero
        // index (3 URLs, random — overwhelmingly likely within 20 calls).
        let mut saw_nonzero = false;
        for _ in 0..20 {
            let _ = manager.get_next_api_url_hash().await;
            let idx = *manager.current_api_url_index.read().await;
            if idx != 0 {
                saw_nonzero = true;
                break;
            }
        }
        assert!(
            saw_nonzero,
            "Random should update current_api_url_index to the chosen URL; \
             after 20 calls it was still 0 every time."
        );
    }

    // ============================================================
    // Bug 2: Random resets last_seen_job_for_current_api_url_at
    // ============================================================
    #[tokio::test]
    async fn test_random_resets_last_seen_timestamp() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::Random,
            vec!["http://A:1337", "http://B:1337"],
        )
        .await;

        // Seed the timestamp with an old value, then run Random and confirm
        // the timestamp is bumped to ~now.
        {
            let mut last_seen = manager.last_seen_job_for_current_api_url_at.write().await;
            *last_seen = 0;
        }

        let before = get_current_unix_timestamp_ms();
        let _ = manager.get_next_api_url_hash().await;
        let after = get_current_unix_timestamp_ms();

        let last_seen = *manager.last_seen_job_for_current_api_url_at.read().await;
        assert!(
            last_seen >= before && last_seen <= after,
            "Random should reset last_seen to now; got {} (before={}, after={})",
            last_seen, before, after
        );
    }

    // ============================================================
    // Bug 3 & 5: Random filters out failed URLs
    // ============================================================
    #[tokio::test]
    async fn test_random_does_not_select_failed_url() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::Random,
            vec!["http://A:1337", "http://B:1337"],
        )
        .await;

        let url_a_hash = hash_api_url_to_32_bytes("http://A:1337");
        manager.report_api_url_failure(&url_a_hash);

        let mut selected_failed_count = 0;
        for _ in 0..1000 {
            let selected_hash = manager.get_next_api_url_hash().await;
            if selected_hash == Some(url_a_hash) {
                selected_failed_count += 1;
            }
        }

        assert_eq!(
            selected_failed_count, 0,
            "Random should filter out failed URLs and never select A; selected it {} times.",
            selected_failed_count
        );
    }

    // ============================================================
    // Random: when ALL urls are failed, still returns one (liveness)
    // ============================================================
    #[tokio::test]
    async fn test_random_all_failed_still_returns_url() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::Random,
            vec!["http://A:1337", "http://B:1337"],
        )
        .await;

        let url_a_hash = hash_api_url_to_32_bytes("http://A:1337");
        let url_b_hash = hash_api_url_to_32_bytes("http://B:1337");
        manager.report_api_url_failure(&url_a_hash);
        manager.report_api_url_failure(&url_b_hash);

        // All failed — should still return a URL (not None) to preserve liveness.
        let selected = manager.get_next_api_url_hash().await;
        assert!(selected.is_some(), "All URLs failed: Random should still return a URL for liveness.");
    }

    // ============================================================
    // Cross-strategy consistency: Random -> ContinueUntilFailure
    // current_api_url_index is consistent after Random.
    // ============================================================
    #[tokio::test]
    async fn test_random_then_continue_state_consistent() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::Random,
            vec!["http://A:1337", "http://B:1337", "http://C:1337"],
        )
        .await;

        // Run Random several times and record the last selected URL.
        let mut last_selected_hash = None;
        for _ in 0..10 {
            last_selected_hash = manager.get_next_api_url_hash().await;
        }
        let last_selected_hash = last_selected_hash.expect("Random should return a URL");

        // The current_api_url_index should point at the URL Random last returned.
        let current_index = *manager.current_api_url_index.read().await;
        let api_url_list = manager.api_url_list.read().await;
        let url_at_index = &api_url_list[current_index];
        let hash_at_index = manager
            .api_url_string_to_hash
            .get(url_at_index)
            .map(|h| *h)
            .expect("URL at current index must have a hash");

        assert_eq!(
            hash_at_index, last_selected_hash,
            "After Random selection, current_api_url_index must point at the URL \
             Random actually returned (cross-strategy consistency)."
        );
    }

    // ============================================================
    // Bug 6: SmartSwapV1 advances before returning (returns NEW url)
    // ============================================================
    #[tokio::test]
    async fn test_smartswap_v1_returns_advanced_url_on_failure() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::SmartSwapV1,
            vec!["http://A:1337", "http://B:1337"],
        )
        .await;

        // current_api_url_index starts at 0 -> URL A.
        // Mark A failed so SmartSwapV1 advances. It must return B (the NEW url),
        // not A (the OLD url). Also current_api_url_index must point at B (1).
        let url_a_hash = hash_api_url_to_32_bytes("http://A:1337");
        let url_b_hash = hash_api_url_to_32_bytes("http://B:1337");
        manager.report_api_url_failure(&url_a_hash);

        let selected = manager.get_next_api_url_hash().await.expect("should return a URL");
        assert_eq!(
            selected, url_b_hash,
            "SmartSwapV1 should return the NEW url (B) after advancing, not the OLD url (A)."
        );

        let current_index = *manager.current_api_url_index.read().await;
        assert_eq!(
            current_index, 1,
            "SmartSwapV1 should update current_api_url_index to the NEW url's index."
        );
    }

    // ============================================================
    // Bug 7: RoundRobin resets last_seen when it advances
    // ============================================================
    #[tokio::test]
    async fn test_roundrobin_resets_last_seen_on_advance() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::RoundRobin,
            vec!["http://A:1337", "http://B:1337"],
        )
        .await;

        // Seed an old timestamp; RoundRobin must reset it when advancing.
        {
            let mut last_seen = manager.last_seen_job_for_current_api_url_at.write().await;
            *last_seen = 0;
        }

        let before = get_current_unix_timestamp_ms();
        let _ = manager.get_next_api_url_hash().await;
        let after = get_current_unix_timestamp_ms();

        let last_seen = *manager.last_seen_job_for_current_api_url_at.read().await;
        assert!(
            last_seen >= before && last_seen <= after,
            "RoundRobin should reset last_seen when advancing to a new URL; got {} (before={}, after={})",
            last_seen, before, after
        );
    }

    // ============================================================
    // Empty list returns None for all strategies.
    // ============================================================
    #[tokio::test]
    async fn test_empty_list_returns_none() {
        for strategy in [
            PsyAPIURLRotationStrategy::RoundRobin,
            PsyAPIURLRotationStrategy::Random,
            PsyAPIURLRotationStrategy::ContinueUntilFailure,
            PsyAPIURLRotationStrategy::ContinueUntilFailureOrNoWorkFor3Seconds,
            PsyAPIURLRotationStrategy::SmartSwapV1,
        ] {
            let manager = create_manager_with_urls(strategy, vec![]).await;
            assert!(
                manager.get_next_api_url_hash().await.is_none(),
                "Empty URL list should return None for every strategy."
            );
        }
    }

    // ============================================================
    // Single URL: all strategies return that URL.
    // ============================================================
    #[tokio::test]
    async fn test_single_url_returned() {
        let url = "http://only:1337";
        let url_hash = hash_api_url_to_32_bytes(url);
        for strategy in [
            PsyAPIURLRotationStrategy::RoundRobin,
            PsyAPIURLRotationStrategy::Random,
            PsyAPIURLRotationStrategy::ContinueUntilFailure,
            PsyAPIURLRotationStrategy::ContinueUntilFailureOrNoWorkFor3Seconds,
            PsyAPIURLRotationStrategy::SmartSwapV1,
        ] {
            let manager = create_manager_with_urls(strategy, vec![url]).await;
            let selected = manager.get_next_api_url_hash().await;
            assert_eq!(
                selected, Some(url_hash),
                "Single-URL case: strategy {:?} should return the only URL.",
                strategy
            );
        }
    }

    // ============================================================
    // report_api_url_success clears the failure entry so Random
    // can select the URL again.
    // ============================================================
    #[tokio::test]
    async fn test_random_reselects_url_after_success_report() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::Random,
            vec!["http://A:1337", "http://B:1337"],
        )
        .await;

        let url_a_hash = hash_api_url_to_32_bytes("http://A:1337");
        manager.report_api_url_failure(&url_a_hash);

        // With A failed, Random only returns B.
        for _ in 0..50 {
            let selected = manager.get_next_api_url_hash().await.unwrap();
            assert_ne!(selected, url_a_hash, "A is failed; Random must not select it.");
        }

        // A recovers — failure entry cleared.
        manager.report_api_url_success(&url_a_hash);
        assert!(!manager.is_url_failed(&url_a_hash));

        // Now A is eligible again; within 200 calls it should appear.
        let mut saw_a = false;
        for _ in 0..200 {
            if manager.get_next_api_url_hash().await.unwrap() == url_a_hash {
                saw_a = true;
                break;
            }
        }
        assert!(saw_a, "After report_api_url_success(A), Random should be able to select A again.");
    }

    // ============================================================
    // ContinueUntilFailure advances past a failed URL and resets
    // last_seen (regression guard).
    // ============================================================
    #[tokio::test]
    async fn test_continue_until_failure_advances_past_failed() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::ContinueUntilFailure,
            vec!["http://A:1337", "http://B:1337"],
        )
        .await;

        let url_a_hash = hash_api_url_to_32_bytes("http://A:1337");
        let url_b_hash = hash_api_url_to_32_bytes("http://B:1337");
        manager.report_api_url_failure(&url_a_hash);

        // current index is 0 (A); A is failed -> must advance to B.
        let selected = manager.get_next_api_url_hash().await.unwrap();
        assert_eq!(selected, url_b_hash, "ContinueUntilFailure should advance past failed A to B.");
        assert_eq!(
            *manager.current_api_url_index.read().await,
            1,
            "current_api_url_index should be 1 after advancing to B."
        );
    }

    // ============================================================
    // Random never panics with a single URL that is then removed.
    // (Regression guard for the race-condition concern; the read
    // lock is held for the whole match block.)
    // ============================================================
    #[tokio::test]
    async fn test_random_no_panic_after_removal() {
        let manager = create_manager_with_urls(
            PsyAPIURLRotationStrategy::Random,
            vec!["http://A:1337"],
        )
        .await;
        let _ = manager.get_next_api_url_hash().await;
        manager.remove_api_url("http://A:1337").await.unwrap();
        assert!(manager.get_next_api_url_hash().await.is_none());
    }
}
