use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_node_core::psy_temp_db::{
    QTempDBWorkerReputationReader, QTempDBWorkerReputationWriter,
};

use crate::constants::worker_reputation::{
    DEFAULT_JOB_DEADLINE_MS, DEFAULT_REPUTATION_REWARD, DEFAULT_REPUTATION_SLASH, MAX_REPUTATION,
};

#[async_trait]
pub trait WorkerReputationOps: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter {
    async fn apply_reputation_on_submit(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        claim_time_ms: u64,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let on_time = now.saturating_sub(claim_time_ms) <= DEFAULT_JOB_DEADLINE_MS;
        let rep = self.get_worker_reputation(rid, public_key).await?;
        let new_rep = if on_time {
            (rep + DEFAULT_REPUTATION_REWARD).min(MAX_REPUTATION)
        } else {
            rep.saturating_sub(DEFAULT_REPUTATION_SLASH)
        };
        self.set_worker_reputation(rid, public_key, new_rep).await
    }

    async fn apply_reputation_slash_on_tag_mismatch(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
    ) -> anyhow::Result<()> {
        let rep = self.get_worker_reputation(rid, public_key).await?;
        let new_rep = rep.saturating_sub(DEFAULT_REPUTATION_SLASH);
        self.set_worker_reputation(rid, public_key, new_rep).await
    }
}

impl<T: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter> WorkerReputationOps for T {}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use parth_core::node::realm_identifier::QRealmIdentifier;
    use psy_node_core::psy_temp_db::{QTempDBWorkerReputationReader, QTempDBWorkerReputationWriter};

    use super::WorkerReputationOps;

    use crate::constants::worker_reputation::{
        DEFAULT_JOB_DEADLINE_MS, DEFAULT_REPUTATION_SLASH, MAX_REPUTATION,
    };

    #[derive(Default)]
    struct FakeReputationStore {
        map: std::sync::Mutex<HashMap<(u32, u16, [u8; 33]), u64>>,
    }

    #[async_trait::async_trait]
    impl QTempDBWorkerReputationReader for FakeReputationStore {
        async fn get_worker_reputation(&self, rid: &QRealmIdentifier, public_key: &[u8; 33]) -> anyhow::Result<u64> {
            let key = (rid.realm_id, rid.realm_sub_id, *public_key);
            Ok(self.map.lock().unwrap().get(&key).copied().unwrap_or(0))
        }
    }

    #[async_trait::async_trait]
    impl QTempDBWorkerReputationWriter for FakeReputationStore {
        async fn set_worker_reputation(&self, rid: &QRealmIdentifier, public_key: &[u8; 33], reputation: u64) -> anyhow::Result<()> {
            let key = (rid.realm_id, rid.realm_sub_id, *public_key);
            self.map.lock().unwrap().insert(key, reputation);
            Ok(())
        }
    }

    fn rid() -> QRealmIdentifier {
        QRealmIdentifier { realm_id: 1, realm_sub_id: 2 }
    }

    async fn reputation_of(store: &FakeReputationStore, public_key: &[u8; 33]) -> u64 {
        store.get_worker_reputation(&rid(), public_key).await.unwrap()
    }

    #[tokio::test]
    async fn on_time_submit_adds_reward_up_to_the_cap() -> anyhow::Result<()> {
        let store = FakeReputationStore::default();
        let public_key = [7u8; 33];
        let now = chrono::Utc::now().timestamp_millis() as u64;

        // fresh worker at 0: on-time submit adds the default reward
        store.apply_reputation_on_submit(&rid(), &public_key, now).await?;
        assert_eq!(reputation_of(&store, &public_key).await, 1);

        // a worker already at the cap stays at the cap
        store.set_worker_reputation(&rid(), &public_key, MAX_REPUTATION).await?;
        store.apply_reputation_on_submit(&rid(), &public_key, now).await?;
        assert_eq!(reputation_of(&store, &public_key).await, MAX_REPUTATION);
        Ok(())
    }

    #[tokio::test]
    async fn late_submit_slashes_but_never_underflows() -> anyhow::Result<()> {
        let store = FakeReputationStore::default();
        let public_key = [8u8; 33];
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let late_claim = now.saturating_sub(DEFAULT_JOB_DEADLINE_MS + 1);

        // late submit from a high reputation loses the default slash
        store.set_worker_reputation(&rid(), &public_key, MAX_REPUTATION).await?;
        store.apply_reputation_on_submit(&rid(), &public_key, late_claim).await?;
        assert_eq!(reputation_of(&store, &public_key).await, MAX_REPUTATION - DEFAULT_REPUTATION_SLASH);

        // a worker with less reputation than the slash saturates at zero
        store.set_worker_reputation(&rid(), &public_key, 2).await?;
        store.apply_reputation_on_submit(&rid(), &public_key, late_claim).await?;
        assert_eq!(reputation_of(&store, &public_key).await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn tag_mismatch_slashes_reputation() -> anyhow::Result<()> {
        let store = FakeReputationStore::default();
        let public_key = [9u8; 33];

        store.set_worker_reputation(&rid(), &public_key, MAX_REPUTATION).await?;
        store.apply_reputation_slash_on_tag_mismatch(&rid(), &public_key).await?;
        assert_eq!(reputation_of(&store, &public_key).await, MAX_REPUTATION - DEFAULT_REPUTATION_SLASH);

        // saturates at zero for a low-reputation worker
        store.set_worker_reputation(&rid(), &public_key, 1).await?;
        store.apply_reputation_slash_on_tag_mismatch(&rid(), &public_key).await?;
        assert_eq!(reputation_of(&store, &public_key).await, 0);
        Ok(())
    }

    #[tokio::test]
    async fn reputations_are_tracked_per_realm_and_worker() -> anyhow::Result<()> {
        let store = FakeReputationStore::default();
        let public_key_a = [1u8; 33];
        let public_key_b = [2u8; 33];
        let other_rid = QRealmIdentifier { realm_id: 9, realm_sub_id: 9 };
        let now = chrono::Utc::now().timestamp_millis() as u64;

        store.apply_reputation_on_submit(&rid(), &public_key_a, now).await?;
        store.apply_reputation_on_submit(&rid(), &public_key_a, now).await?;
        store.apply_reputation_on_submit(&rid(), &public_key_b, now).await?;
        store.apply_reputation_on_submit(&other_rid, &public_key_a, now).await?;

        assert_eq!(reputation_of(&store, &public_key_a).await, 2);
        assert_eq!(reputation_of(&store, &public_key_b).await, 1);
        assert_eq!(
            store.get_worker_reputation(&other_rid, &public_key_a).await?,
            1
        );
        Ok(())
    }
}
