use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_node_core::psy_temp_db::{
    JobClaimRecord, QTempDBJobClaimInfoWriter, QTempDBJobClaimRecordStore, QTempDBWorkerReputationStore, WorkerReputationRecord,
};

use super::policy::{self, Eligibility, ReputationEvent};
use crate::constants::worker_reputation::REPUTATION_CAS_ATTEMPTS;

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

/// How a worker was admitted to claim a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerAdmission {
    Eligible,
    /// A probation slot reserved at this time. Release it if no job is handed out.
    Probation { reserved_at_ms: u64 },
}

fn log_change(
    rid: &QRealmIdentifier,
    public_key: &[u8; 33],
    reason: &str,
    unique_pending_id: u64,
    job: &str,
    old: &WorkerReputationRecord,
    new: &WorkerReputationRecord,
) {
    let worker = hex::encode(public_key);
    if new.score < old.score || new.strikes > old.strikes {
        tracing::warn!(
            event = "worker_reputation",
            reason,
            realm = rid.realm_id,
            subrealm = rid.realm_sub_id,
            worker = %worker,
            upid = unique_pending_id,
            job,
            old = old.score,
            new = new.score,
            strikes = new.strikes,
            eligible_at = (new.score == 0).then(|| new.last_penalty_ms.saturating_add(policy::cooldown_ms(new.strikes))),
            "worker reputation penalty"
        );
    } else {
        tracing::debug!(
            event = "worker_reputation",
            reason,
            realm = rid.realm_id,
            subrealm = rid.realm_sub_id,
            worker = %worker,
            upid = unique_pending_id,
            job,
            old = old.score,
            new = new.score,
            strikes = new.strikes,
            "worker reputation update"
        );
    }
}

#[async_trait]
pub trait WorkerReputationOps: QTempDBWorkerReputationStore + Sync {
    /// Applies `update` with compare-and-set, re-reading on conflict. `update` returns `None` when
    /// nothing changes. Returns the record before and after the write, if one was made.
    async fn update_worker_reputation<F>(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        update: F,
    ) -> anyhow::Result<Option<(WorkerReputationRecord, WorkerReputationRecord)>>
    where
        F: Fn(&WorkerReputationRecord) -> Option<WorkerReputationRecord> + Send + Sync,
    {
        for _ in 0..REPUTATION_CAS_ATTEMPTS {
            let (current, raw) = self.get_worker_reputation_record(rid, public_key).await?;
            let Some(next) = update(&current) else {
                return Ok(None);
            };
            if self
                .compare_and_set_worker_reputation_record(rid, public_key, raw.as_deref(), &next)
                .await?
            {
                return Ok(Some((current, next)));
            }
        }
        anyhow::bail!("worker reputation update lost {} compare-and-set races", REPUTATION_CAS_ATTEMPTS)
    }

    async fn apply_worker_reputation_event(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        event: ReputationEvent,
        unique_pending_id: u64,
        job: &str,
    ) -> anyhow::Result<()> {
        let now = now_ms();
        if let Some((old, new)) = self
            .update_worker_reputation(rid, public_key, |record| policy::apply(record, event, now))
            .await?
        {
            log_change(rid, public_key, event.reason(), unique_pending_id, job, &old, &new);
        }
        Ok(())
    }

    /// Decides whether `public_key` may claim a job now, reserving the probation slot when its
    /// score is zero and its cooldown is over.
    async fn admit_worker(&self, rid: &QRealmIdentifier, public_key: &[u8; 33], lease_ms: u64) -> anyhow::Result<WorkerAdmission> {
        let now = now_ms();
        for _ in 0..REPUTATION_CAS_ATTEMPTS {
            let (current, raw) = self.get_worker_reputation_record(rid, public_key).await?;
            match policy::eligibility(&current, now, lease_ms) {
                Eligibility::Eligible => return Ok(WorkerAdmission::Eligible),
                Eligibility::NotEligible { retry_at_ms } => anyhow::bail!(
                    "worker not eligible: reputation must be positive; retry after {} ms",
                    retry_at_ms.saturating_sub(now)
                ),
                Eligibility::Probation => {
                    let next = policy::reserve_probation(&current, now);
                    if self
                        .compare_and_set_worker_reputation_record(rid, public_key, raw.as_deref(), &next)
                        .await?
                    {
                        tracing::info!(
                            event = "worker_reputation",
                            reason = "probation_reserved",
                            realm = rid.realm_id,
                            subrealm = rid.realm_sub_id,
                            worker = %hex::encode(public_key),
                            strikes = next.strikes,
                            "worker admitted on probation"
                        );
                        return Ok(WorkerAdmission::Probation {
                            reserved_at_ms: next.probation_claim_ms,
                        });
                    }
                }
            }
        }
        anyhow::bail!("worker admission lost {} compare-and-set races", REPUTATION_CAS_ATTEMPTS)
    }

    /// Frees a probation slot that did not lead to a claim.
    async fn release_probation(&self, rid: &QRealmIdentifier, public_key: &[u8; 33], reserved_at_ms: u64) -> anyhow::Result<()> {
        self.update_worker_reputation(rid, public_key, |record| policy::release_probation(record, reserved_at_ms))
            .await?;
        Ok(())
    }

    /// Records `public_key`'s claim of a job, replacing any previous claim. If the previous
    /// claim lapsed (section 7 of the design), its holder is charged once: only the caller whose
    /// compare-and-set replaced that claim applies the penalty.
    async fn record_job_claim<JobId>(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        public_key: &[u8; 33],
        already_submitted: bool,
        lease_ms: u64,
    ) -> anyhow::Result<()>
    where
        Self: QTempDBJobClaimRecordStore<JobId> + QTempDBJobClaimInfoWriter<JobId>,
        JobId: Copy + std::fmt::Debug + Send + Sync + 'static,
    {
        let now = now_ms();
        let claim = JobClaimRecord::open(*public_key, now);
        for _ in 0..REPUTATION_CAS_ATTEMPTS {
            let (previous, raw) = match self.get_job_claim_record(rid, unique_pending_id, job_id).await {
                Ok(Some((previous, raw))) => (Some(previous), Some(raw)),
                Ok(None) => (None, None),
                Err(err) => {
                    // An unreadable claim must not block the job; overwrite it without settling.
                    tracing::error!(upid = unique_pending_id, job = ?job_id, "replacing unreadable job claim: {:?}", err);
                    return self.set_job_claim(rid, unique_pending_id, job_id, public_key, now).await;
                }
            };
            if !self
                .compare_and_set_job_claim_record(rid, unique_pending_id, job_id, raw.as_deref(), &claim)
                .await?
            {
                continue;
            }
            if let Some(previous) = previous.filter(|previous| policy::previous_claim_lapsed(previous, already_submitted, now, lease_ms)) {
                if let Err(err) = self
                    .apply_worker_reputation_event(
                        rid,
                        &previous.public_key,
                        ReputationEvent::LeaseExpired,
                        unique_pending_id,
                        &format!("{:?}", job_id),
                    )
                    .await
                {
                    tracing::error!(upid = unique_pending_id, job = ?job_id, "lease-expiry reputation update failed: {:?}", err);
                }
            }
            return Ok(());
        }
        anyhow::bail!("job claim lost {} compare-and-set races", REPUTATION_CAS_ATTEMPTS)
    }

    /// Settles the claim `(public_key, claim_time_ms)` after its proof was accepted, rewarding the
    /// claimant once. Does nothing if the claim was already settled or has been replaced.
    async fn settle_job_claim_success<JobId>(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        public_key: &[u8; 33],
        claim_time_ms: u64,
        lease_ms: u64,
    ) -> anyhow::Result<()>
    where
        Self: QTempDBJobClaimRecordStore<JobId>,
        JobId: Copy + std::fmt::Debug + Send + Sync + 'static,
    {
        let now = now_ms();
        for _ in 0..REPUTATION_CAS_ATTEMPTS {
            let Some((claim, raw)) = self.get_job_claim_record(rid, unique_pending_id, job_id).await? else {
                return Ok(());
            };
            if claim.settled || claim.public_key != *public_key || claim.claim_time_ms != claim_time_ms {
                tracing::debug!(upid = unique_pending_id, job = ?job_id, "job claim already settled or replaced; no reputation change");
                return Ok(());
            }
            let settled = JobClaimRecord { settled: true, ..claim };
            if self
                .compare_and_set_job_claim_record(rid, unique_pending_id, job_id, Some(&raw), &settled)
                .await?
            {
                return self
                    .apply_worker_reputation_event(
                        rid,
                        public_key,
                        policy::submit_event(claim_time_ms, now, lease_ms),
                        unique_pending_id,
                        &format!("{:?}", job_id),
                    )
                    .await;
            }
        }
        anyhow::bail!("job claim settlement lost {} compare-and-set races", REPUTATION_CAS_ATTEMPTS)
    }

    /// Charges an invalid proof to the claimant of `(claim_public_key, claim_time_ms)`, at most
    /// once per claim, and only when the submit was signed by that claimant.
    ///
    /// The submit signature covers the claim tag but not the job or the proof bytes, and the Edge
    /// does not check its expiry, so a captured request replayed with other proof bytes passes
    /// signature verification. Closing the claim on the first charge bounds the damage to one
    /// charge per claim generation, and a claim that already succeeded cannot be charged. It does
    /// not stop an attacker who sees the signed submit in flight and delivers altered bytes first:
    /// that charges the claimant once and forfeits its success reward. Removing that needs the
    /// signature to bind the job id and a proof hash, a worker and SDK change.
    ///
    /// If the charge itself fails after the claim was closed, the claim stays closed uncharged.
    async fn settle_job_claim_invalid_proof<JobId>(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        signer: &[u8; 33],
        claim_public_key: &[u8; 33],
        claim_time_ms: u64,
    ) -> anyhow::Result<()>
    where
        Self: QTempDBJobClaimRecordStore<JobId>,
        JobId: Copy + std::fmt::Debug + Send + Sync + 'static,
    {
        if signer != claim_public_key {
            tracing::info!(upid = unique_pending_id, job = ?job_id, "invalid proof not signed by the claimant; no reputation change");
            return Ok(());
        }
        for _ in 0..REPUTATION_CAS_ATTEMPTS {
            let Some((claim, raw)) = self.get_job_claim_record(rid, unique_pending_id, job_id).await? else {
                return Ok(());
            };
            if claim.settled || claim.public_key != *claim_public_key || claim.claim_time_ms != claim_time_ms {
                tracing::debug!(upid = unique_pending_id, job = ?job_id, "job claim already settled or replaced; invalid proof not charged");
                return Ok(());
            }
            let settled = JobClaimRecord { settled: true, ..claim };
            if self
                .compare_and_set_job_claim_record(rid, unique_pending_id, job_id, Some(&raw), &settled)
                .await?
            {
                return self
                    .apply_worker_reputation_event(
                        rid,
                        claim_public_key,
                        ReputationEvent::InvalidProof,
                        unique_pending_id,
                        &format!("{:?}", job_id),
                    )
                    .await;
            }
        }
        anyhow::bail!("job claim settlement lost {} compare-and-set races", REPUTATION_CAS_ATTEMPTS)
    }
}

impl<T: QTempDBWorkerReputationStore + Sync> WorkerReputationOps for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_core::job::job_id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic, QProvingJobDataID};
    use psy_node_core::psy_temp_db::{tt_get_worker_reputation_key, QTempDBWorkerReputationReader};
    use psy_node_core::store::traits::temp_db::{
        QTempDatabaseRawKVCompareAndSet, QTempDatabaseRawKVReaderBase, QTempDatabaseRawKVWriterBase,
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Before each of its first `conflicts` compare-and-sets, writes `interloper` to `key`, as a
    /// concurrent Edge would between this caller's read and its write. Each write differs (its
    /// streak counts the attempts), so a stale read never matches by accident.
    struct ConflictingStore {
        inner: InMemoryTempStore,
        key: Vec<u8>,
        interloper: WorkerReputationRecord,
        conflicts: AtomicUsize,
        attempts: AtomicUsize,
    }

    #[async_trait]
    impl QTempDatabaseRawKVReaderBase for ConflictingStore {
        async fn qtdb_raw_kv_get_value(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
            self.inner.qtdb_raw_kv_get_value(key).await
        }
        async fn qtdb_raw_kv_get_many_values(&self, keys: &[&[u8]]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
            self.inner.qtdb_raw_kv_get_many_values(keys).await
        }
        async fn qtdb_raw_kv_get_many_values_vec(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
            self.inner.qtdb_raw_kv_get_many_values_vec(keys).await
        }
        async fn qtdb_raw_kv_get_many_values_vec_owned(&self, keys: Vec<Vec<u8>>) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
            self.inner.qtdb_raw_kv_get_many_values_vec_owned(keys).await
        }
        async fn qtdb_raw_kv_contains_key(&self, key: &[u8]) -> anyhow::Result<bool> {
            self.inner.qtdb_raw_kv_contains_key(key).await
        }
    }

    #[async_trait]
    impl QTempDatabaseRawKVCompareAndSet for ConflictingStore {
        async fn qtdb_raw_kv_compare_and_set(&self, key: &[u8], expected: Option<&[u8]>, new_value: &[u8]) -> anyhow::Result<bool> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if self
                .conflicts
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                let interloper = WorkerReputationRecord {
                    streak: attempt as u8,
                    ..self.interloper
                };
                self.inner.qtdb_raw_kv_put_value(&self.key, &interloper.to_bytes()).await?;
            }
            self.inner.qtdb_raw_kv_compare_and_set(key, expected, new_value).await
        }
    }

    fn conflicting(conflicts: usize, interloper: WorkerReputationRecord) -> ConflictingStore {
        ConflictingStore {
            inner: InMemoryTempStore::new("worker-reputation-conflict".to_string(), 1, 0),
            key: tt_get_worker_reputation_key(1, 0, &A).to_vec(),
            interloper,
            conflicts: AtomicUsize::new(conflicts),
            attempts: AtomicUsize::new(0),
        }
    }

    const A: [u8; 33] = [0xa; 33];
    const B: [u8; 33] = [0xb; 33];
    const LEASE: u64 = 30_000;

    fn rid() -> QRealmIdentifier {
        QRealmIdentifier::new(1, 0)
    }

    fn store() -> Arc<InMemoryTempStore> {
        Arc::new(InMemoryTempStore::new("worker-reputation-test".to_string(), 1, 0))
    }

    fn job() -> QProvingJobDataID {
        QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: 492380,
            circuit_type: ProvingJobCircuitType::BatchDeployContractsAggregate,
            group_id: 1,
            sub_group_id: 2,
            task_index: 3,
            data_type: ProvingJobDataType::StandardProof,
            data_index: 0,
        }
    }

    async fn score(store: &InMemoryTempStore, key: &[u8; 33]) -> u64 {
        store.get_worker_reputation(&rid(), key).await.unwrap()
    }

    async fn put_record(store: &InMemoryTempStore, key: &[u8; 33], record: WorkerReputationRecord) {
        let raw_key = tt_get_worker_reputation_key(1, 0, key);
        store.qtdb_raw_kv_put_value(&raw_key, &record.to_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn update_retries_on_a_conflicting_write_and_keeps_it() {
        let store = conflicting(1, WorkerReputationRecord { score: 9, ..WorkerReputationRecord::initial() });
        store
            .apply_worker_reputation_event(&rid(), &A, ReputationEvent::LeaseExpired, 1, "job")
            .await
            .unwrap();
        // The first write lost to the interloper's 9; the retry charged 1 on top of it.
        assert_eq!(store.get_worker_reputation(&rid(), &A).await.unwrap(), 8);
        assert_eq!(store.attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn update_gives_up_after_bounded_conflicts() {
        let store = conflicting(usize::MAX, WorkerReputationRecord { score: 9, ..WorkerReputationRecord::initial() });
        let err = store
            .apply_worker_reputation_event(&rid(), &A, ReputationEvent::LeaseExpired, 1, "job")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("compare-and-set races"), "{err}");
        assert_eq!(store.attempts.load(Ordering::SeqCst), REPUTATION_CAS_ATTEMPTS);
    }

    #[tokio::test]
    async fn probation_reservation_rechecks_after_a_conflict() {
        // Another Edge reserves the slot between this caller's read and its write.
        let other = policy::reserve_probation(&WorkerReputationRecord { score: 0, ..WorkerReputationRecord::initial() }, now_ms());
        let store = conflicting(1, other);
        store
            .inner
            .qtdb_raw_kv_put_value(&tt_get_worker_reputation_key(1, 0, &A), &0u64.to_le_bytes())
            .await
            .unwrap();
        let err = store.admit_worker(&rid(), &A, LEASE).await.unwrap_err();
        assert!(err.to_string().starts_with("worker not eligible"), "{err}");
    }

    #[tokio::test]
    async fn abandoned_probation_slot_expires_after_one_lease() {
        let store = store();
        put_record(&store, &A, WorkerReputationRecord { score: 0, ..WorkerReputationRecord::initial() }).await;
        assert!(matches!(store.admit_worker(&rid(), &A, LEASE).await.unwrap(), WorkerAdmission::Probation { .. }));
        assert!(store.admit_worker(&rid(), &A, LEASE).await.is_err());
        // With a zero-length lease, the slot reserved above has already run out.
        assert!(matches!(store.admit_worker(&rid(), &A, 0).await.unwrap(), WorkerAdmission::Probation { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_updates_are_not_lost() {
        let store = store();
        put_record(&store, &A, WorkerReputationRecord { score: 10, ..WorkerReputationRecord::initial() }).await;
        let mut tasks = Vec::new();
        for i in 0..8 {
            let store = store.clone();
            let event = if i % 2 == 0 { ReputationEvent::OnTimeSuccess } else { ReputationEvent::LeaseExpired };
            tasks.push(tokio::spawn(async move {
                store.apply_worker_reputation_event(&rid(), &A, event, 1, "job").await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        // Four +1 and four -1, in any order, from 10 and never touching the bounds.
        assert_eq!(score(&store, &A).await, 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn only_one_racer_gets_the_probation_slot() {
        let store = store();
        put_record(&store, &A, WorkerReputationRecord { score: 0, ..WorkerReputationRecord::initial() }).await;
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move { store.admit_worker(&rid(), &A, LEASE).await }));
        }
        let mut admitted = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(WorkerAdmission::Probation { .. }) => admitted += 1,
                Ok(WorkerAdmission::Eligible) => panic!("a zero score is never plainly eligible"),
                Err(err) => assert!(err.to_string().starts_with("worker not eligible: reputation must be positive; retry after")),
            }
        }
        assert_eq!(admitted, 1);
    }

    #[tokio::test]
    async fn released_probation_slot_can_be_reserved_again() {
        let store = store();
        put_record(&store, &A, WorkerReputationRecord { score: 0, ..WorkerReputationRecord::initial() }).await;
        let WorkerAdmission::Probation { reserved_at_ms } = store.admit_worker(&rid(), &A, LEASE).await.unwrap() else {
            panic!("expected probation");
        };
        assert!(store.admit_worker(&rid(), &A, LEASE).await.is_err());
        store.release_probation(&rid(), &A, reserved_at_ms).await.unwrap();
        assert!(matches!(store.admit_worker(&rid(), &A, LEASE).await.unwrap(), WorkerAdmission::Probation { .. }));
    }

    #[tokio::test]
    async fn lapsed_claim_is_charged_once_when_replaced() {
        let store = store();
        // A claimed one lease ago (legacy 41-byte claim, as written before this change).
        let then = now_ms() - LEASE;
        store.set_job_claim(&rid(), 7, job(), &A, then).await.unwrap();
        store.record_job_claim(&rid(), 7, job(), &B, false, LEASE).await.unwrap();
        assert_eq!(score(&store, &A).await, 4);
        // B's fresh claim being replaced at once is not a lapse.
        store.record_job_claim(&rid(), 7, job(), &A, false, LEASE).await.unwrap();
        assert_eq!(score(&store, &B).await, 5);
        assert_eq!(score(&store, &A).await, 4);
    }

    #[tokio::test]
    async fn submitted_or_settled_claims_are_not_charged() {
        let store = store();
        let then = now_ms() - LEASE;
        store.set_job_claim(&rid(), 7, job(), &A, then).await.unwrap();
        store.record_job_claim(&rid(), 7, job(), &B, true, LEASE).await.unwrap();
        assert_eq!(score(&store, &A).await, 5);

        let (claim, _) = store.get_job_claim_record(&rid(), 7, job()).await.unwrap().unwrap();
        store
            .settle_job_claim_success(&rid(), 7, job(), &B, claim.claim_time_ms, LEASE)
            .await
            .unwrap();
        store.record_job_claim(&rid(), 7, job(), &A, false, u64::MIN).await.unwrap();
        assert_eq!(score(&store, &B).await, 6);
    }

    #[tokio::test]
    async fn the_same_worker_reclaiming_its_lapsed_job_pays_one_point() {
        // 2026-10-07, Realm1 goal 492380: the worker's own redelivered job.
        let store = store();
        store.set_job_claim(&rid(), 7, job(), &A, now_ms() - LEASE).await.unwrap();
        store.record_job_claim(&rid(), 7, job(), &A, false, LEASE).await.unwrap();
        assert_eq!(score(&store, &A).await, 4);
        let (claim, _) = store.get_job_claim_record(&rid(), 7, job()).await.unwrap().unwrap();
        store.settle_job_claim_success(&rid(), 7, job(), &A, claim.claim_time_ms, LEASE).await.unwrap();
        assert_eq!(score(&store, &A).await, 5);
    }

    #[tokio::test]
    async fn replayed_success_earns_one_point() {
        let store = store();
        store.record_job_claim(&rid(), 7, job(), &A, false, LEASE).await.unwrap();
        let (claim, _) = store.get_job_claim_record(&rid(), 7, job()).await.unwrap().unwrap();
        for _ in 0..3 {
            store.settle_job_claim_success(&rid(), 7, job(), &A, claim.claim_time_ms, LEASE).await.unwrap();
        }
        assert_eq!(score(&store, &A).await, 6);
    }

    #[tokio::test]
    async fn success_for_a_replaced_claim_does_not_credit_the_new_claimant() {
        let store = store();
        store.record_job_claim(&rid(), 7, job(), &A, false, LEASE).await.unwrap();
        let (a_claim, _) = store.get_job_claim_record(&rid(), 7, job()).await.unwrap().unwrap();
        store.record_job_claim(&rid(), 7, job(), &B, false, LEASE).await.unwrap();
        store.settle_job_claim_success(&rid(), 7, job(), &A, a_claim.claim_time_ms, LEASE).await.unwrap();
        assert_eq!(score(&store, &A).await, 5);
        assert_eq!(score(&store, &B).await, 5);
    }

    #[tokio::test]
    async fn zeroed_worker_recovers_through_probation() {
        let store = store();
        // A legacy zero, as left by the old slashing rules.
        let raw_key = tt_get_worker_reputation_key(1, 0, &A);
        store.qtdb_raw_kv_put_value(&raw_key, &0u64.to_le_bytes()).await.unwrap();

        assert!(matches!(store.admit_worker(&rid(), &A, LEASE).await.unwrap(), WorkerAdmission::Probation { .. }));
        store.record_job_claim(&rid(), 7, job(), &A, false, LEASE).await.unwrap();
        let (claim, _) = store.get_job_claim_record(&rid(), 7, job()).await.unwrap().unwrap();
        store.settle_job_claim_success(&rid(), 7, job(), &A, claim.claim_time_ms, LEASE).await.unwrap();

        assert_eq!(score(&store, &A).await, 1);
        assert_eq!(store.admit_worker(&rid(), &A, LEASE).await.unwrap(), WorkerAdmission::Eligible);
    }

    async fn claim_of(store: &InMemoryTempStore) -> JobClaimRecord {
        store.get_job_claim_record(&rid(), 7, job()).await.unwrap().unwrap().0
    }

    #[tokio::test]
    async fn invalid_proof_is_charged_once_per_claim() {
        let store = store();
        store.record_job_claim(&rid(), 7, job(), &A, false, LEASE).await.unwrap();
        let claim = claim_of(&store).await;
        for _ in 0..3 {
            store
                .settle_job_claim_invalid_proof(&rid(), 7, job(), &A, &A, claim.claim_time_ms)
                .await
                .unwrap();
        }
        assert_eq!(score(&store, &A).await, 0);
        assert!(claim_of(&store).await.settled);
        // The charged claim is closed, so its lapse is not charged again either.
        store.record_job_claim(&rid(), 7, job(), &B, false, 0).await.unwrap();
        let after = store.get_worker_reputation_record(&rid(), &A).await.unwrap().0;
        assert_eq!(after.strikes, 1);
    }

    #[tokio::test]
    async fn replayed_bad_proof_after_success_is_not_charged() {
        let store = store();
        store.record_job_claim(&rid(), 7, job(), &A, false, LEASE).await.unwrap();
        let claim = claim_of(&store).await;
        store.settle_job_claim_success(&rid(), 7, job(), &A, claim.claim_time_ms, LEASE).await.unwrap();
        store
            .settle_job_claim_invalid_proof(&rid(), 7, job(), &A, &A, claim.claim_time_ms)
            .await
            .unwrap();
        assert_eq!(score(&store, &A).await, 6);
    }

    #[tokio::test]
    async fn invalid_proof_from_a_non_claimant_or_old_claim_is_not_charged() {
        let store = store();
        store.record_job_claim(&rid(), 7, job(), &A, false, LEASE).await.unwrap();
        let a_claim = claim_of(&store).await;
        // Signed by B with A's tag: nobody is charged.
        store
            .settle_job_claim_invalid_proof(&rid(), 7, job(), &B, &A, a_claim.claim_time_ms)
            .await
            .unwrap();
        assert_eq!((score(&store, &A).await, score(&store, &B).await), (5, 5));
        // A claim generation that has been replaced is not charged.
        store.record_job_claim(&rid(), 7, job(), &B, false, LEASE).await.unwrap();
        store
            .settle_job_claim_invalid_proof(&rid(), 7, job(), &A, &A, a_claim.claim_time_ms)
            .await
            .unwrap();
        assert_eq!((score(&store, &A).await, score(&store, &B).await), (5, 5));
        assert!(!claim_of(&store).await.settled);
    }

    #[tokio::test]
    async fn invalid_proof_costs_five() {
        let store = store();
        store
            .apply_worker_reputation_event(&rid(), &A, ReputationEvent::InvalidProof, 7, "job")
            .await
            .unwrap();
        assert_eq!(score(&store, &A).await, 0);
        let err = store.admit_worker(&rid(), &A, LEASE).await.unwrap_err();
        assert!(err.to_string().contains("retry after"), "{err}");
    }
}
