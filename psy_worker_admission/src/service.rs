use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{protocol::*, store::*, AdmissionError as Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionStatus {
    pub scope: AdmissionScope,
    pub mode: String,
    /// Deliberately false until lease enforcement and the V2 task API ship.
    pub task_enforcement: bool,
    pub status: AdmissionState,
    #[serde(with = "decimal")]
    pub generation: u64,
    pub reputation: u8,
    /// Policy limit, not an assertion that legacy task RPCs enforce this limit.
    pub max_inflight: u8,
    #[serde(with = "decimal")]
    pub cooldown_until_ms: u64,
    pub policy_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse { pub challenge_id: Hash32, pub challenge: PowChallenge }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationResponse { pub receipt: ActivationReceipt, pub current: AdmissionStatus }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestStatusResponse {
    pub receipt: Option<ActivationReceipt>,
    pub currently_active: bool,
    pub current: AdmissionStatus,
}

#[derive(Clone)]
pub struct AdmissionService {
    scope: AdmissionScope,
    policy: AdmissionPolicy,
    store: Arc<dyn AtomicAdmissionStore>,
}

impl AdmissionService {
    pub fn new(scope: AdmissionScope, policy: AdmissionPolicy, store: Arc<dyn AtomicAdmissionStore>) -> Result<Self> {
        scope.validate()?;
        policy.validate()?;
        Ok(Self { scope, policy, store })
    }
    pub fn scope(&self) -> &AdmissionScope { &self.scope }
    pub fn policy(&self) -> &AdmissionPolicy { &self.policy }

    pub(crate) async fn authenticate(&self, auth: &RequestAuth, method: AdmissionMethod, payload: Hash32) -> Result<()> {
        let now = self.store.request_budget(None).await?;
        auth.verify(&self.scope, &self.policy, method, payload, now)?;
        self.store.request_budget(Some(auth.public_key)).await?;
        Ok(())
    }
    pub(crate) fn decode(&self, key: WorkerKey, snapshot: &Snapshot) -> Result<WorkerRecord> {
        let record: WorkerRecord = match &snapshot.raw {
            Some(raw) => serde_json::from_slice(raw).map_err(|_| Error::StateCorrupt)?,
            None => WorkerRecord::new(&self.scope, &self.policy, key),
        };
        record.validate(&self.scope, &self.policy, key)?;
        Ok(record)
    }
    pub(crate) fn status(&self, record: &WorkerRecord) -> AdmissionStatus {
        let max_inflight = AdmissionPolicy::max_inflight(record.reputation);
        AdmissionStatus { scope: self.scope.clone(), mode: "observe".into(), task_enforcement: false,
            status: record.state, generation: record.generation, reputation: record.reputation, max_inflight,
            cooldown_until_ms: record.cooldown_until_ms, policy_version: self.policy.version }
    }
    async fn save(&self, snapshot: Snapshot, record: &WorkerRecord, deadline: u64, event: &str) -> Result<bool> {
        record.validate(&self.scope, &self.policy, record.public_key)?;
        let pending_expires_at_ms = record.pending_challenge.as_ref().map(|c| c.expires_at_ms);
        let provisional_ttl_ms = record.provisional().then(|| {
            pending_expires_at_ms.unwrap_or(snapshot.now_ms).saturating_sub(snapshot.now_ms)
                .saturating_add(self.policy.request_window_ms).saturating_add(self.policy.clock_skew_ms)
        });
        let audit_json = serde_json::to_vec(&serde_json::json!({
            "event": event, "public_key": record.public_key, "generation": record.generation.to_string(),
            "state": record.state, "reputation": record.reputation, "at_ms": snapshot.now_ms.to_string(),
            "activation": record.last_activation, "revocation": record.last_revocation,
        })).map_err(|_| Error::StateCorrupt)?;
        self.store.compare_exchange(record.public_key, CasWrite {
            expected: snapshot.raw, replacement: serde_json::to_vec(record).map_err(|_| Error::StateCorrupt)?,
            valid_before_ms: deadline, provisional_ttl_ms, pending_expires_at_ms, audit_json,
        }).await
    }

    pub async fn get_status(&self, auth: RequestAuth) -> Result<AdmissionStatus> {
        self.authenticate(&auth, AdmissionMethod::GetStatus, empty_payload()).await?;
        let snapshot = self.store.load(auth.public_key).await?;
        Ok(self.status(&self.decode(auth.public_key, &snapshot)?))
    }

    pub async fn get_challenge(&self, auth: RequestAuth) -> Result<ChallengeResponse> {
        self.authenticate(&auth, AdmissionMethod::GetChallenge, empty_payload()).await?;
        for _ in 0..32 {
            let snapshot = self.store.load(auth.public_key).await?;
            let mut record = self.decode(auth.public_key, &snapshot)?;
            if snapshot.now_ms >= auth.valid_until_ms { return Err(Error::RequestExpired); }
            if record.generation != auth.expected_generation { return Err(Error::AdmissionStale); }
            if record.state == AdmissionState::Active { return Err(Error::AlreadyActive); }
            if snapshot.now_ms < record.cooldown_until_ms { return Err(Error::Cooldown { retry_after_ms: record.cooldown_until_ms - snapshot.now_ms }); }
            if let Some(challenge) = &record.pending_challenge {
                if snapshot.now_ms < challenge.expires_at_ms {
                    return Ok(ChallengeResponse { challenge_id: challenge.id(), challenge: challenge.clone() });
                }
            }
            let challenge = PowChallenge { protocol_version: 1, algorithm: 1, scope: self.scope.clone(),
                worker_public_key: auth.public_key, generation: record.generation, policy_version: self.policy.version,
                issued_at_ms: snapshot.now_ms, expires_at_ms: snapshot.now_ms.checked_add(self.policy.challenge_ttl_ms).ok_or(Error::StateCorrupt)?,
                difficulty_bits: self.policy.bits_for(record.violations), random: FixedBytes::random() };
            record.pending_challenge = Some(challenge.clone());
            if self.save(snapshot, &record, auth.valid_until_ms, "challenge_issued").await? {
                return Ok(ChallengeResponse { challenge_id: challenge.id(), challenge });
            }
        }
        Err(Error::RequestConflict)
    }

    pub async fn submit_pow(&self, auth: RequestAuth, solution: PowSolution) -> Result<ActivationResponse> {
        self.authenticate(&auth, AdmissionMethod::SubmitPow, solution.payload_hash()).await?;
        for _ in 0..32 {
            let snapshot = self.store.load(auth.public_key).await?;
            let mut record = self.decode(auth.public_key, &snapshot)?;
            if snapshot.now_ms >= auth.valid_until_ms { return Err(Error::RequestExpired); }
            if let Some(receipt) = &record.last_activation {
                if receipt.request_id == auth.request_id {
                    if receipt.request_hash != auth.signing_hash() { return Err(Error::RequestConflict); }
                    // A historical receipt is a receipt, never another activation.
                    return Ok(ActivationResponse { receipt: receipt.clone(), current: self.status(&record) });
                }
            }
            if record.generation != auth.expected_generation { return Err(Error::AdmissionStale); }
            if record.state == AdmissionState::Active { return Err(Error::AlreadyActive); }
            if snapshot.now_ms < record.cooldown_until_ms { return Err(Error::Cooldown { retry_after_ms: record.cooldown_until_ms - snapshot.now_ms }); }
            let challenge = record.pending_challenge.as_ref().ok_or(Error::ChallengeStale)?;
            if challenge.id() != solution.challenge_id { return Err(Error::ChallengeStale); }
            if snapshot.now_ms >= challenge.expires_at_ms { return Err(Error::ChallengeExpired); }
            challenge.verify(solution.nonce)?;
            let deadline = auth.valid_until_ms.min(challenge.expires_at_ms);
            let receipt = ActivationReceipt { receipt_id: auth.signing_hash(), request_id: auth.request_id,
                request_hash: auth.signing_hash(), challenge_id: solution.challenge_id, generation: record.generation };
            record.pending_challenge = None;
            record.state = AdmissionState::Active;
            record.reputation = 3;
            record.cooldown_until_ms = 0;
            record.last_activation = Some(receipt.clone());
            if self.save(snapshot, &record, deadline, "pow_activated").await? {
                return Ok(ActivationResponse { receipt, current: self.status(&record) });
            }
        }
        Err(Error::RequestConflict)
    }

    pub async fn get_request_status(&self, auth: RequestAuth, request_id: RequestId) -> Result<RequestStatusResponse> {
        self.authenticate(&auth, AdmissionMethod::GetRequestStatus, request_status_payload(request_id)).await?;
        let snapshot = self.store.load(auth.public_key).await?;
        let record = self.decode(auth.public_key, &snapshot)?;
        let receipt = record.last_activation.as_ref().filter(|r| r.request_id == request_id).cloned();
        let currently_active = receipt.as_ref().is_some_and(|r| record.state == AdmissionState::Active && record.generation == r.generation);
        Ok(RequestStatusResponse { receipt, currently_active, current: self.status(&record) })
    }

    /// Pure transition shared with the lease service: zero reputation, a new
    /// generation and, for attributable violations, a longer cooldown.
    pub(crate) fn revoke(&self, record: &mut WorkerRecord, now_ms: u64, event_id: Hash32, evidence_hash: Hash32, attributable: bool) -> Result<RevocationReceipt> {
        if record.state != AdmissionState::Active { return Err(Error::PowRequired); }
        let from_generation = record.generation;
        let new_generation = from_generation.checked_add(1).ok_or(Error::StateCorrupt)?;
        if attributable {
            record.violations = record.violations.checked_add(1).ok_or(Error::StateCorrupt)?;
            record.cooldown_until_ms = now_ms.checked_add(self.policy.cooldown_for(record.violations)).ok_or(Error::StateCorrupt)?;
        }
        let receipt = RevocationReceipt { event_id, evidence_hash, from_generation, new_generation };
        record.generation = new_generation;
        record.reputation = 0;
        record.state = AdmissionState::NeedsPow;
        record.pending_challenge = None;
        record.last_revocation = Some(receipt.clone());
        Ok(receipt)
    }

    /// Internal only. Call only after authenticated, current-lease evidence has
    /// been established. Deliberately absent from the public RPC trait.
    pub async fn revoke_for_verified_violation(&self, key: WorkerKey, generation: u64, event_id: Hash32, evidence_hash: Hash32) -> Result<RevocationReceipt> {
        for _ in 0..32 {
            let snapshot = self.store.load(key).await?;
            let mut record = self.decode(key, &snapshot)?;
            if let Some(receipt) = &record.last_revocation {
                if receipt.event_id == event_id {
                    if receipt.from_generation != generation || receipt.evidence_hash != evidence_hash { return Err(Error::RequestConflict); }
                    return Ok(receipt.clone());
                }
            }
            if record.generation != generation { return Err(Error::AdmissionStale); }
            let receipt = self.revoke(&mut record, snapshot.now_ms, event_id, evidence_hash, true)?;
            if self.save(snapshot, &record, u64::MAX, "verified_violation").await? { return Ok(receipt); }
        }
        Err(Error::RequestConflict)
    }
}
