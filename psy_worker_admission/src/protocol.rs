use std::{fmt, sync::atomic::{AtomicBool, Ordering}};

use rand::{rngs::OsRng, RngCore};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{AdmissionError as Error, Result};

/// Fixed-size bytes are lowercase hex on the wire, never an unbounded array.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedBytes<N> {
    pub fn random() -> Self {
        let mut bytes = [0; N];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Visitor<const N: usize>;
        impl<const N: usize> de::Visitor<'_> for Visitor<N> {
            type Value = FixedBytes<N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "exactly {} lowercase hexadecimal characters", N * 2)
            }
            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                if value.len() != N * 2 || value.bytes().any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)) {
                    return Err(E::custom("invalid fixed-size lowercase hex"));
                }
                let mut bytes = [0; N];
                hex::decode_to_slice(value, &mut bytes).map_err(E::custom)?;
                Ok(FixedBytes(bytes))
            }
        }
        deserializer.deserialize_str(Visitor::<N>)
    }
}

pub type Hash32 = FixedBytes<32>;
pub type WorkerKey = FixedBytes<33>;
pub type RequestId = FixedBytes<16>;
pub type PowNonce = FixedBytes<16>;

/// U64 values use decimal strings, including inside durable state records.
pub mod decimal {
    use super::*;
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) || (value.len() > 1 && value.starts_with('0')) {
            return Err(de::Error::custom("invalid canonical decimal u64"));
        }
        value.parse().map_err(de::Error::custom)
    }
}

pub fn digest(bytes: &[u8]) -> Hash32 {
    FixedBytes(Sha256::digest(bytes).into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionScope {
    pub network_id: Hash32,
    pub admission_epoch: Hash32,
    pub node_type: u8,
    pub realm_id: u32,
    pub realm_sub_id: u16,
}

impl AdmissionScope {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.node_type, 1 | 2) || self.network_id.0 == [0; 32] || self.admission_epoch.0 == [0; 32] {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.network_id.0);
        out.extend(self.admission_epoch.0);
        out.push(self.node_type);
        out.extend(self.realm_id.to_le_bytes());
        out.extend(self.realm_sub_id.to_le_bytes());
    }
    pub fn hash(&self) -> Hash32 {
        let mut bytes = b"psy-worker-admission-scope-v1\0".to_vec();
        self.encode(&mut bytes);
        digest(&bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionPolicy {
    pub version: u32,
    pub base_bits: u16,
    pub max_bits: u16,
    #[serde(with = "decimal")]
    pub challenge_ttl_ms: u64,
    #[serde(with = "decimal")]
    pub request_window_ms: u64,
    #[serde(with = "decimal")]
    pub clock_skew_ms: u64,
    #[serde(with = "decimal")]
    pub initial_cooldown_ms: u64,
    #[serde(with = "decimal")]
    pub max_cooldown_ms: u64,
    pub max_pending_challenges: u32,
    pub requests_per_minute: u32,
    pub requests_per_key_per_minute: u32,
    /// Leases and reservations held at once across all edges of the scope.
    pub task_budget: u32,
    /// Absolute cap for reputation 1 to 3, inside task_budget. Never scaled by
    /// the number of identities and never borrowed from the remainder.
    pub low_reputation_budget: u32,
    /// How long an edge may hold a reservation before attaching a job.
    #[serde(with = "decimal")]
    pub reservation_ttl_ms: u64,
    /// Upper bound for the per-circuit hard deadline the edge supplies.
    #[serde(with = "decimal")]
    pub max_lease_ms: u64,
    /// Server-side verification bound; overrunning it is an infrastructure failure.
    #[serde(with = "decimal")]
    pub verification_ttl_ms: u64,
    /// How long claim receipts stay queryable after their lease deadline.
    #[serde(with = "decimal")]
    pub receipt_retention_ms: u64,
}

impl AdmissionPolicy {
    /// base_bits is deliberately mandatory; production hardware must be measured.
    pub fn for_base_bits(base_bits: u16) -> Self {
        Self { version: 1, base_bits, max_bits: base_bits.saturating_add(3).min(255), challenge_ttl_ms: 600_000,
            request_window_ms: 60_000, clock_skew_ms: 30_000, initial_cooldown_ms: 60_000,
            max_cooldown_ms: 3_600_000, max_pending_challenges: 1024, requests_per_minute: 6000,
            requests_per_key_per_minute: 120, task_budget: 256, low_reputation_budget: 52,
            reservation_ttl_ms: 30_000, max_lease_ms: 900_000, verification_ttl_ms: 120_000,
            receipt_retention_ms: 3_600_000 }
    }
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 || self.base_bits == 0 || self.base_bits > self.max_bits || self.max_bits > 255
            || !(1000..=86_400_000).contains(&self.challenge_ttl_ms)
            || !(1000..=300_000).contains(&self.request_window_ms) || self.clock_skew_ms > 60_000
            || self.initial_cooldown_ms > self.max_cooldown_ms || self.max_cooldown_ms > 86_400_000
            || self.max_pending_challenges == 0 || self.max_pending_challenges > 100_000
            || self.requests_per_minute == 0 || self.requests_per_key_per_minute == 0
            || self.task_budget == 0 || self.task_budget > 100_000
            || self.low_reputation_budget == 0 || self.low_reputation_budget > self.task_budget
            || !(1000..=300_000).contains(&self.reservation_ttl_ms)
            || !(1000..=86_400_000).contains(&self.max_lease_ms)
            || !(1000..=3_600_000).contains(&self.verification_ttl_ms)
            || !(60_000..=604_800_000).contains(&self.receipt_retention_ms) {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
    pub fn max_inflight(reputation: u8) -> u8 {
        match reputation { 0 => 0, 1..=3 => 1, 4..=6 => 2, _ => 4 }
    }
    pub fn bits_for(&self, violations: u64) -> u16 {
        (self.base_bits + violations.min(3) as u16).min(self.max_bits)
    }
    pub fn cooldown_for(&self, violations: u64) -> u64 {
        self.initial_cooldown_ms.saturating_mul(1u64 << violations.saturating_sub(1).min(32)).min(self.max_cooldown_ms)
    }
    pub fn hash(&self) -> Hash32 {
        // Configuration fingerprint only; the cryptographic wire protocol below
        // always uses explicit binary encoding.
        digest(&serde_json::to_vec(self).expect("serializable policy"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowChallenge {
    pub protocol_version: u16,
    pub algorithm: u8,
    pub scope: AdmissionScope,
    pub worker_public_key: WorkerKey,
    #[serde(with = "decimal")]
    pub generation: u64,
    pub policy_version: u32,
    #[serde(with = "decimal")]
    pub issued_at_ms: u64,
    #[serde(with = "decimal")]
    pub expires_at_ms: u64,
    pub difficulty_bits: u16,
    pub random: Hash32,
}

impl PowChallenge {
    pub fn id(&self) -> Hash32 {
        let mut bytes = b"psy-worker-admission-challenge-v1\0".to_vec();
        bytes.extend(self.protocol_version.to_le_bytes());
        bytes.push(self.algorithm);
        self.scope.encode(&mut bytes);
        bytes.extend(self.worker_public_key.0);
        bytes.extend(self.generation.to_le_bytes());
        bytes.extend(self.policy_version.to_le_bytes());
        bytes.extend(self.issued_at_ms.to_le_bytes());
        bytes.extend(self.expires_at_ms.to_le_bytes());
        bytes.extend(self.difficulty_bits.to_le_bytes());
        bytes.extend(self.random.0);
        digest(&bytes)
    }
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        PublicKey::from_slice(&self.worker_public_key.0).map_err(|_| Error::InvalidRequest)?;
        if self.protocol_version != 1 || self.algorithm != 1 || self.difficulty_bits == 0
            || self.difficulty_bits > 255 || self.expires_at_ms <= self.issued_at_ms || self.policy_version == 0 {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
    pub fn verify(&self, nonce: PowNonce) -> Result<()> {
        self.validate()?;
        if leading_zero_bits(&solution_hash(self.id(), nonce).0) < self.difficulty_bits {
            return Err(Error::InvalidPow);
        }
        Ok(())
    }
}

pub fn solution_hash(challenge_id: Hash32, nonce: PowNonce) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update(b"psy-worker-admission-solution-v1\0");
    hasher.update(challenge_id.0);
    hasher.update(nonce.0);
    FixedBytes(hasher.finalize().into())
}

pub fn leading_zero_bits(bytes: &[u8; 32]) -> u16 {
    bytes.iter().take_while(|&&b| b == 0).count() as u16 * 8
        + bytes.iter().find(|&&b| b != 0).map_or(0, |b| b.leading_zeros() as u16)
}

/// A bounded, cancellable batch for a worker blocking thread. Callers check
/// expiry/state between batches; this never runs on an async executor thread.
pub fn solve_batch(challenge: &PowChallenge, start: u128, attempts: u64, cancel: &AtomicBool) -> Result<Option<PowNonce>> {
    challenge.validate()?;
    let id = challenge.id();
    let mut prefix = Sha256::new();
    prefix.update(b"psy-worker-admission-solution-v1\0");
    prefix.update(id.0);
    for offset in 0..attempts {
        if offset % 1024 == 0 && cancel.load(Ordering::Relaxed) { return Ok(None); }
        let candidate = start.checked_add(offset as u128).ok_or(Error::InvalidRequest)?;
        let nonce = FixedBytes(candidate.to_le_bytes());
        let mut hasher = prefix.clone();
        hasher.update(nonce.0);
        if leading_zero_bits(&hasher.finalize().into()) >= challenge.difficulty_bits { return Ok(Some(nonce)); }
    }
    Ok(None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionMethod { GetStatus, GetChallenge, SubmitPow, GetRequestStatus, ClaimTask, SubmitProof }

impl AdmissionMethod {
    fn id(self) -> u16 { match self { Self::GetStatus => 1, Self::GetChallenge => 2, Self::SubmitPow => 3, Self::GetRequestStatus => 4,
        Self::ClaimTask => 5, Self::SubmitProof => 6 } }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAuth {
    pub scope: AdmissionScope,
    pub public_key: WorkerKey,
    pub method: AdmissionMethod,
    pub request_id: RequestId,
    #[serde(with = "decimal")]
    pub issued_at_ms: u64,
    #[serde(with = "decimal")]
    pub valid_until_ms: u64,
    #[serde(with = "decimal")]
    pub expected_generation: u64,
    pub payload_hash: Hash32,
    pub signature: FixedBytes<64>,
}

impl RequestAuth {
    pub fn signing_hash(&self) -> Hash32 {
        let mut bytes = b"psy-worker-rpc-v2\0".to_vec();
        self.scope.encode(&mut bytes);
        bytes.extend(self.public_key.0);
        bytes.extend(self.method.id().to_le_bytes());
        bytes.extend(self.request_id.0);
        bytes.extend(self.issued_at_ms.to_le_bytes());
        bytes.extend(self.valid_until_ms.to_le_bytes());
        bytes.extend(self.expected_generation.to_le_bytes());
        bytes.extend(self.payload_hash.0);
        digest(&bytes)
    }
    pub fn sign(&mut self, secret: &SecretKey) -> Result<()> {
        let secp = Secp256k1::new();
        if PublicKey::from_secret_key(&secp, secret).serialize() != self.public_key.0 { return Err(Error::InvalidSignature); }
        self.signature = FixedBytes(secp.sign_ecdsa(Message::from_digest(self.signing_hash().0), secret).serialize_compact());
        Ok(())
    }
    pub fn verify(&self, scope: &AdmissionScope, policy: &AdmissionPolicy, method: AdmissionMethod, payload: Hash32, now: u64) -> Result<()> {
        if &self.scope != scope { return Err(Error::AdmissionStale); }
        if self.method != method || self.payload_hash != payload { return Err(Error::InvalidSignature); }
        let window = self.valid_until_ms.checked_sub(self.issued_at_ms).ok_or(Error::InvalidRequest)?;
        if window == 0 || window > policy.request_window_ms { return Err(Error::InvalidRequest); }
        if now >= self.valid_until_ms || self.issued_at_ms > now.saturating_add(policy.clock_skew_ms) { return Err(Error::RequestExpired); }
        let key = PublicKey::from_slice(&self.public_key.0).map_err(|_| Error::InvalidSignature)?;
        let sig = Signature::from_compact(&self.signature.0).map_err(|_| Error::InvalidSignature)?;
        Secp256k1::verification_only().verify_ecdsa(Message::from_digest(self.signing_hash().0), &sig, &key).map_err(|_| Error::InvalidSignature)
    }
}

pub fn empty_payload() -> Hash32 { digest(&[]) }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowSolution { pub challenge_id: Hash32, pub nonce: PowNonce }

impl PowSolution {
    pub fn payload_hash(&self) -> Hash32 {
        let mut bytes = self.challenge_id.0.to_vec();
        bytes.extend(self.nonce.0);
        digest(&bytes)
    }
}

pub fn request_status_payload(request_id: RequestId) -> Hash32 { digest(&request_id.0) }
