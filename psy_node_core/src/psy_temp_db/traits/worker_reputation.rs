use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

/// Score of a key that has no reputation record yet.
pub const INITIAL_WORKER_REPUTATION: u64 = 5;
/// Highest score a worker can hold. Larger stored scores (set by hand) read as this value.
pub const MAX_WORKER_REPUTATION: u64 = 15;
/// The original record: the score alone as a little-endian u64.
pub const LEGACY_WORKER_REPUTATION_RECORD_SIZE: usize = 8;
pub const WORKER_REPUTATION_RECORD_SIZE: usize = 26; // 8 + 1 + 1 + 8 + 8

/// A worker's reputation in one realm/subrealm.
///
/// The score keeps the first 8 bytes of the stored value, exactly as the legacy record did, so an
/// older binary reads the right score from a new record and its 8-byte writes stay readable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerReputationRecord {
    pub score: u64,
    /// Times the score has hit zero since the last reset; sets the cooldown length.
    pub strikes: u8,
    /// On-time successes since the last penalty or strike reset.
    pub streak: u8,
    pub last_penalty_ms: u64,
    /// When the outstanding probation claim was reserved; 0 when there is none.
    pub probation_claim_ms: u64,
}

impl WorkerReputationRecord {
    pub const fn initial() -> Self {
        Self {
            score: INITIAL_WORKER_REPUTATION,
            strikes: 0,
            streak: 0,
            last_penalty_ms: 0,
            probation_claim_ms: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; WORKER_REPUTATION_RECORD_SIZE] {
        let mut bytes = [0u8; WORKER_REPUTATION_RECORD_SIZE];
        bytes[0..8].copy_from_slice(&self.score.to_le_bytes());
        bytes[8] = self.strikes;
        bytes[9] = self.streak;
        bytes[10..18].copy_from_slice(&self.last_penalty_ms.to_le_bytes());
        bytes[18..26].copy_from_slice(&self.probation_claim_ms.to_le_bytes());
        bytes
    }

    /// Decodes a stored value. An absent or empty value is a key never seen before. Scores above
    /// `MAX_WORKER_REPUTATION` are clamped. Any length other than the legacy and current sizes is
    /// an error, never a fresh record, so a corrupt entry cannot silently re-admit a worker.
    pub fn from_stored(bytes: Option<&[u8]>) -> anyhow::Result<Self> {
        let bytes = match bytes {
            None => return Ok(Self::initial()),
            Some(bytes) if bytes.is_empty() => return Ok(Self::initial()),
            Some(bytes) => bytes,
        };
        let score = |bytes: &[u8]| -> anyhow::Result<u64> {
            Ok(u64::from_le_bytes(bytes[0..8].try_into()?).min(MAX_WORKER_REPUTATION))
        };
        match bytes.len() {
            LEGACY_WORKER_REPUTATION_RECORD_SIZE => Ok(Self {
                score: score(bytes)?,
                strikes: 0,
                streak: 0,
                last_penalty_ms: 0,
                probation_claim_ms: 0,
            }),
            WORKER_REPUTATION_RECORD_SIZE => Ok(Self {
                score: score(bytes)?,
                strikes: bytes[8],
                streak: bytes[9],
                last_penalty_ms: u64::from_le_bytes(bytes[10..18].try_into()?),
                probation_claim_ms: u64::from_le_bytes(bytes[18..26].try_into()?),
            }),
            len => anyhow::bail!("worker reputation record corrupt (len={})", len),
        }
    }
}

#[async_trait]
pub trait QTempDBWorkerReputationReader {
    /// The worker's score, clamped to `MAX_WORKER_REPUTATION`.
    async fn get_worker_reputation(&self, rid: &QRealmIdentifier, public_key: &[u8; 33]) -> anyhow::Result<u64>;

    /// The decoded record and the stored bytes, which a later
    /// `compare_and_set_worker_reputation_record` passes back as `observed`.
    async fn get_worker_reputation_record(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
    ) -> anyhow::Result<(WorkerReputationRecord, Option<Vec<u8>>)>;
}

#[async_trait]
pub trait QTempDBWorkerReputationWriter {
    /// Writes `record` only if the stored bytes still equal `observed` (`None`: no record).
    /// Returns whether it was written.
    async fn compare_and_set_worker_reputation_record(
        &self,
        rid: &QRealmIdentifier,
        public_key: &[u8; 33],
        observed: Option<&[u8]>,
        record: &WorkerReputationRecord,
    ) -> anyhow::Result<bool>;
}

pub trait QTempDBWorkerReputationStore: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter {}
impl<T: QTempDBWorkerReputationReader + QTempDBWorkerReputationWriter> QTempDBWorkerReputationStore for T {}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> WorkerReputationRecord {
        WorkerReputationRecord {
            score: 12,
            strikes: 3,
            streak: 4,
            last_penalty_ms: 0x0102_0304_0506_0708,
            probation_claim_ms: 0x1112_1314_1516_1718,
        }
    }

    #[test]
    fn record_round_trips_through_its_bytes() -> anyhow::Result<()> {
        let bytes = record().to_bytes();
        assert_eq!(&bytes[0..8], &12u64.to_le_bytes());
        assert_eq!(WorkerReputationRecord::from_stored(Some(&bytes))?, record());
        Ok(())
    }

    #[test]
    fn absent_or_empty_value_is_a_new_worker() -> anyhow::Result<()> {
        assert_eq!(WorkerReputationRecord::from_stored(None)?, WorkerReputationRecord::initial());
        assert_eq!(WorkerReputationRecord::from_stored(Some(&[]))?, WorkerReputationRecord::initial());
        assert_eq!(WorkerReputationRecord::initial().score, 5);
        Ok(())
    }

    #[test]
    fn legacy_record_keeps_its_score_with_no_history() -> anyhow::Result<()> {
        for (stored, expected) in [(0u64, 0u64), (10, 10), (15, 15), (100, 15)] {
            let rec = WorkerReputationRecord::from_stored(Some(&stored.to_le_bytes()))?;
            assert_eq!(rec.score, expected);
            assert_eq!((rec.strikes, rec.streak, rec.last_penalty_ms, rec.probation_claim_ms), (0, 0, 0, 0));
        }
        Ok(())
    }

    #[test]
    fn oversized_current_record_score_is_clamped() -> anyhow::Result<()> {
        let mut bytes = record().to_bytes();
        bytes[0..8].copy_from_slice(&100u64.to_le_bytes());
        assert_eq!(WorkerReputationRecord::from_stored(Some(&bytes))?.score, 15);
        Ok(())
    }

    #[test]
    fn legacy_reader_sees_the_score_of_a_current_record() {
        // The pre-change reader decoded `v[0..8]` whenever `v.len() >= 8`.
        let bytes = record().to_bytes();
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 12);
    }

    #[test]
    fn other_lengths_are_corrupt() {
        for len in [1usize, 7, 9, 25, 27, 41] {
            let err = WorkerReputationRecord::from_stored(Some(&vec![0u8; len])).unwrap_err();
            assert!(err.to_string().contains("corrupt"), "len {len}: {err}");
        }
    }
}
