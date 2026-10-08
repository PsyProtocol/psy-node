use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

/// The original claim value: public key and claim time, always open.
pub const LEGACY_JOB_CLAIM_RECORD_SIZE: usize = 41; // 33 + 8
pub const JOB_CLAIM_RECORD_SIZE: usize = 42; // 33 + 8 + 1

const JOB_CLAIM_STATE_OPEN: u8 = 0;
const JOB_CLAIM_STATE_SETTLED: u8 = 1;

/// One claim of a job by a worker. The first 41 bytes keep the legacy layout, which older readers
/// decode unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobClaimRecord {
    pub public_key: [u8; 33],
    pub claim_time_ms: u64,
    /// Reputation has been settled for this claim (a submit succeeded), so neither a replayed
    /// submit nor a later re-claim may charge or reward it again.
    pub settled: bool,
}

impl JobClaimRecord {
    pub fn open(public_key: [u8; 33], claim_time_ms: u64) -> Self {
        Self {
            public_key,
            claim_time_ms,
            settled: false,
        }
    }

    pub fn to_bytes(&self) -> [u8; JOB_CLAIM_RECORD_SIZE] {
        let mut bytes = [0u8; JOB_CLAIM_RECORD_SIZE];
        bytes[0..33].copy_from_slice(&self.public_key);
        bytes[33..41].copy_from_slice(&self.claim_time_ms.to_le_bytes());
        bytes[41] = if self.settled { JOB_CLAIM_STATE_SETTLED } else { JOB_CLAIM_STATE_OPEN };
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let settled = match bytes.len() {
            LEGACY_JOB_CLAIM_RECORD_SIZE => false,
            JOB_CLAIM_RECORD_SIZE => match bytes[41] {
                JOB_CLAIM_STATE_OPEN => false,
                JOB_CLAIM_STATE_SETTLED => true,
                state => anyhow::bail!("job claim record has unknown state {}", state),
            },
            len => anyhow::bail!("job claim record corrupt (len={})", len),
        };
        Ok(Self {
            public_key: bytes[0..33].try_into()?,
            claim_time_ms: u64::from_le_bytes(bytes[33..41].try_into()?),
            settled,
        })
    }
}

#[async_trait]
pub trait QTempDBJobClaimInfoReader<JobId> {
    async fn get_job_claim(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
    ) -> anyhow::Result<Option<([u8; 33], u64)>>;
}

#[async_trait]
pub trait QTempDBJobClaimInfoWriter<JobId> {
    async fn set_job_claim(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        public_key: &[u8; 33],
        claim_time_ms: u64,
    ) -> anyhow::Result<()>;
}

pub trait QTempDBJobClaimInfoStore<JobId>: QTempDBJobClaimInfoReader<JobId> + QTempDBJobClaimInfoWriter<JobId> {}
impl<T: QTempDBJobClaimInfoReader<JobId> + QTempDBJobClaimInfoWriter<JobId>, JobId> QTempDBJobClaimInfoStore<JobId> for T {}

/// Claim records with their settlement state, updated by compare-and-set.
#[async_trait]
pub trait QTempDBJobClaimRecordStore<JobId> {
    /// The decoded claim and its stored bytes, which a later `compare_and_set_job_claim_record`
    /// passes back as `observed`.
    async fn get_job_claim_record(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
    ) -> anyhow::Result<Option<(JobClaimRecord, Vec<u8>)>>;

    /// Writes `record` only if the stored bytes still equal `observed` (`None`: no record).
    /// Returns whether it was written.
    async fn compare_and_set_job_claim_record(
        &self,
        rid: &QRealmIdentifier,
        unique_pending_id: u64,
        job_id: JobId,
        observed: Option<&[u8]>,
        record: &JobClaimRecord,
    ) -> anyhow::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_and_keeps_the_legacy_prefix() -> anyhow::Result<()> {
        let mut record = JobClaimRecord::open([7u8; 33], 0x0102_0304_0506_0708);
        let bytes = record.to_bytes();
        assert_eq!(&bytes[0..33], &[7u8; 33]);
        assert_eq!(&bytes[33..41], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(JobClaimRecord::from_bytes(&bytes)?, record);
        record.settled = true;
        assert_eq!(JobClaimRecord::from_bytes(&record.to_bytes())?, record);
        Ok(())
    }

    #[test]
    fn legacy_record_is_open() -> anyhow::Result<()> {
        let bytes = JobClaimRecord::open([9u8; 33], 42).to_bytes();
        let legacy = JobClaimRecord::from_bytes(&bytes[0..41])?;
        assert_eq!(legacy, JobClaimRecord::open([9u8; 33], 42));
        Ok(())
    }

    #[test]
    fn bad_lengths_and_states_are_errors() {
        assert!(JobClaimRecord::from_bytes(&[0u8; 40]).is_err());
        assert!(JobClaimRecord::from_bytes(&[0u8; 43]).is_err());
        let mut bytes = JobClaimRecord::open([1u8; 33], 1).to_bytes();
        bytes[41] = 2;
        assert!(JobClaimRecord::from_bytes(&bytes).is_err());
    }
}
