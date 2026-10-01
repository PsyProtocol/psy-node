use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

pub const GUTA_IN_FLIGHT_RECORD_SIZE: usize = 72; // 32 + 32 + 8

/// The last GUTA update the Coordinator Edge accepted for one submitting Realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GutaInFlightRecord {
    pub old_realm_root: [u8; 32],
    pub new_realm_root: [u8; 32],
    /// The committed checkpoint ID the Edge read when it accepted the update.
    pub accepted_at_checkpoint_id: u64,
}

impl GutaInFlightRecord {
    pub fn to_bytes(&self) -> [u8; GUTA_IN_FLIGHT_RECORD_SIZE] {
        let mut bytes = [0u8; GUTA_IN_FLIGHT_RECORD_SIZE];
        bytes[0..32].copy_from_slice(&self.old_realm_root);
        bytes[32..64].copy_from_slice(&self.new_realm_root);
        bytes[64..72].copy_from_slice(&self.accepted_at_checkpoint_id.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() == GUTA_IN_FLIGHT_RECORD_SIZE,
            "GUTA in-flight record must be {} bytes, got {}",
            GUTA_IN_FLIGHT_RECORD_SIZE,
            bytes.len()
        );
        Ok(Self {
            old_realm_root: bytes[0..32].try_into()?,
            new_realm_root: bytes[32..64].try_into()?,
            accepted_at_checkpoint_id: u64::from_le_bytes(bytes[64..72].try_into()?),
        })
    }
}

#[async_trait]
pub trait QTempDBGutaInFlightStore {
    /// The record for `submitting_realm_id` and its stored bytes, which a later
    /// `claim_guta_in_flight` passes back as `observed`.
    async fn get_guta_in_flight(
        &self,
        rid: &QRealmIdentifier,
        submitting_realm_id: u64,
    ) -> anyhow::Result<Option<(GutaInFlightRecord, Vec<u8>)>>;

    /// Writes `record` only if the stored bytes still equal `observed` (`None`: no record).
    /// Returns whether it was written.
    async fn claim_guta_in_flight(
        &self,
        rid: &QRealmIdentifier,
        submitting_realm_id: u64,
        observed: Option<&[u8]>,
        record: &GutaInFlightRecord,
    ) -> anyhow::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::GutaInFlightRecord;

    #[test]
    fn record_round_trips_through_its_bytes() -> anyhow::Result<()> {
        let record = GutaInFlightRecord {
            old_realm_root: [1u8; 32],
            new_realm_root: [2u8; 32],
            accepted_at_checkpoint_id: 0x0102_0304_0506_0708,
        };
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), 72);
        assert_eq!(&bytes[0..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
        assert_eq!(&bytes[64..72], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(GutaInFlightRecord::from_bytes(&bytes)?, record);
        Ok(())
    }

    #[test]
    fn record_of_the_wrong_length_is_an_error() {
        assert!(GutaInFlightRecord::from_bytes(&[0u8; 71]).is_err());
        assert!(GutaInFlightRecord::from_bytes(&[0u8; 73]).is_err());
        assert!(GutaInFlightRecord::from_bytes(&[]).is_err());
    }
}
