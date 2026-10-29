use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;

const END_CAP_REDELIVERY_RECORD_HEADER_SIZE: usize = 8 + 8 + 32 + 32 + 4;

/// An EndCap admitted by the scheduled proposer's Edge, kept until the user leaf shows whether it was included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndCapRedeliveryRecord {
    pub admitted_unique_pending_id: u64,
    pub admitted_checkpoint_id: u64,
    pub old_user_leaf_hash: [u8; 32],
    pub new_user_leaf_hash: [u8; 32],
    pub end_cap_input: Vec<u8>,
    pub proof: Vec<u8>,
}

impl EndCapRedeliveryRecord {
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let input_len = u32::try_from(self.end_cap_input.len())?;
        let mut bytes = Vec::with_capacity(END_CAP_REDELIVERY_RECORD_HEADER_SIZE + self.end_cap_input.len() + self.proof.len());
        bytes.extend_from_slice(&self.admitted_unique_pending_id.to_le_bytes());
        bytes.extend_from_slice(&self.admitted_checkpoint_id.to_le_bytes());
        bytes.extend_from_slice(&self.old_user_leaf_hash);
        bytes.extend_from_slice(&self.new_user_leaf_hash);
        bytes.extend_from_slice(&input_len.to_le_bytes());
        bytes.extend_from_slice(&self.end_cap_input);
        bytes.extend_from_slice(&self.proof);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() >= END_CAP_REDELIVERY_RECORD_HEADER_SIZE,
            "EndCap redelivery record has {} bytes, below its {}-byte header",
            bytes.len(),
            END_CAP_REDELIVERY_RECORD_HEADER_SIZE
        );
        let input_len = u32::from_le_bytes(bytes[80..84].try_into()?) as usize;
        let input_end = END_CAP_REDELIVERY_RECORD_HEADER_SIZE
            .checked_add(input_len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| anyhow::anyhow!("EndCap redelivery record input length {} exceeds the record", input_len))?;
        Ok(Self {
            admitted_unique_pending_id: u64::from_le_bytes(bytes[0..8].try_into()?),
            admitted_checkpoint_id: u64::from_le_bytes(bytes[8..16].try_into()?),
            old_user_leaf_hash: bytes[16..48].try_into()?,
            new_user_leaf_hash: bytes[48..80].try_into()?,
            end_cap_input: bytes[END_CAP_REDELIVERY_RECORD_HEADER_SIZE..input_end].to_vec(),
            proof: bytes[input_end..].to_vec(),
        })
    }
}

#[async_trait]
pub trait QTempDBEndCapRedeliveryStore {
    async fn add_end_cap_redelivery(&self, rid: &QRealmIdentifier, user_id: u64, record: &EndCapRedeliveryRecord) -> anyhow::Result<()>;

    /// Lists the user under `record`'s pending id and replaces the record only if it still holds `observed`.
    async fn replace_end_cap_redelivery(&self, rid: &QRealmIdentifier, user_id: u64, observed: &[u8], record: &EndCapRedeliveryRecord) -> anyhow::Result<bool>;

    /// The stored record bytes, which `remove_end_cap_redelivery` passes back as `observed`.
    async fn get_end_cap_redelivery(&self, rid: &QRealmIdentifier, user_id: u64) -> anyhow::Result<Option<Vec<u8>>>;

    /// Removes the user's record only if it still holds `observed`, so a newer admission survives.
    async fn remove_end_cap_redelivery(&self, rid: &QRealmIdentifier, user_id: u64, observed: &[u8]) -> anyhow::Result<bool>;

    async fn get_end_cap_redelivery_user_ids(&self, rid: &QRealmIdentifier, unique_pending_id: u64) -> anyhow::Result<Vec<u64>>;

    async fn remove_end_cap_redelivery_user_ids(&self, rid: &QRealmIdentifier, unique_pending_id: u64) -> anyhow::Result<()>;

    async fn get_end_cap_redelivery_cursor(&self, rid: &QRealmIdentifier) -> anyhow::Result<Option<u64>>;

    /// Moves the cursor from `observed` to `next`; returns false when another Edge moved it first.
    async fn set_end_cap_redelivery_cursor(&self, rid: &QRealmIdentifier, observed: Option<u64>, next: u64) -> anyhow::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::EndCapRedeliveryRecord;

    fn record() -> EndCapRedeliveryRecord {
        EndCapRedeliveryRecord {
            admitted_unique_pending_id: 7,
            admitted_checkpoint_id: 9,
            old_user_leaf_hash: [1u8; 32],
            new_user_leaf_hash: [2u8; 32],
            end_cap_input: vec![3, 4, 5],
            proof: vec![6, 7],
        }
    }

    #[test]
    fn record_round_trips_through_its_bytes() -> anyhow::Result<()> {
        let bytes = record().to_bytes()?;
        assert_eq!(bytes.len(), 84 + 3 + 2);
        assert_eq!(EndCapRedeliveryRecord::from_bytes(&bytes)?, record());
        Ok(())
    }

    #[test]
    fn truncated_record_is_an_error() -> anyhow::Result<()> {
        let bytes = record().to_bytes()?;
        assert!(EndCapRedeliveryRecord::from_bytes(&bytes[..83]).is_err());
        let mut oversized_input = bytes.clone();
        oversized_input[80..84].copy_from_slice(&100u32.to_le_bytes());
        assert!(EndCapRedeliveryRecord::from_bytes(&oversized_input).is_err());
        Ok(())
    }
}
