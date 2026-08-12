use async_trait::async_trait;
use parth_core::{
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::Q256BitHash,
};
use psy_data::protocol::chain_context::PendingContext;
use sha2::{Digest, Sha256};

const COORDINATOR_GUTA_SUBMISSION_DIGEST_DOMAIN: &[u8] =
    b"psy/coordinator-guta-submission/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorGutaSubmissionDigest([u8; 32]);

impl CoordinatorGutaSubmissionDigest {
    pub fn from_submission(
        submitted_realm_id: u64,
        canonical_input: &[u8],
        proof_bytes: &[u8],
    ) -> anyhow::Result<Self> {
        let input_len = u64::try_from(canonical_input.len())
            .map_err(|_| anyhow::anyhow!("Coordinator GUTA input length exceeds u64"))?;
        let proof_len = u64::try_from(proof_bytes.len())
            .map_err(|_| anyhow::anyhow!("Coordinator GUTA proof length exceeds u64"))?;
        let mut hasher = Sha256::new();
        hasher.update(COORDINATOR_GUTA_SUBMISSION_DIGEST_DOMAIN);
        hasher.update(submitted_realm_id.to_le_bytes());
        hasher.update(input_len.to_le_bytes());
        hasher.update(canonical_input);
        hasher.update(proof_len.to_le_bytes());
        hasher.update(proof_bytes);
        Ok(Self(hasher.finalize().into()))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "Coordinator GUTA submission digest must contain exactly 32 bytes"
            )
        })?;
        Ok(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorGutaSubmissionClaimOutcome {
    Applied,
    Idempotent,
    Conflict {
        current: CoordinatorGutaSubmissionDigest,
    },
}

#[async_trait]
pub trait QTempDBCoordinatorGutaSubmissionClaimStore {
    async fn claim_coordinator_guta_submission<Hash: Q256BitHash + Send + Sync>(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        submitted_realm_id: u64,
        digest: CoordinatorGutaSubmissionDigest,
    ) -> anyhow::Result<CoordinatorGutaSubmissionClaimOutcome>;

    async fn get_coordinator_guta_submission_claim<Hash: Q256BitHash + Send + Sync>(
        &self,
        rid: &QRealmIdentifier,
        context: &PendingContext<Hash>,
        submitted_realm_id: u64,
    ) -> anyhow::Result<Option<CoordinatorGutaSubmissionDigest>>;
}
