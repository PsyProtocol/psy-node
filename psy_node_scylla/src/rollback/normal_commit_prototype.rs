//! Isolated D-04b metadata executor over the real prototype adapters.
//!
//! State mutation replay and root/proof verification remain an explicit
//! external boundary. This facade owns the durable read/transition order for
//! manifest, authority-local head and timestamp lease; it is not registered
//! in production setup.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::{
        AuthorityTimestampWriteOutcome, SealedAuthorityTimestampCompletion,
    },
    authority_local_head::AuthorityLocalHeadReadState,
    manifest_lifecycle::{
        AuthorityPostWriteObservation, CommittedAuthorityManifest,
        SealedAuthorityManifest,
    },
    manifest_record::{
        AuthorityManifestIdentity, PreparedAuthorityManifestRecord,
    },
    normal_commit::{
        authorize_normal_head_publish, classify_normal_head_publish,
        plan_normal_commit_recovery, seal_verified_changed_realm_commit,
        seal_verified_normal_commit, NormalCommitOrchestrationError,
        NormalCommitRecoveryAction, NormalHeadPublishProgress,
        SealedNormalHeadPublish,
    },
    realm_commit_seal::ChangedRealmCommitSealEvidence,
};

use super::{
    AuthorityLocalHeadPrototypeError, AuthorityTimestampPrototypeError,
    ManifestLifecycleWriteOutcome, ManifestPreparedError,
    ScyllaAuthorityLocalHeadStore, ScyllaAuthorityTimestampStore,
    ScyllaPreparedManifestStore,
};

pub struct ScyllaNormalCommitMetadataExecutor<'a> {
    manifests: &'a ScyllaPreparedManifestStore,
    heads: &'a ScyllaAuthorityLocalHeadStore,
    timestamps: &'a ScyllaAuthorityTimestampStore,
}

impl<'a> ScyllaNormalCommitMetadataExecutor<'a> {
    pub const fn new(
        manifests: &'a ScyllaPreparedManifestStore,
        heads: &'a ScyllaAuthorityLocalHeadStore,
        timestamps: &'a ScyllaAuthorityTimestampStore,
    ) -> Self {
        Self {
            manifests,
            heads,
            timestamps,
        }
    }

    /// Re-read all three durable authorities before deriving one next action.
    pub async fn plan<Hash: Q256BitHash>(
        &self,
        identity: AuthorityManifestIdentity<Hash>,
    ) -> Result<NormalCommitRecoveryAction<Hash>, NormalCommitMetadataError> {
        let key = identity.timestamp_key();
        let manifest = self
            .manifests
            .read_lifecycle(identity)
            .await?
            .ok_or(NormalCommitMetadataError::ManifestMissing)?;
        let head = match self.heads.read(key).await? {
            AuthorityLocalHeadReadState::Uninitialized => {
                return Err(NormalCommitMetadataError::HeadUninitialized)
            }
            AuthorityLocalHeadReadState::Current(head) => head,
        };
        let allocator = self
            .timestamps
            .read_observed(key)
            .await?
            .ok_or(NormalCommitMetadataError::AllocatorUninitialized)?;
        plan_normal_commit_recovery(&manifest, &head, allocator)
            .map_err(Into::into)
    }

    /// Persist externally verified SEALED evidence using the exact lifecycle
    /// LWT. A different current lifecycle is a hard conflict.
    pub async fn persist_sealed<Hash: Q256BitHash>(
        &self,
        sealed: &SealedAuthorityManifest<Hash>,
    ) -> Result<(), NormalCommitMetadataError> {
        match self.manifests.advance_to_sealed(sealed).await? {
            ManifestLifecycleWriteOutcome::Applied(_)
            | ManifestLifecycleWriteOutcome::Idempotent(_) => Ok(()),
            ManifestLifecycleWriteOutcome::Conflict { .. } => {
                Err(NormalCommitMetadataError::ManifestLifecycleConflict)
            }
        }
    }

    /// Re-read the durable authority head and allocator after physical state
    /// verification, seal only the exact PREPARED intent, then persist SEALED.
    /// This closes the stale-observation window without giving callers access
    /// to raw head or allocator coordinates.
    pub async fn verify_and_persist_sealed<Hash: Q256BitHash>(
        &self,
        prepared: PreparedAuthorityManifestRecord<Hash>,
        observation: AuthorityPostWriteObservation<Hash>,
    ) -> Result<SealedAuthorityManifest<Hash>, NormalCommitMetadataError> {
        let key = prepared.identity().timestamp_key();
        let head = match self.heads.read(key).await? {
            AuthorityLocalHeadReadState::Uninitialized => {
                return Err(NormalCommitMetadataError::HeadUninitialized)
            }
            AuthorityLocalHeadReadState::Current(head) => head,
        };
        let allocator = self
            .timestamps
            .read_observed(key)
            .await?
            .ok_or(NormalCommitMetadataError::AllocatorUninitialized)?;
        let sealed = seal_verified_normal_commit(
            prepared,
            observation,
            &head,
            allocator,
        )?;
        self.persist_sealed(&sealed).await?;
        Ok(sealed)
    }

    /// Re-read head and allocator authority before consuming the complete
    /// live changed-Realm evidence and persisting SEALED. Persisted proof or
    /// graph records cannot call this boundary because they cannot construct
    /// `ChangedRealmCommitSealEvidence`.
    pub async fn verify_changed_realm_and_persist_sealed<Hash: Q256BitHash>(
        &self,
        prepared: PreparedAuthorityManifestRecord<Hash>,
        evidence: ChangedRealmCommitSealEvidence<Hash>,
    ) -> Result<SealedAuthorityManifest<Hash>, NormalCommitMetadataError> {
        let key = prepared.identity().timestamp_key();
        let head = match self.heads.read(key).await? {
            AuthorityLocalHeadReadState::Uninitialized => {
                return Err(NormalCommitMetadataError::HeadUninitialized)
            }
            AuthorityLocalHeadReadState::Current(head) => head,
        };
        let allocator = self
            .timestamps
            .read_observed(key)
            .await?
            .ok_or(NormalCommitMetadataError::AllocatorUninitialized)?;
        let sealed = seal_verified_changed_realm_commit(
            prepared,
            evidence,
            &head,
            allocator,
        )?;
        self.persist_sealed(&sealed).await?;
        Ok(sealed)
    }

    /// Execute and classify the exact authority-head CAS. An indeterminate
    /// transport response is reconciled inside the head adapter before this
    /// method returns.
    pub async fn publish_head<Hash: Q256BitHash>(
        &self,
        publish: SealedNormalHeadPublish<Hash>,
    ) -> Result<NormalHeadPublishProgress<Hash>, NormalCommitMetadataError> {
        let key = publish.head_cas().key();
        let allocator_before = self
            .timestamps
            .read_observed(key)
            .await?
            .ok_or(NormalCommitMetadataError::AllocatorUninitialized)?;
        authorize_normal_head_publish(&publish, allocator_before)?;
        let outcome = self.heads.compare_and_set(publish.head_cas()).await?;
        let allocator_after = self
            .timestamps
            .read_observed(key)
            .await?
            .ok_or(NormalCommitMetadataError::AllocatorUninitialized)?;
        classify_normal_head_publish(publish, outcome, allocator_after)
            .map_err(Into::into)
    }

    pub async fn persist_committed<Hash: Q256BitHash>(
        &self,
        committed: &CommittedAuthorityManifest<Hash>,
    ) -> Result<(), NormalCommitMetadataError> {
        match self.manifests.advance_to_committed(committed).await? {
            ManifestLifecycleWriteOutcome::Applied(_)
            | ManifestLifecycleWriteOutcome::Idempotent(_) => Ok(()),
            ManifestLifecycleWriteOutcome::Conflict { .. } => {
                Err(NormalCommitMetadataError::ManifestLifecycleConflict)
            }
        }
    }

    pub async fn complete_timestamp(
        &self,
        completion: SealedAuthorityTimestampCompletion,
    ) -> Result<(), NormalCommitMetadataError> {
        match self.timestamps.complete(completion).await? {
            AuthorityTimestampWriteOutcome::Applied(_)
            | AuthorityTimestampWriteOutcome::Idempotent(_) => Ok(()),
            AuthorityTimestampWriteOutcome::Conflict(_) => {
                Err(NormalCommitMetadataError::TimestampCompletionConflict)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalCommitMetadataError {
    Manifest(ManifestPreparedError),
    Head(AuthorityLocalHeadPrototypeError),
    Timestamp(AuthorityTimestampPrototypeError),
    Orchestration(NormalCommitOrchestrationError),
    ManifestMissing,
    HeadUninitialized,
    AllocatorUninitialized,
    ManifestLifecycleConflict,
    TimestampCompletionConflict,
}

impl From<ManifestPreparedError> for NormalCommitMetadataError {
    fn from(value: ManifestPreparedError) -> Self {
        Self::Manifest(value)
    }
}

impl From<AuthorityLocalHeadPrototypeError> for NormalCommitMetadataError {
    fn from(value: AuthorityLocalHeadPrototypeError) -> Self {
        Self::Head(value)
    }
}

impl From<AuthorityTimestampPrototypeError> for NormalCommitMetadataError {
    fn from(value: AuthorityTimestampPrototypeError) -> Self {
        Self::Timestamp(value)
    }
}

impl From<NormalCommitOrchestrationError> for NormalCommitMetadataError {
    fn from(value: NormalCommitOrchestrationError) -> Self {
        Self::Orchestration(value)
    }
}

impl fmt::Display for NormalCommitMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for NormalCommitMetadataError {}
