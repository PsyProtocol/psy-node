use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    timestamp::{CommitWriteTimestampUs, NewBranchWriteTimestampUs},
    typed::{LogicalMutation, MutationOperation, MutationValue},
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterPrepared, MutationBuildError, ResolvedScyllaMutation,
    build_realm_global_user_proof_after_cutover, expand_logical_mutation,
};

const TIMESTAMPED_PUT_CODEC_VERSION: u16 = 1;

/// Why the sealed timestamp was allocated. The tag is part of retry identity,
/// so a normal commit cannot be silently reinterpreted as a post-fence write.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum TimestampedWriteKind {
    AuthorityCommit = 1,
    NewBranchAfterFence = 2,
}

/// SHA-256 identity of the registry-resolved mutation before its timestamp is
/// attached.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MutationOperationDigest([u8; 32]);

impl MutationOperationDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// SHA-256 identity of the mutation, timestamp value, and timestamp purpose.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimestampedIntentDigest([u8; 32]);

impl TimestampedIntentDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampedMutationError {
    MutationBuild(MutationBuildError),
    ExpectedOnePhysicalMutation { actual: usize },
    ExpectedPut,
    CommitmentOnlyPayload,
    RetryTimestampChanged { sealed: i64, attempted: i64 },
    RetryWriteKindChanged { sealed: TimestampedWriteKind, attempted: TimestampedWriteKind },
    RetryMutationChanged,
}

impl fmt::Display for TimestampedMutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MutationBuild(error) => error.fmt(f),
            Self::ExpectedOnePhysicalMutation { actual } => {
                write!(f, "prototype PUT must resolve to exactly one physical mutation, got {actual}")
            }
            Self::ExpectedPut => write!(f, "timestamped executable mutation must be a PUT"),
            Self::CommitmentOnlyPayload => write!(f, "a digest is a commitment and cannot be executed as a CQL value"),
            Self::RetryTimestampChanged { sealed, attempted } => {
                write!(f, "retry attempted to replace sealed timestamp {sealed} with {attempted}")
            }
            Self::RetryWriteKindChanged { sealed, attempted } => {
                write!(f, "retry attempted to replace sealed write kind {sealed:?} with {attempted:?}")
            }
            Self::RetryMutationChanged => write!(f, "retry mutation differs from the sealed mutation"),
        }
    }
}

impl Error for TimestampedMutationError {}

impl From<MutationBuildError> for TimestampedMutationError {
    fn from(value: MutationBuildError) -> Self {
        Self::MutationBuild(value)
    }
}

/// An immutable in-memory execution plan for one registry-validated PUT.
///
/// The type is deliberately not a durable intent. D-04 must persist allocator
/// state and the intent-to-timestamp association before production writers can
/// rely on this contract.
///
/// ```compile_fail
/// use psy_node_scylla::rollback::SealedTimestampedPut;
/// let _forged = SealedTimestampedPut { /* fields are private */ };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedTimestampedPut {
    resolved: ResolvedScyllaMutation,
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
    mutation_digest: MutationOperationDigest,
    intent_digest: TimestampedIntentDigest,
    canonical_bytes: Vec<u8>,
}

/// An immutable timestamped logical intent which expands to more than one
/// physical PUT (currently the two directions of a bidirectional mapping).
/// Every member carries the same timestamp and write kind; callers cannot
/// partially reseal a retry with a different timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedTimestampedPutBatch {
    members: Vec<SealedTimestampedPut>,
    intent_digest: TimestampedIntentDigest,
}

impl SealedTimestampedPutBatch {
    pub fn members(&self) -> &[SealedTimestampedPut] {
        &self.members
    }

    pub const fn intent_digest(&self) -> TimestampedIntentDigest {
        self.intent_digest
    }

    pub fn ensure_exact_retry(
        &self,
        intent: LogicalMutation,
        timestamp: CommitWriteTimestampUs,
        write_kind: TimestampedWriteKind,
    ) -> Result<(), TimestampedMutationError> {
        if self.members.first().is_some_and(|member| member.write_kind != write_kind) {
            return Err(TimestampedMutationError::RetryWriteKindChanged {
                sealed: self.members[0].write_kind,
                attempted: write_kind,
            });
        }
        if self.members.first().is_some_and(|member| member.timestamp != timestamp) {
            return Err(TimestampedMutationError::RetryTimestampChanged {
                sealed: self.members[0].timestamp.as_i64(),
                attempted: timestamp.as_i64(),
            });
        }
        let candidate = seal_batch_inner(intent, timestamp, write_kind)?;
        if candidate.intent_digest != self.intent_digest {
            return Err(TimestampedMutationError::RetryMutationChanged);
        }
        Ok(())
    }
}

impl SealedTimestampedPut {
    pub const fn resolved(&self) -> &ResolvedScyllaMutation {
        &self.resolved
    }

    pub const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub const fn write_kind(&self) -> TimestampedWriteKind {
        self.write_kind
    }

    pub const fn mutation_digest(&self) -> MutationOperationDigest {
        self.mutation_digest
    }

    pub const fn intent_digest(&self) -> TimestampedIntentDigest {
        self.intent_digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Checks a retry without changing the original seal. The retry must use
    /// the identical mutation, timestamp, and timestamp semantic kind.
    pub fn ensure_exact_retry(
        &self,
        intent: LogicalMutation,
        timestamp: CommitWriteTimestampUs,
        write_kind: TimestampedWriteKind,
    ) -> Result<(), TimestampedMutationError> {
        if write_kind != self.write_kind {
            return Err(TimestampedMutationError::RetryWriteKindChanged { sealed: self.write_kind, attempted: write_kind });
        }
        if timestamp != self.timestamp {
            return Err(TimestampedMutationError::RetryTimestampChanged {
                sealed: self.timestamp.as_i64(),
                attempted: timestamp.as_i64(),
            });
        }
        let candidate = seal_inner(intent, timestamp, write_kind)?;
        if candidate.mutation_digest != self.mutation_digest {
            return Err(TimestampedMutationError::RetryMutationChanged);
        }
        Ok(())
    }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn seal_inner(
    intent: LogicalMutation,
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
) -> Result<SealedTimestampedPut, TimestampedMutationError> {
    let mut resolved = expand_logical_mutation(intent)?;
    if resolved.len() != 1 {
        return Err(TimestampedMutationError::ExpectedOnePhysicalMutation { actual: resolved.len() });
    }
    let resolved = resolved.pop().expect("length was checked");
    seal_resolved(resolved, timestamp, write_kind)
}

fn seal_resolved(
    resolved: ResolvedScyllaMutation,
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
) -> Result<SealedTimestampedPut, TimestampedMutationError> {
    match resolved.mutation().operation() {
        MutationOperation::Put(MutationValue::Digest { .. }) => {
            return Err(TimestampedMutationError::CommitmentOnlyPayload);
        }
        MutationOperation::Put(_) => {}
        MutationOperation::Delete => return Err(TimestampedMutationError::ExpectedPut),
    }

    let resolved_bytes = resolved.encode_canonical();
    let mutation_digest = MutationOperationDigest(sha256(&[b"psy/scylla/mutation/v1", &resolved_bytes]));
    let timestamp_bytes = timestamp.as_i64().to_be_bytes();
    let kind_bytes = [write_kind as u8];
    let intent_digest = TimestampedIntentDigest(sha256(&[
        b"psy/scylla/timestamped-put/v1",
        mutation_digest.as_bytes(),
        &kind_bytes,
        &timestamp_bytes,
    ]));

    let mut canonical_bytes = Vec::with_capacity(resolved_bytes.len() + 48);
    canonical_bytes.extend_from_slice(b"PSTP");
    canonical_bytes.extend_from_slice(&TIMESTAMPED_PUT_CODEC_VERSION.to_be_bytes());
    canonical_bytes.push(write_kind as u8);
    canonical_bytes.extend_from_slice(&timestamp_bytes);
    canonical_bytes.extend_from_slice(&(resolved_bytes.len() as u32).to_be_bytes());
    canonical_bytes.extend_from_slice(&resolved_bytes);

    Ok(SealedTimestampedPut {
        resolved,
        timestamp,
        write_kind,
        mutation_digest,
        intent_digest,
        canonical_bytes,
    })
}

fn seal_batch_inner(
    intent: LogicalMutation,
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
) -> Result<SealedTimestampedPutBatch, TimestampedMutationError> {
    let resolved = expand_logical_mutation(intent)?;
    let members = resolved
        .into_iter()
        .map(|mutation| seal_resolved(mutation, timestamp, write_kind))
        .collect::<Result<Vec<_>, _>>()?;
    let kind_bytes = [write_kind as u8];
    let timestamp_bytes = timestamp.as_i64().to_be_bytes();
    let member_digests = members
        .iter()
        .flat_map(|member| member.mutation_digest.as_bytes().iter().copied())
        .collect::<Vec<_>>();
    let intent_digest = TimestampedIntentDigest(sha256(&[
        b"psy/scylla/timestamped-put-batch/v1",
        &kind_bytes,
        &timestamp_bytes,
        &member_digests,
    ]));
    Ok(SealedTimestampedPutBatch { members, intent_digest })
}

/// Seals a normal authority write. The caller must provide an already
/// allocated timestamp; this function never reads a clock.
///
/// ```compile_fail
/// use psy_node_core::store::typed::LogicalMutation;
/// use psy_node_scylla::rollback::seal_commit_put;
/// # fn cannot_omit_timestamp(intent: LogicalMutation) {
/// let _sealed = seal_commit_put(intent);
/// # }
/// ```
pub fn seal_commit_put(
    intent: LogicalMutation,
    timestamp: CommitWriteTimestampUs,
) -> Result<SealedTimestampedPut, TimestampedMutationError> {
    seal_inner(intent, timestamp, TimestampedWriteKind::AuthorityCommit)
}

/// Seal the checkpoint global-user proof only after the exact h22 writer
/// preparation captured a non-quiescing cutover fence. Generic typed sealing
/// intentionally continues to reject the historical mixed-axis table.
pub(super) fn seal_realm_global_user_proof_after_cutover<Hash: Q256BitHash>(
    prepared: &BranchExactWriterPrepared<Hash>,
    key: psy_node_core::store::typed::TypedTableKey,
    value: MutationValue,
) -> Result<SealedTimestampedPut, TimestampedMutationError> {
    let resolved = build_realm_global_user_proof_after_cutover(prepared, key, value)?;
    seal_resolved(
        resolved,
        prepared.timestamp(),
        TimestampedWriteKind::AuthorityCommit,
    )
}

/// Seals a post-rollback write whose timestamp has already been proven to be
/// strictly newer than the delete fence.
pub fn seal_new_branch_put(
    intent: LogicalMutation,
    timestamp: NewBranchWriteTimestampUs,
) -> Result<SealedTimestampedPut, TimestampedMutationError> {
    seal_inner(intent, timestamp.as_commit_timestamp(), TimestampedWriteKind::NewBranchAfterFence)
}

/// Seals a logical bidirectional mapping as an ordered set of physical PUTs.
/// This is an execution identity contract, not a claim of cross-table CQL
/// atomicity.
pub fn seal_commit_put_batch(
    intent: LogicalMutation,
    timestamp: CommitWriteTimestampUs,
) -> Result<SealedTimestampedPutBatch, TimestampedMutationError> {
    seal_batch_inner(intent, timestamp, TimestampedWriteKind::AuthorityCommit)
}

pub fn seal_new_branch_put_batch(
    intent: LogicalMutation,
    timestamp: NewBranchWriteTimestampUs,
) -> Result<SealedTimestampedPutBatch, TimestampedMutationError> {
    seal_batch_inner(
        intent,
        timestamp.as_commit_timestamp(),
        TimestampedWriteKind::NewBranchAfterFence,
    )
}
