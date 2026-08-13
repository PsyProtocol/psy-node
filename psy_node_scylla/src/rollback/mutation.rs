use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    typed::{
        CheckpointedObjectKey, ImtCursorTransition, ImtCursorTransitionError,
        ImtKeyIndexRow, ImtKeyIndexRowError, LogicalMutation,
        MutationOperation, MutationValue, MutationValueKind,
        PsyLogicalTableId, StructuredValueSchema, TypedTableKey,
        ValueDigestAlgorithm,
    },
};

use super::{
    BranchExactWriterPrepared,
    decode_locator_canonical, describe_existing_key, key_domain_descriptor,
    resolve_key_for_rollback,
    RegistryReadinessError, ResolvedScyllaKey, ScyllaKeyDomain,
    ScyllaPhysicalTableId,
};

/// A registry-validated Scylla mutation.  All fields are private and there is
/// intentionally no public constructor: callers must use
/// [`expand_logical_mutation`], which resolves and checks the registry.
///
/// ```
/// use psy_node_core::store::typed::{CheckpointId, LogicalMutation, MutationValue, TypedTableKey};
/// use psy_node_scylla::rollback::{expand_logical_mutation, ScyllaTypedMutation};
/// let resolved = expand_logical_mutation(LogicalMutation::Put {
///     key: TypedTableKey::CheckpointLeaf(CheckpointId::try_new(1).unwrap()),
///     value: MutationValue::PsyCanonicalBytes(vec![1]),
/// }).unwrap();
/// let _: &ScyllaTypedMutation = resolved[0].mutation();
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::typed::{CheckpointId, MutationOperation, MutationValue, PsyLogicalTableId, TypedTableKey};
/// use psy_node_scylla::rollback::{ScyllaKeyDomain, ScyllaPhysicalTableId, ScyllaTypedMutation};
/// let key = TypedTableKey::CheckpointLeaf(CheckpointId::try_new(1).unwrap());
/// let _forged = ScyllaTypedMutation::new(
///     1,
///     PsyLogicalTableId::CheckpointLeaf,
///     ScyllaPhysicalTableId::CheckpointLeaf,
///     ScyllaKeyDomain::CheckpointLeaf,
///     key,
///     MutationOperation::Put(MutationValue::PsyCanonicalBytes(vec![1])),
/// );
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::typed::{CheckpointId, MutationOperation, MutationValue, PsyLogicalTableId, TypedTableKey};
/// use psy_node_scylla::rollback::{ScyllaKeyDomain, ScyllaPhysicalTableId, ScyllaTypedMutation};
/// let _forged = ScyllaTypedMutation {
///     schema_version: 1,
///     logical_table: PsyLogicalTableId::CheckpointLeaf,
///     physical_table: ScyllaPhysicalTableId::CheckpointLeaf,
///     key_domain: ScyllaKeyDomain::CheckpointLeaf,
///     key: TypedTableKey::CheckpointLeaf(CheckpointId::try_new(1).unwrap()),
///     operation: MutationOperation::Put(MutationValue::PsyCanonicalBytes(vec![1])),
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScyllaTypedMutation {
    schema_version: u16,
    logical_table: PsyLogicalTableId,
    physical_table: ScyllaPhysicalTableId,
    key_domain: ScyllaKeyDomain,
    key: TypedTableKey,
    operation: MutationOperation,
}

impl ScyllaTypedMutation {
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn logical_table(&self) -> PsyLogicalTableId {
        self.logical_table
    }

    pub const fn physical_table(&self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub const fn key_domain(&self) -> ScyllaKeyDomain {
        self.key_domain
    }

    pub const fn key(&self) -> &TypedTableKey {
        &self.key
    }

    pub const fn operation(&self) -> &MutationOperation {
        &self.operation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedScyllaMutation {
    mutation: ScyllaTypedMutation,
    locator_bytes: Vec<u8>,
}

impl ResolvedScyllaMutation {
    pub const fn mutation(&self) -> &ScyllaTypedMutation {
        &self.mutation
    }

    pub fn locator_bytes(&self) -> &[u8] {
        &self.locator_bytes
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.locator_bytes.len() + 48);
        encoded.extend_from_slice(b"PSRM");
        encoded.extend_from_slice(&1_u16.to_be_bytes());
        encoded.extend_from_slice(&(self.locator_bytes.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.locator_bytes);
        match self.mutation.operation() {
            MutationOperation::Put(MutationValue::PsyCanonicalBytes(value)) => {
                encoded.push(1);
                encoded.extend_from_slice(&(value.len() as u32).to_be_bytes());
                encoded.extend_from_slice(value);
            }
            MutationOperation::Put(MutationValue::CqlU64(value)) => {
                encoded.push(2);
                encoded.extend_from_slice(&value.to_be_bytes());
            }
            MutationOperation::Put(MutationValue::CqlU128(value)) => {
                encoded.push(3);
                encoded.extend_from_slice(&value.to_be_bytes());
            }
            MutationOperation::Put(MutationValue::KeyOnly) => encoded.push(4),
            MutationOperation::Put(MutationValue::Structured { schema, canonical_bytes }) => {
                encoded.push(5);
                encoded.push(match schema {
                    StructuredValueSchema::TagTreeNodeV1 => 1,
                    StructuredValueSchema::ImtLeafRowV1 => 2,
                    StructuredValueSchema::ImtKeyIndexRowV1 => 3,
                    StructuredValueSchema::ImtCursorTransitionV1 => 4,
                    StructuredValueSchema::ImtKeyIndexRowV2 => 5,
                });
                encoded.extend_from_slice(&(canonical_bytes.len() as u32).to_be_bytes());
                encoded.extend_from_slice(canonical_bytes);
            }
            MutationOperation::Put(MutationValue::Digest { algorithm, digest }) => {
                encoded.push(6);
                encoded.push(match algorithm {
                    ValueDigestAlgorithm::Sha256 => 1,
                });
                encoded.extend_from_slice(digest);
            }
            MutationOperation::Delete => encoded.push(7),
        }
        encoded
    }

    pub(crate) fn decode_canonical(bytes: &[u8]) -> Result<Self, MutationDecodeError> {
        Self::decode_canonical_inner(bytes, false)
    }

    /// Decode an already-committed Realm inventory row. This narrow read-only
    /// path admits the checkpoint-axis global-user proof whose generic writer
    /// registry remains blocked: producing that row still requires the h22
    /// cutover-fenced builder.
    pub(super) fn decode_realm_commit_inventory_canonical(
        bytes: &[u8],
    ) -> Result<Self, MutationDecodeError> {
        Self::decode_canonical_inner(bytes, true)
    }

    fn decode_canonical_inner(
        bytes: &[u8],
        allow_committed_realm_global_user_proof: bool,
    ) -> Result<Self, MutationDecodeError> {
        let mut cursor = MutationCursor::new(bytes);
        if cursor.take(4)? != b"PSRM" {
            return Err(MutationDecodeError::InvalidEncoding("bad mutation magic"));
        }
        if cursor.u16()? != 1 {
            return Err(MutationDecodeError::InvalidEncoding("unknown mutation schema version"));
        }
        let locator = cursor.bytes()?;
        let resolved = decode_locator_canonical(locator).map_err(MutationDecodeError::InvalidLocator)?;
        let ready = if allow_committed_realm_global_user_proof
            && resolved.key_domain() == ScyllaKeyDomain::CheckpointedGlobalUserProof
        {
            resolved
        } else {
            resolve_key_for_rollback(resolved.typed_key())?
        };
        if ready.locator_bytes() != locator {
            return Err(MutationDecodeError::InvalidEncoding("ready locator differs from encoded locator"));
        }

        let operation = match cursor.u8()? {
            1 => MutationOperation::Put(MutationValue::PsyCanonicalBytes(cursor.bytes()?.to_vec())),
            2 => MutationOperation::Put(MutationValue::CqlU64(cursor.u64()?)),
            3 => MutationOperation::Put(MutationValue::CqlU128(cursor.u128()?)),
            4 => MutationOperation::Put(MutationValue::KeyOnly),
            5 => {
                let schema = match cursor.u8()? {
                    1 => StructuredValueSchema::TagTreeNodeV1,
                    2 => StructuredValueSchema::ImtLeafRowV1,
                    3 => StructuredValueSchema::ImtKeyIndexRowV1,
                    4 => StructuredValueSchema::ImtCursorTransitionV1,
                    5 => StructuredValueSchema::ImtKeyIndexRowV2,
                    _ => return Err(MutationDecodeError::InvalidEncoding("unknown structured value schema")),
                };
                MutationOperation::Put(MutationValue::Structured { schema, canonical_bytes: cursor.bytes()?.to_vec() })
            }
            6 => {
                let algorithm = match cursor.u8()? {
                    1 => ValueDigestAlgorithm::Sha256,
                    _ => return Err(MutationDecodeError::InvalidEncoding("unknown value digest algorithm")),
                };
                MutationOperation::Put(MutationValue::Digest { algorithm, digest: cursor.array_32()? })
            }
            7 => return Err(MutationDecodeError::MutationBuild(MutationBuildError::DeleteNotEnabled)),
            _ => return Err(MutationDecodeError::InvalidEncoding("unknown mutation operation")),
        };
        if !cursor.is_empty() {
            return Err(MutationDecodeError::InvalidEncoding("trailing mutation bytes"));
        }
        if let MutationOperation::Put(value) = &operation {
            validate_put_value(&ready, value)?;
        }
        let decoded = build_resolved(ready, operation);
        if decoded.encode_canonical() != bytes {
            return Err(MutationDecodeError::InvalidEncoding("non-canonical mutation encoding"));
        }
        Ok(decoded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationDecodeError {
    InvalidEncoding(&'static str),
    InvalidLocator(&'static str),
    MutationBuild(MutationBuildError),
}

impl From<MutationBuildError> for MutationDecodeError {
    fn from(value: MutationBuildError) -> Self {
        Self::MutationBuild(value)
    }
}

impl From<RegistryReadinessError> for MutationDecodeError {
    fn from(value: RegistryReadinessError) -> Self {
        Self::MutationBuild(MutationBuildError::Readiness(value))
    }
}

impl fmt::Display for MutationDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for MutationDecodeError {}

struct MutationCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> MutationCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], MutationDecodeError> {
        if self.remaining.len() < length {
            return Err(MutationDecodeError::InvalidEncoding("truncated mutation"));
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, MutationDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, MutationDecodeError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed length")))
    }

    fn u32(&mut self) -> Result<u32, MutationDecodeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed length")))
    }

    fn u64(&mut self) -> Result<u64, MutationDecodeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed length")))
    }

    fn u128(&mut self) -> Result<u128, MutationDecodeError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().expect("fixed length")))
    }

    fn array_32(&mut self) -> Result<[u8; 32], MutationDecodeError> {
        Ok(self.take(32)?.try_into().expect("fixed length"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], MutationDecodeError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationBuildError {
    Readiness(RegistryReadinessError),
    PairDirectionRequiresLogicalIntent,
    DeleteNotEnabled,
    ValueEncodingMismatch { domain: ScyllaKeyDomain, actual: MutationValueKind },
    InvalidImtCursorTransition(ImtCursorTransitionError),
    InvalidImtKeyIndexRow(ImtKeyIndexRowError),
    RealmAuthorityRequiredAfterCutover,
    BranchExactCutoverFenceRequired,
    GlobalUserProofMutationRequired,
}

impl fmt::Display for MutationBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Readiness(error) => write!(f, "table is not rollback-ready: {error:?}"),
            Self::PairDirectionRequiresLogicalIntent => write!(f, "bidirectional physical key requires a sealed logical pair intent"),
            Self::DeleteNotEnabled => write!(f, "typed Delete is reserved until a delete adapter and explicit strategy are enabled"),
            Self::ValueEncodingMismatch { domain, actual } => {
                write!(f, "value encoding {actual:?} is not allowed for key domain {domain:?}")
            }
            Self::InvalidImtCursorTransition(error) => error.fmt(f),
            Self::InvalidImtKeyIndexRow(error) => error.fmt(f),
            Self::RealmAuthorityRequiredAfterCutover => {
                write!(f, "cutover-bound mixed-axis write requires Realm authority")
            }
            Self::BranchExactCutoverFenceRequired => {
                write!(f, "cutover-bound mixed-axis write requires an exact writer fence")
            }
            Self::GlobalUserProofMutationRequired => {
                write!(f, "cutover-bound mixed-axis override only accepts the checkpoint global-user proof")
            }
        }
    }
}

impl Error for MutationBuildError {}

impl From<RegistryReadinessError> for MutationBuildError {
    fn from(value: RegistryReadinessError) -> Self {
        Self::Readiness(value)
    }
}

fn is_pair_direction(physical: ScyllaPhysicalTableId) -> bool {
    matches!(
        physical,
        ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK1
            | ScyllaPhysicalTableId::CheckpointRootToCheckpointIdK2
            | ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK1
            | ScyllaPhysicalTableId::CheckpointLeafToCheckpointIdK2
            | ScyllaPhysicalTableId::PendingIdToPendingProcIdU64ToU128
            | ScyllaPhysicalTableId::PendingIdToPendingProcIdU128ToU64
    )
}

fn build_resolved(resolved: ResolvedScyllaKey, operation: MutationOperation) -> ResolvedScyllaMutation {
    let mutation = ScyllaTypedMutation {
        schema_version: resolved.schema_version(),
        logical_table: resolved.logical_table(),
        physical_table: resolved.physical_table(),
        key_domain: resolved.key_domain(),
        key: resolved.typed_key().clone(),
        operation,
    };
    ResolvedScyllaMutation { mutation, locator_bytes: resolved.locator_bytes().to_vec() }
}

/// Resolve the checkpoint-axis row which remains in the historical mixed-axis
/// object table after h22 moves pending rewards into its target table. The
/// generic registry remains blocked; an exact Realm writer cutover fence is
/// mandatory and cannot be replaced with a bare key or timestamp.
pub(super) fn build_realm_global_user_proof_after_cutover<Hash: Q256BitHash>(
    prepared: &BranchExactWriterPrepared<Hash>,
    key: TypedTableKey,
    value: MutationValue,
) -> Result<ResolvedScyllaMutation, MutationBuildError> {
    if !matches!(prepared.intent().authority(), AuthorityScope::Realm { .. }) {
        return Err(MutationBuildError::RealmAuthorityRequiredAfterCutover);
    }
    if prepared.cutover_fence().is_none() {
        return Err(MutationBuildError::BranchExactCutoverFenceRequired);
    }
    if !matches!(
        key,
        TypedTableKey::CheckpointedObject(
            CheckpointedObjectKey::GlobalUserProofAtCheckpoint(_)
        )
    ) {
        return Err(MutationBuildError::GlobalUserProofMutationRequired);
    }
    let resolved = describe_existing_key(&key);
    debug_assert_eq!(
        resolved.key_domain(),
        ScyllaKeyDomain::CheckpointedGlobalUserProof
    );
    validate_put_value(&resolved, &value)?;
    Ok(build_resolved(resolved, MutationOperation::Put(value)))
}

fn validate_put_value(resolved: &ResolvedScyllaKey, value: &MutationValue) -> Result<(), MutationBuildError> {
    let descriptor = key_domain_descriptor(resolved.key_domain());
    let actual = value.kind();
    if !descriptor.allowed_put_values.contains(&actual) {
        return Err(MutationBuildError::ValueEncodingMismatch {
            domain: resolved.key_domain(),
            actual,
        });
    }
    if let MutationValue::Structured {
        schema: StructuredValueSchema::ImtCursorTransitionV1,
        canonical_bytes,
    } = value
    {
        ImtCursorTransition::decode_canonical(canonical_bytes)
            .map_err(MutationBuildError::InvalidImtCursorTransition)?;
    }
    if let MutationValue::Structured {
        schema: StructuredValueSchema::ImtKeyIndexRowV2,
        canonical_bytes,
    } = value
    {
        ImtKeyIndexRow::decode_canonical(canonical_bytes)
            .map_err(MutationBuildError::InvalidImtKeyIndexRow)?;
    }
    Ok(())
}

fn build_single(key: TypedTableKey, operation: MutationOperation) -> Result<ResolvedScyllaMutation, MutationBuildError> {
    let resolved = resolve_key_for_rollback(&key)?;
    if is_pair_direction(resolved.physical_table()) {
        return Err(MutationBuildError::PairDirectionRequiresLogicalIntent);
    }
    if let MutationOperation::Put(value) = &operation {
        validate_put_value(&resolved, value)?;
    }
    Ok(build_resolved(resolved, operation))
}

fn build_pair_member(key: TypedTableKey, value: MutationValue) -> Result<ResolvedScyllaMutation, MutationBuildError> {
    let resolved = resolve_key_for_rollback(&key)?;
    validate_put_value(&resolved, &value)?;
    Ok(build_resolved(resolved, MutationOperation::Put(value)))
}

/// Deterministically expands a logical intent into one or two physical
/// mutations.  Pair order is stable and each side has its own locator.
pub fn expand_logical_mutation(intent: LogicalMutation) -> Result<Vec<ResolvedScyllaMutation>, MutationBuildError> {
    match intent {
        LogicalMutation::Put { key, value } => Ok(vec![build_single(key, MutationOperation::Put(value))?]),
        LogicalMutation::Delete { .. } => Err(MutationBuildError::DeleteNotEnabled),
        LogicalMutation::CheckpointRootMapping { root, checkpoint } => Ok(vec![
            build_pair_member(
                TypedTableKey::CheckpointRootByHash(root.clone()),
                MutationValue::PsyCanonicalBytes(checkpoint.get().to_le_bytes().to_vec()),
            )?,
            build_pair_member(
                TypedTableKey::CheckpointRootByCheckpoint(checkpoint),
                MutationValue::PsyCanonicalBytes(root.as_bytes().to_vec()),
            )?,
        ]),
        LogicalMutation::CheckpointLeafMapping { leaf, checkpoint } => Ok(vec![
            build_pair_member(
                TypedTableKey::CheckpointLeafByHash(leaf.clone()),
                MutationValue::PsyCanonicalBytes(checkpoint.get().to_le_bytes().to_vec()),
            )?,
            build_pair_member(
                TypedTableKey::CheckpointLeafByCheckpoint(checkpoint),
                MutationValue::PsyCanonicalBytes(leaf.as_bytes().to_vec()),
            )?,
        ]),
        LogicalMutation::PendingProcMapping { pending, proc_id } => Ok(vec![
            build_pair_member(TypedTableKey::PendingToProc(pending), MutationValue::CqlU128(proc_id.as_u128()))?,
            build_pair_member(TypedTableKey::ProcToPending(proc_id), MutationValue::CqlU64(pending.get()))?,
        ]),
    }
}
