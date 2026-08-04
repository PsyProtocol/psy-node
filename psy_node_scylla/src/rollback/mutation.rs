use std::{error::Error, fmt};

use psy_node_core::store::typed::{
    LogicalMutation, MutationOperation, MutationValue, MutationValueKind, PsyLogicalTableId, StructuredValueSchema, TypedTableKey,
    ValueDigestAlgorithm,
};

use super::{
    key_domain_descriptor, resolve_key_for_rollback, RegistryReadinessError, ResolvedScyllaKey, ScyllaKeyDomain, ScyllaPhysicalTableId,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationBuildError {
    Readiness(RegistryReadinessError),
    PairDirectionRequiresLogicalIntent,
    DeleteNotEnabled,
    ValueEncodingMismatch { domain: ScyllaKeyDomain, actual: MutationValueKind },
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

fn validate_put_value(resolved: &ResolvedScyllaKey, value: &MutationValue) -> Result<(), MutationBuildError> {
    let descriptor = key_domain_descriptor(resolved.key_domain());
    let actual = value.kind();
    if descriptor.allowed_put_values.contains(&actual) {
        Ok(())
    } else {
        Err(MutationBuildError::ValueEncodingMismatch { domain: resolved.key_domain(), actual })
    }
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
