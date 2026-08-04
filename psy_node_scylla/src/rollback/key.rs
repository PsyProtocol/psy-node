use psy_node_core::store::typed::{
    CheckpointedObjectKey, ImtEncodedKey, MerkleNode, PsyLogicalTableId, TypedTableKey, STORAGE_KEY_CODEC_VERSION,
};

use super::{
    key_domain_descriptor, physical_descriptor, RegistryReadinessError, ScyllaKeyDomain, ScyllaPhysicalTableId, ScyllaSchemaFamily,
};

const TABLE_SCHEMA_VERSION: u16 = 1;
const LOCATOR_MAGIC: &[u8; 4] = b"PSRK";
const CQL_FINGERPRINT_MAGIC: &[u8; 5] = b"CQLPK";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CqlPrimaryKeyFingerprint(Vec<u8>);

impl CqlPrimaryKeyFingerprint {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedScyllaKey {
    logical_table: PsyLogicalTableId,
    physical_table: ScyllaPhysicalTableId,
    key_domain: ScyllaKeyDomain,
    schema_family: ScyllaSchemaFamily,
    schema_version: u16,
    typed_key: TypedTableKey,
    locator_bytes: Vec<u8>,
    cql_fingerprint: CqlPrimaryKeyFingerprint,
}

impl ResolvedScyllaKey {
    pub const fn logical_table(&self) -> PsyLogicalTableId {
        self.logical_table
    }

    pub const fn physical_table(&self) -> ScyllaPhysicalTableId {
        self.physical_table
    }

    pub const fn key_domain(&self) -> ScyllaKeyDomain {
        self.key_domain
    }

    pub const fn schema_family(&self) -> ScyllaSchemaFamily {
        self.schema_family
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn typed_key(&self) -> &TypedTableKey {
        &self.typed_key
    }

    pub fn locator_bytes(&self) -> &[u8] {
        &self.locator_bytes
    }

    pub const fn cql_fingerprint(&self) -> &CqlPrimaryKeyFingerprint {
        &self.cql_fingerprint
    }
}

#[derive(Clone, Copy)]
enum Field<'a> {
    U8(u8),
    I16(i16),
    U64(u64),
    Bytes(&'a [u8]),
}

impl ScyllaSchemaFamily {
    const fn codec_tag(self) -> u8 {
        match self {
            Self::Kiv => 1,
            Self::Blob => 2,
            Self::ObjectSingle => 3,
            Self::U64 => 4,
            Self::Counter => 5,
            Self::U64ToU128 => 6,
            Self::U128ToU64 => 7,
            Self::HashToMany => 8,
            Self::MerkleZero => 9,
            Self::MerkleSingle => 10,
            Self::MerkleDouble => 11,
            Self::TagTree => 12,
            Self::ImtLeaf => 13,
            Self::ImtKeyIndex => 14,
            Self::ImtCursor => 15,
        }
    }
}

fn field_payload(field: Field<'_>) -> (u8, Vec<u8>) {
    match field {
        Field::U8(value) => (1, vec![value]),
        Field::I16(value) => (2, value.to_be_bytes().to_vec()),
        Field::U64(value) => (3, value.to_be_bytes().to_vec()),
        Field::Bytes(value) => (4, value.to_vec()),
    }
}

fn encode_locator(
    physical: ScyllaPhysicalTableId,
    domain: ScyllaKeyDomain,
    family: ScyllaSchemaFamily,
    fields: &[Field<'_>],
) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(24 + fields.len() * 12);
    encoded.extend_from_slice(LOCATOR_MAGIC);
    encoded.extend_from_slice(&STORAGE_KEY_CODEC_VERSION.to_be_bytes());
    encoded.extend_from_slice(&physical.stable_id().to_be_bytes());
    encoded.extend_from_slice(&TABLE_SCHEMA_VERSION.to_be_bytes());
    encoded.extend_from_slice(&domain.stable_id().to_be_bytes());
    encoded.push(family.codec_tag());
    encoded.push(fields.len() as u8);
    for (index, field) in fields.iter().copied().enumerate() {
        let (wire_type, payload) = field_payload(field);
        encoded.push((index + 1) as u8);
        encoded.push(wire_type);
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
    }
    encoded
}

fn encode_cql_fingerprint(
    physical: ScyllaPhysicalTableId,
    family: ScyllaSchemaFamily,
    fields: &[Field<'_>],
) -> CqlPrimaryKeyFingerprint {
    let mut encoded = Vec::with_capacity(16 + fields.len() * 10);
    encoded.extend_from_slice(CQL_FINGERPRINT_MAGIC);
    encoded.extend_from_slice(&physical.stable_id().to_be_bytes());
    encoded.push(family.codec_tag());
    encoded.push(fields.len() as u8);
    for field in fields.iter().copied() {
        let (wire_type, payload) = field_payload(field);
        encoded.push(wire_type);
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
    }
    CqlPrimaryKeyFingerprint(encoded)
}

fn object_fields(object_id: u64, version: u64) -> [Field<'static>; 2] {
    [Field::U64(object_id), Field::U64(version)]
}

fn merkle_fields(node: MerkleNode, checkpoint: u64) -> [Field<'static>; 3] {
    [Field::U8(node.level()), Field::U64(node.index().get()), Field::U64(checkpoint)]
}

fn imt_index_fields(tree: u64, tree_sub: u64, key: &ImtEncodedKey) -> [Field<'_>; 4] {
    [Field::U64(tree), Field::U64(tree_sub), Field::I16(key.cql_bucket()), Field::Bytes(key.as_bytes())]
}

/// Describes an existing key, including blocked and retired legacy domains.
/// This is intended for inventory/evidence collection and never asserts that
/// a table is safe for rollback.
pub fn describe_existing_key(key: &TypedTableKey) -> ResolvedScyllaKey {
    use ScyllaKeyDomain as D;
    use ScyllaPhysicalTableId as P;

    let (physical, domain, fields): (ScyllaPhysicalTableId, ScyllaKeyDomain, Vec<Field<'_>>) = match key {
        TypedTableKey::CheckpointLeaf(checkpoint) => (P::CheckpointLeaf, D::CheckpointLeaf, vec![Field::U64(checkpoint.get())]),
        TypedTableKey::CheckpointRootByHash(root) => {
            (P::CheckpointRootToCheckpointIdK1, D::CheckpointRootByHash, vec![Field::Bytes(root.as_bytes())])
        }
        TypedTableKey::CheckpointRootByCheckpoint(checkpoint) => (
            P::CheckpointRootToCheckpointIdK2,
            D::CheckpointRootByCheckpoint,
            vec![Field::U64(checkpoint.get())],
        ),
        TypedTableKey::CheckpointLeafByHash(leaf) => {
            (P::CheckpointLeafToCheckpointIdK1, D::CheckpointLeafByHash, vec![Field::Bytes(leaf.as_bytes())])
        }
        TypedTableKey::CheckpointLeafByCheckpoint(checkpoint) => (
            P::CheckpointLeafToCheckpointIdK2,
            D::CheckpointLeafByCheckpoint,
            vec![Field::U64(checkpoint.get())],
        ),
        TypedTableKey::L2BlockState(checkpoint) => (P::L2BlockState, D::L2BlockState, vec![Field::U64(checkpoint.get())]),
        TypedTableKey::UnusedCheckpointRealmRoot(checkpoint) => (
            P::CheckpointIdToRealmRoot,
            D::UnusedCheckpointRealmRoot,
            vec![Field::U64(checkpoint.get())],
        ),
        TypedTableKey::LatestInfo(slot) => (P::LatestInfo, D::LatestInfo, vec![Field::U64(*slot as u8 as u64)]),
        TypedTableKey::CheckpointedObject(object) => match object {
            CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint) => (
                P::CheckpointedObject,
                D::CheckpointedGlobalUserProof,
                object_fields(1, checkpoint.get()).to_vec(),
            ),
            CheckpointedObjectKey::RewardsProofAtCheckpoint(checkpoint) => (
                P::CheckpointedObject,
                D::CheckpointedRewardsProofAtCheckpoint,
                object_fields(2, checkpoint.get()).to_vec(),
            ),
            CheckpointedObjectKey::RewardsProofAtPending(pending) => (
                P::CheckpointedObject,
                D::CheckpointedRewardsProofAtPending,
                object_fields(2, pending.get()).to_vec(),
            ),
            CheckpointedObjectKey::ContractStateProofAtCheckpoint(checkpoint) => (
                P::CheckpointedObject,
                D::CheckpointedContractStateProof,
                object_fields(3, checkpoint.get()).to_vec(),
            ),
        },
        TypedTableKey::CheckpointStateRoots(checkpoint) => {
            (P::CheckpointStateRoots, D::CheckpointStateRoots, vec![Field::U64(checkpoint.get())])
        }
        TypedTableKey::UserLeaf { user, checkpoint } => {
            (P::UserLeaf, D::UserLeaf, object_fields(user.get(), checkpoint.get()).to_vec())
        }
        TypedTableKey::UserPublicKey { user, checkpoint } => {
            (P::UserPublicKey, D::UserPublicKey, object_fields(user.get(), checkpoint.get()).to_vec())
        }
        TypedTableKey::U64Singleton(slot) => (P::U64Singleton, D::U64Singleton, vec![Field::U64(*slot as u8 as u64)]),
        TypedTableKey::U64Counter(slot) => (P::U64CounterSingleton, D::U64Counter, vec![Field::U64(*slot as u8 as u64)]),
        TypedTableKey::ContractStateTreeHeight { contract, checkpoint } => (
            P::ContractStateTreeHeight,
            D::ContractStateTreeHeight,
            object_fields(contract.get(), checkpoint.get()).to_vec(),
        ),
        TypedTableKey::CheckpointToPending(checkpoint) => {
            (P::CheckpointIdToPendingId, D::CheckpointToPending, vec![Field::U64(checkpoint.get())])
        }
        TypedTableKey::PendingToCheckpoint(pending) => {
            (P::PendingIdToCheckpointId, D::PendingToCheckpoint, vec![Field::U64(pending.get())])
        }
        TypedTableKey::PendingToProc(pending) => {
            (P::PendingIdToPendingProcIdU64ToU128, D::PendingToProc, vec![Field::U64(pending.get())])
        }
        TypedTableKey::ProcToPending(proc_id) => (
            P::PendingIdToPendingProcIdU128ToU64,
            D::ProcToPending,
            vec![Field::Bytes(proc_id.as_bytes())],
        ),
        TypedTableKey::RealmRewardNode { realm, pending } => (
            P::RealmRewardsTreeNodeKey,
            D::RealmRewardNode,
            object_fields(realm.get(), pending.get()).to_vec(),
        ),
        TypedTableKey::PublicKeyToUser { public_key_hash, user } => (
            P::PublicKeyHashToUserIds,
            D::PublicKeyToUser,
            vec![Field::Bytes(public_key_hash.as_bytes()), Field::U64(user.get())],
        ),
        TypedTableKey::GlobalUserMerkle { node, checkpoint } => {
            (P::GlobalUserTree, D::GlobalUserMerkle, merkle_fields(*node, checkpoint.get()).to_vec())
        }
        TypedTableKey::UserContractMerkle { user, node, checkpoint } => (
            P::UserContractTree,
            D::UserContractMerkle,
            vec![Field::U64(user.get()), Field::U8(node.level()), Field::U64(node.index().get()), Field::U64(checkpoint.get())],
        ),
        TypedTableKey::ContractStateMerkle { user, contract, node, checkpoint } => (
            P::ContractStateTree,
            D::ContractStateMerkle,
            vec![
                Field::U64(user.get()),
                Field::U64(contract.get()),
                Field::U8(node.level()),
                Field::U64(node.index().get()),
                Field::U64(checkpoint.get()),
            ],
        ),
        TypedTableKey::GlobalCheckpointMerkle { node, checkpoint } => (
            P::GlobalCheckpointTree,
            D::GlobalCheckpointMerkle,
            merkle_fields(*node, checkpoint.get()).to_vec(),
        ),
        TypedTableKey::RewardTagMerkle { pending, node } => (
            P::GutaRewardTagTree,
            D::RewardTagMerkle,
            vec![Field::U64(pending.get()), Field::U8(node.level()), Field::U64(node.index().get())],
        ),
        TypedTableKey::UserRegistrationMerkle { node, checkpoint } => (
            P::UserRegistrationTree,
            D::UserRegistrationMerkle,
            merkle_fields(*node, checkpoint.get()).to_vec(),
        ),
        TypedTableKey::GlobalContractMerkle { node, checkpoint } => (
            P::GlobalContractTree,
            D::GlobalContractMerkle,
            merkle_fields(*node, checkpoint.get()).to_vec(),
        ),
        TypedTableKey::ContractFunctionMerkle { contract, node, checkpoint } => (
            P::ContractFunctionTree,
            D::ContractFunctionMerkle,
            vec![
                Field::U64(contract.get()),
                Field::U8(node.level()),
                Field::U64(node.index().get()),
                Field::U64(checkpoint.get()),
            ],
        ),
        TypedTableKey::ContractLeaf { contract, checkpoint } => {
            (P::ContractLeaf, D::ContractLeaf, object_fields(contract.get(), checkpoint.get()).to_vec())
        }
        TypedTableKey::ContractCodeDefinition { contract, checkpoint } => (
            P::ContractCodeDefinition,
            D::ContractCodeDefinition,
            object_fields(contract.get(), checkpoint.get()).to_vec(),
        ),
        TypedTableKey::CheckpointZkProof(checkpoint) => {
            (P::CheckpointZkProofAndTransition, D::CheckpointZkProof, vec![Field::U64(checkpoint.get())])
        }
        TypedTableKey::ImtLeaf { tree, tree_sub, leaf, checkpoint } => (
            P::ImtLeaf,
            D::ImtLeaf,
            vec![Field::U64(tree.get()), Field::U64(tree_sub.get()), Field::U64(leaf.get()), Field::U64(checkpoint.get())],
        ),
        TypedTableKey::ImtKeyIndex { tree, tree_sub, encoded_key } => (
            P::ImtKeyIndex,
            D::ImtKeyIndex,
            imt_index_fields(tree.get(), tree_sub.get(), encoded_key).to_vec(),
        ),
        TypedTableKey::ImtCursor { tree, tree_sub } => {
            (P::ImtNextAppendIndex, D::ImtCursor, vec![Field::U64(tree.get()), Field::U64(tree_sub.get())])
        }
    };

    let descriptor = physical_descriptor(physical);
    let locator_bytes = encode_locator(physical, domain, descriptor.schema_family, &fields);
    let cql_fingerprint = encode_cql_fingerprint(physical, descriptor.schema_family, &fields);
    ResolvedScyllaKey {
        logical_table: descriptor.logical_owner,
        physical_table: physical,
        key_domain: domain,
        schema_family: descriptor.schema_family,
        schema_version: TABLE_SCHEMA_VERSION,
        typed_key: key.clone(),
        locator_bytes,
        cql_fingerprint,
    }
}

pub fn resolve_key_for_rollback(key: &TypedTableKey) -> Result<ResolvedScyllaKey, RegistryReadinessError> {
    let resolved = describe_existing_key(key);
    let domain = key_domain_descriptor(resolved.key_domain);
    debug_assert_eq!(domain.physical_table, resolved.physical_table);
    debug_assert_eq!(domain.logical_owner, resolved.logical_table);
    domain.require_rollback_ready()?;
    Ok(resolved)
}
