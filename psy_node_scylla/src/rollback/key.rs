use psy_node_core::store::typed::{
    CheckpointId, CheckpointLeafKey, CheckpointRootKey, CheckpointedObjectKey,
    ContractId, ImtEncodedKey, LatestInfoSlot, LeafIndex, MerkleNode, NodeIndex,
    ProcCheckpointUniqueId, PsyLogicalTableId, PublicKeyHash, RealmId, TreeId,
    TreeSubId, TypedTableKey, U64CounterSlot, U64SingletonSlot, UniquePendingId,
    UserId, STORAGE_KEY_CODEC_VERSION,
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
        TypedTableKey::LatestInfo(slot) => (
            P::LatestInfo,
            match slot {
                LatestInfoSlot::RealmAuthorityObservation => D::RealmAuthorityObservation,
                LatestInfoSlot::LatestL2BlockState | LatestInfoSlot::LatestCheckpointTreeRoot => D::LatestInfo,
            },
            vec![Field::U64(*slot as u8 as u64)],
        ),
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum DecodedField {
    U8(u8),
    I16(i16),
    U64(u64),
    Bytes(Vec<u8>),
}

struct LocatorCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> LocatorCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        if self.remaining.len() < length {
            return Err("truncated locator");
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed length")))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed length")))
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn physical_from_stable_id(value: u16) -> Result<ScyllaPhysicalTableId, &'static str> {
    use ScyllaPhysicalTableId as P;
    match value {
        1 => Ok(P::CheckpointLeaf),
        2 => Ok(P::CheckpointRootToCheckpointIdK1),
        3 => Ok(P::CheckpointRootToCheckpointIdK2),
        4 => Ok(P::CheckpointLeafToCheckpointIdK1),
        5 => Ok(P::CheckpointLeafToCheckpointIdK2),
        6 => Ok(P::L2BlockState),
        7 => Ok(P::CheckpointIdToRealmRoot),
        8 => Ok(P::LatestInfo),
        9 => Ok(P::CheckpointedObject),
        10 => Ok(P::CheckpointStateRoots),
        11 => Ok(P::UserLeaf),
        12 => Ok(P::UserPublicKey),
        13 => Ok(P::U64Singleton),
        14 => Ok(P::U64CounterSingleton),
        15 => Ok(P::ContractStateTreeHeight),
        16 => Ok(P::CheckpointIdToPendingId),
        17 => Ok(P::PendingIdToCheckpointId),
        18 => Ok(P::PendingIdToPendingProcIdU64ToU128),
        19 => Ok(P::PendingIdToPendingProcIdU128ToU64),
        20 => Ok(P::RealmRewardsTreeNodeKey),
        21 => Ok(P::PublicKeyHashToUserIds),
        22 => Ok(P::GlobalUserTree),
        23 => Ok(P::UserContractTree),
        24 => Ok(P::ContractStateTree),
        25 => Ok(P::GlobalCheckpointTree),
        26 => Ok(P::GutaRewardTagTree),
        27 => Ok(P::UserRegistrationTree),
        28 => Ok(P::GlobalContractTree),
        29 => Ok(P::ContractFunctionTree),
        30 => Ok(P::ContractLeaf),
        31 => Ok(P::ContractCodeDefinition),
        32 => Ok(P::CheckpointZkProofAndTransition),
        33 => Ok(P::ImtLeaf),
        34 => Ok(P::ImtKeyIndex),
        35 => Ok(P::ImtNextAppendIndex),
        _ => Err("unknown physical table id"),
    }
}

fn domain_from_stable_id(value: u16) -> Result<ScyllaKeyDomain, &'static str> {
    use ScyllaKeyDomain as D;
    match value {
        1 => Ok(D::CheckpointLeaf),
        2 => Ok(D::CheckpointRootByHash),
        3 => Ok(D::CheckpointRootByCheckpoint),
        4 => Ok(D::CheckpointLeafByHash),
        5 => Ok(D::CheckpointLeafByCheckpoint),
        6 => Ok(D::L2BlockState),
        7 => Ok(D::UnusedCheckpointRealmRoot),
        8 => Ok(D::LatestInfo),
        9 => Ok(D::CheckpointedGlobalUserProof),
        10 => Ok(D::CheckpointedRewardsProofAtCheckpoint),
        11 => Ok(D::CheckpointedRewardsProofAtPending),
        12 => Ok(D::CheckpointedContractStateProof),
        13 => Ok(D::CheckpointStateRoots),
        14 => Ok(D::UserLeaf),
        15 => Ok(D::UserPublicKey),
        16 => Ok(D::U64Singleton),
        17 => Ok(D::U64Counter),
        18 => Ok(D::ContractStateTreeHeight),
        19 => Ok(D::CheckpointToPending),
        20 => Ok(D::PendingToCheckpoint),
        21 => Ok(D::PendingToProc),
        22 => Ok(D::ProcToPending),
        23 => Ok(D::RealmRewardNode),
        24 => Ok(D::PublicKeyToUser),
        25 => Ok(D::GlobalUserMerkle),
        26 => Ok(D::UserContractMerkle),
        27 => Ok(D::ContractStateMerkle),
        28 => Ok(D::GlobalCheckpointMerkle),
        29 => Ok(D::RewardTagMerkle),
        30 => Ok(D::UserRegistrationMerkle),
        31 => Ok(D::GlobalContractMerkle),
        32 => Ok(D::ContractFunctionMerkle),
        33 => Ok(D::ContractLeaf),
        34 => Ok(D::ContractCodeDefinition),
        35 => Ok(D::CheckpointZkProof),
        36 => Ok(D::ImtLeaf),
        37 => Ok(D::ImtKeyIndex),
        38 => Ok(D::ImtCursor),
        39 => Ok(D::RealmAuthorityObservation),
        _ => Err("unknown key domain id"),
    }
}

fn checkpoint(value: u64) -> Result<CheckpointId, &'static str> {
    CheckpointId::try_new(value).map_err(|_| "checkpoint out of range")
}

fn pending(value: u64) -> Result<UniquePendingId, &'static str> {
    UniquePendingId::try_new(value).map_err(|_| "pending id out of range")
}

fn expect_u8(fields: &[DecodedField], index: usize) -> Result<u8, &'static str> {
    match fields.get(index) {
        Some(DecodedField::U8(value)) => Ok(*value),
        _ => Err("locator field is not u8"),
    }
}

fn expect_i16(fields: &[DecodedField], index: usize) -> Result<i16, &'static str> {
    match fields.get(index) {
        Some(DecodedField::I16(value)) => Ok(*value),
        _ => Err("locator field is not i16"),
    }
}

fn expect_u64(fields: &[DecodedField], index: usize) -> Result<u64, &'static str> {
    match fields.get(index) {
        Some(DecodedField::U64(value)) => Ok(*value),
        _ => Err("locator field is not u64"),
    }
}

fn expect_bytes(fields: &[DecodedField], index: usize) -> Result<&[u8], &'static str> {
    match fields.get(index) {
        Some(DecodedField::Bytes(value)) => Ok(value),
        _ => Err("locator field is not bytes"),
    }
}

fn expect_field_count(fields: &[DecodedField], count: usize) -> Result<(), &'static str> {
    if fields.len() == count {
        Ok(())
    } else {
        Err("wrong locator field count")
    }
}

fn merkle_node(fields: &[DecodedField], level: usize, index: usize) -> Result<MerkleNode, &'static str> {
    Ok(MerkleNode::new(expect_u8(fields, level)?, NodeIndex::new(expect_u64(fields, index)?)))
}

fn typed_key_from_fields(domain: ScyllaKeyDomain, fields: &[DecodedField]) -> Result<TypedTableKey, &'static str> {
    use ScyllaKeyDomain as D;
    let key = match domain {
        D::CheckpointLeaf => {
            expect_field_count(fields, 1)?;
            TypedTableKey::CheckpointLeaf(checkpoint(expect_u64(fields, 0)?)?)
        }
        D::CheckpointRootByHash => {
            expect_field_count(fields, 1)?;
            TypedTableKey::CheckpointRootByHash(CheckpointRootKey::new(expect_bytes(fields, 0)?.to_vec()))
        }
        D::CheckpointRootByCheckpoint => {
            expect_field_count(fields, 1)?;
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint(expect_u64(fields, 0)?)?)
        }
        D::CheckpointLeafByHash => {
            expect_field_count(fields, 1)?;
            TypedTableKey::CheckpointLeafByHash(CheckpointLeafKey::new(expect_bytes(fields, 0)?.to_vec()))
        }
        D::CheckpointLeafByCheckpoint => {
            expect_field_count(fields, 1)?;
            TypedTableKey::CheckpointLeafByCheckpoint(checkpoint(expect_u64(fields, 0)?)?)
        }
        D::L2BlockState => {
            expect_field_count(fields, 1)?;
            TypedTableKey::L2BlockState(checkpoint(expect_u64(fields, 0)?)?)
        }
        D::UnusedCheckpointRealmRoot => {
            expect_field_count(fields, 1)?;
            TypedTableKey::UnusedCheckpointRealmRoot(checkpoint(expect_u64(fields, 0)?)?)
        }
        D::LatestInfo | D::RealmAuthorityObservation => {
            expect_field_count(fields, 1)?;
            let slot = match expect_u64(fields, 0)? {
                1 if domain == D::LatestInfo => LatestInfoSlot::LatestL2BlockState,
                2 if domain == D::LatestInfo => LatestInfoSlot::LatestCheckpointTreeRoot,
                3 if domain == D::RealmAuthorityObservation => LatestInfoSlot::RealmAuthorityObservation,
                _ => return Err("invalid latest-info slot/domain pair"),
            };
            TypedTableKey::LatestInfo(slot)
        }
        D::CheckpointedGlobalUserProof
        | D::CheckpointedRewardsProofAtCheckpoint
        | D::CheckpointedRewardsProofAtPending
        | D::CheckpointedContractStateProof => {
            expect_field_count(fields, 2)?;
            let object_id = expect_u64(fields, 0)?;
            let version = expect_u64(fields, 1)?;
            let object = match domain {
                D::CheckpointedGlobalUserProof if object_id == 1 => {
                    CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint(version)?)
                }
                D::CheckpointedRewardsProofAtCheckpoint if object_id == 2 => {
                    CheckpointedObjectKey::RewardsProofAtCheckpoint(checkpoint(version)?)
                }
                D::CheckpointedRewardsProofAtPending if object_id == 2 => {
                    CheckpointedObjectKey::RewardsProofAtPending(pending(version)?)
                }
                D::CheckpointedContractStateProof if object_id == 3 => {
                    CheckpointedObjectKey::ContractStateProofAtCheckpoint(checkpoint(version)?)
                }
                _ => return Err("invalid checkpointed-object id/domain pair"),
            };
            TypedTableKey::CheckpointedObject(object)
        }
        D::CheckpointStateRoots => {
            expect_field_count(fields, 1)?;
            TypedTableKey::CheckpointStateRoots(checkpoint(expect_u64(fields, 0)?)?)
        }
        D::UserLeaf | D::UserPublicKey => {
            expect_field_count(fields, 2)?;
            let user = UserId::new(expect_u64(fields, 0)?);
            let checkpoint = checkpoint(expect_u64(fields, 1)?)?;
            match domain {
                D::UserLeaf => TypedTableKey::UserLeaf { user, checkpoint },
                D::UserPublicKey => TypedTableKey::UserPublicKey { user, checkpoint },
                _ => unreachable!(),
            }
        }
        D::U64Singleton => {
            expect_field_count(fields, 1)?;
            if expect_u64(fields, 0)? != U64SingletonSlot::LatestCheckpoint as u8 as u64 {
                return Err("invalid u64 singleton slot");
            }
            TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint)
        }
        D::U64Counter => {
            expect_field_count(fields, 1)?;
            if expect_u64(fields, 0)? != U64CounterSlot::UniquePending as u8 as u64 {
                return Err("invalid u64 counter slot");
            }
            TypedTableKey::U64Counter(U64CounterSlot::UniquePending)
        }
        D::ContractStateTreeHeight => {
            expect_field_count(fields, 2)?;
            TypedTableKey::ContractStateTreeHeight {
                contract: ContractId::new(expect_u64(fields, 0)?),
                checkpoint: checkpoint(expect_u64(fields, 1)?)?,
            }
        }
        D::CheckpointToPending => {
            expect_field_count(fields, 1)?;
            TypedTableKey::CheckpointToPending(checkpoint(expect_u64(fields, 0)?)?)
        }
        D::PendingToCheckpoint => {
            expect_field_count(fields, 1)?;
            TypedTableKey::PendingToCheckpoint(pending(expect_u64(fields, 0)?)?)
        }
        D::PendingToProc => {
            expect_field_count(fields, 1)?;
            TypedTableKey::PendingToProc(pending(expect_u64(fields, 0)?)?)
        }
        D::ProcToPending => {
            expect_field_count(fields, 1)?;
            let bytes: [u8; 16] = expect_bytes(fields, 0)?.try_into().map_err(|_| "proc id is not 16 bytes")?;
            TypedTableKey::ProcToPending(ProcCheckpointUniqueId::from_bytes(bytes))
        }
        D::RealmRewardNode => {
            expect_field_count(fields, 2)?;
            TypedTableKey::RealmRewardNode {
                realm: RealmId::new(expect_u64(fields, 0)?),
                pending: pending(expect_u64(fields, 1)?)?,
            }
        }
        D::PublicKeyToUser => {
            expect_field_count(fields, 2)?;
            TypedTableKey::PublicKeyToUser {
                public_key_hash: PublicKeyHash::new(expect_bytes(fields, 0)?.to_vec()),
                user: UserId::new(expect_u64(fields, 1)?),
            }
        }
        D::GlobalUserMerkle | D::GlobalCheckpointMerkle | D::UserRegistrationMerkle | D::GlobalContractMerkle => {
            expect_field_count(fields, 3)?;
            let node = merkle_node(fields, 0, 1)?;
            let checkpoint = checkpoint(expect_u64(fields, 2)?)?;
            match domain {
                D::GlobalUserMerkle => TypedTableKey::GlobalUserMerkle { node, checkpoint },
                D::GlobalCheckpointMerkle => TypedTableKey::GlobalCheckpointMerkle { node, checkpoint },
                D::UserRegistrationMerkle => TypedTableKey::UserRegistrationMerkle { node, checkpoint },
                D::GlobalContractMerkle => TypedTableKey::GlobalContractMerkle { node, checkpoint },
                _ => unreachable!(),
            }
        }
        D::UserContractMerkle => {
            expect_field_count(fields, 4)?;
            TypedTableKey::UserContractMerkle {
                user: UserId::new(expect_u64(fields, 0)?),
                node: merkle_node(fields, 1, 2)?,
                checkpoint: checkpoint(expect_u64(fields, 3)?)?,
            }
        }
        D::ContractStateMerkle => {
            expect_field_count(fields, 5)?;
            TypedTableKey::ContractStateMerkle {
                user: UserId::new(expect_u64(fields, 0)?),
                contract: ContractId::new(expect_u64(fields, 1)?),
                node: merkle_node(fields, 2, 3)?,
                checkpoint: checkpoint(expect_u64(fields, 4)?)?,
            }
        }
        D::RewardTagMerkle => {
            expect_field_count(fields, 3)?;
            TypedTableKey::RewardTagMerkle {
                pending: pending(expect_u64(fields, 0)?)?,
                node: merkle_node(fields, 1, 2)?,
            }
        }
        D::ContractFunctionMerkle => {
            expect_field_count(fields, 4)?;
            TypedTableKey::ContractFunctionMerkle {
                contract: ContractId::new(expect_u64(fields, 0)?),
                node: merkle_node(fields, 1, 2)?,
                checkpoint: checkpoint(expect_u64(fields, 3)?)?,
            }
        }
        D::ContractLeaf | D::ContractCodeDefinition => {
            expect_field_count(fields, 2)?;
            let contract = ContractId::new(expect_u64(fields, 0)?);
            let checkpoint = checkpoint(expect_u64(fields, 1)?)?;
            match domain {
                D::ContractLeaf => TypedTableKey::ContractLeaf { contract, checkpoint },
                D::ContractCodeDefinition => TypedTableKey::ContractCodeDefinition { contract, checkpoint },
                _ => unreachable!(),
            }
        }
        D::CheckpointZkProof => {
            expect_field_count(fields, 1)?;
            TypedTableKey::CheckpointZkProof(checkpoint(expect_u64(fields, 0)?)?)
        }
        D::ImtLeaf => {
            expect_field_count(fields, 4)?;
            TypedTableKey::ImtLeaf {
                tree: TreeId::new(expect_u64(fields, 0)?),
                tree_sub: TreeSubId::new(expect_u64(fields, 1)?),
                leaf: LeafIndex::new(expect_u64(fields, 2)?),
                checkpoint: checkpoint(expect_u64(fields, 3)?)?,
            }
        }
        D::ImtKeyIndex => {
            expect_field_count(fields, 4)?;
            let bytes: [u8; 32] = expect_bytes(fields, 3)?.try_into().map_err(|_| "IMT encoded key is not 32 bytes")?;
            let encoded_key = ImtEncodedKey::new(bytes);
            if encoded_key.cql_bucket() != expect_i16(fields, 2)? {
                return Err("IMT key bucket does not match encoded key");
            }
            TypedTableKey::ImtKeyIndex {
                tree: TreeId::new(expect_u64(fields, 0)?),
                tree_sub: TreeSubId::new(expect_u64(fields, 1)?),
                encoded_key,
            }
        }
        D::ImtCursor => {
            expect_field_count(fields, 2)?;
            TypedTableKey::ImtCursor {
                tree: TreeId::new(expect_u64(fields, 0)?),
                tree_sub: TreeSubId::new(expect_u64(fields, 1)?),
            }
        }
    };
    Ok(key)
}

/// Strictly decodes the stable locator codec and reconstructs its typed key.
/// The result is accepted only when resolving that key reproduces every byte.
/// Decode a locator back to the typed key it names.
///
/// Public because the rollback path outside this module -- archive, delete and
/// the acceptance assertion -- all start from a recorded locator and must resolve
/// it exactly as the recorder did.  A second decoder would verify itself.
pub fn decode_locator_canonical(bytes: &[u8]) -> Result<ResolvedScyllaKey, &'static str> {
    let mut cursor = LocatorCursor::new(bytes);
    if cursor.take(4)? != LOCATOR_MAGIC {
        return Err("bad locator magic");
    }
    if cursor.u16()? != STORAGE_KEY_CODEC_VERSION {
        return Err("unknown storage key codec version");
    }
    let physical = physical_from_stable_id(cursor.u16()?)?;
    if cursor.u16()? != TABLE_SCHEMA_VERSION {
        return Err("unknown table schema version");
    }
    let domain = domain_from_stable_id(cursor.u16()?)?;
    let family_tag = cursor.u8()?;
    let field_count = cursor.u8()? as usize;
    let mut fields = Vec::with_capacity(field_count);
    for expected_index in 1..=field_count {
        if cursor.u8()? as usize != expected_index {
            return Err("non-canonical locator field index");
        }
        let wire_type = cursor.u8()?;
        let payload_length = cursor.u32()? as usize;
        let payload = cursor.take(payload_length)?;
        let field = match wire_type {
            1 if payload.len() == 1 => DecodedField::U8(payload[0]),
            2 if payload.len() == 2 => DecodedField::I16(i16::from_be_bytes(payload.try_into().expect("fixed length"))),
            3 if payload.len() == 8 => DecodedField::U64(u64::from_be_bytes(payload.try_into().expect("fixed length"))),
            4 => DecodedField::Bytes(payload.to_vec()),
            _ => return Err("invalid locator field wire type or length"),
        };
        fields.push(field);
    }
    if !cursor.is_empty() {
        return Err("trailing locator bytes");
    }

    let descriptor = physical_descriptor(physical);
    if descriptor.schema_family.codec_tag() != family_tag {
        return Err("locator schema family mismatch");
    }
    let key = typed_key_from_fields(domain, &fields)?;
    let resolved = describe_existing_key(&key);
    if resolved.physical_table != physical || resolved.key_domain != domain || resolved.locator_bytes != bytes {
        return Err("locator does not canonically resolve to encoded identity");
    }
    Ok(resolved)
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    #[test]
    fn every_key_domain_locator_round_trips_through_typed_resolution() {
        let checkpoint = CheckpointId::try_new(7).unwrap();
        let pending = UniquePendingId::try_new(9).unwrap();
        let proc_id = ProcCheckpointUniqueId::from_u128(0x00112233445566778899aabbccddeeff);
        let node = MerkleNode::new(4, NodeIndex::new(11));
        let mut imt_bytes = [0x44; 32];
        imt_bytes[..2].copy_from_slice(&0x8123_u16.to_be_bytes());
        let samples = vec![
            TypedTableKey::CheckpointLeaf(checkpoint),
            TypedTableKey::CheckpointRootByHash(CheckpointRootKey::new(vec![0xaa])),
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint),
            TypedTableKey::CheckpointLeafByHash(CheckpointLeafKey::new(vec![0xbb])),
            TypedTableKey::CheckpointLeafByCheckpoint(checkpoint),
            TypedTableKey::L2BlockState(checkpoint),
            TypedTableKey::UnusedCheckpointRealmRoot(checkpoint),
            TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
            TypedTableKey::CheckpointedObject(CheckpointedObjectKey::GlobalUserProofAtCheckpoint(checkpoint)),
            TypedTableKey::CheckpointedObject(CheckpointedObjectKey::RewardsProofAtCheckpoint(checkpoint)),
            TypedTableKey::CheckpointedObject(CheckpointedObjectKey::RewardsProofAtPending(pending)),
            TypedTableKey::CheckpointedObject(CheckpointedObjectKey::ContractStateProofAtCheckpoint(checkpoint)),
            TypedTableKey::CheckpointStateRoots(checkpoint),
            TypedTableKey::UserLeaf { user: UserId::new(5), checkpoint },
            TypedTableKey::UserPublicKey { user: UserId::new(5), checkpoint },
            TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
            TypedTableKey::U64Counter(U64CounterSlot::UniquePending),
            TypedTableKey::ContractStateTreeHeight { contract: ContractId::new(6), checkpoint },
            TypedTableKey::CheckpointToPending(checkpoint),
            TypedTableKey::PendingToCheckpoint(pending),
            TypedTableKey::PendingToProc(pending),
            TypedTableKey::ProcToPending(proc_id),
            TypedTableKey::RealmRewardNode { realm: RealmId::new(4), pending },
            TypedTableKey::PublicKeyToUser { public_key_hash: PublicKeyHash::new(vec![1, 2]), user: UserId::new(5) },
            TypedTableKey::GlobalUserMerkle { node, checkpoint },
            TypedTableKey::UserContractMerkle { user: UserId::new(5), node, checkpoint },
            TypedTableKey::ContractStateMerkle { user: UserId::new(5), contract: ContractId::new(6), node, checkpoint },
            TypedTableKey::GlobalCheckpointMerkle { node, checkpoint },
            TypedTableKey::RewardTagMerkle { pending, node },
            TypedTableKey::UserRegistrationMerkle { node, checkpoint },
            TypedTableKey::GlobalContractMerkle { node, checkpoint },
            TypedTableKey::ContractFunctionMerkle { contract: ContractId::new(6), node, checkpoint },
            TypedTableKey::ContractLeaf { contract: ContractId::new(6), checkpoint },
            TypedTableKey::ContractCodeDefinition { contract: ContractId::new(6), checkpoint },
            TypedTableKey::CheckpointZkProof(checkpoint),
            TypedTableKey::ImtLeaf {
                tree: TreeId::new(5),
                tree_sub: TreeSubId::new(6),
                leaf: LeafIndex::new(7),
                checkpoint,
            },
            TypedTableKey::ImtKeyIndex {
                tree: TreeId::new(5),
                tree_sub: TreeSubId::new(6),
                encoded_key: ImtEncodedKey::new(imt_bytes),
            },
            TypedTableKey::ImtCursor { tree: TreeId::new(5), tree_sub: TreeSubId::new(6) },
            TypedTableKey::LatestInfo(LatestInfoSlot::RealmAuthorityObservation),
        ];
        assert_eq!(samples.len(), 39);
        for sample in samples {
            let encoded = describe_existing_key(&sample);
            let decoded = decode_locator_canonical(encoded.locator_bytes()).unwrap();
            assert_eq!(decoded, encoded, "failed domain {:?}", encoded.key_domain());
        }
    }
}
