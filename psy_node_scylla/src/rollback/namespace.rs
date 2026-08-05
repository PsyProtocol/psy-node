//! Typed identities and deterministic data commitments for the isolated
//! G0-03 namespace/cutover prototype.
//!
//! A recovery namespace is an internal physical storage identity. It is not a
//! chain identity or rollback ID. The same recovery intent deterministically
//! derives the same namespace pair, so a retry cannot silently select fresh
//! keyspaces.

use std::{collections::HashSet, error::Error, fmt};

use psy_node_core::store::typed::{CheckpointId, MerkleNode, NodeIndex};
use sha2::{Digest, Sha256};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

const NAMESPACE_DOMAIN: &[u8] = b"psy/scylla/recovery-namespace/v1";
const DATASET_DOMAIN: &[u8] = b"psy/scylla/representative-dataset/v1";
const STATE_ROOT_DOMAIN: &[u8] = b"psy/scylla/representative-state-root/v1";
const KEYSPACE_PREFIX: &str = "psy_rb_";
const NAMESPACE_NAME_BYTES: usize = 16;

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(i8)]
pub enum StorageAuthorityKind {
    Coordinator = 1,
    Realm = 2,
}

impl StorageAuthorityKind {
    pub const fn as_i8(self) -> i8 {
        self as i8
    }

    pub const fn try_from_i8(value: i8) -> Result<Self, NamespaceModelError> {
        match value {
            1 => Ok(Self::Coordinator),
            2 => Ok(Self::Realm),
            _ => Err(NamespaceModelError::InvalidAuthorityKind(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StorageAuthority {
    network_id: String,
    kind: StorageAuthorityKind,
    authority_id: u64,
}

impl StorageAuthority {
    pub fn try_new(
        network_id: impl Into<String>,
        kind: StorageAuthorityKind,
        authority_id: u64,
    ) -> Result<Self, NamespaceModelError> {
        let network_id = network_id.into();
        if network_id.is_empty() || network_id.len() > 128 || network_id.bytes().any(|byte| byte == 0) {
            return Err(NamespaceModelError::InvalidNetworkId(network_id));
        }
        if authority_id > i64::MAX as u64 {
            return Err(NamespaceModelError::IntegerOutOfCqlRange {
                field: "authority_id",
                value: authority_id,
            });
        }
        Ok(Self {
            network_id,
            kind,
            authority_id,
        })
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub const fn kind(&self) -> StorageAuthorityKind {
        self.kind
    }

    pub const fn authority_id(&self) -> u64 {
        self.authority_id
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BindingGeneration(u64);

impl BindingGeneration {
    pub const fn try_new(value: u64) -> Result<Self, NamespaceModelError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(NamespaceModelError::IntegerOutOfCqlRange {
                field: "binding_generation",
                value,
            })
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, NamespaceModelError> {
        match self.0.checked_add(1) {
            Some(value) if value <= i64::MAX as u64 => Ok(Self(value)),
            _ => Err(NamespaceModelError::BindingGenerationExhausted(self.0)),
        }
    }
}

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

digest_type!(NamespaceCheckpointHash);
digest_type!(RepresentativeDatasetDigest);
digest_type!(RepresentativeStateRoot);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecoveryNamespaceId([u8; 32]);

impl RecoveryNamespaceId {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn keyspace_suffix(&self) -> String {
        hex::encode(&self.0[..NAMESPACE_NAME_BYTES])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryNamespaceIntent {
    authority: StorageAuthority,
    target_checkpoint: CheckpointId,
    target_checkpoint_hash: NamespaceCheckpointHash,
    dataset_digest: RepresentativeDatasetDigest,
    state_root: RepresentativeStateRoot,
    expected_generation: BindingGeneration,
}

impl RecoveryNamespaceIntent {
    pub fn new(
        authority: StorageAuthority,
        target_checkpoint: CheckpointId,
        target_checkpoint_hash: NamespaceCheckpointHash,
        dataset_digest: RepresentativeDatasetDigest,
        state_root: RepresentativeStateRoot,
        expected_generation: BindingGeneration,
    ) -> Self {
        Self {
            authority,
            target_checkpoint,
            target_checkpoint_hash,
            dataset_digest,
            state_root,
            expected_generation,
        }
    }

    pub fn derive_namespace_id(&self) -> RecoveryNamespaceId {
        RecoveryNamespaceId(hash_parts(
            NAMESPACE_DOMAIN,
            &[
                self.authority.network_id().as_bytes(),
                &[self.authority.kind().as_i8() as u8],
                &self.authority.authority_id().to_be_bytes(),
                &self.target_checkpoint.get().to_be_bytes(),
                self.target_checkpoint_hash.as_bytes(),
                self.dataset_digest.as_bytes(),
                self.state_root.as_bytes(),
                &self.expected_generation.get().to_be_bytes(),
            ],
        ))
    }

    pub fn authority(&self) -> &StorageAuthority {
        &self.authority
    }

    pub const fn target_checkpoint(&self) -> CheckpointId {
        self.target_checkpoint
    }

    pub const fn target_checkpoint_hash(&self) -> NamespaceCheckpointHash {
        self.target_checkpoint_hash
    }

    pub const fn dataset_digest(&self) -> RepresentativeDatasetDigest {
        self.dataset_digest
    }

    pub const fn state_root(&self) -> RepresentativeStateRoot {
        self.state_root
    }

    pub const fn expected_generation(&self) -> BindingGeneration {
        self.expected_generation
    }
}

/// The standard/no-tablet keyspaces are one typed namespace. There is no
/// constructor accepting two unrelated strings.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityStorageNamespace {
    id: RecoveryNamespaceId,
    standard: CqlKeyspaceName,
    no_tablet: CqlKeyspaceName,
}

impl AuthorityStorageNamespace {
    pub fn derive(intent: &RecoveryNamespaceIntent) -> Result<Self, NamespaceModelError> {
        Self::from_id(intent.derive_namespace_id())
    }

    pub(crate) fn from_id(id: RecoveryNamespaceId) -> Result<Self, NamespaceModelError> {
        let suffix = id.keyspace_suffix();
        let standard = CqlKeyspaceName::try_new(format!("{KEYSPACE_PREFIX}{suffix}"))?;
        let no_tablet = CqlKeyspaceName::try_new(format!("{KEYSPACE_PREFIX}{suffix}_nt"))?;
        Ok(Self {
            id,
            standard,
            no_tablet,
        })
    }

    pub fn validate_persisted_pair(
        id: RecoveryNamespaceId,
        standard: impl Into<String>,
        no_tablet: impl Into<String>,
    ) -> Result<Self, NamespaceModelError> {
        let expected = Self::from_id(id)?;
        let standard = CqlKeyspaceName::try_new(standard)?;
        let no_tablet = CqlKeyspaceName::try_new(no_tablet)?;
        if standard != expected.standard || no_tablet != expected.no_tablet {
            return Err(NamespaceModelError::MixedNamespacePair {
                expected_standard: expected.standard.as_str().to_owned(),
                actual_standard: standard.as_str().to_owned(),
                expected_no_tablet: expected.no_tablet.as_str().to_owned(),
                actual_no_tablet: no_tablet.as_str().to_owned(),
            });
        }
        Ok(expected)
    }

    pub const fn id(&self) -> RecoveryNamespaceId {
        self.id
    }

    pub const fn standard(&self) -> &CqlKeyspaceName {
        &self.standard
    }

    pub const fn no_tablet(&self) -> &CqlKeyspaceName {
        &self.no_tablet
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointLeafSnapshotRow {
    checkpoint: CheckpointId,
    value: Vec<u8>,
}

impl CheckpointLeafSnapshotRow {
    pub fn try_new(checkpoint: CheckpointId, value: Vec<u8>) -> Result<Self, NamespaceModelError> {
        if value.is_empty() {
            return Err(NamespaceModelError::EmptyValue("checkpoint_leaf_table"));
        }
        Ok(Self { checkpoint, value })
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalUserMerkleSnapshotRow {
    node: MerkleNode,
    checkpoint: CheckpointId,
    value: [u8; 32],
}

impl GlobalUserMerkleSnapshotRow {
    pub const fn new(node: MerkleNode, checkpoint: CheckpointId, value: [u8; 32]) -> Self {
        Self {
            node,
            checkpoint,
            value,
        }
    }

    pub const fn node(&self) -> MerkleNode {
        self.node
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn value(&self) -> &[u8; 32] {
        &self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoTabletCounterSnapshotRow {
    obj_id: u64,
    value: u64,
}

impl NoTabletCounterSnapshotRow {
    pub const fn try_new(obj_id: u64, value: u64) -> Result<Self, NamespaceModelError> {
        if obj_id > i64::MAX as u64 {
            return Err(NamespaceModelError::IntegerOutOfCqlRange {
                field: "counter_obj_id",
                value: obj_id,
            });
        }
        if value > i64::MAX as u64 {
            return Err(NamespaceModelError::IntegerOutOfCqlRange {
                field: "counter_value",
                value,
            });
        }
        Ok(Self { obj_id, value })
    }

    pub const fn obj_id(self) -> u64 {
        self.obj_id
    }

    pub const fn value(self) -> u64 {
        self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepresentativeRowCounts {
    checkpoint_leaf: u64,
    global_user_merkle: u64,
    no_tablet_counter: u64,
}

impl RepresentativeRowCounts {
    pub const fn try_new(
        checkpoint_leaf: u64,
        global_user_merkle: u64,
        no_tablet_counter: u64,
    ) -> Result<Self, NamespaceModelError> {
        if checkpoint_leaf == 0 {
            return Err(NamespaceModelError::EmptyRepresentativeTable("checkpoint_leaf_table"));
        }
        if global_user_merkle == 0 {
            return Err(NamespaceModelError::EmptyRepresentativeTable("global_user_tree_table"));
        }
        if no_tablet_counter == 0 {
            return Err(NamespaceModelError::EmptyRepresentativeTable("u64_counter_singleton_table"));
        }
        if checkpoint_leaf > i64::MAX as u64 {
            return Err(NamespaceModelError::IntegerOutOfCqlRange {
                field: "checkpoint_leaf_rows",
                value: checkpoint_leaf,
            });
        }
        if global_user_merkle > i64::MAX as u64 {
            return Err(NamespaceModelError::IntegerOutOfCqlRange {
                field: "global_user_merkle_rows",
                value: global_user_merkle,
            });
        }
        if no_tablet_counter > i64::MAX as u64 {
            return Err(NamespaceModelError::IntegerOutOfCqlRange {
                field: "no_tablet_counter_rows",
                value: no_tablet_counter,
            });
        }
        Ok(Self {
            checkpoint_leaf,
            global_user_merkle,
            no_tablet_counter,
        })
    }

    pub const fn checkpoint_leaf(self) -> u64 {
        self.checkpoint_leaf
    }

    pub const fn global_user_merkle(self) -> u64 {
        self.global_user_merkle
    }

    pub const fn no_tablet_counter(self) -> u64 {
        self.no_tablet_counter
    }

    pub const fn total(self) -> u64 {
        self.checkpoint_leaf + self.global_user_merkle + self.no_tablet_counter
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepresentativeDataset {
    checkpoint_leaves: Vec<CheckpointLeafSnapshotRow>,
    global_user_merkle: Vec<GlobalUserMerkleSnapshotRow>,
    no_tablet_counters: Vec<NoTabletCounterSnapshotRow>,
    digest: RepresentativeDatasetDigest,
    state_root: RepresentativeStateRoot,
}

impl RepresentativeDataset {
    pub fn try_new(
        mut checkpoint_leaves: Vec<CheckpointLeafSnapshotRow>,
        mut global_user_merkle: Vec<GlobalUserMerkleSnapshotRow>,
        mut no_tablet_counters: Vec<NoTabletCounterSnapshotRow>,
    ) -> Result<Self, NamespaceModelError> {
        if checkpoint_leaves.is_empty() {
            return Err(NamespaceModelError::EmptyRepresentativeTable("checkpoint_leaf_table"));
        }
        if global_user_merkle.is_empty() {
            return Err(NamespaceModelError::EmptyRepresentativeTable("global_user_tree_table"));
        }
        if no_tablet_counters.is_empty() {
            return Err(NamespaceModelError::EmptyRepresentativeTable("u64_counter_singleton_table"));
        }

        checkpoint_leaves.sort_by_key(|row| row.checkpoint.get());
        global_user_merkle.sort_by_key(|row| (row.node.level(), row.node.index().get(), row.checkpoint.get()));
        no_tablet_counters.sort_by_key(|row| row.obj_id);

        reject_duplicates(
            checkpoint_leaves.iter().map(|row| row.checkpoint.get()),
            "checkpoint_leaf_table",
        )?;
        reject_duplicates(
            global_user_merkle
                .iter()
                .map(|row| (row.node.level(), row.node.index().get(), row.checkpoint.get())),
            "global_user_tree_table",
        )?;
        reject_duplicates(
            no_tablet_counters.iter().map(|row| row.obj_id),
            "u64_counter_singleton_table",
        )?;

        let state_root = RepresentativeStateRoot(hash_merkle_rows(&global_user_merkle));
        let canonical = encode_dataset(
            &checkpoint_leaves,
            &global_user_merkle,
            &no_tablet_counters,
            state_root,
        );
        let digest = RepresentativeDatasetDigest(hash_parts(DATASET_DOMAIN, &[&canonical]));
        Ok(Self {
            checkpoint_leaves,
            global_user_merkle,
            no_tablet_counters,
            digest,
            state_root,
        })
    }

    pub fn artificial(
        seed: u64,
        target: CheckpointId,
        leaf_rows: u64,
        merkle_rows: u64,
        counter_rows: u64,
    ) -> Result<Self, NamespaceModelError> {
        if leaf_rows == 0 || merkle_rows == 0 || counter_rows == 0 {
            return Err(NamespaceModelError::ArtificialDatasetMustCoverAllTables);
        }
        if target.get() + 1 < leaf_rows {
            return Err(NamespaceModelError::ArtificialTargetTooSmall {
                target: target.get(),
                leaf_rows,
            });
        }
        let mut leaves = Vec::with_capacity(leaf_rows as usize);
        for offset in 0..leaf_rows {
            let checkpoint = CheckpointId::try_new(target.get() - (leaf_rows - 1 - offset))?;
            let value = hash_parts(
                b"psy/scylla/artificial-leaf/v1",
                &[&seed.to_be_bytes(), &checkpoint.get().to_be_bytes()],
            )
            .to_vec();
            leaves.push(CheckpointLeafSnapshotRow::try_new(checkpoint, value)?);
        }
        let mut merkle = Vec::with_capacity(merkle_rows as usize);
        for position in 0..merkle_rows {
            let node = MerkleNode::new(10 + (position % 3) as u8, NodeIndex::new(position));
            let value = hash_parts(
                b"psy/scylla/artificial-merkle/v1",
                &[
                    &seed.to_be_bytes(),
                    &[node.level()],
                    &node.index().get().to_be_bytes(),
                    &target.get().to_be_bytes(),
                ],
            );
            merkle.push(GlobalUserMerkleSnapshotRow::new(node, target, value));
        }
        let mut counters = Vec::with_capacity(counter_rows as usize);
        for offset in 0..counter_rows {
            counters.push(NoTabletCounterSnapshotRow::try_new(
                10_000 + offset,
                seed.checked_mul(100).and_then(|value| value.checked_add(offset)).ok_or(
                    NamespaceModelError::ArtificialCounterOverflow,
                )?,
            )?);
        }
        Self::try_new(leaves, merkle, counters)
    }

    pub fn checkpoint_leaves(&self) -> &[CheckpointLeafSnapshotRow] {
        &self.checkpoint_leaves
    }

    pub fn global_user_merkle(&self) -> &[GlobalUserMerkleSnapshotRow] {
        &self.global_user_merkle
    }

    pub fn no_tablet_counters(&self) -> &[NoTabletCounterSnapshotRow] {
        &self.no_tablet_counters
    }

    pub const fn digest(&self) -> RepresentativeDatasetDigest {
        self.digest
    }

    pub const fn state_root(&self) -> RepresentativeStateRoot {
        self.state_root
    }

    pub fn counts(&self) -> RepresentativeRowCounts {
        RepresentativeRowCounts {
            checkpoint_leaf: self.checkpoint_leaves.len() as u64,
            global_user_merkle: self.global_user_merkle.len() as u64,
            no_tablet_counter: self.no_tablet_counters.len() as u64,
        }
    }
}

fn reject_duplicates<T>(values: impl IntoIterator<Item = T>, table: &'static str) -> Result<(), NamespaceModelError>
where
    T: Eq + std::hash::Hash,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(NamespaceModelError::DuplicateRepresentativeKey(table));
        }
    }
    Ok(())
}

fn hash_merkle_rows(rows: &[GlobalUserMerkleSnapshotRow]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(rows.len() * 57);
    encoded.extend_from_slice(&(rows.len() as u64).to_be_bytes());
    for row in rows {
        encoded.push(row.node.level());
        encoded.extend_from_slice(&row.node.index().get().to_be_bytes());
        encoded.extend_from_slice(&row.checkpoint.get().to_be_bytes());
        encoded.extend_from_slice(&row.value);
    }
    hash_parts(STATE_ROOT_DOMAIN, &[&encoded])
}

fn encode_dataset(
    leaves: &[CheckpointLeafSnapshotRow],
    merkle: &[GlobalUserMerkleSnapshotRow],
    counters: &[NoTabletCounterSnapshotRow],
    state_root: RepresentativeStateRoot,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(leaves.len() as u64).to_be_bytes());
    for row in leaves {
        encoded.extend_from_slice(&row.checkpoint.get().to_be_bytes());
        encoded.extend_from_slice(&(row.value.len() as u64).to_be_bytes());
        encoded.extend_from_slice(&row.value);
    }
    encoded.extend_from_slice(&(merkle.len() as u64).to_be_bytes());
    for row in merkle {
        encoded.push(row.node.level());
        encoded.extend_from_slice(&row.node.index().get().to_be_bytes());
        encoded.extend_from_slice(&row.checkpoint.get().to_be_bytes());
        encoded.extend_from_slice(&row.value);
    }
    encoded.extend_from_slice(&(counters.len() as u64).to_be_bytes());
    for row in counters {
        encoded.extend_from_slice(&row.obj_id.to_be_bytes());
        encoded.extend_from_slice(&row.value.to_be_bytes());
    }
    encoded.extend_from_slice(state_root.as_bytes());
    encoded
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryNamespaceDescriptor {
    intent: RecoveryNamespaceIntent,
    namespace: AuthorityStorageNamespace,
    row_counts: RepresentativeRowCounts,
}

impl RecoveryNamespaceDescriptor {
    pub fn from_dataset(
        authority: StorageAuthority,
        target_checkpoint: CheckpointId,
        target_checkpoint_hash: NamespaceCheckpointHash,
        expected_generation: BindingGeneration,
        dataset: &RepresentativeDataset,
    ) -> Result<Self, NamespaceModelError> {
        let intent = RecoveryNamespaceIntent::new(
            authority,
            target_checkpoint,
            target_checkpoint_hash,
            dataset.digest(),
            dataset.state_root(),
            expected_generation,
        );
        let namespace = AuthorityStorageNamespace::derive(&intent)?;
        Ok(Self {
            intent,
            namespace,
            row_counts: dataset.counts(),
        })
    }

    pub(crate) fn from_persisted(
        intent: RecoveryNamespaceIntent,
        namespace: AuthorityStorageNamespace,
        row_counts: RepresentativeRowCounts,
    ) -> Result<Self, NamespaceModelError> {
        let descriptor = Self {
            intent,
            namespace,
            row_counts,
        };
        descriptor.validate_identity()?;
        Ok(descriptor)
    }

    pub fn validate_identity(&self) -> Result<(), NamespaceModelError> {
        let expected = AuthorityStorageNamespace::derive(&self.intent)?;
        if expected != self.namespace {
            return Err(NamespaceModelError::NamespaceIdentityMismatch);
        }
        Ok(())
    }

    pub fn intent(&self) -> &RecoveryNamespaceIntent {
        &self.intent
    }

    pub fn namespace(&self) -> &AuthorityStorageNamespace {
        &self.namespace
    }

    pub const fn row_counts(&self) -> RepresentativeRowCounts {
        self.row_counts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i8)]
pub enum RecoveryNamespaceStatus {
    Loading = 1,
    Verified = 2,
    Failed = 3,
}

impl RecoveryNamespaceStatus {
    pub const fn as_i8(self) -> i8 {
        self as i8
    }

    pub const fn try_from_i8(value: i8) -> Result<Self, NamespaceModelError> {
        match value {
            1 => Ok(Self::Loading),
            2 => Ok(Self::Verified),
            3 => Ok(Self::Failed),
            _ => Err(NamespaceModelError::InvalidNamespaceStatus(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadingRecoveryNamespace {
    descriptor: RecoveryNamespaceDescriptor,
}

impl LoadingRecoveryNamespace {
    pub(crate) fn new(descriptor: RecoveryNamespaceDescriptor) -> Self {
        Self { descriptor }
    }

    pub fn descriptor(&self) -> &RecoveryNamespaceDescriptor {
        &self.descriptor
    }
}

/// A durable catalog record which has passed read-back verification.
///
/// ```compile_fail
/// use psy_node_scylla::rollback::VerifiedRecoveryNamespace;
/// let _forged = VerifiedRecoveryNamespace { /* fields are private */ };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecoveryNamespace {
    descriptor: RecoveryNamespaceDescriptor,
    verified_at_unix_ms: i64,
}

impl VerifiedRecoveryNamespace {
    pub(crate) fn new(descriptor: RecoveryNamespaceDescriptor, verified_at_unix_ms: i64) -> Self {
        Self {
            descriptor,
            verified_at_unix_ms,
        }
    }

    pub fn descriptor(&self) -> &RecoveryNamespaceDescriptor {
        &self.descriptor
    }

    pub const fn verified_at_unix_ms(&self) -> i64 {
        self.verified_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityStorageBinding {
    authority: StorageAuthority,
    generation: BindingGeneration,
    namespace: AuthorityStorageNamespace,
    checkpoint: CheckpointId,
    checkpoint_hash: NamespaceCheckpointHash,
    state_root: RepresentativeStateRoot,
    dataset_digest: RepresentativeDatasetDigest,
    updated_at_unix_ms: i64,
}

impl AuthorityStorageBinding {
    pub(crate) fn new(
        authority: StorageAuthority,
        generation: BindingGeneration,
        namespace: AuthorityStorageNamespace,
        checkpoint: CheckpointId,
        checkpoint_hash: NamespaceCheckpointHash,
        state_root: RepresentativeStateRoot,
        dataset_digest: RepresentativeDatasetDigest,
        updated_at_unix_ms: i64,
    ) -> Self {
        Self {
            authority,
            generation,
            namespace,
            checkpoint,
            checkpoint_hash,
            state_root,
            dataset_digest,
            updated_at_unix_ms,
        }
    }

    pub fn authority(&self) -> &StorageAuthority {
        &self.authority
    }

    pub const fn generation(&self) -> BindingGeneration {
        self.generation
    }

    pub fn namespace(&self) -> &AuthorityStorageNamespace {
        &self.namespace
    }

    pub const fn checkpoint(&self) -> CheckpointId {
        self.checkpoint
    }

    pub const fn checkpoint_hash(&self) -> NamespaceCheckpointHash {
        self.checkpoint_hash
    }

    pub const fn state_root(&self) -> RepresentativeStateRoot {
        self.state_root
    }

    pub const fn dataset_digest(&self) -> RepresentativeDatasetDigest {
        self.dataset_digest
    }

    pub const fn updated_at_unix_ms(&self) -> i64 {
        self.updated_at_unix_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespaceModelError {
    InvalidNetworkId(String),
    InvalidAuthorityKind(i8),
    InvalidNamespaceStatus(i8),
    IntegerOutOfCqlRange {
        field: &'static str,
        value: u64,
    },
    BindingGenerationExhausted(u64),
    InvalidKeyspace(InvalidCqlKeyspaceName),
    MixedNamespacePair {
        expected_standard: String,
        actual_standard: String,
        expected_no_tablet: String,
        actual_no_tablet: String,
    },
    NamespaceIdentityMismatch,
    EmptyValue(&'static str),
    EmptyRepresentativeTable(&'static str),
    DuplicateRepresentativeKey(&'static str),
    ArtificialDatasetMustCoverAllTables,
    ArtificialTargetTooSmall {
        target: u64,
        leaf_rows: u64,
    },
    ArtificialCounterOverflow,
    CheckpointOutOfRange(u64),
}

impl fmt::Display for NamespaceModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNetworkId(value) => write!(f, "invalid network id {value:?}"),
            Self::InvalidAuthorityKind(value) => write!(f, "unknown storage authority kind {value}"),
            Self::InvalidNamespaceStatus(value) => write!(f, "unknown recovery namespace status {value}"),
            Self::IntegerOutOfCqlRange { field, value } => {
                write!(f, "{field}={value} exceeds the non-negative CQL BIGINT range")
            }
            Self::BindingGenerationExhausted(value) => write!(f, "binding generation cannot advance past {value}"),
            Self::InvalidKeyspace(error) => error.fmt(f),
            Self::MixedNamespacePair {
                expected_standard,
                actual_standard,
                expected_no_tablet,
                actual_no_tablet,
            } => write!(
                f,
                "mixed namespace pair: expected ({expected_standard},{expected_no_tablet}), got ({actual_standard},{actual_no_tablet})"
            ),
            Self::NamespaceIdentityMismatch => write!(f, "namespace keyspace pair does not match its deterministic intent identity"),
            Self::EmptyValue(table) => write!(f, "representative row for {table} has an empty value"),
            Self::EmptyRepresentativeTable(table) => write!(f, "representative dataset has no rows for {table}"),
            Self::DuplicateRepresentativeKey(table) => write!(f, "representative dataset contains a duplicate key for {table}"),
            Self::ArtificialDatasetMustCoverAllTables => {
                write!(f, "artificial dataset must contain rows for all three representative tables")
            }
            Self::ArtificialTargetTooSmall { target, leaf_rows } => {
                write!(f, "target checkpoint {target} cannot provide {leaf_rows} non-negative leaf checkpoints")
            }
            Self::ArtificialCounterOverflow => write!(f, "artificial counter value overflowed u64"),
            Self::CheckpointOutOfRange(value) => write!(f, "checkpoint {value} is outside the typed CQL range"),
        }
    }
}

impl Error for NamespaceModelError {}

impl From<InvalidCqlKeyspaceName> for NamespaceModelError {
    fn from(value: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(value)
    }
}

impl From<psy_node_core::store::typed::CheckpointIdOutOfRange> for NamespaceModelError {
    fn from(value: psy_node_core::store::typed::CheckpointIdOutOfRange) -> Self {
        Self::CheckpointOutOfRange(value.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> StorageAuthority {
        StorageAuthority::try_new("g003", StorageAuthorityKind::Realm, 7).unwrap()
    }

    fn dataset(seed: u64) -> RepresentativeDataset {
        RepresentativeDataset::artificial(seed, CheckpointId::try_new(100).unwrap(), 3, 4, 2).unwrap()
    }

    fn descriptor(seed: u64, generation: u64) -> RecoveryNamespaceDescriptor {
        let dataset = dataset(seed);
        RecoveryNamespaceDescriptor::from_dataset(
            authority(),
            CheckpointId::try_new(100).unwrap(),
            NamespaceCheckpointHash::new([seed as u8; 32]),
            BindingGeneration::try_new(generation).unwrap(),
            &dataset,
        )
        .unwrap()
    }

    #[test]
    fn namespace_identity_is_deterministic_and_domain_separated() {
        let first = descriptor(1, 0);
        let retry = descriptor(1, 0);
        assert_eq!(first, retry);
        assert_ne!(first.namespace().id(), descriptor(2, 0).namespace().id());
        assert_ne!(first.namespace().id(), descriptor(1, 1).namespace().id());

        let other_authority = StorageAuthority::try_new("g003", StorageAuthorityKind::Realm, 8).unwrap();
        let data = dataset(1);
        let other = RecoveryNamespaceDescriptor::from_dataset(
            other_authority,
            CheckpointId::try_new(100).unwrap(),
            NamespaceCheckpointHash::new([1; 32]),
            BindingGeneration::try_new(0).unwrap(),
            &data,
        )
        .unwrap();
        assert_ne!(first.namespace().id(), other.namespace().id());
    }

    #[test]
    fn mixed_standard_and_no_tablet_pair_is_rejected() {
        let first = descriptor(1, 0);
        let second = descriptor(2, 0);
        assert!(matches!(
            AuthorityStorageNamespace::validate_persisted_pair(
                first.namespace().id(),
                first.namespace().standard().as_str(),
                second.namespace().no_tablet().as_str(),
            ),
            Err(NamespaceModelError::MixedNamespacePair { .. })
        ));
    }

    #[test]
    fn dataset_digest_is_canonical_and_covers_every_family() {
        let first = dataset(1);
        let mut reversed_leaves = first.checkpoint_leaves().to_vec();
        let mut reversed_merkle = first.global_user_merkle().to_vec();
        let mut reversed_counters = first.no_tablet_counters().to_vec();
        reversed_leaves.reverse();
        reversed_merkle.reverse();
        reversed_counters.reverse();
        let reordered = RepresentativeDataset::try_new(reversed_leaves, reversed_merkle, reversed_counters).unwrap();
        assert_eq!(first.digest(), reordered.digest());
        assert_eq!(first.state_root(), reordered.state_root());
        assert_ne!(first.digest(), dataset(2).digest());
        assert_eq!(first.counts().total(), 9);
    }

    #[test]
    fn forged_descriptor_identity_fails_closed() {
        let mut forged = descriptor(1, 0);
        forged.namespace = descriptor(2, 0).namespace().clone();
        assert_eq!(forged.validate_identity(), Err(NamespaceModelError::NamespaceIdentityMismatch));
    }
}
