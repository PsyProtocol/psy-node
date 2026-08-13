//! Strict, driver-independent physical-key inventory for one committed
//! Coordinator checkpoint.
//!
//! The inventory mirrors the current production `commit_state` branches. It
//! does not read or write Scylla, archive values, delete rows, restore mutable
//! singletons, or publish a canonical head. Values and writetimes are selected
//! from the hot tables later by the archive executor; this object only freezes
//! the exact physical primary-key set and its rollback treatment.

use std::{
    collections::BTreeSet, error::Error, fmt, io::Cursor as IoCursor,
};

use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher, QFieldHashable},
    data::hash::{
        fast_node_serializer::QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
        merkle_node_key::PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE,
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::{
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    protocol::canonical_chain::{
        CanonicalChainRef, CANONICAL_CHAIN_REF_V1_LEN,
    },
    v1::qdata::ffs_sizes::{
        PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF, PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY,
    },
};
use psy_node_core::store::{
    coordinator_commit_source::{
        CoordinatorCommitSource, CoordinatorCommitSourceCommitted,
        CoordinatorCommitSourcePayload, CoordinatorRollbackFloor,
    },
    typed::{
        CheckpointId, CheckpointRootKey, ContractId, LatestInfoSlot,
        MerkleNode, NodeIndex, ProcCheckpointUniqueId, PublicKeyHash, RealmId,
        TypedTableKey, U64SingletonSlot, UniquePendingId, UserId,
    },
};
use psy_serialize::PsyIOReadWrite;
use sha2::{Digest, Sha256};

use super::{decode_locator_canonical, describe_existing_key, ResolvedScyllaKey};

const INVENTORY_MAGIC: &[u8; 8] = b"PSYCCINV";
const INVENTORY_CODEC_VERSION: u16 = 1;
const INVENTORY_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-inventory.v1\0";
const CATALOG_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-catalog.v1\0";
// This byte is a versioned contract for the later executor, not proof that any
// of these gates has passed. An inventory can describe rows, but it can never
// authorize deletion by itself.
const EXECUTOR_REQUIRES_ARCHIVE_EXACT_READBACK: u8 = 1 << 0;
const EXECUTOR_REQUIRES_ALL_PARTICIPANT_BARRIER: u8 = 1 << 1;
const EXECUTOR_REQUIRES_ROLLBACK_WRITE_FENCE: u8 = 1 << 2;
const REQUIRED_EXECUTOR_GATES: u8 = EXECUTOR_REQUIRES_ARCHIVE_EXACT_READBACK
    | EXECUTOR_REQUIRES_ALL_PARTICIPANT_BARRIER
    | EXECUTOR_REQUIRES_ROLLBACK_WRITE_FENCE;
const MAX_INVENTORY_ROWS: usize = 1_048_576;
const HASH_TO_USER_ROW_BYTES: usize = 40;
const REWARD_NODE_ROW_BYTES: usize = 8 + 9;

/// Treatment of one hot-table primary key during delete-only rollback.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CoordinatorCommitInventoryAction {
    /// The key is owned by this checkpoint/pending suffix and can be archived
    /// and deleted after the all-participant archive barrier.
    ArchiveThenDelete = 1,
    /// The physical singleton is overwritten by every checkpoint. Archive its
    /// current value, then restore the target value under the rollback fence.
    ArchiveThenRestoreTarget = 2,
}

impl TryFrom<u8> for CoordinatorCommitInventoryAction {
    type Error = CoordinatorCommitPhysicalInventoryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ArchiveThenDelete),
            2 => Ok(Self::ArchiveThenRestoreTarget),
            value => Err(CoordinatorCommitPhysicalInventoryError::UnknownAction(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorCommitInventoryEntry {
    action: CoordinatorCommitInventoryAction,
    key: ResolvedScyllaKey,
}

impl CoordinatorCommitInventoryEntry {
    pub const fn action(&self) -> CoordinatorCommitInventoryAction {
        self.action
    }

    pub const fn key(&self) -> &ResolvedScyllaKey {
        &self.key
    }
}

/// Complete physical primary-key set for one exact committed source object.
/// It is evidence, not an archive/delete capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorCommitPhysicalInventory<Hash> {
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    candidate: CanonicalChainRef<Hash>,
    committed_marker: [u8; 106],
    entries: Vec<CoordinatorCommitInventoryEntry>,
    digest: [u8; 32],
}

impl<Hash> CoordinatorCommitPhysicalInventory<Hash> {
    pub const fn source_slot(&self) -> &[u8; 32] {
        &self.source_slot
    }

    pub const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub fn entries(&self) -> &[CoordinatorCommitInventoryEntry] {
        &self.entries
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn delete_row_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| {
                entry.action == CoordinatorCommitInventoryAction::ArchiveThenDelete
            })
            .count()
    }

    pub fn restore_row_count(&self) -> usize {
        self.entries.len() - self.delete_row_count()
    }
}

impl<Hash: Q256BitHash> CoordinatorCommitPhysicalInventory<Hash> {
    /// Assemble one exact branch suffix. Checkpoint numbers alone are not
    /// sufficient: every source must name the preceding candidate as its
    /// expected head, and the final candidate must equal `old_head`.
    pub fn try_suffix_from_committed_sources<F, Hasher>(
        target: &CanonicalChainRef<Hash>,
        old_head: &CanonicalChainRef<Hash>,
        sources: &[(CoordinatorCommitSource<Hash>, CoordinatorCommitSourceCommitted)],
        checkpoint_tree_height: u8,
    ) -> Result<Vec<Self>, CoordinatorCommitPhysicalInventoryError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        let target_checkpoint = target.checkpoint().checkpoint_id().get();
        let old_head_checkpoint = old_head.checkpoint().checkpoint_id().get();
        if target.network_id() != old_head.network_id()
            || target.chain_epoch() != old_head.chain_epoch()
            || target_checkpoint > old_head_checkpoint
        {
            return Err(CoordinatorCommitPhysicalInventoryError::SuffixBranchMismatch);
        }
        let expected_len = old_head_checkpoint - target_checkpoint;
        if sources.len() as u64 != expected_len {
            return Err(CoordinatorCommitPhysicalInventoryError::SuffixLengthMismatch {
                expected: expected_len,
                actual: sources.len() as u64,
            });
        }

        let mut preceding = *target;
        let mut inventories = Vec::with_capacity(sources.len());
        for (offset, (source, marker)) in sources.iter().enumerate() {
            let expected_checkpoint = target_checkpoint + 1 + offset as u64;
            if source.expected() != &preceding
                || source.candidate().network_id() != target.network_id()
                || source.candidate().chain_epoch() != target.chain_epoch()
                || source.candidate().checkpoint().checkpoint_id().get()
                    != expected_checkpoint
            {
                return Err(CoordinatorCommitPhysicalInventoryError::SuffixLinkMismatch {
                    checkpoint: expected_checkpoint,
                });
            }
            let inventory = Self::try_from_committed_source::<F, Hasher>(
                source,
                *marker,
                checkpoint_tree_height,
            )?;
            preceding = *source.candidate();
            inventories.push(inventory);
        }
        if preceding != *old_head {
            return Err(CoordinatorCommitPhysicalInventoryError::SuffixHeadMismatch);
        }
        Ok(inventories)
    }

    /// Decode the exact source payload only after matching an independent
    /// COMMITTED marker, then mirror every production hot-table branch.
    pub fn try_from_committed_source<F, Hasher>(
        source: &CoordinatorCommitSource<Hash>,
        marker: CoordinatorCommitSourceCommitted,
        checkpoint_tree_height: u8,
    ) -> Result<Self, CoordinatorCommitPhysicalInventoryError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        if !marker.matches(source) {
            return Err(CoordinatorCommitPhysicalInventoryError::CommittedMarkerMismatch);
        }
        let payload = CoordinatorCommitSourcePayload::decode_canonical(
            source.prepared_update(),
        )
        .map_err(|error| {
            CoordinatorCommitPhysicalInventoryError::SourcePayload(error.to_string())
        })?;
        let mut cursor = IoCursor::new(payload.prepared_update());
        let prepared = PsyPreparedCoordinatorBlockStateUpdates::<F, Hash>::pio_read_from_io(
            &mut cursor,
        )
        .map_err(|error| {
            CoordinatorCommitPhysicalInventoryError::PreparedUpdate(error.to_string())
        })?;
        if cursor.position() != payload.prepared_update().len() as u64 {
            return Err(CoordinatorCommitPhysicalInventoryError::TrailingPreparedUpdateBytes);
        }
        Self::try_from_parts::<F, Hasher>(
            source,
            marker,
            &prepared,
            checkpoint_tree_height,
        )
    }

    fn try_from_parts<F, Hasher>(
        source: &CoordinatorCommitSource<Hash>,
        marker: CoordinatorCommitSourceCommitted,
        prepared: &PsyPreparedCoordinatorBlockStateUpdates<F, Hash>,
        checkpoint_tree_height: u8,
    ) -> Result<Self, CoordinatorCommitPhysicalInventoryError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        let checkpoint_u64 = source
            .candidate()
            .checkpoint()
            .checkpoint_id()
            .get();
        if checkpoint_u64 == 0
            || prepared.checkpoint_id != checkpoint_u64
            || prepared.new_base.block_state.checkpoint_id != checkpoint_u64
            || prepared.old_base.block_state.checkpoint_id
                != source.expected().checkpoint().checkpoint_id().get()
        {
            return Err(CoordinatorCommitPhysicalInventoryError::CheckpointIdentityMismatch);
        }
        if checkpoint_tree_height == 0
            || checkpoint_tree_height > 64
            || prepared.checkpoint_tree_update_proof.siblings.len()
                != checkpoint_tree_height as usize
        {
            return Err(CoordinatorCommitPhysicalInventoryError::CheckpointTreeHeightMismatch);
        }
        let computed_leaf_hash = prepared
            .new_base
            .checkpoint_leaf
            .qfhash::<Hasher>();
        let proof = &prepared.checkpoint_tree_update_proof;
        if computed_leaf_hash != prepared.new_base.checkpoint_leaf_hash
            || proof.index != checkpoint_u64
            || proof.old_root != prepared.old_base.checkpoint_tree_root
            || proof.old_value != prepared.old_base.checkpoint_leaf_hash
            || proof.new_root != prepared.new_base.checkpoint_tree_root
            || proof.new_value != prepared.new_base.checkpoint_leaf_hash
            || !proof.verify::<Hasher>()
        {
            return Err(CoordinatorCommitPhysicalInventoryError::CheckpointTreeProofMismatch);
        }

        let checkpoint = CheckpointId::try_new(checkpoint_u64).map_err(|_| {
            CoordinatorCommitPhysicalInventoryError::CheckpointOutOfRange(checkpoint_u64)
        })?;
        let pending = UniquePendingId::try_new(prepared.unique_pending_id).map_err(|_| {
            CoordinatorCommitPhysicalInventoryError::PendingOutOfRange(
                prepared.unique_pending_id,
            )
        })?;
        let proc_id = ProcCheckpointUniqueId::from_u128(
            prepared.proc_checkpoint_unique_id,
        );

        let mut keys = Vec::new();
        // Critical proof + four exact mapping rows written before state data.
        keys.push(TypedTableKey::CheckpointZkProof(checkpoint));
        keys.push(TypedTableKey::PendingToCheckpoint(pending));
        keys.push(TypedTableKey::CheckpointToPending(checkpoint));
        keys.push(TypedTableKey::PendingToProc(pending));
        keys.push(TypedTableKey::ProcToPending(proc_id));

        // Contract branch is entered only when the leaf FFS is non-empty.
        if !prepared.new_contract_leaves_ffs.is_empty() {
            push_object_ids(
                &mut keys,
                &prepared.new_contract_leaves_ffs,
                8 + PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF,
                |contract| TypedTableKey::ContractLeaf {
                    contract: ContractId::new(contract),
                    checkpoint,
                },
                "contract leaf",
            )?;
            for definition in &prepared.new_contract_code_definitions {
                keys.push(TypedTableKey::ContractCodeDefinition {
                    contract: ContractId::new(definition.contract_id),
                    checkpoint,
                });
            }
            let first_contract = u64::from(prepared.old_base.block_state.next_contract_id);
            for index in 0..prepared.new_contract_code_definitions.len() {
                let contract = first_contract.checked_add(index as u64).ok_or(
                    CoordinatorCommitPhysicalInventoryError::IdentifierOverflow(
                        "contract state-tree height",
                    ),
                )?;
                keys.push(TypedTableKey::ContractStateTreeHeight {
                    contract: ContractId::new(contract),
                    checkpoint,
                });
            }
            push_single_merkle_keys(
                &mut keys,
                &prepared.update_contract_function_tree_nodes_ffs,
                checkpoint,
            )?;
            push_zero_merkle_keys(
                &mut keys,
                &prepared.update_global_contract_tree_nodes_ffs,
                checkpoint,
                ZeroMerkleDomain::GlobalContract,
            )?;
        }

        // User-registration branch mirrors the public-key emptiness guard.
        if !prepared.new_user_public_keys_ffs.is_empty() {
            push_object_ids(
                &mut keys,
                &prepared.new_user_public_keys_ffs,
                8 + PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY,
                |user| TypedTableKey::UserPublicKey {
                    user: UserId::new(user),
                    checkpoint,
                },
                "user public key",
            )?;
            push_public_key_projection(
                &mut keys,
                &prepared.new_public_key_hash_to_user_id_rows_ffs,
            )?;
            push_zero_merkle_keys(
                &mut keys,
                &prepared.update_user_registration_tree_nodes_ffs,
                checkpoint,
                ZeroMerkleDomain::UserRegistration,
            )?;
        }

        if !prepared.update_global_user_tree_nodes_ffs.is_empty() {
            push_zero_merkle_keys(
                &mut keys,
                &prepared.update_global_user_tree_nodes_ffs,
                checkpoint,
                ZeroMerkleDomain::GlobalUser,
            )?;
        }
        if !prepared.new_realm_guta_reward_tree_node_keys_ffs.is_empty() {
            push_reward_node_keys(
                &mut keys,
                &prepared.new_realm_guta_reward_tree_node_keys_ffs,
                pending,
            )?;
        }

        // Always-written checkpoint rows and compatibility singletons.
        keys.push(TypedTableKey::CheckpointStateRoots(checkpoint));
        keys.push(TypedTableKey::L2BlockState(checkpoint));
        keys.push(TypedTableKey::LatestInfo(
            LatestInfoSlot::LatestL2BlockState,
        ));
        keys.push(TypedTableKey::CheckpointLeaf(checkpoint));

        let mut level = checkpoint_tree_height;
        let mut index = checkpoint_u64;
        loop {
            keys.push(TypedTableKey::GlobalCheckpointMerkle {
                node: MerkleNode::new(level, NodeIndex::new(index)),
                checkpoint,
            });
            if level == 0 {
                break;
            }
            level -= 1;
            index >>= 1;
        }
        let root = CheckpointRootKey::new(
            prepared
                .new_base
                .checkpoint_tree_root
                .into_owned_32bytes()
                .to_vec(),
        );
        keys.push(TypedTableKey::CheckpointRootByHash(root));
        keys.push(TypedTableKey::CheckpointRootByCheckpoint(checkpoint));
        keys.push(TypedTableKey::U64Singleton(
            U64SingletonSlot::LatestCheckpoint,
        ));

        let entries = canonicalize_keys(keys)?;
        let source_slot = source.slot().as_bytes();
        let source_digest = source.digest().as_bytes();
        let committed_marker = marker.encode_canonical();
        let mut inventory = Self {
            source_slot,
            source_digest,
            candidate: *source.candidate(),
            committed_marker,
            entries,
            digest: [0; 32],
        };
        inventory.digest = inventory_digest(&inventory.commitment_bytes());
        Ok(inventory)
    }

    pub fn validate_source(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> Result<(), CoordinatorCommitPhysicalInventoryError> {
        let marker = CoordinatorCommitSourceCommitted::decode_canonical(
            &self.committed_marker,
        )
        .map_err(|error| {
            CoordinatorCommitPhysicalInventoryError::SourcePayload(error.to_string())
        })?;
        if self.source_slot != source.slot().as_bytes()
            || self.source_digest != source.digest().as_bytes()
            || self.candidate != *source.candidate()
            || !marker.matches(source)
        {
            return Err(CoordinatorCommitPhysicalInventoryError::SourceBindingMismatch);
        }
        Ok(())
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = self.commitment_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, CoordinatorCommitPhysicalInventoryError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != INVENTORY_MAGIC {
            return Err(CoordinatorCommitPhysicalInventoryError::InvalidMagic);
        }
        let version = cursor.u16()?;
        if version != INVENTORY_CODEC_VERSION {
            return Err(CoordinatorCommitPhysicalInventoryError::UnknownVersion(version));
        }
        let source_slot = cursor.array_32()?;
        let source_digest = cursor.array_32()?;
        let candidate = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|error| {
            CoordinatorCommitPhysicalInventoryError::CanonicalRef(error.to_string())
        })?;
        let committed_marker: [u8; 106] = cursor
            .take(106)?
            .try_into()
            .expect("fixed-length marker");
        let marker = CoordinatorCommitSourceCommitted::decode_canonical(&committed_marker)
            .map_err(|error| {
                CoordinatorCommitPhysicalInventoryError::SourcePayload(error.to_string())
            })?;
        if marker.slot().as_bytes() != source_slot
            || marker.source_digest().as_bytes() != source_digest
        {
            return Err(CoordinatorCommitPhysicalInventoryError::SourceBindingMismatch);
        }
        if cursor.u8()? != REQUIRED_EXECUTOR_GATES {
            return Err(
                CoordinatorCommitPhysicalInventoryError::ExecutorGateContractMismatch,
            );
        }
        let count = cursor.u32()? as usize;
        if count > MAX_INVENTORY_ROWS {
            return Err(CoordinatorCommitPhysicalInventoryError::TooManyRows(count));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let action = CoordinatorCommitInventoryAction::try_from(cursor.u8()?)?;
            let locator = cursor.bytes()?;
            let key = decode_locator_canonical(locator).map_err(
                CoordinatorCommitPhysicalInventoryError::InvalidLocator,
            )?;
            let expected = action_for_key(key.typed_key());
            if action != expected {
                return Err(CoordinatorCommitPhysicalInventoryError::ActionMismatch);
            }
            entries.push(CoordinatorCommitInventoryEntry { action, key });
        }
        let digest = cursor.array_32()?;
        if !cursor.is_empty() {
            return Err(CoordinatorCommitPhysicalInventoryError::TrailingBytes);
        }
        validate_canonical_entries(&entries)?;
        let decoded = Self {
            source_slot,
            source_digest,
            candidate,
            committed_marker,
            entries,
            digest,
        };
        if inventory_digest(&decoded.commitment_bytes()) != decoded.digest {
            return Err(CoordinatorCommitPhysicalInventoryError::DigestMismatch);
        }
        if decoded.encode_canonical() != bytes {
            return Err(CoordinatorCommitPhysicalInventoryError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }

    fn commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256 + self.entries.len() * 64);
        bytes.extend_from_slice(INVENTORY_MAGIC);
        bytes.extend_from_slice(&INVENTORY_CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.source_slot);
        bytes.extend_from_slice(&self.source_digest);
        bytes.extend_from_slice(&self.candidate.to_canonical_bytes());
        bytes.extend_from_slice(&self.committed_marker);
        bytes.push(REQUIRED_EXECUTOR_GATES);
        bytes.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for entry in &self.entries {
            bytes.push(entry.action as u8);
            bytes.extend_from_slice(
                &(entry.key.locator_bytes().len() as u32).to_be_bytes(),
            );
            bytes.extend_from_slice(entry.key.locator_bytes());
        }
        bytes
    }
}

/// One storage-selected physical row in the floor-bound suffix catalog.
///
/// The source and inventory coordinates remain attached so the archive reader
/// can fresh-revalidate both objects around the hot-row read. This is still an
/// observation: it contains no archive receipt, barrier receipt, or delete
/// capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalCatalogEntry<Hash> {
    source_candidate: CanonicalChainRef<Hash>,
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    inventory_digest: [u8; 32],
    action: CoordinatorCommitInventoryAction,
    key: ResolvedScyllaKey,
}

impl<Hash> CoordinatorCommitPhysicalCatalogEntry<Hash> {
    pub(crate) const fn source_candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.source_candidate
    }

    pub(crate) const fn source_slot(&self) -> &[u8; 32] {
        &self.source_slot
    }

    pub(crate) const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub(crate) const fn inventory_digest(&self) -> &[u8; 32] {
        &self.inventory_digest
    }

    pub(crate) const fn action(&self) -> CoordinatorCommitInventoryAction {
        self.action
    }

    pub(crate) const fn key(&self) -> &ResolvedScyllaKey {
        &self.key
    }
}

/// Non-clone, storage-selected Coordinator suffix catalog.
///
/// It proves that the requested suffix is above the immutable rollback floor,
/// is a complete source/marker/hash-linked chain, and has no duplicate
/// delete-row identity. Mutable singletons intentionally occur in every
/// per-checkpoint inventory; they are required to have the same two locators
/// throughout and are selected exactly once from the old-head inventory.
///
/// The catalog is not durable write authority. A later archive owner must
/// fresh-read the floor, sources, markers, hot rows and canonical control head
/// before and after persisting exact before-images.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalCatalog<Hash> {
    floor: CoordinatorRollbackFloor<Hash>,
    target: CanonicalChainRef<Hash>,
    old_head: CanonicalChainRef<Hash>,
    sources: Vec<(CoordinatorCommitSource<Hash>, CoordinatorCommitSourceCommitted)>,
    inventories: Vec<CoordinatorCommitPhysicalInventory<Hash>>,
    entries: Vec<CoordinatorCommitPhysicalCatalogEntry<Hash>>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> CoordinatorCommitPhysicalCatalog<Hash> {
    pub(crate) fn try_from_committed_sources<F, Hasher>(
        floor: CoordinatorRollbackFloor<Hash>,
        target: &CanonicalChainRef<Hash>,
        old_head: &CanonicalChainRef<Hash>,
        sources: Vec<(CoordinatorCommitSource<Hash>, CoordinatorCommitSourceCommitted)>,
        checkpoint_tree_height: u8,
    ) -> Result<Self, CoordinatorCommitPhysicalInventoryError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        if floor.floor().network_id() != target.network_id()
            || floor.floor().chain_epoch() != target.chain_epoch()
            || target.network_id() != old_head.network_id()
            || target.chain_epoch() != old_head.chain_epoch()
            || floor.floor().checkpoint().checkpoint_id().get()
                > target.checkpoint().checkpoint_id().get()
        {
            return Err(CoordinatorCommitPhysicalInventoryError::CatalogFloorMismatch);
        }
        let inventories = CoordinatorCommitPhysicalInventory::try_suffix_from_committed_sources::<
            F,
            Hasher,
        >(target, old_head, &sources, checkpoint_tree_height)?;
        if inventories.is_empty() {
            return Err(CoordinatorCommitPhysicalInventoryError::EmptyCatalogSuffix);
        }

        let mut delete_locators = BTreeSet::new();
        let mut restore_locators: Option<Vec<Vec<u8>>> = None;
        let mut entries = Vec::new();
        for (source_index, inventory) in inventories.iter().enumerate() {
            let current_restore = inventory
                .entries()
                .iter()
                .filter(|entry| {
                    entry.action()
                        == CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget
                })
                .map(|entry| entry.key().locator_bytes().to_vec())
                .collect::<Vec<_>>();
            if current_restore.len() != 2
                || restore_locators
                    .as_ref()
                    .is_some_and(|expected| *expected != current_restore)
            {
                return Err(
                    CoordinatorCommitPhysicalInventoryError::CatalogRestoreSetMismatch,
                );
            }
            restore_locators.get_or_insert(current_restore);

            for entry in inventory.entries().iter().filter(|entry| {
                entry.action() == CoordinatorCommitInventoryAction::ArchiveThenDelete
            }) {
                if !delete_locators.insert(entry.key().locator_bytes().to_vec()) {
                    return Err(
                        CoordinatorCommitPhysicalInventoryError::DuplicateCatalogDeleteKey,
                    );
                }
                entries.push(catalog_entry(
                    &sources[source_index].0,
                    inventory,
                    entry,
                ));
            }
        }
        let last_index = inventories.len() - 1;
        for entry in inventories[last_index].entries().iter().filter(|entry| {
            entry.action()
                == CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget
        }) {
            entries.push(catalog_entry(
                &sources[last_index].0,
                &inventories[last_index],
                entry,
            ));
        }
        entries.sort_by(|left, right| {
            left.key
                .locator_bytes()
                .cmp(right.key.locator_bytes())
                .then_with(|| {
                    left.source_candidate
                        .checkpoint()
                        .checkpoint_id()
                        .get()
                        .cmp(
                            &right
                                .source_candidate
                                .checkpoint()
                                .checkpoint_id()
                                .get(),
                        )
                })
        });

        let mut catalog = Self {
            floor,
            target: *target,
            old_head: *old_head,
            sources,
            inventories,
            entries,
            digest: [0; 32],
        };
        catalog.digest = catalog_digest(&catalog);
        Ok(catalog)
    }

    pub(crate) const fn floor(&self) -> &CoordinatorRollbackFloor<Hash> {
        &self.floor
    }

    pub(crate) const fn target(&self) -> &CanonicalChainRef<Hash> {
        &self.target
    }

    pub(crate) const fn old_head(&self) -> &CanonicalChainRef<Hash> {
        &self.old_head
    }

    pub(crate) fn sources(
        &self,
    ) -> &[(CoordinatorCommitSource<Hash>, CoordinatorCommitSourceCommitted)] {
        &self.sources
    }

    pub(crate) fn inventories(&self) -> &[CoordinatorCommitPhysicalInventory<Hash>] {
        &self.inventories
    }

    pub(crate) fn entries(&self) -> &[CoordinatorCommitPhysicalCatalogEntry<Hash>] {
        &self.entries
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn catalog_entry<Hash: Q256BitHash>(
    source: &CoordinatorCommitSource<Hash>,
    inventory: &CoordinatorCommitPhysicalInventory<Hash>,
    entry: &CoordinatorCommitInventoryEntry,
) -> CoordinatorCommitPhysicalCatalogEntry<Hash> {
    CoordinatorCommitPhysicalCatalogEntry {
        source_candidate: *source.candidate(),
        source_slot: source.slot().as_bytes(),
        source_digest: source.digest().as_bytes(),
        inventory_digest: *inventory.digest(),
        action: entry.action(),
        key: entry.key().clone(),
    }
}

fn catalog_digest<Hash: Q256BitHash>(
    catalog: &CoordinatorCommitPhysicalCatalog<Hash>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CATALOG_DIGEST_DOMAIN);
    hasher.update(catalog.floor.digest());
    hasher.update(catalog.target.to_canonical_bytes());
    hasher.update(catalog.old_head.to_canonical_bytes());
    hasher.update((catalog.sources.len() as u64).to_be_bytes());
    for ((source, marker), inventory) in
        catalog.sources.iter().zip(catalog.inventories.iter())
    {
        hasher.update(source.slot().as_bytes());
        hasher.update(source.digest().as_bytes());
        hasher.update(marker.encode_canonical());
        hasher.update(inventory.digest());
    }
    hasher.update((catalog.entries.len() as u64).to_be_bytes());
    for entry in &catalog.entries {
        hasher.update(entry.source_candidate.to_canonical_bytes());
        hasher.update(entry.source_slot);
        hasher.update(entry.source_digest);
        hasher.update(entry.inventory_digest);
        hasher.update([entry.action as u8]);
        hasher.update((entry.key.locator_bytes().len() as u64).to_be_bytes());
        hasher.update(entry.key.locator_bytes());
    }
    hasher.finalize().into()
}

fn canonicalize_keys(
    keys: Vec<TypedTableKey>,
) -> Result<Vec<CoordinatorCommitInventoryEntry>, CoordinatorCommitPhysicalInventoryError> {
    if keys.len() > MAX_INVENTORY_ROWS {
        return Err(CoordinatorCommitPhysicalInventoryError::TooManyRows(keys.len()));
    }
    let mut entries = keys
        .into_iter()
        .map(|typed| CoordinatorCommitInventoryEntry {
            action: action_for_key(&typed),
            key: describe_existing_key(&typed),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.key.locator_bytes().cmp(right.key.locator_bytes()));
    validate_canonical_entries(&entries)?;
    Ok(entries)
}

fn validate_canonical_entries(
    entries: &[CoordinatorCommitInventoryEntry],
) -> Result<(), CoordinatorCommitPhysicalInventoryError> {
    for pair in entries.windows(2) {
        match pair[0].key.locator_bytes().cmp(pair[1].key.locator_bytes()) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => {
                return Err(CoordinatorCommitPhysicalInventoryError::DuplicatePhysicalKey)
            }
            std::cmp::Ordering::Greater => {
                return Err(CoordinatorCommitPhysicalInventoryError::NonCanonicalEntryOrder)
            }
        }
    }
    Ok(())
}

fn action_for_key(key: &TypedTableKey) -> CoordinatorCommitInventoryAction {
    match key {
        TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState)
        | TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint) => {
            CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget
        }
        _ => CoordinatorCommitInventoryAction::ArchiveThenDelete,
    }
}

fn push_object_ids(
    keys: &mut Vec<TypedTableKey>,
    bytes: &[u8],
    row_bytes: usize,
    make: impl Fn(u64) -> TypedTableKey,
    domain: &'static str,
) -> Result<(), CoordinatorCommitPhysicalInventoryError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(row_bytes) {
        return Err(CoordinatorCommitPhysicalInventoryError::InvalidFfs {
            domain,
            bytes: bytes.len(),
        });
    }
    for row in bytes.chunks_exact(row_bytes) {
        keys.push(make(u64::from_le_bytes(
            row[..8].try_into().expect("fixed identifier"),
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ZeroMerkleDomain {
    GlobalUser,
    UserRegistration,
    GlobalContract,
}

fn push_zero_merkle_keys(
    keys: &mut Vec<TypedTableKey>,
    bytes: &[u8],
    checkpoint: CheckpointId,
    domain: ZeroMerkleDomain,
) -> Result<(), CoordinatorCommitPhysicalInventoryError> {
    if !bytes.len().is_multiple_of(PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE) {
        return Err(CoordinatorCommitPhysicalInventoryError::InvalidFfs {
            domain: "zero-id Merkle node",
            bytes: bytes.len(),
        });
    }
    for row in bytes.chunks_exact(PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE) {
        let node = MerkleNode::new(
            row[0],
            NodeIndex::new(u64::from_le_bytes(
                row[1..9].try_into().expect("fixed node index"),
            )),
        );
        keys.push(match domain {
            ZeroMerkleDomain::GlobalUser => {
                TypedTableKey::GlobalUserMerkle { node, checkpoint }
            }
            ZeroMerkleDomain::UserRegistration => {
                TypedTableKey::UserRegistrationMerkle { node, checkpoint }
            }
            ZeroMerkleDomain::GlobalContract => {
                TypedTableKey::GlobalContractMerkle { node, checkpoint }
            }
        });
    }
    Ok(())
}

fn push_single_merkle_keys(
    keys: &mut Vec<TypedTableKey>,
    bytes: &[u8],
    checkpoint: CheckpointId,
) -> Result<(), CoordinatorCommitPhysicalInventoryError> {
    if !bytes
        .len()
        .is_multiple_of(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE)
    {
        return Err(CoordinatorCommitPhysicalInventoryError::InvalidFfs {
            domain: "single-id Merkle node",
            bytes: bytes.len(),
        });
    }
    for row in bytes.chunks_exact(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE) {
        let contract = u64::from_le_bytes(row[..8].try_into().expect("fixed tree id"));
        let node = MerkleNode::new(
            row[8],
            NodeIndex::new(u64::from_le_bytes(
                row[9..17].try_into().expect("fixed node index"),
            )),
        );
        keys.push(TypedTableKey::ContractFunctionMerkle {
            contract: ContractId::new(contract),
            node,
            checkpoint,
        });
    }
    Ok(())
}

fn push_public_key_projection(
    keys: &mut Vec<TypedTableKey>,
    bytes: &[u8],
) -> Result<(), CoordinatorCommitPhysicalInventoryError> {
    if !bytes.len().is_multiple_of(HASH_TO_USER_ROW_BYTES) {
        return Err(CoordinatorCommitPhysicalInventoryError::InvalidFfs {
            domain: "public-key projection",
            bytes: bytes.len(),
        });
    }
    for row in bytes.chunks_exact(HASH_TO_USER_ROW_BYTES) {
        keys.push(TypedTableKey::PublicKeyToUser {
            public_key_hash: PublicKeyHash::new(row[..32].to_vec()),
            user: UserId::new(u64::from_le_bytes(
                row[32..40].try_into().expect("fixed user id"),
            )),
        });
    }
    Ok(())
}

fn push_reward_node_keys(
    keys: &mut Vec<TypedTableKey>,
    bytes: &[u8],
    pending: UniquePendingId,
) -> Result<(), CoordinatorCommitPhysicalInventoryError> {
    if !bytes.len().is_multiple_of(REWARD_NODE_ROW_BYTES) {
        return Err(CoordinatorCommitPhysicalInventoryError::InvalidFfs {
            domain: "Realm reward node key",
            bytes: bytes.len(),
        });
    }
    for row in bytes.chunks_exact(REWARD_NODE_ROW_BYTES) {
        keys.push(TypedTableKey::RealmRewardNode {
            realm: RealmId::new(u64::from_le_bytes(
                row[..8].try_into().expect("fixed Realm id"),
            )),
            pending,
        });
    }
    Ok(())
}

fn inventory_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_DIGEST_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Debug, Eq, PartialEq)]
pub enum CoordinatorCommitPhysicalInventoryError {
    CommittedMarkerMismatch,
    SourcePayload(String),
    PreparedUpdate(String),
    TrailingPreparedUpdateBytes,
    CheckpointIdentityMismatch,
    CheckpointTreeHeightMismatch,
    CheckpointTreeProofMismatch,
    CheckpointOutOfRange(u64),
    PendingOutOfRange(u64),
    IdentifierOverflow(&'static str),
    InvalidFfs { domain: &'static str, bytes: usize },
    TooManyRows(usize),
    DuplicatePhysicalKey,
    InvalidMagic,
    UnknownVersion(u16),
    UnknownAction(u8),
    ActionMismatch,
    ExecutorGateContractMismatch,
    InvalidLocator(&'static str),
    NonCanonicalEntryOrder,
    DigestMismatch,
    TrailingBytes,
    NonCanonicalEncoding,
    CanonicalRef(String),
    SourceBindingMismatch,
    SuffixBranchMismatch,
    SuffixLengthMismatch { expected: u64, actual: u64 },
    SuffixLinkMismatch { checkpoint: u64 },
    SuffixHeadMismatch,
    CatalogFloorMismatch,
    EmptyCatalogSuffix,
    CatalogRestoreSetMismatch,
    DuplicateCatalogDeleteKey,
    Truncated,
    InvalidLength,
}

impl fmt::Display for CoordinatorCommitPhysicalInventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Coordinator commit physical inventory: {self:?}")
    }
}

impl Error for CoordinatorCommitPhysicalInventoryError {}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], CoordinatorCommitPhysicalInventoryError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CoordinatorCommitPhysicalInventoryError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(CoordinatorCommitPhysicalInventoryError::Truncated);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CoordinatorCommitPhysicalInventoryError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoordinatorCommitPhysicalInventoryError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed u16"),
        ))
    }

    fn u32(&mut self) -> Result<u32, CoordinatorCommitPhysicalInventoryError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("fixed u32"),
        ))
    }

    fn bytes(&mut self) -> Result<&'a [u8], CoordinatorCommitPhysicalInventoryError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn array_32(
        &mut self,
    ) -> Result<[u8; 32], CoordinatorCommitPhysicalInventoryError> {
        Ok(self.take(32)?.try_into().expect("fixed digest"))
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::{
            merkle_proof::DeltaMerkleProofCore,
            traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
        },
        pgoldilocks::PoseidonHasher,
        PHash, PF,
    };
    use psy_data::{
        prepared_block::{
            common::PsyCoordinatorPendingCheckpointBase,
            coordinator::PsyPreparedCoordinatorBlockStateUpdates,
        },
        protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId as ChainCheckpointId,
            CheckpointRef, NetworkId,
        },
        v1::qdata::{
            checkpoint::{
                PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats, QEDL2BlockState,
            },
            contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId},
            populated_checkpoint::PsyCheckpointLeafPopulated,
        },
    };
    use psy_node_core::store::{
        canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile, StoredCanonicalHead},
        coordinator_commit_source::{CoordinatorCommitSource, CoordinatorCommitSourcePayload},
    };

    use crate::rollback::{
        CoordinatorCommitPhysicalBeforeImage, CoordinatorCommitPhysicalBeforeImageError,
        CoordinatorCommitPhysicalSourceCell, CoordinatorCommitPhysicalSourceObservation,
    };

    use super::*;

    const CHECKPOINT_TREE_HEIGHT: u8 = 8;

    fn hash(seed: u64) -> PHash {
        PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
    }

    fn canonical(checkpoint: u64, seed: u64) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(0),
            CheckpointRef::new(
                ChainCheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(hash(seed)),
            ),
        )
    }

    fn stored_head(chain: CanonicalChainRef<PHash>) -> StoredCanonicalHead<PHash> {
        *CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            chain,
        )
        .unwrap()
        .candidate()
    }

    fn head() -> StoredCanonicalHead<PHash> {
        stored_head(canonical(7, 700))
    }

    fn leaf(contract_root: PHash) -> PsyCheckpointLeafPopulated<PF, PHash> {
        PsyCheckpointLeafPopulated {
            global_state_roots: PQEDCheckpointGlobalStateRoots {
                contract_tree_root: contract_root,
                deposit_tree_root: PHash::get_zero_value(),
                user_tree_root: PHash::get_zero_value(),
                withdrawal_tree_root: PHash::get_zero_value(),
                user_registration_tree_root: PHash::get_zero_value(),
            },
            stats: PQEDCheckpointLeafStats::get_empty_stats(),
        }
    }

    fn block_state(checkpoint_id: u64, next_contract_id: u32) -> QEDL2BlockState {
        QEDL2BlockState {
            checkpoint_id,
            next_add_withdrawal_id: 11,
            next_process_withdrawal_id: 12,
            next_deposit_id: 13,
            total_deposits_claimed_epoch: 14,
            next_user_id: 15,
            end_balance: 16,
            next_contract_id,
        }
    }

    fn prepared() -> PsyPreparedCoordinatorBlockStateUpdates<PF, PHash> {
        let old_leaf = leaf(PHash::get_zero_value());
        let new_leaf = leaf(hash(900));
        let old_leaf_hash = old_leaf.qfhash::<PoseidonHasher>();
        let new_leaf_hash = new_leaf.qfhash::<PoseidonHasher>();
        let siblings = (0..CHECKPOINT_TREE_HEIGHT as usize)
            .map(PoseidonHasher::get_zero_hash)
            .collect::<Vec<_>>();
        let proof = DeltaMerkleProofCore::from_params::<PoseidonHasher>(
            8,
            old_leaf_hash,
            new_leaf_hash,
            siblings,
        );
        PsyPreparedCoordinatorBlockStateUpdates {
            coordinator_id: 0,
            checkpoint_id: 8,
            unique_pending_id: 81,
            proc_checkpoint_unique_id: 82,
            old_base: PsyCoordinatorPendingCheckpointBase {
                block_state: block_state(7, 41),
                checkpoint_leaf: old_leaf,
                checkpoint_leaf_hash: old_leaf_hash,
                checkpoint_tree_root: proof.old_root,
            },
            new_base: PsyCoordinatorPendingCheckpointBase {
                block_state: block_state(8, 42),
                checkpoint_leaf: new_leaf,
                checkpoint_leaf_hash: new_leaf_hash,
                checkpoint_tree_root: proof.new_root,
            },
            update_global_contract_tree_nodes_ffs: Vec::new(),
            update_contract_function_tree_nodes_ffs: Vec::new(),
            new_contract_leaves_ffs: Vec::new(),
            new_contract_code_definitions: Vec::new(),
            update_user_registration_tree_nodes_ffs: Vec::new(),
            new_user_public_keys_ffs: Vec::new(),
            new_public_key_hash_to_user_id_rows_ffs: Vec::new(),
            update_global_user_tree_nodes_ffs: Vec::new(),
            new_realm_guta_reward_tree_node_keys_ffs: Vec::new(),
            checkpoint_tree_update_proof: proof,
        }
    }

    fn source(
        prepared: &PsyPreparedCoordinatorBlockStateUpdates<PF, PHash>,
    ) -> CoordinatorCommitSource<PHash> {
        source_between(prepared, head(), canonical(8, 800))
    }

    fn source_between(
        prepared: &PsyPreparedCoordinatorBlockStateUpdates<PF, PHash>,
        expected: StoredCanonicalHead<PHash>,
        candidate: CanonicalChainRef<PHash>,
    ) -> CoordinatorCommitSource<PHash> {
        let mut prepared_bytes = Vec::new();
        prepared.pio_write_to_io(&mut prepared_bytes).unwrap();
        let payload = CoordinatorCommitSourcePayload::try_new(
            prepared_bytes,
            17,
            vec![3; 64],
        )
        .unwrap();
        CoordinatorCommitSource::try_new(
            expected,
            candidate,
            payload.encode_canonical(),
        )
        .unwrap()
    }

    #[test]
    fn committed_source_yields_canonical_inventory_and_two_restore_singletons() {
        let source = source(&prepared());
        let inventory = CoordinatorCommitPhysicalInventory::<PHash>::try_from_committed_source::<
            PF,
            PoseidonHasher,
        >(&source, source.committed_marker(), CHECKPOINT_TREE_HEIGHT)
        .unwrap();

        assert_eq!(inventory.entries().len(), CHECKPOINT_TREE_HEIGHT as usize + 13);
        assert_eq!(inventory.restore_row_count(), 2);
        assert_eq!(inventory.delete_row_count(), inventory.entries().len() - 2);
        assert!(inventory.entries().iter().any(|entry| {
            entry.action() == CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget
                && matches!(
                    entry.key().typed_key(),
                    TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState)
                )
        }));
        assert!(inventory.entries().iter().any(|entry| {
            entry.action() == CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget
                && matches!(
                    entry.key().typed_key(),
                    TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint)
                )
        }));
        assert!(inventory
            .entries()
            .windows(2)
            .all(|pair| pair[0].key().locator_bytes() < pair[1].key().locator_bytes()));

        let encoded = inventory.encode_canonical();
        let decoded = CoordinatorCommitPhysicalInventory::<PHash>::decode_canonical(&encoded)
            .unwrap();
        assert_eq!(decoded, inventory);
        decoded.validate_source(&source).unwrap();
    }

    #[test]
    fn inventory_mirrors_every_optional_commit_branch() {
        let mut prepared = prepared();
        prepared.new_contract_leaves_ffs = vec![0; 8 + PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];
        prepared.new_contract_leaves_ffs[..8].copy_from_slice(&41_u64.to_le_bytes());
        prepared.new_contract_code_definitions.push(
            ContractCodeDefinitionWithContractId::new(
                41,
                ContractCodeDefinition { state_tree_height: 8, functions: Vec::new() },
            ),
        );
        prepared.update_contract_function_tree_nodes_ffs =
            vec![0; QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE];
        prepared.update_contract_function_tree_nodes_ffs[..8]
            .copy_from_slice(&41_u64.to_le_bytes());
        prepared.update_global_contract_tree_nodes_ffs =
            vec![0; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE];

        prepared.new_user_public_keys_ffs = vec![0; 8 + PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY];
        prepared.new_user_public_keys_ffs[..8].copy_from_slice(&51_u64.to_le_bytes());
        prepared.new_public_key_hash_to_user_id_rows_ffs = vec![7; HASH_TO_USER_ROW_BYTES];
        prepared.new_public_key_hash_to_user_id_rows_ffs[32..]
            .copy_from_slice(&51_u64.to_le_bytes());
        prepared.update_user_registration_tree_nodes_ffs =
            vec![0; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE];
        prepared.update_global_user_tree_nodes_ffs =
            vec![0; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE];
        prepared.new_realm_guta_reward_tree_node_keys_ffs = vec![0; REWARD_NODE_ROW_BYTES];
        prepared.new_realm_guta_reward_tree_node_keys_ffs[..8]
            .copy_from_slice(&61_u64.to_le_bytes());

        let source = source(&prepared);
        let inventory = CoordinatorCommitPhysicalInventory::<PHash>::try_from_committed_source::<
            PF,
            PoseidonHasher,
        >(&source, source.committed_marker(), CHECKPOINT_TREE_HEIGHT)
        .unwrap();
        let keys = inventory
            .entries()
            .iter()
            .map(|entry| entry.key().typed_key())
            .collect::<Vec<_>>();
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::ContractLeaf { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::ContractCodeDefinition { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::ContractStateTreeHeight { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::ContractFunctionMerkle { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::GlobalContractMerkle { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::UserPublicKey { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::PublicKeyToUser { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::UserRegistrationMerkle { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::GlobalUserMerkle { .. })));
        assert!(keys.iter().any(|key| matches!(key, TypedTableKey::RealmRewardNode { .. })));
    }

    #[test]
    fn marker_proof_and_ffs_mismatches_fail_closed() {
        let prepared = prepared();
        let valid_source = source(&prepared);
        let other_source = CoordinatorCommitSource::try_new(
            head(),
            canonical(8, 800),
            CoordinatorCommitSourcePayload::try_new(vec![1], 17, vec![2])
                .unwrap()
                .encode_canonical(),
        )
        .unwrap();
        assert_eq!(
            CoordinatorCommitPhysicalInventory::<PHash>::try_from_committed_source::<
                PF,
                PoseidonHasher,
            >(
                &valid_source,
                other_source.committed_marker(),
                CHECKPOINT_TREE_HEIGHT,
            ),
            Err(CoordinatorCommitPhysicalInventoryError::CommittedMarkerMismatch)
        );

        let mut invalid_proof = prepared.clone();
        invalid_proof.checkpoint_tree_update_proof.index = 7;
        let invalid_source = source(&invalid_proof);
        assert_eq!(
            CoordinatorCommitPhysicalInventory::<PHash>::try_from_committed_source::<
                PF,
                PoseidonHasher,
            >(&invalid_source, invalid_source.committed_marker(), CHECKPOINT_TREE_HEIGHT),
            Err(CoordinatorCommitPhysicalInventoryError::CheckpointTreeProofMismatch)
        );

        let mut invalid_ffs = prepared;
        invalid_ffs.new_contract_leaves_ffs = vec![1];
        let invalid_source = source(&invalid_ffs);
        assert!(matches!(
            CoordinatorCommitPhysicalInventory::<PHash>::try_from_committed_source::<
                PF,
                PoseidonHasher,
            >(&invalid_source, invalid_source.committed_marker(), CHECKPOINT_TREE_HEIGHT),
            Err(CoordinatorCommitPhysicalInventoryError::InvalidFfs {
                domain: "contract leaf",
                bytes: 1,
            })
        ));
    }

    #[test]
    fn canonical_decoder_rejects_forged_action_and_marker_binding() {
        let source = source(&prepared());
        let inventory = CoordinatorCommitPhysicalInventory::<PHash>::try_from_committed_source::<
            PF,
            PoseidonHasher,
        >(&source, source.committed_marker(), CHECKPOINT_TREE_HEIGHT)
        .unwrap();
        let mut forged_action = inventory.encode_canonical();
        let first_action = 8 + 2 + 32 + 32 + CANONICAL_CHAIN_REF_V1_LEN + 106 + 1 + 4;
        forged_action[first_action] = CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget as u8;
        assert_eq!(
            CoordinatorCommitPhysicalInventory::<PHash>::decode_canonical(&forged_action),
            Err(CoordinatorCommitPhysicalInventoryError::ActionMismatch)
        );

        let mut forged_marker_binding = inventory.encode_canonical();
        let marker_slot = 8 + 2 + 32 + 32 + CANONICAL_CHAIN_REF_V1_LEN + 10;
        forged_marker_binding[marker_slot] ^= 1;
        let digest_offset = forged_marker_binding.len() - 32;
        let digest = inventory_digest(&forged_marker_binding[..digest_offset]);
        forged_marker_binding[digest_offset..].copy_from_slice(&digest);
        assert_eq!(
            CoordinatorCommitPhysicalInventory::<PHash>::decode_canonical(&forged_marker_binding),
            Err(CoordinatorCommitPhysicalInventoryError::SourcePayload(
                "invalid Coordinator commit source: MarkerDigestMismatch".to_string(),
            ))
        );
    }

    #[test]
    fn suffix_requires_exact_hash_linkage_and_old_head() {
        let first_prepared = prepared();
        let first = source(&first_prepared);

        let mut second_prepared = prepared();
        second_prepared.checkpoint_id = 9;
        second_prepared.unique_pending_id = 91;
        second_prepared.proc_checkpoint_unique_id = 92;
        second_prepared.old_base.block_state.checkpoint_id = 8;
        second_prepared.new_base.block_state.checkpoint_id = 9;
        let proof = DeltaMerkleProofCore::from_params::<PoseidonHasher>(
            9,
            second_prepared.old_base.checkpoint_leaf_hash,
            second_prepared.new_base.checkpoint_leaf_hash,
            (0..CHECKPOINT_TREE_HEIGHT as usize)
                .map(PoseidonHasher::get_zero_hash)
                .collect(),
        );
        second_prepared.old_base.checkpoint_tree_root = proof.old_root;
        second_prepared.new_base.checkpoint_tree_root = proof.new_root;
        second_prepared.checkpoint_tree_update_proof = proof;
        let second = source_between(
            &second_prepared,
            stored_head(*first.candidate()),
            canonical(9, 900),
        );
        let committed = vec![
            (first.clone(), first.committed_marker()),
            (second.clone(), second.committed_marker()),
        ];
        let inventories = CoordinatorCommitPhysicalInventory::<PHash>::try_suffix_from_committed_sources::<
            PF,
            PoseidonHasher,
        >(
            first.expected(),
            second.candidate(),
            &committed,
            CHECKPOINT_TREE_HEIGHT,
        )
        .unwrap();
        assert_eq!(inventories.len(), 2);
        assert_eq!(inventories[0].candidate(), first.candidate());
        assert_eq!(inventories[1].candidate(), second.candidate());

        let wrong_link = source_between(
            &second_prepared,
            stored_head(canonical(8, 801)),
            canonical(9, 900),
        );
        let wrong = vec![
            (first.clone(), first.committed_marker()),
            (wrong_link.clone(), wrong_link.committed_marker()),
        ];
        assert_eq!(
            CoordinatorCommitPhysicalInventory::<PHash>::try_suffix_from_committed_sources::<
                PF,
                PoseidonHasher,
            >(
                first.expected(),
                second.candidate(),
                &wrong,
                CHECKPOINT_TREE_HEIGHT,
            ),
            Err(CoordinatorCommitPhysicalInventoryError::SuffixLinkMismatch {
                checkpoint: 9,
            })
        );
        assert_eq!(
            CoordinatorCommitPhysicalInventory::<PHash>::try_suffix_from_committed_sources::<
                PF,
                PoseidonHasher,
            >(
                first.expected(),
                &canonical(9, 901),
                &committed,
                CHECKPOINT_TREE_HEIGHT,
            ),
            Err(CoordinatorCommitPhysicalInventoryError::SuffixHeadMismatch)
        );
    }

    #[test]
    fn floor_bound_catalog_deduplicates_singletons_and_rejects_duplicate_delete_keys() {
        let first_prepared = prepared();
        let first = source(&first_prepared);

        let mut second_prepared = prepared();
        second_prepared.checkpoint_id = 9;
        second_prepared.unique_pending_id = 91;
        second_prepared.proc_checkpoint_unique_id = 92;
        second_prepared.old_base.block_state.checkpoint_id = 8;
        second_prepared.new_base.block_state.checkpoint_id = 9;
        let proof = DeltaMerkleProofCore::from_params::<PoseidonHasher>(
            9,
            second_prepared.old_base.checkpoint_leaf_hash,
            second_prepared.new_base.checkpoint_leaf_hash,
            (0..CHECKPOINT_TREE_HEIGHT as usize)
                .map(PoseidonHasher::get_zero_hash)
                .collect(),
        );
        second_prepared.old_base.checkpoint_tree_root = proof.old_root;
        second_prepared.new_base.checkpoint_tree_root = proof.new_root;
        second_prepared.checkpoint_tree_update_proof = proof;
        let second = source_between(
            &second_prepared,
            stored_head(*first.candidate()),
            canonical(9, 900),
        );
        let sources = vec![
            (first.clone(), first.committed_marker()),
            (second.clone(), second.committed_marker()),
        ];
        let floor = CoordinatorRollbackFloor::try_new(head()).unwrap();
        let catalog = CoordinatorCommitPhysicalCatalog::<PHash>::try_from_committed_sources::<
            PF,
            PoseidonHasher,
        >(
            floor,
            first.expected(),
            second.candidate(),
            sources,
            CHECKPOINT_TREE_HEIGHT,
        )
        .unwrap();
        assert_eq!(catalog.sources().len(), 2);
        assert_eq!(catalog.inventories().len(), 2);
        assert_eq!(catalog.floor(), &floor);
        assert_eq!(catalog.target(), first.expected());
        assert_eq!(catalog.old_head(), second.candidate());
        assert_ne!(catalog.digest(), &[0; 32]);
        let restore = catalog
            .entries()
            .iter()
            .filter(|entry| {
                entry.action()
                    == CoordinatorCommitInventoryAction::ArchiveThenRestoreTarget
            })
            .collect::<Vec<_>>();
        assert_eq!(restore.len(), 2);
        assert!(restore
            .iter()
            .all(|entry| entry.source_candidate() == second.candidate()));
        assert!(catalog.entries().iter().all(|entry| {
            entry.source_slot() != &[0; 32]
                && entry.source_digest() != &[0; 32]
                && entry.inventory_digest() != &[0; 32]
                && !entry.key().locator_bytes().is_empty()
        }));
        let before = CoordinatorCommitPhysicalBeforeImage::try_from_catalog_entry(
            &catalog,
            0,
            CoordinatorCommitPhysicalSourceObservation::Value(
                CoordinatorCommitPhysicalSourceCell::value(vec![7, 8, 9], 44),
            ),
        )
        .unwrap();
        let decoded = CoordinatorCommitPhysicalBeforeImage::<PHash>::decode_for_catalog(
            before.canonical_bytes(),
            &catalog,
        )
        .unwrap();
        assert_eq!(decoded.slot(), before.slot());
        assert_eq!(decoded.digest(), before.digest());
        assert_eq!(decoded.action(), before.action());
        assert_eq!(decoded.key(), before.key());
        let CoordinatorCommitPhysicalSourceObservation::Value(cell) = decoded.observation()
        else {
            panic!("ordinary value row decoded as key-only");
        };
        assert_eq!(cell.kind(), crate::rollback::CoordinatorCommitPhysicalCellKind::Value);
        assert_eq!(cell.bytes(), &[7, 8, 9]);
        assert_eq!(cell.writetime_us(), 44);

        let mut tampered = before.canonical_bytes().to_vec();
        let value_offset = tampered.len() - 32 - 32 - 3;
        tampered[value_offset] ^= 1;
        assert_eq!(
            CoordinatorCommitPhysicalBeforeImage::<PHash>::decode_canonical(&tampered),
            Err(CoordinatorCommitPhysicalBeforeImageError::DigestMismatch)
        );
        assert_eq!(
            CoordinatorCommitPhysicalBeforeImage::try_from_catalog_entry(
                &catalog,
                0,
                CoordinatorCommitPhysicalSourceObservation::KeyOnlyPresent,
            ),
            Err(CoordinatorCommitPhysicalBeforeImageError::ObservationSchemaMismatch)
        );

        let mut duplicate_prepared = second_prepared;
        duplicate_prepared.unique_pending_id = first_prepared.unique_pending_id;
        duplicate_prepared.proc_checkpoint_unique_id =
            first_prepared.proc_checkpoint_unique_id;
        let duplicate = source_between(
            &duplicate_prepared,
            stored_head(*first.candidate()),
            canonical(9, 900),
        );
        assert_eq!(
            CoordinatorCommitPhysicalCatalog::<PHash>::try_from_committed_sources::<
                PF,
                PoseidonHasher,
            >(
                floor,
                first.expected(),
                duplicate.candidate(),
                vec![
                    (first.clone(), first.committed_marker()),
                    (duplicate.clone(), duplicate.committed_marker()),
                ],
                CHECKPOINT_TREE_HEIGHT,
            ),
            Err(CoordinatorCommitPhysicalInventoryError::DuplicateCatalogDeleteKey)
        );

        let floor_above_target = CoordinatorRollbackFloor::try_new(stored_head(
            canonical(8, 801),
        ))
        .unwrap();
        assert_eq!(
            CoordinatorCommitPhysicalCatalog::<PHash>::try_from_committed_sources::<
                PF,
                PoseidonHasher,
            >(
                floor_above_target,
                first.expected(),
                second.candidate(),
                vec![
                    (first.clone(), first.committed_marker()),
                    (second.clone(), second.committed_marker()),
                ],
                CHECKPOINT_TREE_HEIGHT,
            ),
            Err(CoordinatorCommitPhysicalInventoryError::CatalogFloorMismatch)
        );
    }
}
