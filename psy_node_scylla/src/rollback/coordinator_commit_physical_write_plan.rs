//! Exact, explicitly timestamped physical write plan for one normal
//! Coordinator checkpoint.
//!
//! The durable commit source is the only input carrying the prepared update,
//! proof bytes, and branch identity.  This module reconstructs every value
//! written by the current Coordinator `commit_state`. Four operational
//! mapping domains remain owned by the existing branch-exact narrow writer;
//! the other 19 semantic domains are registry-resolved here, with two
//! deliberately narrow cutover overrides for reusable/read-through keys. The
//! legacy physical locator subset must equal the independently derived
//! rollback inventory. This performs no CQL, does not mark the source
//! committed, and cannot publish a canonical head.

use std::{collections::BTreeSet, error::Error, fmt, io::Cursor as IoCursor};

use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, MerkleHasher},
    },
    data::hash::{
        fast_node_serializer::QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
        merkle_node_key::PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE,
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::{
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    protocol::{
        canonical_chain::CanonicalChainRef,
        verifiable_checkpoint_transition::PsyVerifiableCheckpointTransitionWithProof,
    },
    v1::qdata::ffs_sizes::{
        PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF, PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY,
    },
};
use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    coordinator_commit_source::{CoordinatorCommitSource, CoordinatorCommitSourcePayload},
    coordinator_normal_commit_coverage::{
        CoordinatorNormalCommitCoveragePlan, CoordinatorNormalCommitWriteDomain,
    },
    timestamp::{CommitWriteTimestampUs, NewBranchWriteTimestampUs},
    typed::{
        CheckpointId, CheckpointRootKey, ContractId, LatestInfoSlot,
        LogicalMutation, MerkleNode, MutationValue, NodeIndex,
        ProcCheckpointUniqueId, PublicKeyHash, RealmId, TypedTableKey,
        U64SingletonSlot, UniquePendingId, UserId,
    },
};
use psy_serialize::PsyIOReadWrite;
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterPrepared,
    CoordinatorCommitPhysicalInventory, CoordinatorCommitPhysicalInventoryError,
    SealedTimestampedPut, SealedTimestampedPutBatch, TimestampedMutationError,
    TimestampedWriteKind, seal_commit_put, seal_commit_put_batch,
    seal_coordinator_reward_node_after_cutover,
    seal_coordinator_reward_node_after_rollback,
    seal_new_branch_put, seal_new_branch_put_batch,
};

const PLAN_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-commit-physical-write-plan.v1\0";
const HASH_TO_USER_ROW_BYTES: usize = 40;
const REWARD_NODE_ROW_BYTES: usize = 8 + 9;
const MAX_PLAN_ROWS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoordinatorCommitTimestamp {
    Authority(CommitWriteTimestampUs),
    NewBranch(NewBranchWriteTimestampUs),
}

impl CoordinatorCommitTimestamp {
    const fn timestamp(self) -> CommitWriteTimestampUs {
        match self {
            Self::Authority(timestamp) => timestamp,
            Self::NewBranch(timestamp) => timestamp.as_commit_timestamp(),
        }
    }

    const fn write_kind(self) -> TimestampedWriteKind {
        match self {
            Self::Authority(_) => TimestampedWriteKind::AuthorityCommit,
            Self::NewBranch(_) => TimestampedWriteKind::NewBranchAfterFence,
        }
    }

    fn seal(
        self,
        mutation: LogicalMutation,
    ) -> Result<SealedTimestampedPut, TimestampedMutationError> {
        match self {
            Self::Authority(timestamp) => seal_commit_put(mutation, timestamp),
            Self::NewBranch(timestamp) => seal_new_branch_put(mutation, timestamp),
        }
    }

    fn seal_batch(
        self,
        mutation: LogicalMutation,
    ) -> Result<SealedTimestampedPutBatch, TimestampedMutationError> {
        match self {
            Self::Authority(timestamp) => seal_commit_put_batch(mutation, timestamp),
            Self::NewBranch(timestamp) => seal_new_branch_put_batch(mutation, timestamp),
        }
    }
}

/// Concrete rows for one selected Coordinator semantic domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalDomainBatch {
    domain: CoordinatorNormalCommitWriteDomain,
    puts: Vec<SealedTimestampedPut>,
}

impl CoordinatorCommitPhysicalDomainBatch {
    pub(crate) const fn domain(&self) -> CoordinatorNormalCommitWriteDomain {
        self.domain
    }

    pub(crate) fn puts(&self) -> &[SealedTimestampedPut] {
        &self.puts
    }
}

/// Complete storage-private physical input for one normal Coordinator commit.
///
/// This value is reusable plan evidence, not a writer receipt.  A later
/// executor must still preflight, write, point-read every row, persist a
/// manifest, update the checkpoint-tree backup, mark the source committed,
/// and publish the canonical head last.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitPhysicalWritePlan<Hash> {
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    candidate: CanonicalChainRef<Hash>,
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
    narrow_prepared_digest: [u8; 32],
    narrow_intent_digest: [u8; 32],
    inventory_digest: [u8; 32],
    batches: Vec<CoordinatorCommitPhysicalDomainBatch>,
    digest: [u8; 32],
}

impl<Hash> CoordinatorCommitPhysicalWritePlan<Hash> {
    pub(crate) const fn source_slot(&self) -> &[u8; 32] {
        &self.source_slot
    }

    pub(crate) const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub(crate) const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub(crate) const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub(crate) const fn write_kind(&self) -> TimestampedWriteKind {
        self.write_kind
    }

    pub(crate) const fn inventory_digest(&self) -> &[u8; 32] {
        &self.inventory_digest
    }

    pub(crate) const fn narrow_prepared_digest(&self) -> &[u8; 32] {
        &self.narrow_prepared_digest
    }

    pub(crate) const fn narrow_intent_digest(&self) -> &[u8; 32] {
        &self.narrow_intent_digest
    }

    pub(crate) fn batches(&self) -> &[CoordinatorCommitPhysicalDomainBatch] {
        &self.batches
    }

    pub(crate) fn typed_row_count(&self) -> usize {
        self.batches.iter().map(|batch| batch.puts.len()).sum()
    }

    pub(crate) fn semantic_domain_count(&self) -> usize {
        self.batches.len() + 4
    }

    /// Total physical mutations, including the six exact mapping writes
    /// owned by the narrow branch-exact writer.
    pub(crate) fn row_count(&self) -> usize {
        self.typed_row_count()
            + psy_node_core::store::branch_exact_dual_write::BranchExactDualWriteMutationKind::COORDINATOR.len()
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl<Hash: Q256BitHash> CoordinatorCommitPhysicalWritePlan<Hash> {
    /// Build an ordinary explicit-timestamp authority commit.
    pub(crate) fn try_new<F, Hasher>(
        source: &CoordinatorCommitSource<Hash>,
        narrow: &BranchExactWriterPrepared<Hash>,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
        checkpoint_tree_height: u8,
    ) -> Result<Self, CoordinatorCommitPhysicalWritePlanError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        Self::try_new_inner::<F, Hasher>(
            source,
            narrow,
            CoordinatorCommitTimestamp::Authority(narrow.timestamp()),
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
            checkpoint_tree_height,
        )
    }

    /// Build the first or later commit after a rollback delete fence.  The
    /// timestamp kind remains part of every sealed row's retry identity.
    pub(crate) fn try_new_after_rollback<F, Hasher>(
        source: &CoordinatorCommitSource<Hash>,
        narrow: &BranchExactWriterPrepared<Hash>,
        timestamp: NewBranchWriteTimestampUs,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
        checkpoint_tree_height: u8,
    ) -> Result<Self, CoordinatorCommitPhysicalWritePlanError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        Self::try_new_inner::<F, Hasher>(
            source,
            narrow,
            CoordinatorCommitTimestamp::NewBranch(timestamp),
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
            checkpoint_tree_height,
        )
    }

    fn try_new_inner<F, Hasher>(
        source: &CoordinatorCommitSource<Hash>,
        narrow: &BranchExactWriterPrepared<Hash>,
        timestamp: CoordinatorCommitTimestamp,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
        checkpoint_tree_height: u8,
    ) -> Result<Self, CoordinatorCommitPhysicalWritePlanError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    {
        validate_narrow(source, narrow, timestamp)?;
        // This predicted marker is used only to reuse the independent
        // inventory validator. It is not evidence that the durable COMMITTED
        // marker already exists; normal execution writes that marker later.
        let inventory = CoordinatorCommitPhysicalInventory::try_from_committed_source::<
            F,
            Hasher,
        >(
            source,
            source.committed_marker(),
            checkpoint_tree_height,
        )?;

        let payload = CoordinatorCommitSourcePayload::decode_canonical(
            source.prepared_update(),
        )
        .map_err(|error| {
            CoordinatorCommitPhysicalWritePlanError::SourcePayload(error.to_string())
        })?;
        let mut cursor = IoCursor::new(payload.prepared_update());
        let prepared = PsyPreparedCoordinatorBlockStateUpdates::<F, Hash>::pio_read_from_io(
            &mut cursor,
        )
        .map_err(|error| {
            CoordinatorCommitPhysicalWritePlanError::PreparedUpdate(error.to_string())
        })?;
        if cursor.position() != payload.prepared_update().len() as u64 {
            return Err(CoordinatorCommitPhysicalWritePlanError::TrailingPreparedUpdateBytes);
        }

        let coverage = CoordinatorNormalCommitCoveragePlan::from_prepared(&prepared);
        if coverage.has_ignored_prepared_payload() {
            return Err(
                CoordinatorCommitPhysicalWritePlanError::PreparedPayloadOutsideSelectedBranch,
            );
        }

        let checkpoint_u64 = prepared.checkpoint_id;
        if checkpoint_u64 == 0
            || checkpoint_u64
                != source
                    .candidate()
                    .checkpoint()
                    .checkpoint_id()
                    .get()
            || prepared.old_base.block_state.checkpoint_id
                != source.expected().checkpoint().checkpoint_id().get()
        {
            return Err(CoordinatorCommitPhysicalWritePlanError::CheckpointIdentityMismatch);
        }
        let checkpoint = CheckpointId::try_new(checkpoint_u64).map_err(|_| {
            CoordinatorCommitPhysicalWritePlanError::CheckpointOutOfRange(checkpoint_u64)
        })?;
        let pending = UniquePendingId::try_new(prepared.unique_pending_id).map_err(|_| {
            CoordinatorCommitPhysicalWritePlanError::PendingOutOfRange(
                prepared.unique_pending_id,
            )
        })?;
        let proc_id = ProcCheckpointUniqueId::from_u128(
            prepared.proc_checkpoint_unique_id,
        );
        validate_narrow_payload(narrow, pending, proc_id)?;

        let verifiable = PsyVerifiableCheckpointTransitionWithProof {
            info: prepared.get_public_inputs_verifiable_state_transition(
                genesis_checkpoint_state_transition_hash,
                checkpoint_state_transition_circuit_fingerprint,
            ),
            circuit_type: payload.circuit_type(),
            zk_proof: payload.proof().to_vec(),
        };
        let expected_candidate_hash = verifiable
            .info
            .state_transition
            .get_chain_hash_from_previous::<Hasher>(
                source.expected().checkpoint().checkpoint_hash().as_inner(),
            );
        if source.candidate().checkpoint().checkpoint_hash().as_inner()
            != &expected_candidate_hash
        {
            return Err(CoordinatorCommitPhysicalWritePlanError::CandidateChainMismatch);
        }

        let mut batches = Vec::new();
        push_batch(
            &mut batches,
            CoordinatorNormalCommitWriteDomain::CheckpointZkProof,
            vec![timestamp.seal(LogicalMutation::Put {
                key: TypedTableKey::CheckpointZkProof(checkpoint),
                value: MutationValue::PsyCanonicalBytes(canonical_bytes(&verifiable)?),
            })?],
        )?;
        // Four legacy mapping rows plus the two branch-exact target rows are
        // owned by `narrow`. They are deliberately not resealed as generic
        // typed mutations here: checkpoint keys are reusable after rollback.

        if coverage.invokes_contract_branch() {
            let leaves = parse_object_rows(
                &prepared.new_contract_leaves_ffs,
                8 + PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF,
                "contract leaf",
                |id, value| {
                    (
                        TypedTableKey::ContractLeaf {
                            contract: ContractId::new(id),
                            checkpoint,
                        },
                        value,
                    )
                },
            )?;
            push_mutation_rows(
                &mut batches,
                CoordinatorNormalCommitWriteDomain::ContractLeaf,
                leaves,
                timestamp,
            )?;

            let definitions = prepared
                .new_contract_code_definitions
                .iter()
                .map(|definition| {
                    Ok((
                        TypedTableKey::ContractCodeDefinition {
                            contract: ContractId::new(definition.contract_id),
                            checkpoint,
                        },
                        canonical_bytes(&definition.code_definition)?,
                    ))
                })
                .collect::<Result<Vec<_>, CoordinatorCommitPhysicalWritePlanError>>()?;
            push_mutation_rows(
                &mut batches,
                CoordinatorNormalCommitWriteDomain::ContractCodeDefinition,
                definitions,
                timestamp,
            )?;

            let first_contract = u64::from(prepared.old_base.block_state.next_contract_id);
            let heights = prepared
                .new_contract_code_definitions
                .iter()
                .enumerate()
                .map(|(index, definition)| {
                    let contract = first_contract.checked_add(index as u64).ok_or(
                        CoordinatorCommitPhysicalWritePlanError::IdentifierOverflow(
                            "contract state-tree height",
                        ),
                    )?;
                    let height = u8::try_from(definition.code_definition.state_tree_height)
                        .map_err(|_| {
                            CoordinatorCommitPhysicalWritePlanError::ContractTreeHeightOutOfRange(
                                definition.code_definition.state_tree_height,
                            )
                        })?;
                    Ok((
                        TypedTableKey::ContractStateTreeHeight {
                            contract: ContractId::new(contract),
                            checkpoint,
                        },
                        canonical_bytes(&height)?,
                    ))
                })
                .collect::<Result<Vec<_>, CoordinatorCommitPhysicalWritePlanError>>()?;
            push_mutation_rows(
                &mut batches,
                CoordinatorNormalCommitWriteDomain::ContractStateTreeHeight,
                heights,
                timestamp,
            )?;

            push_merkle_single_rows(
                &mut batches,
                CoordinatorNormalCommitWriteDomain::ContractFunctionMerkle,
                &prepared.update_contract_function_tree_nodes_ffs,
                checkpoint,
                timestamp,
            )?;
            push_merkle_zero_rows(
                &mut batches,
                CoordinatorNormalCommitWriteDomain::GlobalContractMerkle,
                &prepared.update_global_contract_tree_nodes_ffs,
                checkpoint,
                timestamp,
                |node| TypedTableKey::GlobalContractMerkle { node, checkpoint },
            )?;
        }

        if coverage.invokes_registration_branch() {
            let public_keys = parse_object_rows(
                &prepared.new_user_public_keys_ffs,
                8 + PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY,
                "user public key",
                |id, value| {
                    (
                        TypedTableKey::UserPublicKey {
                            user: UserId::new(id),
                            checkpoint,
                        },
                        value,
                    )
                },
            )?;
            push_mutation_rows(
                &mut batches,
                CoordinatorNormalCommitWriteDomain::UserPublicKey,
                public_keys,
                timestamp,
            )?;
            push_public_key_rows(
                &mut batches,
                &prepared.new_public_key_hash_to_user_id_rows_ffs,
                timestamp,
            )?;
            push_merkle_zero_rows(
                &mut batches,
                CoordinatorNormalCommitWriteDomain::UserRegistrationMerkle,
                &prepared.update_user_registration_tree_nodes_ffs,
                checkpoint,
                timestamp,
                |node| TypedTableKey::UserRegistrationMerkle { node, checkpoint },
            )?;
        }

        if coverage.invokes_global_user_branch() {
            push_merkle_zero_rows(
                &mut batches,
                CoordinatorNormalCommitWriteDomain::GlobalUserMerkle,
                &prepared.update_global_user_tree_nodes_ffs,
                checkpoint,
                timestamp,
                |node| TypedTableKey::GlobalUserMerkle { node, checkpoint },
            )?;
        }

        if coverage.invokes_reward_branch() {
            push_reward_rows(
                &mut batches,
                &prepared.new_realm_guta_reward_tree_node_keys_ffs,
                pending,
                narrow,
                timestamp,
            )?;
        }

        push_single_canonical(
            &mut batches,
            CoordinatorNormalCommitWriteDomain::CheckpointStateRoots,
            TypedTableKey::CheckpointStateRoots(checkpoint),
            &prepared.new_base.checkpoint_leaf.global_state_roots,
            timestamp,
        )?;
        push_single_canonical(
            &mut batches,
            CoordinatorNormalCommitWriteDomain::L2BlockState,
            TypedTableKey::L2BlockState(checkpoint),
            &prepared.new_base.block_state,
            timestamp,
        )?;
        push_single_canonical(
            &mut batches,
            CoordinatorNormalCommitWriteDomain::LatestL2BlockState,
            TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
            &prepared.new_base.block_state,
            timestamp,
        )?;
        let checkpoint_leaf = prepared
            .new_base
            .checkpoint_leaf
            .to_checkpoint_leaf::<Hasher>();
        push_single_canonical(
            &mut batches,
            CoordinatorNormalCommitWriteDomain::CheckpointLeaf,
            TypedTableKey::CheckpointLeaf(checkpoint),
            &checkpoint_leaf,
            timestamp,
        )?;

        let new_proof = MerkleProofCore {
            root: prepared.checkpoint_tree_update_proof.new_root,
            value: prepared.checkpoint_tree_update_proof.new_value,
            index: prepared.checkpoint_tree_update_proof.index,
            siblings: prepared.checkpoint_tree_update_proof.siblings.clone(),
        };
        let all_nodes = new_proof
            .get_all_merkle_nodes_and_verify::<Hasher>()
            .map_err(|_| CoordinatorCommitPhysicalWritePlanError::CheckpointTreeProofMismatch)?;
        let mut path_rows = Vec::with_capacity(checkpoint_tree_height as usize + 1);
        let mut level = checkpoint_tree_height;
        let mut node_index = checkpoint_u64;
        loop {
            let node = all_nodes
                .iter()
                .find(|node| node.key.level == level && node.key.index == node_index)
                .ok_or(CoordinatorCommitPhysicalWritePlanError::CheckpointTreePathMissing {
                    level,
                    index: node_index,
                })?;
            path_rows.push((
                TypedTableKey::GlobalCheckpointMerkle {
                    node: MerkleNode::new(level, NodeIndex::new(node_index)),
                    checkpoint,
                },
                node.value.into_owned_32bytes().to_vec(),
            ));
            if level == 0 {
                break;
            }
            level -= 1;
            node_index >>= 1;
        }
        push_mutation_rows(
            &mut batches,
            CoordinatorNormalCommitWriteDomain::GlobalCheckpointMerkle,
            path_rows,
            timestamp,
        )?;

        let root = CheckpointRootKey::new(
            prepared
                .new_base
                .checkpoint_tree_root
                .into_owned_32bytes()
                .to_vec(),
        );
        let root_pair = timestamp.seal_batch(LogicalMutation::CheckpointRootMapping {
            root,
            checkpoint,
        })?;
        split_root_pair_batch(&mut batches, root_pair)?;
        push_batch(
            &mut batches,
            CoordinatorNormalCommitWriteDomain::LatestCheckpoint,
            vec![timestamp.seal(LogicalMutation::Put {
                key: TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
                value: MutationValue::CqlU64(checkpoint.get()),
            })?],
        )?;

        canonicalize_batches(&mut batches)?;
        require_domain_coverage(coverage, &batches)?;
        require_inventory_match(&inventory, &batches)?;

        let mut plan = Self {
            source_slot: source.slot().as_bytes(),
            source_digest: source.digest().as_bytes(),
            candidate: *source.candidate(),
            timestamp: timestamp.timestamp(),
            write_kind: timestamp.write_kind(),
            narrow_prepared_digest: *narrow.digest(),
            narrow_intent_digest: *narrow.intent().intent_digest().as_bytes(),
            inventory_digest: *inventory.digest(),
            batches,
            digest: [0; 32],
        };
        plan.digest = plan_digest(&plan);
        Ok(plan)
    }
}

fn canonical_bytes<T: PsyIOReadWrite>(
    value: &T,
) -> Result<Vec<u8>, CoordinatorCommitPhysicalWritePlanError> {
    let mut bytes = Vec::with_capacity(value.pio_serialized_size());
    value
        .pio_write_to_io(&mut bytes)
        .map_err(|error| CoordinatorCommitPhysicalWritePlanError::ValueEncoding(error.to_string()))?;
    Ok(bytes)
}

fn push_single_canonical<T: PsyIOReadWrite>(
    batches: &mut Vec<CoordinatorCommitPhysicalDomainBatch>,
    domain: CoordinatorNormalCommitWriteDomain,
    key: TypedTableKey,
    value: &T,
    timestamp: CoordinatorCommitTimestamp,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    push_batch(
        batches,
        domain,
        vec![timestamp.seal(LogicalMutation::Put {
            key,
            value: MutationValue::PsyCanonicalBytes(canonical_bytes(value)?),
        })?],
    )
}

fn push_mutation_rows(
    batches: &mut Vec<CoordinatorCommitPhysicalDomainBatch>,
    domain: CoordinatorNormalCommitWriteDomain,
    rows: Vec<(TypedTableKey, Vec<u8>)>,
    timestamp: CoordinatorCommitTimestamp,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    let puts = rows
        .into_iter()
        .map(|(key, value)| {
            timestamp.seal(LogicalMutation::Put {
                key,
                value: MutationValue::PsyCanonicalBytes(value),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    push_batch(batches, domain, puts)
}

fn validate_narrow<Hash: Q256BitHash>(
    source: &CoordinatorCommitSource<Hash>,
    narrow: &BranchExactWriterPrepared<Hash>,
    timestamp: CoordinatorCommitTimestamp,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    let intent = narrow.intent();
    if !matches!(intent.authority(), AuthorityScope::Coordinator)
        || intent.predecessor().canonical_chain() != source.expected()
        || intent.candidate().canonical_chain() != source.candidate()
    {
        return Err(CoordinatorCommitPhysicalWritePlanError::NarrowIdentityMismatch);
    }
    if narrow.cutover_fence().is_none() {
        return Err(CoordinatorCommitPhysicalWritePlanError::NarrowCutoverFenceMissing);
    }
    if narrow.timestamp() != timestamp.timestamp() {
        return Err(CoordinatorCommitPhysicalWritePlanError::NarrowTimestampMismatch {
            expected: narrow.timestamp(),
            actual: timestamp.timestamp(),
        });
    }
    Ok(())
}

fn validate_narrow_payload<Hash: Q256BitHash>(
    narrow: &BranchExactWriterPrepared<Hash>,
    pending: UniquePendingId,
    proc_id: ProcCheckpointUniqueId,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    if narrow.intent().candidate().pending_id() != pending
        || narrow.intent().proc_checkpoint_id() != proc_id
    {
        return Err(CoordinatorCommitPhysicalWritePlanError::NarrowPayloadMismatch);
    }
    Ok(())
}

fn push_batch(
    batches: &mut Vec<CoordinatorCommitPhysicalDomainBatch>,
    domain: CoordinatorNormalCommitWriteDomain,
    puts: Vec<SealedTimestampedPut>,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    if puts.is_empty() {
        return Err(CoordinatorCommitPhysicalWritePlanError::EmptySelectedDomain(domain));
    }
    batches.push(CoordinatorCommitPhysicalDomainBatch { domain, puts });
    Ok(())
}

fn split_root_pair_batch(
    batches: &mut Vec<CoordinatorCommitPhysicalDomainBatch>,
    pair: SealedTimestampedPutBatch,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    let mut by_hash = Vec::new();
    let mut by_checkpoint = Vec::new();
    for member in pair.members() {
        match member.resolved().mutation().key() {
            TypedTableKey::CheckpointRootByHash(_) => by_hash.push(member.clone()),
            TypedTableKey::CheckpointRootByCheckpoint(_) => {
                by_checkpoint.push(member.clone());
            }
            _ => return Err(CoordinatorCommitPhysicalWritePlanError::PairShapeMismatch),
        }
    }
    push_batch(
        batches,
        CoordinatorNormalCommitWriteDomain::CheckpointRootByHash,
        by_hash,
    )?;
    push_batch(
        batches,
        CoordinatorNormalCommitWriteDomain::CheckpointRootByCheckpoint,
        by_checkpoint,
    )
}

fn parse_object_rows(
    bytes: &[u8],
    row_bytes: usize,
    domain: &'static str,
    make: impl Fn(u64, Vec<u8>) -> (TypedTableKey, Vec<u8>),
) -> Result<Vec<(TypedTableKey, Vec<u8>)>, CoordinatorCommitPhysicalWritePlanError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(row_bytes) {
        return Err(CoordinatorCommitPhysicalWritePlanError::InvalidFfs {
            domain,
            bytes: bytes.len(),
        });
    }
    Ok(bytes
        .chunks_exact(row_bytes)
        .map(|row| {
            make(
                u64::from_le_bytes(row[..8].try_into().expect("fixed identifier")),
                row[8..].to_vec(),
            )
        })
        .collect())
}

fn push_merkle_zero_rows(
    batches: &mut Vec<CoordinatorCommitPhysicalDomainBatch>,
    domain: CoordinatorNormalCommitWriteDomain,
    bytes: &[u8],
    _checkpoint: CheckpointId,
    timestamp: CoordinatorCommitTimestamp,
    make: impl Fn(MerkleNode) -> TypedTableKey,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    if !bytes.len().is_multiple_of(PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE) {
        return Err(CoordinatorCommitPhysicalWritePlanError::InvalidFfs {
            domain: "zero-id Merkle node",
            bytes: bytes.len(),
        });
    }
    let rows = bytes
        .chunks_exact(PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE)
        .map(|row| {
            let node = MerkleNode::new(
                row[0],
                NodeIndex::new(u64::from_le_bytes(
                    row[1..9].try_into().expect("fixed node index"),
                )),
            );
            (make(node), row[9..41].to_vec())
        })
        .collect();
    push_mutation_rows(batches, domain, rows, timestamp)
}

fn push_merkle_single_rows(
    batches: &mut Vec<CoordinatorCommitPhysicalDomainBatch>,
    domain: CoordinatorNormalCommitWriteDomain,
    bytes: &[u8],
    checkpoint: CheckpointId,
    timestamp: CoordinatorCommitTimestamp,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    if !bytes
        .len()
        .is_multiple_of(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE)
    {
        return Err(CoordinatorCommitPhysicalWritePlanError::InvalidFfs {
            domain: "single-id Merkle node",
            bytes: bytes.len(),
        });
    }
    let rows = bytes
        .chunks_exact(QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE)
        .map(|row| {
            let contract = ContractId::new(u64::from_le_bytes(
                row[..8].try_into().expect("fixed tree id"),
            ));
            let node = MerkleNode::new(
                row[8],
                NodeIndex::new(u64::from_le_bytes(
                    row[9..17].try_into().expect("fixed node index"),
                )),
            );
            (
                TypedTableKey::ContractFunctionMerkle {
                    contract,
                    node,
                    checkpoint,
                },
                row[17..49].to_vec(),
            )
        })
        .collect();
    push_mutation_rows(batches, domain, rows, timestamp)
}

fn push_public_key_rows(
    batches: &mut Vec<CoordinatorCommitPhysicalDomainBatch>,
    bytes: &[u8],
    timestamp: CoordinatorCommitTimestamp,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    if !bytes.len().is_multiple_of(HASH_TO_USER_ROW_BYTES) {
        return Err(CoordinatorCommitPhysicalWritePlanError::InvalidFfs {
            domain: "public-key projection",
            bytes: bytes.len(),
        });
    }
    let puts = bytes
        .chunks_exact(HASH_TO_USER_ROW_BYTES)
        .map(|row| {
            timestamp.seal(LogicalMutation::Put {
                key: TypedTableKey::PublicKeyToUser {
                    public_key_hash: PublicKeyHash::new(row[..32].to_vec()),
                    user: UserId::new(u64::from_le_bytes(
                        row[32..40].try_into().expect("fixed user id"),
                    )),
                },
                value: MutationValue::KeyOnly,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    push_batch(
        batches,
        CoordinatorNormalCommitWriteDomain::PublicKeyToUser,
        puts,
    )
}

fn push_reward_rows<Hash: Q256BitHash>(
    batches: &mut Vec<CoordinatorCommitPhysicalDomainBatch>,
    bytes: &[u8],
    pending: UniquePendingId,
    narrow: &BranchExactWriterPrepared<Hash>,
    timestamp: CoordinatorCommitTimestamp,
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    if !bytes.len().is_multiple_of(REWARD_NODE_ROW_BYTES) {
        return Err(CoordinatorCommitPhysicalWritePlanError::InvalidFfs {
            domain: "Realm reward node key",
            bytes: bytes.len(),
        });
    }
    let puts = bytes
        .chunks_exact(REWARD_NODE_ROW_BYTES)
        .map(|row| {
            let key = TypedTableKey::RealmRewardNode {
                    realm: RealmId::new(u64::from_le_bytes(
                        row[..8].try_into().expect("fixed Realm id"),
                    )),
                    pending,
                };
            let value = MutationValue::PsyCanonicalBytes(row[8..17].to_vec());
            match timestamp {
                CoordinatorCommitTimestamp::Authority(_) => {
                    seal_coordinator_reward_node_after_cutover(
                        narrow, key, value,
                    )
                }
                CoordinatorCommitTimestamp::NewBranch(new_branch) => {
                    seal_coordinator_reward_node_after_rollback(
                        narrow, new_branch, key, value,
                    )
                }
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    push_batch(
        batches,
        CoordinatorNormalCommitWriteDomain::RealmRewardNode,
        puts,
    )
}

fn canonicalize_batches(
    batches: &mut [CoordinatorCommitPhysicalDomainBatch],
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    for batch in batches.iter_mut() {
        batch.puts.sort_by(|left, right| {
            left.resolved()
                .locator_bytes()
                .cmp(right.resolved().locator_bytes())
        });
        if batch.puts.windows(2).any(|pair| {
            pair[0].resolved().locator_bytes() == pair[1].resolved().locator_bytes()
        }) {
            return Err(CoordinatorCommitPhysicalWritePlanError::DuplicatePhysicalRow);
        }
    }
    batches.sort_by_key(|batch| batch.domain);
    if batches.windows(2).any(|pair| pair[0].domain == pair[1].domain) {
        return Err(CoordinatorCommitPhysicalWritePlanError::DuplicateSemanticDomain);
    }
    let row_count = batches.iter().map(|batch| batch.puts.len()).sum::<usize>();
    if row_count > MAX_PLAN_ROWS {
        return Err(CoordinatorCommitPhysicalWritePlanError::TooManyRows(row_count));
    }
    Ok(())
}

fn require_domain_coverage(
    coverage: CoordinatorNormalCommitCoveragePlan,
    batches: &[CoordinatorCommitPhysicalDomainBatch],
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    let expected = coverage
        .domains()
        .filter(|domain| !is_narrow_domain(*domain))
        .collect::<BTreeSet<_>>();
    let actual = batches.iter().map(|batch| batch.domain).collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(CoordinatorCommitPhysicalWritePlanError::DomainCoverageMismatch);
    }
    Ok(())
}

fn require_inventory_match<Hash>(
    inventory: &CoordinatorCommitPhysicalInventory<Hash>,
    batches: &[CoordinatorCommitPhysicalDomainBatch],
) -> Result<(), CoordinatorCommitPhysicalWritePlanError> {
    let mut actual = batches
        .iter()
        .flat_map(|batch| batch.puts.iter())
        .map(|put| put.resolved().locator_bytes().to_vec())
        .collect::<Vec<_>>();
    actual.sort();
    if actual.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CoordinatorCommitPhysicalWritePlanError::DuplicatePhysicalRow);
    }
    let expected = inventory
        .entries()
        .iter()
        .filter(|entry| !is_narrow_inventory_key(entry.key().typed_key()))
        .map(|entry| entry.key().locator_bytes().to_vec())
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(CoordinatorCommitPhysicalWritePlanError::InventoryMismatch);
    }
    Ok(())
}

const fn is_narrow_domain(domain: CoordinatorNormalCommitWriteDomain) -> bool {
    matches!(
        domain,
        CoordinatorNormalCommitWriteDomain::PendingToCheckpoint
            | CoordinatorNormalCommitWriteDomain::CheckpointToPending
            | CoordinatorNormalCommitWriteDomain::PendingToProc
            | CoordinatorNormalCommitWriteDomain::ProcToPending
    )
}

const fn is_narrow_inventory_key(key: &TypedTableKey) -> bool {
    matches!(
        key,
        TypedTableKey::PendingToCheckpoint(_)
            | TypedTableKey::CheckpointToPending(_)
            | TypedTableKey::PendingToProc(_)
            | TypedTableKey::ProcToPending(_)
    )
}

fn plan_digest<Hash: Q256BitHash>(
    plan: &CoordinatorCommitPhysicalWritePlan<Hash>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
    hasher.update(plan.source_slot);
    hasher.update(plan.source_digest);
    hasher.update(plan.candidate.to_canonical_bytes());
    hasher.update(plan.timestamp.as_i64().to_be_bytes());
    hasher.update([plan.write_kind as u8]);
    hasher.update(plan.narrow_prepared_digest);
    hasher.update(plan.narrow_intent_digest);
    hasher.update(plan.inventory_digest);
    hasher.update((plan.batches.len() as u64).to_be_bytes());
    for batch in &plan.batches {
        hasher.update([domain_id(batch.domain)]);
        hasher.update((batch.puts.len() as u64).to_be_bytes());
        for put in &batch.puts {
            hasher.update((put.canonical_bytes().len() as u64).to_be_bytes());
            hasher.update(put.canonical_bytes());
        }
    }
    hasher.finalize().into()
}

const fn domain_id(domain: CoordinatorNormalCommitWriteDomain) -> u8 {
    match domain {
        CoordinatorNormalCommitWriteDomain::CheckpointZkProof => 1,
        CoordinatorNormalCommitWriteDomain::PendingToCheckpoint => 2,
        CoordinatorNormalCommitWriteDomain::CheckpointToPending => 3,
        CoordinatorNormalCommitWriteDomain::PendingToProc => 4,
        CoordinatorNormalCommitWriteDomain::ProcToPending => 5,
        CoordinatorNormalCommitWriteDomain::ContractLeaf => 6,
        CoordinatorNormalCommitWriteDomain::ContractCodeDefinition => 7,
        CoordinatorNormalCommitWriteDomain::ContractStateTreeHeight => 8,
        CoordinatorNormalCommitWriteDomain::ContractFunctionMerkle => 9,
        CoordinatorNormalCommitWriteDomain::GlobalContractMerkle => 10,
        CoordinatorNormalCommitWriteDomain::UserPublicKey => 11,
        CoordinatorNormalCommitWriteDomain::PublicKeyToUser => 12,
        CoordinatorNormalCommitWriteDomain::UserRegistrationMerkle => 13,
        CoordinatorNormalCommitWriteDomain::GlobalUserMerkle => 14,
        CoordinatorNormalCommitWriteDomain::RealmRewardNode => 15,
        CoordinatorNormalCommitWriteDomain::CheckpointStateRoots => 16,
        CoordinatorNormalCommitWriteDomain::L2BlockState => 17,
        CoordinatorNormalCommitWriteDomain::LatestL2BlockState => 18,
        CoordinatorNormalCommitWriteDomain::CheckpointLeaf => 19,
        CoordinatorNormalCommitWriteDomain::GlobalCheckpointMerkle => 20,
        CoordinatorNormalCommitWriteDomain::CheckpointRootByHash => 21,
        CoordinatorNormalCommitWriteDomain::CheckpointRootByCheckpoint => 22,
        CoordinatorNormalCommitWriteDomain::LatestCheckpoint => 23,
    }
}

#[derive(Debug)]
pub(crate) enum CoordinatorCommitPhysicalWritePlanError {
    Inventory(CoordinatorCommitPhysicalInventoryError),
    SourcePayload(String),
    PreparedUpdate(String),
    TrailingPreparedUpdateBytes,
    PreparedPayloadOutsideSelectedBranch,
    CheckpointIdentityMismatch,
    CheckpointOutOfRange(u64),
    PendingOutOfRange(u64),
    CandidateChainMismatch,
    CheckpointTreeProofMismatch,
    CheckpointTreePathMissing { level: u8, index: u64 },
    ContractTreeHeightOutOfRange(u16),
    IdentifierOverflow(&'static str),
    ValueEncoding(String),
    InvalidFfs { domain: &'static str, bytes: usize },
    NarrowIdentityMismatch,
    NarrowCutoverFenceMissing,
    NarrowPayloadMismatch,
    NarrowTimestampMismatch {
        expected: CommitWriteTimestampUs,
        actual: CommitWriteTimestampUs,
    },
    Timestamped(TimestampedMutationError),
    EmptySelectedDomain(CoordinatorNormalCommitWriteDomain),
    PairShapeMismatch,
    DuplicateSemanticDomain,
    DuplicatePhysicalRow,
    TooManyRows(usize),
    DomainCoverageMismatch,
    InventoryMismatch,
}

impl From<CoordinatorCommitPhysicalInventoryError>
    for CoordinatorCommitPhysicalWritePlanError
{
    fn from(value: CoordinatorCommitPhysicalInventoryError) -> Self {
        Self::Inventory(value)
    }
}

impl From<TimestampedMutationError> for CoordinatorCommitPhysicalWritePlanError {
    fn from(value: TimestampedMutationError) -> Self {
        Self::Timestamped(value)
    }
}

impl fmt::Display for CoordinatorCommitPhysicalWritePlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Coordinator physical write plan: {self:?}")
    }
}

impl Error for CoordinatorCommitPhysicalWritePlanError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        PHash, PF,
        crypto::hash::{
            merkle_proof::DeltaMerkleProofCore,
            traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
        },
        pgoldilocks::PoseidonHasher,
    };
    use psy_data::{
        prepared_block::common::PsyCoordinatorPendingCheckpointBase,
        protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash,
            CheckpointId as ChainCheckpointId, CheckpointRef, NetworkId,
            checkpoint_hash_from_previous,
        },
        v1::qdata::{
            checkpoint::{
                PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafStats,
                QEDL2BlockState,
            },
            contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId},
            populated_checkpoint::PsyCheckpointLeafPopulated,
        },
    };
    use psy_node_core::store::{
        branch_exact_dual_write::BranchExactDualWriteIntent,
        branch_pending_mapping::BranchPendingMapping,
        canonical_head::{
            CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
            StoredCanonicalHead,
        },
        coordinator_commit_source::{
            CoordinatorCommitSource, CoordinatorCommitSourcePayload,
        },
        timestamp::{
            CommitWriteTimestampUs, DeleteFenceTimestampUs,
            NewBranchWriteTimestampUs,
        },
    };

    use crate::rollback::{
        BranchExactCutoverPhase, BranchExactWriterCutoverFence,
    };

    use super::*;

    const HEIGHT: u8 = 8;

    fn hash(seed: u64) -> PHash {
        PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
    }

    fn canonical(checkpoint: u64, hash: PHash) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(0),
            CheckpointRef::new(
                ChainCheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(hash),
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
        let siblings = (0..HEIGHT as usize)
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
        genesis_hash: PHash,
        circuit_fingerprint: PHash,
    ) -> CoordinatorCommitSource<PHash> {
        let expected_hash = hash(700);
        let expected = stored_head(canonical(7, expected_hash));
        let candidate_hash = checkpoint_hash_from_previous::<_, PoseidonHasher>(
            CheckpointHash::from_last_chain_hash(expected_hash),
            prepared.new_base.checkpoint_tree_root,
            prepared.new_base.checkpoint_leaf_hash,
            circuit_fingerprint,
        )
        .into_inner();
        let mut prepared_bytes = Vec::new();
        prepared.pio_write_to_io(&mut prepared_bytes).unwrap();
        let payload = CoordinatorCommitSourcePayload::try_new(
            prepared_bytes,
            17,
            vec![3; 64],
        )
        .unwrap();
        let _ = genesis_hash;
        CoordinatorCommitSource::try_new(
            expected,
            canonical(8, candidate_hash),
            payload.encode_canonical(),
        )
        .unwrap()
    }

    fn narrow(
        source: &CoordinatorCommitSource<PHash>,
        pending: u64,
        proc_id: u128,
        timestamp: CommitWriteTimestampUs,
    ) -> BranchExactWriterPrepared<PHash> {
        let predecessor = BranchPendingMapping::new(
            *source.expected(),
            UniquePendingId::try_new(pending - 1).unwrap(),
        );
        let candidate = BranchPendingMapping::new(
            *source.candidate(),
            UniquePendingId::try_new(pending).unwrap(),
        );
        let intent = BranchExactDualWriteIntent::try_coordinator(
            predecessor,
            candidate,
            ProcCheckpointUniqueId::from_u128(proc_id),
        )
        .unwrap();
        let mut bytes = [0u8; 81];
        bytes[..8].copy_from_slice(&9_u64.to_be_bytes());
        bytes[8..16].copy_from_slice(&3_u64.to_be_bytes());
        bytes[16..48].fill(0x44);
        bytes[48..80].fill(0x55);
        bytes[80] = BranchExactCutoverPhase::LegacyPrimaryDualWrite as u8;
        let fence = BranchExactWriterCutoverFence::decode_canonical(&bytes).unwrap();
        BranchExactWriterPrepared::test_fixture(intent, timestamp, fence)
    }

    #[test]
    fn exact_plan_covers_inventory_and_distinguishes_post_fence_writes() {
        let prepared = prepared();
        let genesis_hash = hash(1000);
        let circuit = hash(2000);
        let source = source(&prepared, genesis_hash, circuit);
        let ordinary = CommitWriteTimestampUs::try_from_i128(50).unwrap();
        let ordinary_narrow = narrow(&source, 81, 82, ordinary);
        let ordinary_plan = CoordinatorCommitPhysicalWritePlan::try_new::<
            PF,
            PoseidonHasher,
        >(&source, &ordinary_narrow, genesis_hash, circuit, HEIGHT)
        .unwrap();
        assert_eq!(ordinary_plan.typed_row_count(), HEIGHT as usize + 9);
        assert_eq!(ordinary_plan.row_count(), HEIGHT as usize + 15);
        assert_eq!(ordinary_plan.batches().len(), 9);
        assert_eq!(ordinary_plan.write_kind(), TimestampedWriteKind::AuthorityCommit);
        assert!(ordinary_plan.batches().iter().all(|batch| {
            batch.puts().iter().all(|put| {
                put.timestamp() == ordinary
                    && put.write_kind() == TimestampedWriteKind::AuthorityCommit
            })
        }));

        let fence = DeleteFenceTimestampUs::try_after(ordinary, 51).unwrap();
        let new_branch = NewBranchWriteTimestampUs::try_after(fence, 52).unwrap();
        let rollback_narrow = narrow(
            &source,
            81,
            82,
            new_branch.as_commit_timestamp(),
        );
        let rollback_plan = CoordinatorCommitPhysicalWritePlan::try_new_after_rollback::<
            PF,
            PoseidonHasher,
        >(&source, &rollback_narrow, new_branch, genesis_hash, circuit, HEIGHT)
        .unwrap();
        assert_eq!(rollback_plan.row_count(), ordinary_plan.row_count());
        assert_eq!(
            rollback_plan.write_kind(),
            TimestampedWriteKind::NewBranchAfterFence
        );
        assert_ne!(rollback_plan.digest(), ordinary_plan.digest());
        assert_eq!(rollback_plan.inventory_digest(), ordinary_plan.inventory_digest());
        let rollback_schedule = crate::rollback::coordinator_commit_physical_execution::CoordinatorCommitPhysicalExecutionSchedule::try_from_plan(
            &rollback_plan,
            &rollback_narrow,
        )
        .unwrap();
        assert_eq!(
            crate::rollback::coordinator_commit_physical_scylla::validate_schedule_bindings(
                &rollback_schedule,
            )
            .unwrap(),
            rollback_plan.typed_row_count(),
        );
    }

    #[test]
    fn optional_domains_carry_exact_ffs_values() {
        let mut prepared = prepared();
        prepared.new_contract_leaves_ffs =
            vec![0; 8 + PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];
        prepared.new_contract_leaves_ffs[..8]
            .copy_from_slice(&41_u64.to_le_bytes());
        prepared.new_contract_leaves_ffs[8..].fill(0x41);
        prepared.new_contract_code_definitions.push(
            ContractCodeDefinitionWithContractId::new(
                41,
                ContractCodeDefinition {
                    state_tree_height: 8,
                    functions: Vec::new(),
                },
            ),
        );
        prepared.update_contract_function_tree_nodes_ffs =
            vec![0; QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE];
        prepared.update_contract_function_tree_nodes_ffs[..8]
            .copy_from_slice(&41_u64.to_le_bytes());
        prepared.update_contract_function_tree_nodes_ffs[17..49].fill(0x42);
        prepared.update_global_contract_tree_nodes_ffs =
            vec![0; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE];
        prepared.update_global_contract_tree_nodes_ffs[9..41].fill(0x43);
        prepared.new_user_public_keys_ffs =
            vec![0; 8 + PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY];
        prepared.new_user_public_keys_ffs[..8]
            .copy_from_slice(&51_u64.to_le_bytes());
        prepared.new_user_public_keys_ffs[8..].fill(0x51);
        prepared.new_public_key_hash_to_user_id_rows_ffs =
            vec![7; HASH_TO_USER_ROW_BYTES];
        prepared.new_public_key_hash_to_user_id_rows_ffs[32..]
            .copy_from_slice(&51_u64.to_le_bytes());
        prepared.update_user_registration_tree_nodes_ffs =
            vec![0; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE];
        prepared.update_user_registration_tree_nodes_ffs[9..41].fill(0x52);
        prepared.update_global_user_tree_nodes_ffs =
            vec![0; PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE];
        prepared.update_global_user_tree_nodes_ffs[9..41].fill(0x53);
        prepared.new_realm_guta_reward_tree_node_keys_ffs =
            vec![0; REWARD_NODE_ROW_BYTES];
        prepared.new_realm_guta_reward_tree_node_keys_ffs[..8]
            .copy_from_slice(&61_u64.to_le_bytes());
        prepared.new_realm_guta_reward_tree_node_keys_ffs[8..17]
            .copy_from_slice(&[0x61; 9]);

        let genesis_hash = hash(1000);
        let circuit = hash(2000);
        let source = source(&prepared, genesis_hash, circuit);
        let narrow = narrow(
            &source,
            81,
            82,
            CommitWriteTimestampUs::try_from_i128(50).unwrap(),
        );
        let plan = CoordinatorCommitPhysicalWritePlan::try_new::<PF, PoseidonHasher>(
            &source,
            &narrow,
            genesis_hash,
            circuit,
            HEIGHT,
        )
        .unwrap();
        assert_eq!(plan.batches().len(), 19);
        assert_eq!(plan.semantic_domain_count(), 23);
        assert!(plan.batches().iter().all(|batch| !batch.puts().is_empty()));
        assert!(plan.row_count() > HEIGHT as usize + 13);
        let schedule = crate::rollback::coordinator_commit_physical_execution::CoordinatorCommitPhysicalExecutionSchedule::try_from_plan(
            &plan,
            &narrow,
        )
        .unwrap();
        assert_eq!(
            crate::rollback::coordinator_commit_physical_scylla::validate_schedule_bindings(
                &schedule,
            )
            .unwrap(),
            plan.typed_row_count(),
        );
        let typed = crate::rollback::coordinator_commit_physical_execution::exact_observation_fixture(
            &schedule,
        );
        let full = crate::rollback::coordinator_commit_full_write::CoordinatorCommitFullWriteObservation::test_fixture(
            &source,
            &schedule,
            &narrow,
            typed,
        )
        .unwrap();
        assert_eq!(full.candidate(), source.candidate());
        assert_eq!(full.semantic_domain_count(), 23);
        assert_eq!(full.typed_row_count(), plan.typed_row_count());
        assert_eq!(full.total_physical_row_count(), plan.row_count());
        assert_ne!(full.digest(), &[0; 32]);
    }

    #[test]
    fn candidate_and_hidden_branch_payload_fail_closed() {
        let genesis_hash = hash(1000);
        let circuit = hash(2000);
        let prepared = prepared();
        let bad_source = CoordinatorCommitSource::try_new(
            stored_head(canonical(7, hash(700))),
            canonical(8, hash(9999)),
            {
                let mut bytes = Vec::new();
                prepared.pio_write_to_io(&mut bytes).unwrap();
                CoordinatorCommitSourcePayload::try_new(bytes, 17, vec![3; 64])
                    .unwrap()
                    .encode_canonical()
            },
        )
        .unwrap();
        let bad_narrow = narrow(
            &bad_source,
            81,
            82,
            CommitWriteTimestampUs::try_from_i128(50).unwrap(),
        );
        assert!(matches!(
            CoordinatorCommitPhysicalWritePlan::try_new::<PF, PoseidonHasher>(
                &bad_source,
                &bad_narrow,
                genesis_hash,
                circuit,
                HEIGHT,
            ),
            Err(CoordinatorCommitPhysicalWritePlanError::CandidateChainMismatch)
        ));

        let mut hidden = prepared;
        hidden.new_contract_code_definitions.push(
            ContractCodeDefinitionWithContractId::new(
                41,
                ContractCodeDefinition {
                    state_tree_height: 8,
                    functions: Vec::new(),
                },
            ),
        );
        let source = source(&hidden, genesis_hash, circuit);
        let hidden_narrow = narrow(
            &source,
            81,
            82,
            CommitWriteTimestampUs::try_from_i128(50).unwrap(),
        );
        assert!(matches!(
            CoordinatorCommitPhysicalWritePlan::try_new::<PF, PoseidonHasher>(
                &source,
                &hidden_narrow,
                genesis_hash,
                circuit,
                HEIGHT,
            ),
            Err(
                CoordinatorCommitPhysicalWritePlanError::PreparedPayloadOutsideSelectedBranch
            )
        ));
    }

    #[test]
    fn narrow_candidate_timestamp_and_reusable_keys_are_fail_closed() {
        let genesis_hash = hash(1000);
        let circuit = hash(2000);
        let prepared = prepared();
        let source = source(&prepared, genesis_hash, circuit);
        let timestamp = CommitWriteTimestampUs::try_from_i128(50).unwrap();

        let wrong_pending = narrow(&source, 82, 82, timestamp);
        assert!(matches!(
            CoordinatorCommitPhysicalWritePlan::try_new::<PF, PoseidonHasher>(
                &source,
                &wrong_pending,
                genesis_hash,
                circuit,
                HEIGHT,
            ),
            Err(CoordinatorCommitPhysicalWritePlanError::NarrowPayloadMismatch)
        ));

        let delete_fence = DeleteFenceTimestampUs::try_after(timestamp, 51).unwrap();
        let new_branch = NewBranchWriteTimestampUs::try_after(delete_fence, 52).unwrap();
        let stale_narrow = narrow(&source, 81, 82, timestamp);
        assert!(matches!(
            CoordinatorCommitPhysicalWritePlan::try_new_after_rollback::<
                PF,
                PoseidonHasher,
            >(
                &source,
                &stale_narrow,
                new_branch,
                genesis_hash,
                circuit,
                HEIGHT,
            ),
            Err(CoordinatorCommitPhysicalWritePlanError::NarrowTimestampMismatch { .. })
        ));

        assert!(seal_commit_put(
            LogicalMutation::Put {
                key: TypedTableKey::CheckpointToPending(
                    CheckpointId::try_new(8).unwrap(),
                ),
                value: MutationValue::CqlU64(81),
            },
            timestamp,
        )
        .is_err());
        assert!(seal_commit_put(
            LogicalMutation::Put {
                key: TypedTableKey::RealmRewardNode {
                    realm: RealmId::new(61),
                    pending: UniquePendingId::try_new(81).unwrap(),
                },
                value: MutationValue::PsyCanonicalBytes(vec![0x61; 9]),
            },
            timestamp,
        )
        .is_err());
    }
}
