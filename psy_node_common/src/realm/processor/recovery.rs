//! Historical proposal verification and baseline FFS replay.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, HashTo4Felts, MerkleHasher, MerkleZeroHasher, QFieldHashable},
    },
    data::hash::{
        fast_node_serializer::{
            QMerkleStoreFastDoubleNodeSerializer, QMerkleStoreFastSingleNodeSerializer,
            QMerkleStoreFastZeroNodeSerializer, QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
            QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE,
        },
        merkle_node_key::SimpleMerkleNodeKey,
    },
    felt::{FromPrimitiveValuesFelt, QFelt64, ToU64Value},
    protocol::core_types::{Q256BitHash, QFHashBase, QNetworkTypesConfig},
};
use psy_config::CHECKPOINTS_PER_EPOCH;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    p2p::{
        sha256, BodyChunkRequest, BodyChunkResponse, NodeId, Proposal, ProposalLookupEntry,
        ProposalLookupRequest, ProposalLookupResponse, ProposalLookupStatus, RealmTransition,
        BODY_CHUNK_MAX_BYTES, MAX_PROPOSAL_BODY_BYTES, PROPOSAL_LOOKUP_CANDIDATES_PER_PAIR,
        PROPOSAL_LOOKUP_CONCURRENCY, PROPOSAL_LOOKUP_ROUND_SECS, PROPOSAL_LOOKUP_TIMEOUT_SECS,
        PROPOSAL_LOOKUP_WINDOW_PAIRS,
    },
    prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate},
    v1::qdata::{
        contract::{
            deserialize_imt_leaf_ffs_entry_v2, IMTContractStateLeaf, IMT_LEAF_FFS_ENTRY_SIZE_V2,
        },
        ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF,
        user::PQEDUserLeaf,
    },
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::{traits::realm_coordinantor::RealmCoordinatorClient, validator_lookup::load_realm_validators_from_tree},
    psy_core_db::traits::full::{
        PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    backup::realm::load_realm_memory_trees_from_db,
    realm::{
        network::{NetworkError, RealmNetworkCommands},
        processor::{
            consensus::{
                decode_proposal_state_updates, validator_tree_root_matches_proof_base,
                verify_proposal_submission, require_declared_roots_match_zk_output,
            },
            db::PsyRealmDatabaseProcessor,
            proposal_store::{ProposalStore, StagedProposal},
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointIdentity {
    pub checkpoint_id: u64,
    pub checkpoint_hash: [u8; 32],
}

pub struct BaselineReplayRequest<Hash: Q256BitHash> {
    pub previous_checkpoint_id: u64,
    pub updates: PsyPreparedRealmBlockStateUpdates<Hash>,
    pub reply: tokio::sync::oneshot::Sender<anyhow::Result<()>>,
}

pub struct VerifiedHistoryCandidate<F: QFelt64, Hash: Q256BitHash> {
    pub updates: PsyPreparedRealmBlockStateUpdates<Hash>,
    pub state_updates: Vec<u8>,
    pub coordinator_update: PsyRealmCoordinatorUpdate<F, Hash>,
}

fn history_error(kind: &str, checkpoint_id: u64, detail: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{kind} at C={checkpoint_id}: {detail}")
}

/// Why one history transition failed to verify: local material is absent or
/// stale (wait and retry), or the fetched candidate failed validation (prune
/// it and try the next candidate).
#[derive(Debug, thiserror::Error)]
pub(crate) enum RecoveryError {
    #[error("{reason}")]
    MissingLocalState {
        #[source]
        reason: anyhow::Error,
    },
    #[error("{reason}")]
    InvalidCandidate {
        proposal_id: [u8; 32],
        #[source]
        reason: anyhow::Error,
    },
}

pub(crate) fn invalid_candidate_id(error: &anyhow::Error) -> Option<[u8; 32]> {
    match error.downcast_ref::<RecoveryError>()? {
        RecoveryError::InvalidCandidate { proposal_id, .. } => Some(*proposal_id),
        RecoveryError::MissingLocalState { .. } => None,
    }
}

fn missing_local_state(checkpoint_id: u64, detail: impl std::fmt::Display) -> RecoveryError {
    RecoveryError::MissingLocalState {
        reason: history_error("MissingHistoryProof", checkpoint_id, detail),
    }
}

fn gut_local_key(
    key: SimpleMerkleNodeKey,
    coordinator_height: u8,
    realm_id: u64,
) -> anyhow::Result<SimpleMerkleNodeKey> {
    anyhow::ensure!(
        key.level >= coordinator_height,
        "InvalidStateUpdates: GUT node level {} is below coordinator height {}",
        key.level,
        coordinator_height
    );
    let local_level = key.level - coordinator_height;
    let expected_realm_id = if local_level >= 64 {
        anyhow::ensure!(key.index == 0, "InvalidStateUpdates: GUT node index does not fit local level");
        0
    } else {
        key.index >> local_level
    };
    anyhow::ensure!(
        expected_realm_id == realm_id,
        "InvalidStateUpdates: GUT node realm {expected_realm_id} does not match {realm_id}"
    );
    let local_index = if local_level == 0 {
        0
    } else if local_level >= 64 {
        key.index
    } else {
        key.index & ((1u64 << local_level) - 1)
    };
    Ok(SimpleMerkleNodeKey {
        level: local_level,
        index: local_index,
    })
}

fn require_width(bytes: &[u8], width: usize, what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes.is_empty() || bytes.len() % width == 0,
        "InvalidStateUpdates: {what} length {} is not a multiple of {width}",
        bytes.len()
    );
    Ok(())
}

fn decode_double_id_node_ffs(
    bytes: &[u8],
    width: usize,
    mut visit: impl FnMut(&[u8]),
) -> anyhow::Result<()> {
    require_width(bytes, width, "tree node FFS")?;
    for chunk in bytes.chunks_exact(width) {
        visit(chunk);
    }
    Ok(())
}

fn seed_tree_from_merkle_proof<H, Hash>(
    tree: &mut SimpleMemoryMerkleRecorderStore<H, Hash>,
    proof: &MerkleProofCore<Hash>,
) -> anyhow::Result<()>
where
    H: MerkleZeroHasher<Hash> + MerkleHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
{
    anyhow::ensure!(
        proof.verify::<H>(),
        "MissingAuthenticatedState: previous merkle proof does not verify"
    );
    let mut key = SimpleMerkleNodeKey::new(tree.get_height(), proof.index);
    for sibling in &proof.siblings {
        tree.set_node_value(key.sibling(), *sibling);
        key = key.parent();
    }
    tree.set_leaf(proof.index, proof.value);
    Ok(())
}

fn require_declared_double_id_nodes_match<H, Hash>(
    tree: &SimpleMemoryMerkleRecorderStore<H, Hash>,
    nodes: &[(u8, u64, Hash)],
) -> anyhow::Result<()>
where
    H: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
{
    for (level, index, value) in nodes {
        let key = SimpleMerkleNodeKey {
            level: *level,
            index: *index,
        };
        anyhow::ensure!(
            tree.get_node_value(&key) == *value,
            "InvalidStateUpdates: declared tree node {:?}={:?} does not match recomputed {:?}",
            key,
            value,
            tree.get_node_value(&key)
        );
    }
    Ok(())
}

fn double_id_leaves_at_level<Hash: Copy>(
    nodes: &[(u8, u64, Hash)],
    height: u8,
) -> HashMap<u64, Hash> {
    let mut last_leaf = HashMap::new();
    for (level, index, value) in nodes {
        if *level == height {
            last_leaf.insert(*index, *value);
        }
    }
    last_leaf
}

pub fn replay_double_id_nodes_from_leaves<H, Hash>(
    tree: &mut SimpleMemoryMerkleRecorderStore<H, Hash>,
    nodes: &[(u8, u64, Hash)],
) -> anyhow::Result<()>
where
    H: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
{
    let height = tree.get_height();
    for (index, value) in double_id_leaves_at_level(nodes, height) {
        tree.set_leaf(index, value);
    }
    require_declared_double_id_nodes_match(tree, nodes)
}

fn require_imt_leaf_ffs_consistency<F, Hash, H>(bytes: &[u8]) -> anyhow::Result<()>
where
    F: parth_core::felt::QFelt64 + FromPrimitiveValuesFelt,
    Hash: Q256BitHash + QFHashBase<F> + Copy + PartialEq + Default + std::fmt::Debug,
    H: MerkleZeroHasher<Hash> + FieldQHasher<F, Hash>,
{
    require_width(bytes, IMT_LEAF_FFS_ENTRY_SIZE_V2, "IMT leaf FFS")?;
    let mut first: HashMap<(u64, u64, u64), ([u8; 32], bool)> = HashMap::new();
    let mut first_key_index: HashMap<(u64, u64, [u8; 32]), u64> = HashMap::new();
    let mut first_new_keys: HashSet<(u64, u64, [u8; 32])> = HashSet::new();
    for chunk in bytes.chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2) {
        let (tree_id, tree_sub_id, leaf_index, leaf_hash, leaf_key, leaf_value, next_key, next_index, is_new_key) =
            deserialize_imt_leaf_ffs_entry_v2(chunk)?;
        let leaf = IMTContractStateLeaf::<F, Hash> {
            key: Hash::from_owned_32bytes(leaf_key),
            value: Hash::from_owned_32bytes(leaf_value),
            next_key: Hash::from_owned_32bytes(next_key),
            next_index: F::from_u64_value(next_index),
        };
        anyhow::ensure!(
            leaf.qfhash::<H>().into_owned_32bytes() == leaf_hash,
            "InvalidStateUpdates: IMT leaf preimage does not bind leaf_hash"
        );
        let id = (tree_id, tree_sub_id, leaf_index);
        let key_id = (tree_id, tree_sub_id, leaf_key);
        if let Some(first_index) = first_key_index.get(&key_id) {
            if *first_index != leaf_index {
                anyhow::bail!("InvalidStateUpdates: duplicate IMT key changed derived next fields");
            }
        } else {
            first_key_index.insert(key_id, leaf_index);
        }
        if let Some((first_key, first_new)) = first.get(&id) {
            if is_new_key && !first_new_keys.contains(&key_id) {
                anyhow::bail!("InvalidStateUpdates: duplicate IMT key changed derived next fields");
            }
            if !*first_new && is_new_key {
                anyhow::bail!("InvalidStateUpdates: duplicate IMT key changed derived next fields");
            }
            if *first_key != leaf_key {
                anyhow::bail!("InvalidStateUpdates: duplicate IMT key changed derived next fields");
            }
        } else {
            first.insert(id, (leaf_key, is_new_key));
            if is_new_key {
                first_new_keys.insert(key_id);
            }
        }
    }
    let mut finals: HashMap<(u64, u64, u64), ([u8; 32], [u8; 32], u64)> = HashMap::new();
    let mut seen_final = HashSet::new();
    for chunk in bytes.chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2) {
        let (tree_id, tree_sub_id, leaf_index, _, leaf_key, _, next_key, next_index, _) =
            deserialize_imt_leaf_ffs_entry_v2(chunk)?;
        if seen_final.insert((tree_id, tree_sub_id, leaf_index)) {
            finals.insert((tree_id, tree_sub_id, leaf_index), (leaf_key, next_key, next_index));
        }
    }
    for ((tree_id, tree_sub_id, leaf_index), (leaf_key, next_key, next_index)) in &finals {
        if *next_index == 0 {
            anyhow::ensure!(
                *next_key == [0u8; 32],
                "InvalidStateUpdates: IMT terminal next_key must be zero user={tree_id} contract={tree_sub_id} index={leaf_index}"
            );
            continue;
        }
        let Some((successor_key, _, _)) = finals.get(&(*tree_id, *tree_sub_id, *next_index)) else {
            continue;
        };
        anyhow::ensure!(
            successor_key == next_key,
            "InvalidStateUpdates: IMT next_key does not match successor leaf user={tree_id} contract={tree_sub_id} index={leaf_index} next_index={next_index}"
        );
        anyhow::ensure!(
            successor_key != leaf_key || *next_index == *leaf_index,
            "InvalidStateUpdates: IMT successor key collides with source user={tree_id} contract={tree_sub_id} index={leaf_index}"
        );
    }
    Ok(())
}

/// Changed contract-state leaves keyed by (user, contract, index).
pub fn contract_state_leaves_from_ffs<Hash>(
    updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
) -> anyhow::Result<HashMap<(u64, u64, u64), Hash>>
where
    Hash: Copy + Q256BitHash,
{
    let empty_leaf = Hash::from_owned_32bytes([0u8; 32]);
    let mut contract_state_leaves: HashMap<(u64, u64, u64), Hash> = HashMap::new();
    if !updates.update_contract_state_tree_nodes_ffs.is_empty() {
        let mut grouped: HashMap<(u64, u64), Vec<(u8, u64, Hash)>> = HashMap::new();
        decode_double_id_node_ffs(
            &updates.update_contract_state_tree_nodes_ffs,
            QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
            |chunk| {
                let node = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_from_slice::<Hash>(
                    chunk,
                );
                grouped
                    .entry((node.key.tree_id, node.key.tree_sub_id))
                    .or_default()
                    .push((node.key.level, node.key.index, node.value));
            },
        )?;
        for ((user_id, contract_id), nodes) in grouped {
            let height = nodes.iter().map(|(level, _, _)| *level).max().unwrap_or(0);
            for (index, value) in double_id_leaves_at_level(&nodes, height) {
                contract_state_leaves.insert((user_id, contract_id, index), value);
            }
        }
    }
    Ok(contract_state_leaves)
}

pub fn require_state_update_record_coverage<Hash>(
    updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
    checkpoint_id: u64,
    imt_managed: &HashSet<(u64, u64, u64)>,
) -> anyhow::Result<()>
where
    Hash: Copy + Q256BitHash,
{
    require_width(
        &updates.update_global_user_tree_nodes_ffs,
        QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE,
        "global user tree FFS",
    )?;
    require_width(
        &updates.update_user_contract_tree_nodes_ffs,
        QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
        "user contract tree FFS",
    )?;
    require_width(
        &updates.update_contract_state_tree_nodes_ffs,
        QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
        "contract state tree FFS",
    )?;
    require_width(
        &updates.update_user_leaves_ffs,
        PSY_OBJECT_FFS_SIZE_USER_LEAF,
        "user leaf FFS",
    )?;
    require_width(
        &updates.update_contract_state_imt_leaves_ffs,
        IMT_LEAF_FFS_ENTRY_SIZE_V2,
        "IMT leaf FFS",
    )?;
    if checkpoint_id == 0 {
        return Ok(());
    }
    let contract_state_leaves = contract_state_leaves_from_ffs(updates)?;
    let mut imt_leaves: HashSet<(u64, u64, u64)> = HashSet::new();
    for chunk in updates
        .update_contract_state_imt_leaves_ffs
        .chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2)
    {
        let (tree_id, tree_sub_id, leaf_index, _, _, _, _, _, _) =
            deserialize_imt_leaf_ffs_entry_v2(chunk)?;
        imt_leaves.insert((tree_id, tree_sub_id, leaf_index));
    }
    for (user_id, contract_id, index) in imt_managed {
        anyhow::ensure!(
            imt_leaves.contains(&(*user_id, *contract_id, *index)),
            "InvalidStateUpdates: contract-state leaf user={user_id} contract={contract_id} index={index} has no IMT record"
        );
    }
    let mut user_contract_leaves: HashSet<(u64, u64)> = HashSet::new();
    if !updates.update_user_contract_tree_nodes_ffs.is_empty() {
        let mut grouped: HashMap<u64, Vec<(u8, u64)>> = HashMap::new();
        decode_double_id_node_ffs(
            &updates.update_user_contract_tree_nodes_ffs,
            QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
            |chunk| {
                let node = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_from_slice::<Hash>(
                    chunk,
                );
                grouped
                    .entry(node.key.tree_id)
                    .or_default()
                    .push((node.key.level, node.key.index));
            },
        )?;
        for (user_id, nodes) in grouped {
            let height = nodes.iter().map(|(level, _)| *level).max().unwrap_or(0);
            for (level, index) in nodes {
                if level == height {
                    user_contract_leaves.insert((user_id, index));
                }
            }
        }
    }
    let contract_pairs: HashSet<(u64, u64)> = contract_state_leaves
        .keys()
        .map(|(user_id, contract_id, _)| (*user_id, *contract_id))
        .collect();
    for (user_id, contract_id) in &user_contract_leaves {
        anyhow::ensure!(
            contract_pairs.contains(&(*user_id, *contract_id)),
            "InvalidStateUpdates: user-contract leaf user={user_id} contract={contract_id} has no contract-state FFS"
        );
    }
    Ok(())
}

pub fn replay_state_updates_into_tree<F, Hash, H>(
    tree: &mut SimpleMemoryMerkleRecorderStore<H, Hash>,
    updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
    coordinator_height: u8,
    realm_user_tree_height: u8,
    realm_id: u64,
    checkpoint_id: u64,
    imt_managed: &HashSet<(u64, u64, u64)>,
) -> anyhow::Result<()>
where
    F: parth_core::felt::QFelt64 + FromPrimitiveValuesFelt,
    Hash: Q256BitHash + QFHashBase<F> + Copy + PartialEq + Default + std::fmt::Debug,
    H: MerkleZeroHasher<Hash> + FieldQHasher<F, Hash>,
{
    require_state_update_record_coverage(updates, checkpoint_id, imt_managed)?;
    anyhow::ensure!(
        tree.get_root() == updates.old_realm_root,
        "MissingAuthenticatedState: tree root {:?} is not old_realm_root {:?}",
        tree.get_root(),
        updates.old_realm_root
    );

    let gut_nodes = if updates.update_global_user_tree_nodes_ffs.is_empty() {
        Vec::new()
    } else {
        QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_nodes_from_slice::<Hash>(
            &updates.update_global_user_tree_nodes_ffs,
        )
    };
    let min_user_id = realm_id << realm_user_tree_height;
    let mut last_user: HashMap<u64, PQEDUserLeaf<F, Hash>> = HashMap::new();
    for bytes in updates
        .update_user_leaves_ffs
        .chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF)
    {
        let leaf = PQEDUserLeaf::<F, Hash>::psy_ser_from_slice(bytes)?;
        last_user.insert(leaf.user_id.to_u64_value(), leaf);
    }
    let mut last_leaf: HashMap<u64, Hash> = HashMap::new();
    for node in &gut_nodes {
        let local = gut_local_key(node.key, coordinator_height, realm_id)?;
        if local.level == realm_user_tree_height {
            last_leaf.insert(local.index, node.value);
        }
    }
    for (index, value) in &last_leaf {
        let previous_leaf = tree.get_leaf_value(*index);
        if previous_leaf == *value {
            continue;
        }
        let user_id = min_user_id + *index;
        let leaf = last_user.get(&user_id).ok_or_else(|| {
            anyhow::anyhow!("InvalidStateUpdates: GUT leaf {index} changed without preimage")
        })?;
        anyhow::ensure!(
            leaf.qfhash::<H>() == *value,
            "InvalidStateUpdates: user {user_id} preimage does not bind the GUT leaf"
        );
    }
    for (index, value) in last_leaf {
        tree.set_leaf(index, value);
    }

    for node in &gut_nodes {
        let local = gut_local_key(node.key, coordinator_height, realm_id)?;
        anyhow::ensure!(
            tree.get_node_value(&local) == node.value,
            "InvalidStateUpdates: declared GUT node {:?}={:?} does not match recomputed {:?}",
            local,
            node.value,
            tree.get_node_value(&local)
        );
    }

    for (user_id, leaf) in &last_user {
        anyhow::ensure!(
            *user_id >= min_user_id,
            "InvalidStateUpdates: user_id {user_id} is outside realm {realm_id}"
        );
        let local_index = user_id - min_user_id;
        let expected = leaf.qfhash::<H>();
        anyhow::ensure!(
            tree.get_leaf_value(local_index) == expected,
            "InvalidStateUpdates: user {user_id} preimage does not bind the recomputed GUT leaf"
        );
    }

    require_imt_leaf_ffs_consistency::<F, Hash, H>(&updates.update_contract_state_imt_leaves_ffs)?;

    anyhow::ensure!(
        tree.get_root() == updates.new_realm_root,
        "InvalidStateUpdates: recomputed root {:?} is not new_realm_root {:?}",
        tree.get_root(),
        updates.new_realm_root
    );
    Ok(())
}

/// Non-empty changed leaves of every contract-state tree the previous
/// checkpoint's IMT index manages: those must ship IMT records — including
/// first-time inserts, whose `is_new_key` write is mandatory — or the IMT
/// index keeps proving a stale value or misses the key entirely. Trees the
/// IMT index has no entries for are positional and fully exempt; a leaf
/// cleared to zero keeps the no-IMT-required behavior. The next-append
/// pointer is read before this block's IMT FFS applies, so it still reflects
/// the state the update builds on.
pub async fn imt_managed_leaves_from_db<S, F, Hash>(
    db: &S,
    updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
) -> anyhow::Result<HashSet<(u64, u64, u64)>>
where
    S: psy_node_core::psy_core_db::traits::full::PsyNodeContractStateIMTDatabaseReader<F, Hash> + Sync,
    F: parth_core::felt::QFelt64,
    Hash: Q256BitHash + Copy + PartialEq,
{
    let empty_leaf = Hash::from_owned_32bytes([0u8; 32]);
    let mut changed_trees: HashMap<(u64, u64), Vec<u64>> = HashMap::new();
    for ((user_id, contract_id, index), new_value) in contract_state_leaves_from_ffs(updates)? {
        if new_value == empty_leaf {
            continue;
        }
        changed_trees
            .entry((user_id, contract_id))
            .or_default()
            .push(index);
    }
    let mut managed = HashSet::new();
    for ((user_id, contract_id), leaves) in changed_trees {
        let next_append_index = db
            .contract_state_imt_get_next_append_index(user_id, contract_id)
            .await
            .with_context(|| format!("previous-checkpoint IMT append index read failed user={user_id} contract={contract_id}"))?;
        if next_append_index == 0 {
            continue;
        }
        for index in leaves {
            managed.insert((user_id, contract_id, index));
        }
    }
    Ok(managed)
}

async fn load_previous_contract_heights<S, F, Hash>(
    db: &S,
    previous_checkpoint_id: u64,
    contract_ids: impl IntoIterator<Item = u64>,
) -> anyhow::Result<HashMap<u64, u8>>
where
    S: psy_node_core::psy_core_db::traits::full::PsyNodeCoreDatabaseBasicContractInfoStoreReader<F, Hash> + Sync,
    F: Send + Sync,
    Hash: Send + Sync,
{
    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for contract_id in contract_ids {
        if seen.insert(contract_id) {
            unique.push(contract_id);
        }
    }
    if unique.is_empty() {
        return Ok(HashMap::new());
    }
    let fetched = db
        .get_contract_tree_heights(previous_checkpoint_id, &unique)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "MissingAuthenticatedState: contract heights unavailable at previous checkpoint {previous_checkpoint_id}: {error}"
            )
        })?;
    let mut heights = HashMap::with_capacity(unique.len());
    for (i, contract_id) in unique.into_iter().enumerate() {
        heights.insert(contract_id, fetched.get(i).copied().unwrap_or(0));
    }
    Ok(heights)
}

fn require_previous_contract_height(heights: &HashMap<u64, u8>, contract_id: u64) -> anyhow::Result<u8> {
    let height = heights.get(&contract_id).copied().unwrap_or(0);
    anyhow::ensure!(
        height > 0,
        "MissingAuthenticatedState: contract {contract_id} height is zero"
    );
    Ok(height)
}





impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
            + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
            + Send
            + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    >
    PsyRealmDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
        CoordinatorClient,
    >
where
    N::HasherBase: 'static + Send + Sync + MerkleZeroHasher<N::QHash> + FieldQHasher<N::F, N::QHash>,
{
    pub async fn verify_state_updates_from_baseline(
        &self,
        previous_checkpoint_id: u64,
        updates: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
    ) -> anyhow::Result<()> {
        let imt_managed = crate::realm::processor::recovery::imt_managed_leaves_from_db::<S, N::F, N::QHash>(self.db.as_ref(), updates)
            .await?;
        let mut trees = load_realm_memory_trees_from_db::<N, _>(
            &*self.db,
            previous_checkpoint_id,
            self.state.realm_id_u64,
        )
        .await
        .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState at previous checkpoint {previous_checkpoint_id}: {error}"))?;
        let mut tree = trees.into_tuple().0;
        let checkpoint_id = previous_checkpoint_id.saturating_add(1);
        replay_state_updates_into_tree::<N::F, N::QHash, N::HasherBase>(
            &mut tree,
            updates,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            self.state.realm_id_u64,
            checkpoint_id,
            &imt_managed,
        )
        .with_context(|| format!("baseline replay failed at previous checkpoint {previous_checkpoint_id}"))?;
        self.verify_double_id_trees_from_previous(previous_checkpoint_id, updates)
            .await
            .with_context(|| format!("baseline replay failed at previous checkpoint {previous_checkpoint_id}"))
    }

    async fn verify_double_id_trees_from_previous(
        &self,
        previous_checkpoint_id: u64,
        updates: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
    ) -> anyhow::Result<()> {
        let mut last_user: HashMap<u64, PQEDUserLeaf<N::F, N::QHash>> = HashMap::new();
        for bytes in updates
            .update_user_leaves_ffs
            .chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF)
        {
            let leaf = PQEDUserLeaf::<N::F, N::QHash>::psy_ser_from_slice(bytes)?;
            last_user.insert(leaf.user_id.to_u64_value(), leaf);
        }
        let mut user_contract_leaves: HashMap<(u64, u64), N::QHash> = HashMap::new();
        if !updates.update_user_contract_tree_nodes_ffs.is_empty() {
            let mut grouped: HashMap<u64, Vec<(u8, u64, N::QHash)>> = HashMap::new();
            decode_double_id_node_ffs(
                &updates.update_user_contract_tree_nodes_ffs,
                QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
                |chunk| {
                    let node = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_from_slice::<N::QHash>(
                        chunk,
                    );
                    grouped
                        .entry(node.key.tree_id)
                        .or_default()
                        .push((node.key.level, node.key.index, node.value));
                },
            )?;
            for (user_id, nodes) in grouped {
                anyhow::ensure!(
                    nodes.iter().all(|(level, _, _)| *level <= N::GLOBAL_CONTRACT_TREE_HEIGHT),
                    "InvalidStateUpdates: user-contract node level exceeds tree height"
                );
                let mut tree = SimpleMemoryMerkleRecorderStore::<N::HasherBase, N::QHash>::new(
                    N::GLOBAL_CONTRACT_TREE_HEIGHT,
                );
                let leaves = double_id_leaves_at_level(&nodes, N::GLOBAL_CONTRACT_TREE_HEIGHT);
                if leaves.is_empty() && !nodes.is_empty() {
                    anyhow::bail!(
                        "MissingAuthenticatedState: user-contract internals for user {user_id} have no leaf preimages"
                    );
                }
                for index in leaves.keys() {
                    let proof = self
                        .db
                        .user_contract_tree_get_merkle_proof(previous_checkpoint_id, user_id, *index)
                        .await
                        .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: user-contract proof user={user_id} index={index}: {error}"))?;
                    seed_tree_from_merkle_proof(&mut tree, &proof)?;
                }
                replay_double_id_nodes_from_leaves(&mut tree, &nodes)?;
                for (index, value) in leaves {
                    user_contract_leaves.insert((user_id, index), value);
                }
                let new_root = tree.get_root();
                let bound = if let Some(leaf) = last_user.get(&user_id) {
                    leaf.user_state_tree_root
                } else {
                    self.db
                        .get_user_leaf(previous_checkpoint_id, user_id)
                        .await
                        .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: user {user_id} leaf unavailable: {error}"))?
                        .user_state_tree_root
                };
                anyhow::ensure!(
                    new_root == bound,
                    "InvalidStateUpdates: user {user_id} contract tree root does not bind the user leaf"
                );
            }
        }
        let mut grouped: HashMap<(u64, u64), Vec<(u8, u64, N::QHash)>> = HashMap::new();
        if !updates.update_contract_state_tree_nodes_ffs.is_empty() {
            decode_double_id_node_ffs(
                &updates.update_contract_state_tree_nodes_ffs,
                QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
                |chunk| {
                    let node = QMerkleStoreFastDoubleNodeSerializer::deserialize_double_id_node_from_slice::<N::QHash>(
                        chunk,
                    );
                    grouped
                        .entry((node.key.tree_id, node.key.tree_sub_id))
                        .or_default()
                        .push((node.key.level, node.key.index, node.value));
                },
            )?;
        }
        let mut finals: HashMap<(u64, u64, u64), ([u8; 32], [u8; 32], [u8; 32], u64, bool)> = HashMap::new();
        if !updates.update_contract_state_imt_leaves_ffs.is_empty() {
            for chunk in updates
                .update_contract_state_imt_leaves_ffs
                .chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2)
            {
                let (tree_id, tree_sub_id, leaf_index, leaf_hash, leaf_key, _, next_key, next_index, is_new_key) =
                    deserialize_imt_leaf_ffs_entry_v2(chunk)?;
                finals.entry((tree_id, tree_sub_id, leaf_index)).or_insert((
                    leaf_hash,
                    leaf_key,
                    next_key,
                    next_index,
                    is_new_key,
                ));
            }
        }
        let heights = load_previous_contract_heights(
            self.db.as_ref(),
            previous_checkpoint_id,
            grouped
                .keys()
                .map(|(_, contract_id)| *contract_id)
                .chain(finals.keys().map(|(_, contract_id, _)| *contract_id)),
        )
        .await?;
        let mut contract_state_leaves: HashMap<(u64, u64, u64), N::QHash> = HashMap::new();
        for ((user_id, contract_id), nodes) in grouped {
            let height = require_previous_contract_height(&heights, contract_id)?;
            anyhow::ensure!(
                nodes.iter().all(|(level, _, _)| *level <= height),
                "InvalidStateUpdates: contract-state node level exceeds authenticated height {height}"
            );
            let mut tree = SimpleMemoryMerkleRecorderStore::<N::HasherBase, N::QHash>::new(height);
            let leaves = double_id_leaves_at_level(&nodes, height);
            if leaves.is_empty() && !nodes.is_empty() {
                anyhow::bail!(
                    "MissingAuthenticatedState: contract-state internals for user={user_id} contract={contract_id} have no leaf preimages"
                );
            }
            for index in leaves.keys() {
                let proof = self
                    .db
                    .contract_state_tree_get_merkle_proof(
                        previous_checkpoint_id,
                        user_id,
                        contract_id,
                        height,
                        *index,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: contract-state proof user={user_id} contract={contract_id} index={index}: {error}"))?;
                seed_tree_from_merkle_proof(&mut tree, &proof)?;
            }
            replay_double_id_nodes_from_leaves(&mut tree, &nodes)?;
            for (index, value) in leaves {
                contract_state_leaves.insert((user_id, contract_id, index), value);
            }
            let new_root = tree.get_root();
            let bound = if let Some(leaf) = user_contract_leaves.get(&(user_id, contract_id)) {
                *leaf
            } else {
                self.db
                    .user_contract_tree_get_leaf_hash(previous_checkpoint_id, user_id, contract_id)
                    .await
                    .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: user-contract leaf user={user_id} contract={contract_id}: {error}"))?
            };
            anyhow::ensure!(
                new_root == bound,
                "InvalidStateUpdates: contract-state root does not bind user {user_id} contract {contract_id}"
            );
        }
        self.verify_imt_from_previous(previous_checkpoint_id, finals, &contract_state_leaves, &heights)
            .await
    }

    async fn verify_imt_from_previous(
        &self,
        previous_checkpoint_id: u64,
        finals: HashMap<(u64, u64, u64), ([u8; 32], [u8; 32], [u8; 32], u64, bool)>,
        contract_state_leaves: &HashMap<(u64, u64, u64), N::QHash>,
        heights: &HashMap<u64, u8>,
    ) -> anyhow::Result<()> {
        for ((tree_id, tree_sub_id, leaf_index), (leaf_hash, leaf_key, next_key, next_index, is_new_key)) in &finals {
            let height = require_previous_contract_height(heights, *tree_sub_id)?;
            let expected = if let Some(value) = contract_state_leaves.get(&(*tree_id, *tree_sub_id, *leaf_index)) {
                *value
            } else {
                self.db
                    .contract_state_tree_get_leaf_hash(
                        previous_checkpoint_id,
                        *tree_id,
                        *tree_sub_id,
                        height,
                        *leaf_index,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: IMT contract-state leaf user={tree_id} contract={tree_sub_id} index={leaf_index}: {error}"))?
            };
            anyhow::ensure!(
                expected.into_owned_32bytes() == *leaf_hash,
                "InvalidStateUpdates: IMT leaf_hash does not bind contract-state leaf user={tree_id} contract={tree_sub_id} index={leaf_index}"
            );
            let key = N::QHash::from_owned_32bytes(*leaf_key);
            let old_index = self
                .db
                .contract_state_imt_get_leaf_index_for_key(previous_checkpoint_id, *tree_id, *tree_sub_id, &key)
                .await
                .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: IMT key index user={tree_id} contract={tree_sub_id}: {error}"))?;
            if *is_new_key {
                anyhow::ensure!(
                    old_index.is_none(),
                    "InvalidStateUpdates: IMT is_new_key already indexed user={tree_id} contract={tree_sub_id}"
                );
                let previous_at_index = self
                    .db
                    .contract_state_imt_get_leaf_preimage(
                        previous_checkpoint_id,
                        *tree_id,
                        *tree_sub_id,
                        *leaf_index,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: IMT previous leaf user={tree_id} contract={tree_sub_id} index={leaf_index}: {error}"))?;
                anyhow::ensure!(
                    previous_at_index.is_none(),
                    "InvalidStateUpdates: IMT new key overwrites an authenticated index user={tree_id} contract={tree_sub_id} index={leaf_index}"
                );
            } else {
                let old_index = old_index.ok_or_else(|| {
                    anyhow::anyhow!(
                        "InvalidStateUpdates: IMT key is not new but has no authenticated index user={tree_id} contract={tree_sub_id} index={leaf_index}"
                    )
                })?;
                anyhow::ensure!(
                    old_index == *leaf_index,
                    "InvalidStateUpdates: IMT key index moved user={tree_id} contract={tree_sub_id}"
                );
            }
            if *next_index == 0 {
                anyhow::ensure!(
                    *next_key == [0u8; 32],
                    "InvalidStateUpdates: IMT terminal next_key must be zero user={tree_id} contract={tree_sub_id} index={leaf_index}"
                );
                continue;
            }
            if let Some((_, successor_key, _, _, _)) = finals.get(&(*tree_id, *tree_sub_id, *next_index)) {
                anyhow::ensure!(
                    successor_key == next_key,
                    "InvalidStateUpdates: IMT next_key does not match successor leaf user={tree_id} contract={tree_sub_id} index={leaf_index}"
                );
                continue;
            }
            let successor = self
                .db
                .contract_state_imt_get_leaf_preimage(
                    previous_checkpoint_id,
                    *tree_id,
                    *tree_sub_id,
                    *next_index,
                )
                .await
                .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: IMT successor user={tree_id} contract={tree_sub_id} next_index={next_index}: {error}"))?;
            let successor = successor.ok_or_else(|| {
                anyhow::anyhow!("MissingAuthenticatedState: IMT successor missing user={tree_id} contract={tree_sub_id} next_index={next_index}")
            })?;
            anyhow::ensure!(
                successor.key.into_owned_32bytes() == *next_key,
                "InvalidStateUpdates: IMT next_key does not match authenticated successor user={tree_id} contract={tree_sub_id} index={leaf_index}"
            );
        }
        Ok(())
    }

    pub async fn verify_history_proposal(
        &self,
        included: &CheckpointIdentity,
        proposal: &Proposal,
        body: &[u8],
    ) -> anyhow::Result<(
        PsyPreparedRealmBlockStateUpdates<N::QHash>,
        Vec<u8>,
        PsyRealmCoordinatorUpdate<N::F, N::QHash>,
    )> {
        anyhow::ensure!(
            proposal.realm_id == self.state.realm_id_u64 as u32,
            "InvalidStateUpdates at C={}: proposal realm mismatch",
            included.checkpoint_id
        );
        anyhow::ensure!(
            proposal.chain_id == self.state.chain_id,
            "InvalidStateUpdates at C={}: proposal chain mismatch",
            included.checkpoint_id
        );
        let coordinator_update = self
            .coordinator_client
            .rc_get_realm_sync_info(included.checkpoint_id, self.state.realm_id_u64)
            .await
            .map_err(|error| missing_local_state(
                included.checkpoint_id,
                format!("Coordinator C materials unavailable: {error:#}"),
            ))?;
        anyhow::ensure!(
            coordinator_update.checkpoint_sync_info.checkpoint_id == included.checkpoint_id,
            "MissingHistoryProof at C={}: coordinator checkpoint id mismatch",
            included.checkpoint_id
        );
        anyhow::ensure!(
            coordinator_update
                .checkpoint_sync_info
                .checkpoint_leaf_hash
                .into_owned_32bytes()
                == included.checkpoint_hash,
            "MissingHistoryProof at C={}: coordinator leaf hash does not match included.checkpoint_hash",
            included.checkpoint_id
        );
        let authenticated_leaf = self
            .checkpoint_tree_backup_manager
            .checkpoint_tree
            .get_leaf(included.checkpoint_id);
        if authenticated_leaf.value.into_owned_32bytes() != included.checkpoint_hash {
            return Err(missing_local_state(
                included.checkpoint_id,
                "included.checkpoint_hash does not match the authenticated checkpoint tree leaf",
            )
            .into());
        }
        let roots = self
            .db
            .get_checkpoint_global_state_roots(proposal.base_checkpoint_id)
            .await
            .map_err(|error| missing_local_state(
                included.checkpoint_id,
                format!("proof-base P={} roots unavailable: {error:#}", proposal.base_checkpoint_id),
            ))?;
        anyhow::ensure!(
            validator_tree_root_matches_proof_base(
                &proposal.validator_tree_root,
                &roots.validator_tree_root.into_owned_32bytes(),
            ),
            "MissingHistoryProof at C={}: proposal.validator_tree_root does not match P={}",
            included.checkpoint_id,
            proposal.base_checkpoint_id
        );
        let (_, _, user_ids, _) =
            load_realm_validators_from_tree::<N::HasherBase, N::QHash, _>(
                &*self.db,
                self.state.chain_id,
                proposal.base_checkpoint_id,
                proposal.realm_id,
                &roots.validator_tree_root,
            )
            .await
            .map_err(|error| missing_local_state(
                included.checkpoint_id,
                format!("proof-base P={} validator tree unavailable: {error:#}", proposal.base_checkpoint_id),
            ))?;
        let proposer_user_id = user_ids
            .iter()
            .find(|(sub_id, _)| *sub_id == proposal.proposer_sub_id)
            .map(|(_, user_id)| *user_id)
            .ok_or_else(|| {
                history_error(
                    "MissingHistoryProof",
                    included.checkpoint_id,
                    format!("proposer sub_id {} is not a validator", proposal.proposer_sub_id),
                )
            })?;
        let decoded =
            verify_proposal_submission::<N>(proposal, body, proposer_user_id, self.proof_verifier.as_ref())?;
        let updates = decode_proposal_state_updates::<N::QHash>(&decoded.state_updates)?;
        anyhow::ensure!(
            updates.realm_id == proposal.realm_id as u64,
            "InvalidStateUpdates at C={}: FFS realm_id {} does not match proposal {}",
            included.checkpoint_id,
            updates.realm_id,
            proposal.realm_id
        );
        anyhow::ensure!(
            updates.realm_sub_id == proposal.proposer_sub_id as u64,
            "InvalidStateUpdates at C={}: FFS realm_sub_id {} does not match proposer {}",
            included.checkpoint_id,
            updates.realm_sub_id,
            proposal.proposer_sub_id
        );
        let output = psy_data::guta::realm_finalize::protocol_decode_finalize_output::<N::F, N::QHash>(
            &decoded.output,
        )?;
        require_declared_roots_match_zk_output(&updates, &output)?;
        anyhow::ensure!(
            updates.new_realm_root.into_owned_32bytes() != [0u8; 32]
                || updates.old_realm_root == updates.new_realm_root,
            "InvalidStateUpdates at C={}: empty new root",
            included.checkpoint_id
        );
        let realm_proof = &coordinator_update.merkle_proof_to_realm_root;
        anyhow::ensure!(
            realm_proof.verify::<N::HasherBase>(),
            "MissingHistoryProof at C={}: realm-root path does not verify",
            included.checkpoint_id
        );
        anyhow::ensure!(
            realm_proof.index == self.state.realm_id_u64,
            "MissingHistoryProof at C={}: realm-root path index mismatch",
            included.checkpoint_id
        );
        anyhow::ensure!(
            realm_proof.value == updates.new_realm_root,
            "MissingHistoryProof at C={}: authenticated realm root does not match proposal new_realm_root",
            included.checkpoint_id
        );
        anyhow::ensure!(
            realm_proof.root == coordinator_update.checkpoint_sync_info.state_roots.user_tree_root,
            "MissingHistoryProof at C={}: realm-root path is not bound to C user_tree_root",
            included.checkpoint_id
        );
        let previous = included
            .checkpoint_id
            .checked_sub(1)
            .ok_or_else(|| history_error("MissingHistoryProof", included.checkpoint_id, "C=0 has no predecessor"))?;
        self.verify_state_updates_from_baseline(previous, &updates)
            .await
            .with_context(|| {
                format!(
                    "InvalidStateUpdates at C={} proposal_id={}",
                    included.checkpoint_id,
                    hex::encode(proposal.proposal_id)
                )
            })?;
        Ok((updates, decoded.state_updates, coordinator_update))
    }

    pub async fn ensure_uncommitted_processing_ids(&mut self, checkpoint_id: u64) -> anyhow::Result<()> {
        let pending_id = self.state.processing_unique_pending_id;
        let mapped_checkpoint = self.db.get_checkpoint_id_for_unique_pending_id(pending_id).await?;
        if pending_id != 0 && mapped_checkpoint == Some(checkpoint_id) {
            return Ok(());
        }
        let (pending_id, proc_checkpoint_unique_id) =
            if let Some(ids) = self.db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await? {
                ids
            } else if pending_id != 0 && mapped_checkpoint.is_none() {
                return Ok(());
            } else {
                self.db.inc_unique_pending_id(1).await?
            };
        self.state.processing_unique_pending_id = pending_id;
        self.state.processing_proc_checkpoint_unique_id = proc_checkpoint_unique_id;
        self.temp_db
            .set_unique_pending_ids(&self.state.realm_identifier, pending_id, proc_checkpoint_unique_id)
            .await?;
        Ok(())
    }

    pub async fn apply_history_proposal(
        &mut self,
        included: &CheckpointIdentity,
        verified: VerifiedHistoryCandidate<N::F, N::QHash>,
    ) -> anyhow::Result<(PsyPreparedRealmBlockStateUpdates<N::QHash>, Vec<u8>)> {
        let VerifiedHistoryCandidate {
            updates,
            state_updates,
            coordinator_update,
        } = verified;
        self.ensure_uncommitted_processing_ids(included.checkpoint_id).await?;
        self.state.processing_checkpoint_id = included.checkpoint_id;
        self.state.processing_checkpoint_root = coordinator_update.checkpoint_sync_info.checkpoint_tree_root;
        self.state.processing_realm_start_root = updates.old_realm_root;
        self.state.processing_realm_end_root = updates.new_realm_root;
        if self.state.last_committed_checkpoint_id >= included.checkpoint_id {
            anyhow::ensure!(
                self.state.last_committed_realm_end_root == updates.new_realm_root,
                "InvalidStateUpdates at C={}: committed realm root does not match candidate; refusing second FFS",
                included.checkpoint_id
            );
        } else {
            self.commit_state(
                &coordinator_update,
                &updates,
                ProvingJobCircuitType::GUTANoChange,
                vec![],
            )
            .await?;
        }
        Ok((updates, state_updates))
    }

    /// Verify the candidate for one root pair, reading it from the staged bytes
    /// when the fetch stage supplied them and from the pair slot otherwise.
    pub async fn verify_history_transition(
        &self,
        included: &CheckpointIdentity,
        pair: RealmTransition,
        staged: Option<&StagedProposal>,
        store: &ProposalStore,
    ) -> anyhow::Result<Option<VerifiedHistoryCandidate<N::F, N::QHash>>> {
        let loaded = match staged {
            Some(staged) => Some(store.read_staged(staged).await?),
            None => store
                .load_proposal(&pair.old_root, &pair.new_root)
                .await?,
        };
        let Some((proposal, body)) = loaded else {
            return Ok(None);
        };
        match self
            .verify_history_proposal(included, &proposal, &body)
            .await
        {
            Ok((updates, state_updates, coordinator_update)) => {
                Ok(Some(VerifiedHistoryCandidate {
                    updates,
                    state_updates,
                    coordinator_update,
                }))
            }
            Err(error) => {
                if error
                    .downcast_ref::<RecoveryError>()
                    .is_some_and(|classified| matches!(classified, RecoveryError::MissingLocalState { .. }))
                {
                    return Err(error);
                }
                tracing::warn!(
                    "history verify rejected C={} pair=({},{}) proposal={} error={error}",
                    included.checkpoint_id,
                    hex::encode(pair.old_root),
                    hex::encode(pair.new_root),
                    hex::encode(proposal.proposal_id)
                );
                Err(anyhow::Error::new(RecoveryError::InvalidCandidate {
                    proposal_id: proposal.proposal_id,
                    reason: anyhow::anyhow!("history verify rejected C={}: {error:#}", included.checkpoint_id),
                }))
            }
        }
    }
}

/// Attempts per checkpoint: the staged window candidate plus re-fetches that
/// exclude the candidates already rejected for that pair.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm::processor::catchup::*;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
        data::hash::merkle_node_key::SimpleMerkleNode,
        pgoldilocks::{PGoldilocksFelt, PGoldilocksHash, PoseidonHasher},
        protocol::core_types::Q256BitHash,
    };
    use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;

    fn verify_double_id_node_ffs_bytes<H, Hash>(
        bytes: &[u8],
        width: usize,
        parse: impl Fn(&[u8]) -> (u64, u64, u8, u64, Hash),
    ) -> anyhow::Result<()>
    where
        H: MerkleZeroHasher<Hash>,
        Hash: Q256BitHash + Copy + PartialEq + Default + std::fmt::Debug,
    {
        require_width(bytes, width, "tree node FFS")?;
        let mut grouped: HashMap<(u64, u64), Vec<(u8, u64, Hash)>> = HashMap::new();
        for chunk in bytes.chunks_exact(width) {
            let (tree_id, tree_sub_id, level, index, value) = parse(chunk);
            grouped.entry((tree_id, tree_sub_id)).or_default().push((level, index, value));
        }
        for nodes in grouped.values() {
            let height = nodes.iter().map(|(level, _, _)| *level).max().unwrap_or(0);
            let mut tree = SimpleMemoryMerkleRecorderStore::<H, Hash>::new(height.max(1));
            replay_double_id_nodes_from_leaves(&mut tree, nodes)?;
        }
        Ok(())
    }

    fn empty_updates(old: PGoldilocksHash, new: PGoldilocksHash) -> PsyPreparedRealmBlockStateUpdates<PGoldilocksHash> {
        PsyPreparedRealmBlockStateUpdates {
            realm_id: 0,
            realm_sub_id: 0,
            unique_pending_id: 0,
            proc_checkpoint_unique_id: Default::default(),
            old_realm_root: old,
            new_realm_root: new,
            update_global_user_tree_nodes_ffs: vec![],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            update_contract_state_imt_leaves_ffs: vec![],
        }
    }

    #[test]
    fn history_bad_ffs() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8);
        let old = tree.get_root();
        let mut updates = empty_updates(old, old);
        let poison = SimpleMerkleNode {
            key: SimpleMerkleNodeKey { level: 8, index: 0 },
            value: PGoldilocksHash::from_owned_32bytes([0x11; 32]),
        };
        updates.update_global_user_tree_nodes_ffs =
            QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_node_to_vec(&poison);
        let error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut tree, &updates, 8, 8, 0, 1, &HashSet::new(),
        )
            .expect_err("poisoned GUT node must fail baseline replay");
        assert!(
            error.to_string().contains("InvalidStateUpdates"),
            "{error}"
        );
        let contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 1,
                level: 8,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x01; 32]),
        };
        let poison_contract = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 1,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x44; 32]),
        };
        let mut contract_ffs =
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&contract_leaf);
        contract_ffs.extend_from_slice(
            &QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&poison_contract),
        );
        let leaf_poison = SimpleMerkleNode {
            key: SimpleMerkleNodeKey { level: 16, index: 0 },
            value: PGoldilocksHash::from_owned_32bytes([0x22; 32]),
        };
        let mut leaf_updates = empty_updates(old, old);
        leaf_updates.update_global_user_tree_nodes_ffs =
            QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_node_to_vec(&leaf_poison);
        let preimage_error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8),
            &leaf_updates,
            8,
            8,
            0,
            1,
            &HashSet::new(),
        )
        .expect_err("changed GUT leaf without preimage must fail");
        assert!(
            preimage_error.to_string().contains("InvalidStateUpdates"),
            "{preimage_error}"
        );
        let contract_error = verify_double_id_node_ffs_bytes::<PoseidonHasher, PGoldilocksHash>(
            &contract_ffs,
            QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
            |chunk| {
                let node = QMerkleStoreFastSingleNodeSerializer::deserialize_single_id_node_from_slice::<PGoldilocksHash>(
                    chunk,
                );
                (node.key.tree_id, 0, node.key.level, node.key.index, node.value)
            },
        )
        .expect_err("poisoned contract node must fail baseline replay");
        assert!(
            contract_error.to_string().contains("InvalidStateUpdates"),
            "{contract_error}"
        );
    }

    #[test]
    fn history_duplicate_imt() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8);
        let old = tree.get_root();
        let mut updates = empty_updates(old, old);
        let first_key = PGoldilocksHash::from_owned_32bytes([0x22; 32]);
        let first_value = PGoldilocksHash::from_owned_32bytes([0x33; 32]);
        let first_next_key = PGoldilocksHash::from_owned_32bytes([0u8; 32]);
        let first_leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: first_key,
            value: first_value,
            next_key: first_next_key,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(0),
        };
        let first_hash = first_leaf.qfhash::<PoseidonHasher>();
        let first_entry = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 3, &first_hash, &first_key, &first_value, &first_next_key, 0, false,
        );
        let second_entry = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 3, &first_hash, &first_key, &first_value, &first_next_key, 7, true,
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first_entry);
        bytes.extend_from_slice(&second_entry);
        updates.update_contract_state_imt_leaves_ffs = bytes;
        let error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut tree, &updates, 8, 8, 0, 1, &HashSet::new(),
        )
            .expect_err("conflicting IMT history must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        let moved = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 9, &first_hash, &first_key, &first_value, &first_next_key, 0, false,
        );
        let mut moved_bytes = Vec::new();
        moved_bytes.extend_from_slice(&first_entry);
        moved_bytes.extend_from_slice(&moved);
        let mut moved_updates = empty_updates(old, old);
        moved_updates.update_contract_state_imt_leaves_ffs = moved_bytes;
        let moved_error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8),
            &moved_updates,
            8,
            8,
            0,
            1,
            &HashSet::new(),
        )
        .expect_err("same IMT key at a second leaf index must fail");
        assert!(moved_error.to_string().contains("InvalidStateUpdates"), "{moved_error}");
        let successor_key = PGoldilocksHash::from_owned_32bytes([0x44u8; 32]);
        let successor_leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: successor_key,
            value: first_value,
            next_key: first_next_key,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(0),
        };
        let successor_hash = successor_leaf.qfhash::<PoseidonHasher>();
        let successor = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 4, &successor_hash, &successor_key, &first_value, &first_next_key, 0, false,
        );
        let mismatched_next = PGoldilocksHash::from_owned_32bytes([0x99u8; 32]);
        let mismatched_leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: first_key,
            value: first_value,
            next_key: mismatched_next,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(4),
        };
        let mismatched_hash = mismatched_leaf.qfhash::<PoseidonHasher>();
        let mismatched = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 3, &mismatched_hash, &first_key, &first_value, &mismatched_next, 4, false,
        );
        let mut successor_bytes = Vec::new();
        successor_bytes.extend_from_slice(&mismatched);
        successor_bytes.extend_from_slice(&successor);
        let successor_error = require_imt_leaf_ffs_consistency::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(&successor_bytes)
            .expect_err("IMT next_key must match the successor leaf in the same FFS");
        assert!(successor_error.to_string().contains("InvalidStateUpdates"), "{successor_error}");
    }

    #[test]
    fn history_ffs_coverage_requires_imt_for_changed_contract_leaf() {
        let old = PGoldilocksHash::from_owned_32bytes([1u8; 32]);
        let mut updates = empty_updates(old, old);
        let contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 1,
                tree_sub_id: 2,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x01; 32]),
        };
        updates.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&contract_leaf);
        let error = require_state_update_record_coverage(&updates, 1, &HashSet::from_iter([(1u64, 2u64, 0u64)]))
            .expect_err("changed contract-state leaf without IMT must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        assert!(error.to_string().contains("no IMT record"), "{error}");
        let first_key = PGoldilocksHash::from_owned_32bytes([0x22; 32]);
        let first_value = PGoldilocksHash::from_owned_32bytes([0x33; 32]);
        let first_next_key = PGoldilocksHash::from_owned_32bytes([0u8; 32]);
        let first_leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: first_key,
            value: first_value,
            next_key: first_next_key,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(0),
        };
        let first_hash = first_leaf.qfhash::<PoseidonHasher>();
        updates.update_contract_state_imt_leaves_ffs =
            psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
                1, 2, 0, &first_hash, &first_key, &first_value, &first_next_key, 0, false,
            )
            .to_vec();
        require_state_update_record_coverage(&updates, 1, &HashSet::from_iter([(1u64, 2u64, 0u64)]))
            .expect("matching IMT record must close the coverage set");
        require_state_update_record_coverage(&updates, 0, &HashSet::new())
            .expect("genesis may carry contract-state FFS with empty IMT");
        let mut genesis = empty_updates(old, old);
        genesis.update_contract_state_tree_nodes_ffs = updates.update_contract_state_tree_nodes_ffs.clone();
        require_state_update_record_coverage(&genesis, 0, &HashSet::new())
            .expect("genesis contract-state leaves with empty IMT are a legal empty IMT");
        let genesis_error = require_state_update_record_coverage(&genesis, 1, &HashSet::from_iter([(1u64, 2u64, 0u64)]))
            .expect_err("the same missing IMT must fail after genesis");
        assert!(genesis_error.to_string().contains("no IMT record"), "{genesis_error}");
        require_state_update_record_coverage(&empty_updates(old, old), 1, &HashSet::new())
            .expect("empty contract-state FFS and empty IMT is a legal no-op");
    }

    #[test]
    fn history_ffs_user_contract_requires_contract_state() {
        let old = PGoldilocksHash::from_owned_32bytes([1u8; 32]);
        let mut updates = empty_updates(old, old);
        let user_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 1,
                level: 8,
                index: 2,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x02; 32]),
        };
        updates.update_user_contract_tree_nodes_ffs =
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&user_contract_leaf);
        let error = require_state_update_record_coverage(&updates, 1, &HashSet::new())
            .expect_err("user-contract leaf without contract-state FFS must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        assert!(error.to_string().contains("no contract-state FFS"), "{error}");
        require_state_update_record_coverage(&updates, 0, &HashSet::new())
            .expect("genesis may register a user-contract leaf with empty contract-state and IMT");
        let contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 1,
                tree_sub_id: 2,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x01; 32]),
        };
        updates.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&contract_leaf);
        let first_key = PGoldilocksHash::from_owned_32bytes([0x22; 32]);
        let first_value = PGoldilocksHash::from_owned_32bytes([0x33; 32]);
        let first_next_key = PGoldilocksHash::from_owned_32bytes([0u8; 32]);
        let first_leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: first_key,
            value: first_value,
            next_key: first_next_key,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(0),
        };
        let first_hash = first_leaf.qfhash::<PoseidonHasher>();
        updates.update_contract_state_imt_leaves_ffs =
            psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
                1, 2, 0, &first_hash, &first_key, &first_value, &first_next_key, 0, false,
            )
            .to_vec();
        require_state_update_record_coverage(&updates, 1, &HashSet::new())
            .expect("user-contract plus matching contract-state and IMT must close the coverage set");
    }

    #[test]
    fn history_ffs_genesis_skips_imt_coverage() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8);
        let old = tree.get_root();
        let mut registered = empty_updates(old, old);
        let user_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 262144,
                level: 8,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x02; 32]),
        };
        registered.update_user_contract_tree_nodes_ffs =
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&user_contract_leaf);
        require_state_update_record_coverage(&registered, 0, &HashSet::new())
            .expect("genesis contract registration has empty contract-state and IMT");
        let registered_error = require_state_update_record_coverage(&registered, 1, &HashSet::new())
            .expect_err("non-genesis registration without contract-state FFS must fail");
        assert!(
            registered_error.to_string().contains("no contract-state FFS"),
            "{registered_error}"
        );
        let mut empty_value = empty_updates(old, old);
        let empty_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 262144,
                tree_sub_id: 0,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0u8; 32]),
        };
        empty_value.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&empty_contract_leaf);
        require_state_update_record_coverage(&empty_value, 0, &HashSet::new())
            .expect("genesis empty contract-state leaf with empty IMT is trusted setup");
        require_state_update_record_coverage(&empty_value, 1, &HashSet::new())
            .expect("new empty contract-state leaf does not require IMT");
        let mut nonempty = empty_updates(old, old);
        let nonempty_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 262144,
                tree_sub_id: 0,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x11; 32]),
        };
        nonempty.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&nonempty_contract_leaf);
        require_state_update_record_coverage(&nonempty, 0, &HashSet::new())
            .expect("genesis non-empty contract-state leaf with empty IMT is trusted setup");
        let nonempty_error = require_state_update_record_coverage(&nonempty, 1, &HashSet::from_iter([(262144u64, 0u64, 0u64)]))
            .expect_err("updated non-empty contract-state leaf without IMT must fail");
        assert!(nonempty_error.to_string().contains("no IMT record"), "{nonempty_error}");
        replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut tree, &nonempty, 8, 8, 0, 0, &HashSet::new(),
        )
        .expect("verify path must honor checkpoint_id=0 and skip IMT pairing");
        let verify_error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8),
            &nonempty,
            8,
            8,
            0,
            1,
            &HashSet::from_iter([(262144u64, 0u64, 0u64)]),
        )
        .expect_err("verify path at C=1 must still require IMT for a non-empty leaf");
        assert!(verify_error.to_string().contains("no IMT record"), "{verify_error}");
        let mut poisoned = empty_updates(old, old);
        poisoned.update_user_leaves_ffs = vec![0u8; PSY_OBJECT_FFS_SIZE_USER_LEAF + 1];
        let width_error = require_state_update_record_coverage(&poisoned, 0, &HashSet::new())
            .expect_err("genesis still rejects poisoned FFS widths");
        assert!(width_error.to_string().contains("user leaf FFS"), "{width_error}");
    }

    #[test]
    fn history_ffs_positional_contract_leaf_needs_no_imt() {
        let old = PGoldilocksHash::from_owned_32bytes([1u8; 32]);
        let mut positional = empty_updates(old, old);
        let positional_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 1310720,
                tree_sub_id: 0,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x01; 32]),
        };
        positional.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&positional_leaf);
        require_state_update_record_coverage(&positional, 1, &HashSet::new())
            .expect("positional non-empty contract-state leaf with no previous IMT entry is exempt");
        let mut cleared = empty_updates(old, old);
        let user_contract_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreSingleIdKey {
                tree_id: 1,
                level: 8,
                index: 2,
            },
            value: PGoldilocksHash::from_owned_32bytes([0x02; 32]),
        };
        cleared.update_user_contract_tree_nodes_ffs =
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_node_to_vec(&user_contract_leaf);
        let zero_leaf = parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
            key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                tree_id: 1,
                tree_sub_id: 2,
                level: 4,
                index: 0,
            },
            value: PGoldilocksHash::from_owned_32bytes([0u8; 32]),
        };
        cleared.update_contract_state_tree_nodes_ffs =
            QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(&zero_leaf);
        require_state_update_record_coverage(&cleared, 1, &HashSet::new())
            .expect("user-contract pairing survives a contract-state leaf cleared to zero");
        require_state_update_record_coverage(&cleared, 0, &HashSet::from_iter([(1u64, 2u64, 0u64)]))
            .expect("genesis skips IMT coverage even with a declared managed set");
    }

    struct IMTPreimageFixture {
        next_append: HashMap<(u64, u64), u64>,
    }

    #[async_trait::async_trait]
    impl psy_node_core::psy_core_db::traits::full::PsyNodeContractStateIMTDatabaseReader<PGoldilocksFelt, PGoldilocksHash> for IMTPreimageFixture {
        async fn contract_state_imt_get_leaf_preimage(
            &self,
            _checkpoint_id: u64,
            _user_id: u64,
            _contract_id: u64,
            _leaf_index: u64,
        ) -> anyhow::Result<Option<IMTContractStateLeaf<PGoldilocksFelt, PGoldilocksHash>>> {
            Ok(None)
        }

        async fn contract_state_imt_get_leaf_index_for_key(
            &self,
            _checkpoint_id: u64,
            _user_id: u64,
            _contract_id: u64,
            _key: &PGoldilocksHash,
        ) -> anyhow::Result<Option<u64>> {
            Ok(None)
        }

        async fn contract_state_imt_find_predecessor(
            &self,
            _checkpoint_id: u64,
            _user_id: u64,
            _contract_id: u64,
            _key: &PGoldilocksHash,
        ) -> anyhow::Result<(u64, IMTContractStateLeaf<PGoldilocksFelt, PGoldilocksHash>)> {
            Ok((0, IMTContractStateLeaf::default()))
        }

        async fn contract_state_imt_get_next_append_index(&self, user_id: u64, contract_id: u64) -> anyhow::Result<u64> {
            Ok(self.next_append.get(&(user_id, contract_id)).copied().unwrap_or(0))
        }
    }

    fn contract_state_leaf_ffs(user_id: u64, contract_id: u64, index: u64, value_byte: u8) -> Vec<u8> {
        QMerkleStoreFastDoubleNodeSerializer::serialize_double_id_node_to_vec(
            &parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdNode {
                key: parth_core::data::hash::merkle_store_key::QMerkleStoreDoubleIdKey {
                    tree_id: user_id,
                    tree_sub_id: contract_id,
                    level: 4,
                    index,
                },
                value: PGoldilocksHash::from_owned_32bytes([value_byte; 32]),
            },
        )
    }

    struct CountingHeightStore {
        heights: HashMap<(u64, u64), u8>,
        calls: std::sync::atomic::AtomicUsize,
        batches: std::sync::Mutex<Vec<(u64, Vec<u64>)>>,
        fail: bool,
    }

    impl CountingHeightStore {
        fn new(heights: HashMap<(u64, u64), u8>) -> Self {
            Self {
                heights,
                calls: std::sync::atomic::AtomicUsize::new(0),
                batches: std::sync::Mutex::new(Vec::new()),
                fail: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl psy_node_core::psy_core_db::traits::full::PsyNodeCoreDatabaseBasicContractInfoStoreReader<
        PGoldilocksFelt,
        PGoldilocksHash,
    > for CountingHeightStore
    {
        async fn get_contract_tree_heights(
            &self,
            checkpoint_id: u64,
            contract_ids: &[u64],
        ) -> anyhow::Result<Vec<u8>> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.batches
                .lock()
                .expect("height batch log")
                .push((checkpoint_id, contract_ids.to_vec()));
            if self.fail {
                anyhow::bail!("injected height store failure");
            }
            Ok(contract_ids
                .iter()
                .map(|contract_id| self.heights.get(&(checkpoint_id, *contract_id)).copied().unwrap_or(0))
                .collect())
        }
    }

    // Same C+I union the verify path feeds the loader: CST groups (1,7),(2,7),(1,8)
    // then IMT finals (1,7,0),(1,9,0) with a duplicate (1,7,0) that or_insert keeps first.
    const C_AND_I_IDS: [u64; 5] = [7, 7, 8, 7, 9];

    #[tokio::test]
    async fn previous_heights_batch_unique_c_and_i_at_historical_checkpoint() {
        let previous = 10u64;
        let store = CountingHeightStore::new(HashMap::from([
            ((previous, 7), 8),
            ((previous, 8), 16),
            ((previous, 9), 24),
            ((previous + 1, 7), 32),
        ]));
        let heights = load_previous_contract_heights::<_, PGoldilocksFelt, PGoldilocksHash>(
            &store,
            previous,
            C_AND_I_IDS,
        )
        .await
        .expect("batch heights");
        assert_eq!(store.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let batches = store.batches.lock().expect("height batch log");
        assert_eq!(batches.as_slice(), &[(previous, vec![7, 8, 9])]);
        drop(batches);
        assert_eq!(require_previous_contract_height(&heights, 7).unwrap(), 8);
        assert_eq!(require_previous_contract_height(&heights, 8).unwrap(), 16);
        assert_eq!(require_previous_contract_height(&heights, 9).unwrap(), 24);
        let later = load_previous_contract_heights::<_, PGoldilocksFelt, PGoldilocksHash>(&store, previous + 1, [7])
            .await
            .expect("later checkpoint is a different key");
        assert_eq!(require_previous_contract_height(&later, 7).unwrap(), 32);
    }

    #[tokio::test]
    async fn previous_heights_reject_zero_missing_and_injected_db_error() {
        let previous = 10u64;
        let store = CountingHeightStore::new(HashMap::from([((previous, 7), 0)]));
        let heights = load_previous_contract_heights::<_, PGoldilocksFelt, PGoldilocksHash>(&store, previous, [7, 8])
            .await
            .expect("missing maps to zero without a store error");
        let zero = require_previous_contract_height(&heights, 7).expect_err("zero height must reject");
        assert!(zero.to_string().contains("height is zero"), "{zero}");
        let missing = require_previous_contract_height(&heights, 8).expect_err("absent height must reject");
        assert!(missing.to_string().contains("height is zero"), "{missing}");
        let failing = CountingHeightStore {
            fail: true,
            ..CountingHeightStore::new(HashMap::new())
        };
        let error = load_previous_contract_heights::<_, PGoldilocksFelt, PGoldilocksHash>(&failing, previous, [7])
            .await
            .expect_err("store failure must reject");
        assert!(error.to_string().contains("MissingAuthenticatedState"), "{error}");
        assert!(error.to_string().contains("injected height store failure"), "{error}");
        assert_eq!(failing.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }


    #[tokio::test]
    async fn history_imt_managed_set_follows_tree_append_index() {
        let mut managed_tree = IMTPreimageFixture { next_append: HashMap::new() };
        managed_tree.next_append.insert((1, 2), 2);

        // A first-time insert on an IMT-managed tree is NOT exempt: the is_new_key
        // index write is mandatory, so the new slot must ship its IMT record too.
        let mut new_key = empty_updates(
            PGoldilocksHash::from_owned_32bytes([1u8; 32]),
            PGoldilocksHash::from_owned_32bytes([2u8; 32]),
        );
        new_key.update_contract_state_tree_nodes_ffs = contract_state_leaf_ffs(1, 2, 5, 0x07);
        let managed = imt_managed_leaves_from_db::<_, PGoldilocksFelt, PGoldilocksHash>(&managed_tree, &new_key)
            .await
            .unwrap();
        assert_eq!(managed, HashSet::from_iter([(1u64, 2u64, 5u64)]));
        let error = require_state_update_record_coverage(&new_key, 1, &managed)
            .expect_err("new key on a managed tree without IMT record must fail");
        assert!(error.to_string().contains("no IMT record"), "{error}");

        let mut tracked_changed = empty_updates(
            PGoldilocksHash::from_owned_32bytes([1u8; 32]),
            PGoldilocksHash::from_owned_32bytes([2u8; 32]),
        );
        tracked_changed.update_contract_state_tree_nodes_ffs = contract_state_leaf_ffs(1, 2, 0, 0x05);
        let tracked_managed = imt_managed_leaves_from_db::<_, PGoldilocksFelt, PGoldilocksHash>(&managed_tree, &tracked_changed)
            .await
            .unwrap();
        assert_eq!(tracked_managed, HashSet::from_iter([(1u64, 2u64, 0u64)]));

        let positional_tree = IMTPreimageFixture { next_append: HashMap::new() };
        let untracked = imt_managed_leaves_from_db::<_, PGoldilocksFelt, PGoldilocksHash>(&positional_tree, &tracked_changed)
            .await
            .unwrap();
        assert!(untracked.is_empty(), "trees with no IMT entries are positional");
        require_state_update_record_coverage(&tracked_changed, 1, &untracked)
            .expect("collector output for a positional leaf must pass coverage");

        let mut cleared = empty_updates(
            PGoldilocksHash::from_owned_32bytes([1u8; 32]),
            PGoldilocksHash::from_owned_32bytes([2u8; 32]),
        );
        cleared.update_contract_state_tree_nodes_ffs = contract_state_leaf_ffs(1, 2, 0, 0x00);
        let cleared_managed = imt_managed_leaves_from_db::<_, PGoldilocksFelt, PGoldilocksHash>(&managed_tree, &cleared)
            .await
            .unwrap();
        assert!(cleared_managed.is_empty(), "leaf cleared to zero keeps the no-IMT behavior");
    }


    #[test]
    fn history_imt_terminal_next_key_must_be_zero() {
        let first_key = PGoldilocksHash::from_owned_32bytes([0x22; 32]);
        let first_value = PGoldilocksHash::from_owned_32bytes([0x33; 32]);
        let nonzero_next = PGoldilocksHash::from_owned_32bytes([0x99; 32]);
        let leaf = IMTContractStateLeaf::<PGoldilocksFelt, PGoldilocksHash> {
            key: first_key,
            value: first_value,
            next_key: nonzero_next,
            next_index: parth_core::felt::FromPrimitiveValuesFelt::from_u64_value(0),
        };
        let leaf_hash = leaf.qfhash::<PoseidonHasher>();
        let entry = psy_data::v1::qdata::contract::serialize_imt_leaf_ffs_entry_v2(
            1, 0, 3, &leaf_hash, &first_key, &first_value, &nonzero_next, 0, false,
        );
        let error = require_imt_leaf_ffs_consistency::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(&entry)
            .expect_err("terminal IMT next_index=0 with nonzero next_key must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        assert!(error.to_string().contains("terminal next_key"), "{error}");
    }

    #[test]
    fn history_poison_included_transition() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PGoldilocksHash>::new(8);
        let old = tree.get_root();
        let mut updates = empty_updates(old, old);
        updates.update_user_leaves_ffs = vec![0u8; PSY_OBJECT_FFS_SIZE_USER_LEAF + 1];
        let error = replay_state_updates_into_tree::<PGoldilocksFelt, PGoldilocksHash, PoseidonHasher>(
            &mut tree, &updates, 8, 8, 0, 1, &HashSet::new(),
        )
            .expect_err("poisoned user-leaf width must fail");
        assert!(error.to_string().contains("InvalidStateUpdates"), "{error}");
        assert!(!error.to_string().contains("auto"));
    }

    fn sample_store_object(old_root: [u8; 32], new_root: [u8; 32], salt: u8) -> (psy_data::p2p::Proposal, Vec<u8>) {
        sample_store_object_at(old_root, new_root, salt, 99, 1)
    }

    fn sample_store_object_at(
        old_root: [u8; 32],
        new_root: [u8; 32],
        salt: u8,
        base_checkpoint_id: u64,
        proposer_sub_id: u16,
    ) -> (psy_data::p2p::Proposal, Vec<u8>) {
        let output = vec![salt; psy_data::p2p::MAX_FINALIZER_OUTPUT_BYTES];
        let proof = vec![0xABu8; 32];
        let mut state_updates = vec![0u8; 40 + 64 + 20];
        state_updates[40..72].copy_from_slice(&old_root);
        state_updates[72..104].copy_from_slice(&new_root);
        let worker_tag = [0x11u8; 32];
        let body = psy_data::p2p::encode_proposal_body(&output, &proof, &state_updates, &worker_tag).unwrap();
        let proposal = psy_data::p2p::proposal_from_parts(
            1,
            0,
            base_checkpoint_id,
            proposer_sub_id,
            [salt; 32],
            psy_data::p2p::sha256(&output),
            psy_data::p2p::sha256(&proof),
            psy_data::p2p::sha256(&state_updates),
            psy_data::p2p::sha256(&body),
        );
        (proposal, body)
    }

    #[tokio::test]
    async fn history_ready_store_selection() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (proposal, body) = sample_store_object([1u8; 32], [2u8; 32], 1);
        store.save_proposal(&proposal, &body).await.unwrap();
        let found = store.lookup_transition(&[1u8; 32], &[2u8; 32]).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].proposal_id, proposal.proposal_id);
        let loaded = store
            .load_proposal(&[1u8; 32], &[2u8; 32])
            .await
            .unwrap()
            .expect("slot holds the stored pair");
        assert_eq!(loaded.0.proposal_id, proposal.proposal_id);
        assert_eq!(loaded.1, body);
    }

    #[tokio::test]
    async fn history_ready_single_body_per_pair() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (first, first_body) = sample_store_object([9u8; 32], [8u8; 32], 3);
        let (second, second_body) = sample_store_object([9u8; 32], [8u8; 32], 4);
        store.save_proposal(&first, &first_body).await.unwrap();
        store.save_proposal(&second, &second_body).await.unwrap();
        let found = store.lookup_transition(&[9u8; 32], &[8u8; 32]).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].proposal_id, second.proposal_id);
        let found = store.lookup_transition(&[9u8; 32], &[8u8; 32]).await.unwrap();
        assert_eq!(found[0].proposal_id, second.proposal_id);
    }

    fn test_node(seed: u8) -> NodeId {
        let mut raw = [0u8; 38];
        raw[..6].copy_from_slice(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
        raw[6..].fill(seed);
        NodeId::from_raw(raw).unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum PeerFault {
        Timeout,
        NotAValidator(NodeId),
        Closed,
    }

    impl PeerFault {
        fn to_error(self) -> crate::realm::network::NetworkError {
            use crate::realm::network::NetworkError;
            match self {
                PeerFault::Timeout => NetworkError::Timeout("test fault".to_string()),
                PeerFault::NotAValidator(node) => NetworkError::NotAValidator(node),
                PeerFault::Closed => NetworkError::CommandChannelClosed,
            }
        }
    }

    #[derive(Default)]
    struct PeerDoubleState {
        offers: std::collections::HashMap<NodeId, Vec<(RealmTransition, Proposal)>>,
        bodies: std::collections::HashMap<(NodeId, [u8; 32]), Result<Vec<u8>, PeerFault>>,
        faults: std::collections::HashMap<NodeId, PeerFault>,
        looked_up: tokio::sync::Mutex<std::collections::HashSet<([u8; 32], [u8; 32])>>,
        inflight: std::sync::atomic::AtomicUsize,
        max_inflight: std::sync::atomic::AtomicUsize,
    }

    impl PeerDoubleState {
        fn offer(mut self, peer: NodeId, lookup: RealmTransition, proposal: Proposal) -> Self {
            self.offers.entry(peer).or_default().push((lookup, proposal));
            self
        }

        fn body(mut self, peer: NodeId, proposal_id: [u8; 32], body: Result<Vec<u8>, PeerFault>) -> Self {
            self.bodies.insert((peer, proposal_id), body);
            self
        }

        fn failing(mut self, peer: NodeId, fault: PeerFault) -> Self {
            self.faults.insert(peer, fault);
            self
        }
    }

    /// A command channel answering lookups and body ranges from a fixed inventory.
    fn spawn_peer_double(state: std::sync::Arc<PeerDoubleState>) -> RealmNetworkCommands {
        use crate::realm::network::{NetworkError, RealmNetworkCommand};
        let (commands, mut rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    RealmNetworkCommand::LookupProposal {
                        destination,
                        request,
                        response,
                    } => {
                        let live = state
                            .inflight
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            + 1;
                        state
                            .max_inflight
                            .fetch_max(live, std::sync::atomic::Ordering::SeqCst);
                        let answered = match state.faults.get(&destination) {
                            Some(fault) => Err(fault.to_error()),
                            None => {
                                let mut looked = state.looked_up.lock().await;
                                let offers = state.offers.get(&destination);
                                let mut entries = Vec::with_capacity(request.pairs.len());
                                for pair in &request.pairs {
                                    looked.insert((pair.old_root, pair.new_root));
                                    let candidates = offers
                                        .map(|offers| {
                                            offers
                                                .iter()
                                                .filter(|(lookup, _)| *lookup == *pair)
                                                .map(|(_, proposal)| proposal.clone())
                                                .take(PROPOSAL_LOOKUP_CANDIDATES_PER_PAIR)
                                                .collect()
                                        })
                                        .unwrap_or_default();
                                    entries.push(ProposalLookupEntry {
                                        transition: *pair,
                                        candidates,
                                    });
                                }
                                Ok(ProposalLookupResponse::candidates(entries))
                            }
                        };
                        let _ = response.send(answered);
                        state
                            .inflight
                            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    RealmNetworkCommand::RequestBody {
                        destination,
                        request,
                        response,
                    } => {
                        let answered = match state.bodies.get(&(destination, request.proposal_id)) {
                            Some(Ok(body)) => {
                                let start = request.offset as usize;
                                let take = (request.max_bytes as usize)
                                    .min(body.len().saturating_sub(start));
                                Ok(BodyChunkResponse {
                                    offset: request.offset,
                                    data: body[start..start + take].to_vec(),
                                    eof: start + take == body.len(),
                                    body_len: body.len() as u64,
                                    body_hash: sha256(body),
                                })
                            }
                            Some(Err(fault)) => Err(fault.to_error()),
                            None => Err(NetworkError::CommandChannelClosed),
                        };
                        let _ = response.send(answered);
                    }
                    _ => {}
                }
            }
        });
        RealmNetworkCommands::from_channel(commands, test_node(200))
    }

    fn lookup_of(old_root: [u8; 32], new_root: [u8; 32]) -> RealmTransition {
        RealmTransition { old_root, new_root }
    }

    fn single_peer(seed: u8) -> (Vec<(u16, NodeId)>, NodeId) {
        let peer = test_node(seed);
        (vec![(1, peer)], peer)
    }

    async fn promote_all(store: &ProposalStore, outcomes: Vec<TransitionFetchOutcome>) -> usize {
        let mut promoted = 0usize;
        for outcome in outcomes {
            if let TransitionFetchOutcome::Staged(_, staged) = outcome {
                store.install(staged).await.unwrap();
                promoted += 1;
            }
        }
        promoted
    }

    #[tokio::test]
    async fn history_window_stages_each_offered_pair() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (first, first_body) = sample_store_object([1u8; 32], [2u8; 32], 1);
        let (second, second_body) = sample_store_object([2u8; 32], [3u8; 32], 2);
        let first_lookup = lookup_of([1u8; 32], [2u8; 32]);
        let second_lookup = lookup_of([2u8; 32], [3u8; 32]);
        let (members, peer) = single_peer(1);
        let client = spawn_peer_double(std::sync::Arc::new(
            PeerDoubleState::default()
                .offer(peer, first_lookup, first.clone())
                .offer(peer, second_lookup, second.clone())
                .body(peer, first.proposal_id, Ok(first_body))
                .body(peer, second.proposal_id, Ok(second_body)),
        ));
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(
            &client,
            &store,
            &peers,
            1,
            0,
            &[first_lookup, second_lookup],
            &[],
        )
        .await;
        assert_eq!(outcomes.len(), 2);
        assert!(store.lookup_transition(&[1u8; 32], &[2u8; 32]).await.unwrap().is_empty());
        assert_eq!(promote_all(&store, outcomes).await, 2);
        assert_eq!(
            store.lookup_transition(&[1u8; 32], &[2u8; 32]).await.unwrap()[0].proposal_id,
            first.proposal_id
        );
        assert_eq!(
            store.lookup_transition(&[2u8; 32], &[3u8; 32]).await.unwrap()[0].proposal_id,
            second.proposal_id
        );
    }

    #[tokio::test]
    async fn history_window_pair_failure_does_not_poison_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (good, good_body) = sample_store_object([4u8; 32], [5u8; 32], 5);
        let (bad, mut bad_body) = sample_store_object([5u8; 32], [6u8; 32], 6);
        bad_body[0] ^= 0xFF;
        let good_lookup = lookup_of([4u8; 32], [5u8; 32]);
        let bad_lookup = lookup_of([5u8; 32], [6u8; 32]);
        let (members, peer) = single_peer(3);
        let client = spawn_peer_double(std::sync::Arc::new(
            PeerDoubleState::default()
                .offer(peer, good_lookup, good.clone())
                .offer(peer, bad_lookup, bad.clone())
                .body(peer, good.proposal_id, Ok(good_body))
                .body(peer, bad.proposal_id, Ok(bad_body)),
        ));
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(
            &client,
            &store,
            &peers,
            1,
            0,
            &[good_lookup, bad_lookup],
            &[],
        )
        .await;
        assert!(matches!(outcomes[0], TransitionFetchOutcome::Staged(..)));
        assert!(matches!(outcomes[1], TransitionFetchOutcome::Failed(..)));
        assert_eq!(promote_all(&store, outcomes).await, 1);
        assert_eq!(store.lookup_transition(&[4u8; 32], &[5u8; 32]).await.unwrap().len(), 1);
        assert!(store.lookup_transition(&[5u8; 32], &[6u8; 32]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn history_lookup_failure_switches_to_backup_peer() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (proposal, body) = sample_store_object([7u8; 32], [8u8; 32], 7);
        let lookup = lookup_of([7u8; 32], [8u8; 32]);
        let primary = test_node(4);
        let backup = test_node(5);
        let members = vec![(1, primary), (2, backup)];
        let client = spawn_peer_double(std::sync::Arc::new(
            PeerDoubleState::default()
                .failing(primary, PeerFault::Timeout)
                .offer(backup, lookup, proposal.clone())
                .body(backup, proposal.proposal_id, Ok(body)),
        ));
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(&client, &store, &peers, 1, 0, &[lookup], &[]).await;
        assert_eq!(promote_all(&store, outcomes).await, 1);
        assert_eq!(
            store.lookup_transition(&[7u8; 32], &[8u8; 32]).await.unwrap()[0].proposal_id,
            proposal.proposal_id
        );
    }

    #[tokio::test]
    async fn history_window_fetch_concurrency_and_coverage() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (members, peer) = single_peer(8);
        let mut state = PeerDoubleState::default();
        let mut needed = Vec::new();
        for i in 0..5u8 {
            let old = [i; 32];
            let new = [i + 1; 32];
            let (proposal, mut body) = sample_store_object(old, new, 20 + i);
            if i == 2 {
                body[0] ^= 0xFF;
            }
            let lookup = lookup_of(old, new);
            state = state
                .offer(peer, lookup, proposal.clone())
                .body(peer, proposal.proposal_id, Ok(body));
            needed.push(lookup);
        }
        let state = std::sync::Arc::new(state);
        let client = spawn_peer_double(state.clone());
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(&client, &store, &peers, 1, 0, &needed, &[]).await;
        assert_eq!(promote_all(&store, outcomes).await, 4);
        assert!(
            state.max_inflight.load(std::sync::atomic::Ordering::SeqCst) <= PROPOSAL_LOOKUP_CONCURRENCY
        );
        let looked = state.looked_up.lock().await;
        for lookup in &needed {
            assert!(
                looked.contains(&(lookup.old_root, lookup.new_root)),
                "missing lookup pair=({},{})",
                hex::encode(lookup.old_root),
                hex::encode(lookup.new_root)
            );
        }
        drop(looked);
        assert_eq!(store.lookup_transition(&[2u8; 32], &[3u8; 32]).await.unwrap().len(), 0);
        assert_eq!(store.lookup_transition(&[0u8; 32], &[1u8; 32]).await.unwrap().len(), 1);
        assert_eq!(store.lookup_transition(&[3u8; 32], &[4u8; 32]).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn history_window_across_epochs() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let epoch = CHECKPOINTS_PER_EPOCH;
        let first_proposal_count = epoch - 1;
        let second_proposal_count = epoch * 3 - 1;
        let (first, first_body) =
            sample_store_object_at([1u8; 32], [2u8; 32], 30, first_proposal_count, 1);
        let (second, second_body) =
            sample_store_object_at([2u8; 32], [3u8; 32], 31, second_proposal_count, 2);
        let first_lookup = lookup_of([1u8; 32], [2u8; 32]);
        let second_lookup = lookup_of([2u8; 32], [3u8; 32]);
        let supplier = test_node(9);
        let members = vec![(3, supplier)];
        let client = spawn_peer_double(std::sync::Arc::new(
            PeerDoubleState::default()
                .offer(supplier, first_lookup, first.clone())
                .offer(supplier, second_lookup, second.clone())
                .body(supplier, first.proposal_id, Ok(first_body))
                .body(supplier, second.proposal_id, Ok(second_body)),
        ));
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(
            &client,
            &store,
            &peers,
            1,
            0,
            &[first_lookup, second_lookup],
            &[],
        )
        .await;
        assert_eq!(promote_all(&store, outcomes).await, 2);
        assert_eq!(first.proposer_sub_id, 1);
        assert_eq!(second.proposer_sub_id, 2);
        let first_found = store.lookup_transition(&[1u8; 32], &[2u8; 32]).await.unwrap();
        let second_found = store.lookup_transition(&[2u8; 32], &[3u8; 32]).await.unwrap();
        assert_eq!(first_found[0].proposal_id, first.proposal_id);
        assert_eq!(second_found[0].proposal_id, second.proposal_id);
        assert!(first.base_checkpoint_id < second.base_checkpoint_id);
    }

    #[tokio::test]
    async fn history_window_without_anchor_leaf_fails_closed() {
        let error = CatchupPeers::select(&[], 1).expect_err("empty occupied leaves must fail closed");
        assert!(
            error
                .to_string()
                .contains("no other validator peer at this checkpoint"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn history_empty_answer_marks_every_pair_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (members, _peer) = single_peer(10);
        let state = std::sync::Arc::new(PeerDoubleState::default());
        let client = spawn_peer_double(state.clone());
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let needed = vec![lookup_of([8u8; 32], [9u8; 32])];
        let outcomes = stage_transition_blocks(&client, &store, &peers, 1, 0, &needed, &[]).await;
        assert!(matches!(outcomes[0], TransitionFetchOutcome::Absent(..)));
        assert!(state.looked_up.lock().await.contains(&([8u8; 32], [9u8; 32])));
    }

    #[tokio::test]
    async fn history_resend_revotes() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (proposal, body) = sample_store_object([3u8; 32], [4u8; 32], 3);
        store.save_proposal(&proposal, &body).await.unwrap();
        store.save_proposal(&proposal, &body).await.unwrap();
        let first = store
            .read_body_chunk(&BodyChunkRequest {
                proposal_id: proposal.proposal_id,
                offset: 0,
                max_bytes: 64,
            })
            .await
            .unwrap();
        store.save_proposal(&proposal, &body).await.unwrap();
        let second = store
            .read_body_chunk(&BodyChunkRequest {
                proposal_id: proposal.proposal_id,
                offset: 0,
                max_bytes: 64,
            })
            .await
            .unwrap();
        assert_eq!(first.body_hash, proposal.body_hash);
        assert_eq!(second.body_hash, proposal.body_hash);
        assert_eq!(first.body_len, second.body_len);
    }

    #[tokio::test]
    async fn history_invalid_candidate_ab() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProposalStore::open(dir.path()).await.unwrap();
        let (candidate_b, body_b) = sample_store_object([10u8; 32], [11u8; 32], 40);
        let (mut candidate_x, body_x) = sample_store_object([10u8; 32], [12u8; 32], 41);
        candidate_x.base_checkpoint_id = candidate_b.base_checkpoint_id;
        store.save_proposal(&candidate_b, &body_b).await.unwrap();
        store.save_proposal(&candidate_x, &body_x).await.unwrap();
        let found = store.lookup_transition(&[10u8; 32], &[12u8; 32]).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].proposal_id, candidate_x.proposal_id);
        let sibling = store.lookup_transition(&[10u8; 32], &[11u8; 32]).await.unwrap();
        assert_eq!(sibling[0].proposal_id, candidate_b.proposal_id);
        let absent = store.lookup_transition(&[11u8; 32], &[10u8; 32]).await.unwrap();
        assert!(absent.is_empty());
        assert!(dir
            .path()
            .join("bodies")
            .join(format!("{}_{}", hex::encode([10u8; 32]), hex::encode([11u8; 32])))
            .exists());
    }
}
