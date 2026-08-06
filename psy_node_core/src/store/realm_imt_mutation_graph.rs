//! Fail-closed verification of the Realm IMT prepared-mutation graph.
//!
//! The prepared payload contains final rows, not the original delta proofs.
//! Planning therefore validates every cross-table commitment and produces the
//! exact predecessor-state sibling read-set needed to recompute every written
//! Merkle parent.  A seal is only available after that complete read-set has
//! been observed and verified.

use std::{collections::{BTreeMap, BTreeSet}, error::Error, fmt, marker::PhantomData};

use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleHasher, QFieldHashable},
    data::hash::{
        fast_node_serializer::{QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE},
        merkle_node_key::{SimpleMerkleNode, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE},
        merkle_store_key::{QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdNode},
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::{
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    protocol::chain_context::{AuthorityScope, AuthorityStateCheckpointId},
    v1::qdata::{
        contract::{deserialize_imt_leaf_ffs_entry_v2, IMTContractStateLeaf, IMT_LEAF_FFS_ENTRY_SIZE_V2},
        ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF,
        user::PQEDUserLeaf,
    },
};
use psy_serialize::{FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseSingle};
use sha2::{Digest, Sha256};

const PREPARED_GRAPH_DOMAIN: &[u8] = b"psy.rollback.realm-imt-mutation-graph.v1\0";
const PREPARED_PAYLOAD_DOMAIN: &[u8] = b"psy.rollback.realm-imt-prepared-payload.v1\0";
const BASELINE_OBSERVATION_DOMAIN: &[u8] = b"psy.rollback.realm-imt-baseline-observation.v1\0";

type MerkleNodeMap<Hash> = BTreeMap<RealmImtBaselineNodeKey, Hash>;
type UsedContractHeightMap = BTreeMap<(u64, u64), u8>;
type FinalImtLeafMap<Hash> = BTreeMap<(u64, u64, u64), FinalImtLeaf<Hash>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmImtMutationGraphConfig {
    global_user_tree_height: u8,
    coordinator_tree_height: u8,
    user_contract_tree_height: u8,
}

impl RealmImtMutationGraphConfig {
    pub fn try_new(
        global_user_tree_height: u8,
        coordinator_tree_height: u8,
        user_contract_tree_height: u8,
    ) -> Result<Self, RealmImtMutationGraphError> {
        if global_user_tree_height == 0 || global_user_tree_height >= 64 {
            return Err(RealmImtMutationGraphError::InvalidGlobalUserTreeHeight(global_user_tree_height));
        }
        if coordinator_tree_height == 0 || coordinator_tree_height >= global_user_tree_height {
            return Err(RealmImtMutationGraphError::InvalidCoordinatorTreeHeight(coordinator_tree_height));
        }
        if user_contract_tree_height == 0 || user_contract_tree_height >= 64 {
            return Err(RealmImtMutationGraphError::InvalidUserContractTreeHeight(user_contract_tree_height));
        }
        Ok(Self { global_user_tree_height, coordinator_tree_height, user_contract_tree_height })
    }

    pub const fn global_user_tree_height(self) -> u8 { self.global_user_tree_height }
    pub const fn coordinator_tree_height(self) -> u8 { self.coordinator_tree_height }
    pub const fn user_contract_tree_height(self) -> u8 { self.user_contract_tree_height }
}

/// Physical Merkle node required from the predecessor authority state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RealmImtBaselineNodeKey {
    GlobalUser { level: u8, index: u64 },
    UserContract { user_id: u64, level: u8, index: u64 },
    ContractState { user_id: u64, contract_id: u64, level: u8, index: u64 },
}

impl RealmImtBaselineNodeKey {
    fn encode_into(self, output: &mut Vec<u8>) {
        match self {
            Self::GlobalUser { level, index } => {
                output.push(0);
                output.push(level);
                output.extend_from_slice(&index.to_le_bytes());
            }
            Self::UserContract { user_id, level, index } => {
                output.push(1);
                output.extend_from_slice(&user_id.to_le_bytes());
                output.push(level);
                output.extend_from_slice(&index.to_le_bytes());
            }
            Self::ContractState { user_id, contract_id, level, index } => {
                output.push(2);
                output.extend_from_slice(&user_id.to_le_bytes());
                output.extend_from_slice(&contract_id.to_le_bytes());
                output.push(level);
                output.extend_from_slice(&index.to_le_bytes());
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmImtMutationGraphDigest([u8; 32]);

impl RealmImtMutationGraphDigest {
    pub const fn as_bytes(self) -> [u8; 32] { self.0 }
}

#[derive(Clone, Debug)]
pub struct SealedRealmImtMutationGraph<Hash, Hasher> {
    authority: AuthorityScope,
    predecessor_checkpoint: AuthorityStateCheckpointId,
    state_checkpoint: AuthorityStateCheckpointId,
    old_realm_root: Hash,
    new_realm_root: Hash,
    prepared_payload_digest: [u8; 32],
    baseline_observation_digest: [u8; 32],
    digest: RealmImtMutationGraphDigest,
    counts: RealmImtMutationGraphCounts,
    _hasher: PhantomData<Hasher>,
}

impl<Hash, Hasher> SealedRealmImtMutationGraph<Hash, Hasher> {
    pub const fn authority(&self) -> AuthorityScope { self.authority }
    pub const fn predecessor_checkpoint(&self) -> AuthorityStateCheckpointId { self.predecessor_checkpoint }
    pub const fn state_checkpoint(&self) -> AuthorityStateCheckpointId { self.state_checkpoint }
    pub const fn old_realm_root(&self) -> &Hash { &self.old_realm_root }
    pub const fn new_realm_root(&self) -> &Hash { &self.new_realm_root }
    pub const fn prepared_payload_digest(&self) -> &[u8; 32] { &self.prepared_payload_digest }
    pub const fn baseline_observation_digest(&self) -> &[u8; 32] { &self.baseline_observation_digest }
    pub const fn digest(&self) -> RealmImtMutationGraphDigest { self.digest }
    pub const fn counts(&self) -> RealmImtMutationGraphCounts { self.counts }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmImtMutationGraphCounts {
    pub global_nodes: usize,
    pub user_contract_nodes: usize,
    pub contract_state_nodes: usize,
    pub user_leaves: usize,
    pub final_imt_leaves: usize,
    pub baseline_reads: usize,
}

#[derive(Clone, Debug)]
pub struct RealmImtMutationGraphPlan<Hash, Hasher> {
    authority: AuthorityScope,
    predecessor_checkpoint: AuthorityStateCheckpointId,
    state_checkpoint: AuthorityStateCheckpointId,
    config: RealmImtMutationGraphConfig,
    old_realm_root: Hash,
    new_realm_root: Hash,
    global_nodes: BTreeMap<RealmImtBaselineNodeKey, Hash>,
    user_contract_nodes: BTreeMap<RealmImtBaselineNodeKey, Hash>,
    contract_state_nodes: BTreeMap<RealmImtBaselineNodeKey, Hash>,
    contract_heights: BTreeMap<(u64, u64), u8>,
    baseline_requests: Vec<RealmImtBaselineNodeKey>,
    prepared_payload_digest: [u8; 32],
    counts: RealmImtMutationGraphCounts,
    _hasher: PhantomData<Hasher>,
}

impl<Hash: Q256BitHash, Hasher: MerkleHasher<Hash>> RealmImtMutationGraphPlan<Hash, Hasher> {
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_prepared<F>(
        authority: AuthorityScope,
        predecessor_checkpoint: AuthorityStateCheckpointId,
        state_checkpoint: AuthorityStateCheckpointId,
        config: RealmImtMutationGraphConfig,
        contract_state_tree_heights: &BTreeMap<u64, u8>,
        prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
    ) -> Result<Self, RealmImtMutationGraphError>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
        Hasher: FieldQHasher<F, Hash>,
    {
        let (realm_id, realm_sub_id) = match authority {
            AuthorityScope::Realm { realm_id, realm_sub_id } => (u64::from(realm_id), u64::from(realm_sub_id)),
            AuthorityScope::Coordinator => return Err(RealmImtMutationGraphError::RealmAuthorityRequired),
        };
        if realm_id != prepared.realm_id || realm_sub_id != prepared.realm_sub_id {
            return Err(RealmImtMutationGraphError::PreparedAuthorityMismatch);
        }
        if predecessor_checkpoint.get() >= state_checkpoint.get() {
            return Err(RealmImtMutationGraphError::InvalidCheckpointOrder);
        }
        if prepared.old_realm_root == prepared.new_realm_root {
            return Err(RealmImtMutationGraphError::ChangedRealmStateRequired);
        }
        let realm_limit = 1u64 << config.coordinator_tree_height;
        if realm_id >= realm_limit {
            return Err(RealmImtMutationGraphError::RealmIndexOutOfRange);
        }

        let global_nodes = parse_global_nodes(prepared, config, realm_id)?;
        let user_contract_nodes = parse_user_contract_nodes(prepared, config, realm_id)?;
        let (contract_state_nodes, contract_heights) = parse_contract_state_nodes(
            prepared, config, realm_id, contract_state_tree_heights,
        )?;
        let user_leaves = parse_user_leaves::<F, Hash>(prepared, config, realm_id)?;
        let final_imt_leaves = parse_final_imt_leaves::<F, Hash, Hasher>(
            prepared, config, realm_id, contract_state_tree_heights,
        )?;

        validate_graph_edges::<F, Hash, Hasher>(
            prepared,
            config,
            realm_id,
            &global_nodes,
            &user_contract_nodes,
            &contract_state_nodes,
            &user_leaves,
            &final_imt_leaves,
            &contract_heights,
        )?;
        validate_path_closure(&global_nodes, &user_contract_nodes, &contract_state_nodes, config)?;

        let baseline_requests = build_baseline_requests(
            realm_id,
            config,
            &global_nodes,
            &user_contract_nodes,
            &contract_state_nodes,
            &contract_heights,
        );
        let prepared_bytes = prepared.psy_ser_to_bytes_vec()
            .map_err(|_| RealmImtMutationGraphError::PreparedSerializationFailed)?;
        let prepared_payload_digest = digest(PREPARED_PAYLOAD_DOMAIN, &prepared_bytes);
        let counts = RealmImtMutationGraphCounts {
            global_nodes: global_nodes.len(),
            user_contract_nodes: user_contract_nodes.len(),
            contract_state_nodes: contract_state_nodes.len(),
            user_leaves: user_leaves.len(),
            final_imt_leaves: final_imt_leaves.len(),
            baseline_reads: baseline_requests.len(),
        };
        Ok(Self {
            authority,
            predecessor_checkpoint,
            state_checkpoint,
            config,
            old_realm_root: prepared.old_realm_root,
            new_realm_root: prepared.new_realm_root,
            global_nodes,
            user_contract_nodes,
            contract_state_nodes,
            contract_heights,
            baseline_requests,
            prepared_payload_digest,
            counts,
            _hasher: PhantomData,
        })
    }

    pub fn baseline_requests(&self) -> &[RealmImtBaselineNodeKey] { &self.baseline_requests }
    pub const fn counts(&self) -> RealmImtMutationGraphCounts { self.counts }

    pub fn verify_and_seal(
        &self,
        observations: &[(RealmImtBaselineNodeKey, Hash)],
    ) -> Result<SealedRealmImtMutationGraph<Hash, Hasher>, RealmImtMutationGraphError> {
        let mut observed = BTreeMap::new();
        for (key, value) in observations {
            if observed.insert(*key, *value).is_some() {
                return Err(RealmImtMutationGraphError::DuplicateBaselineObservation(*key));
            }
        }
        let expected = self.baseline_requests.iter().copied().collect::<BTreeSet<_>>();
        let actual = observed.keys().copied().collect::<BTreeSet<_>>();
        if expected != actual {
            let missing = expected.difference(&actual).next().copied();
            let unexpected = actual.difference(&expected).next().copied();
            return Err(RealmImtMutationGraphError::BaselineCoverageMismatch { missing, unexpected });
        }

        let root_key = match self.authority {
            AuthorityScope::Realm { realm_id, .. } => RealmImtBaselineNodeKey::GlobalUser {
                level: self.config.coordinator_tree_height,
                index: u64::from(realm_id),
            },
            AuthorityScope::Coordinator => unreachable!("plan requires Realm authority"),
        };
        if observed[&root_key] != self.old_realm_root {
            return Err(RealmImtMutationGraphError::PredecessorRealmRootMismatch);
        }

        verify_tree::<Hash, Hasher>(&self.global_nodes, self.config.global_user_tree_height, &observed)?;
        verify_tree::<Hash, Hasher>(&self.user_contract_nodes, self.config.user_contract_tree_height, &observed)?;
        for (&(user_id, contract_id), &height) in &self.contract_heights {
            let tree = self.contract_state_nodes.iter()
                .filter(|(key, _)| matches!(key, RealmImtBaselineNodeKey::ContractState { user_id: u, contract_id: c, .. } if *u == user_id && *c == contract_id))
                .map(|(key, value)| (*key, *value))
                .collect::<BTreeMap<_, _>>();
            verify_tree::<Hash, Hasher>(&tree, height, &observed)?;
        }

        let mut baseline_bytes = Vec::new();
        for (key, value) in &observed {
            key.encode_into(&mut baseline_bytes);
            baseline_bytes.extend_from_slice(&value.into_owned_32bytes());
        }
        let baseline_observation_digest = digest(BASELINE_OBSERVATION_DOMAIN, &baseline_bytes);
        let mut graph_bytes = Vec::new();
        encode_authority(self.authority, &mut graph_bytes);
        graph_bytes.extend_from_slice(&self.predecessor_checkpoint.get().to_le_bytes());
        graph_bytes.extend_from_slice(&self.state_checkpoint.get().to_le_bytes());
        graph_bytes.extend_from_slice(&[
            self.config.global_user_tree_height,
            self.config.coordinator_tree_height,
            self.config.user_contract_tree_height,
        ]);
        graph_bytes.extend_from_slice(&(self.contract_heights.len() as u32).to_le_bytes());
        for (&(user_id, contract_id), &height) in &self.contract_heights {
            graph_bytes.extend_from_slice(&user_id.to_le_bytes());
            graph_bytes.extend_from_slice(&contract_id.to_le_bytes());
            graph_bytes.push(height);
        }
        graph_bytes.extend_from_slice(&self.old_realm_root.into_owned_32bytes());
        graph_bytes.extend_from_slice(&self.new_realm_root.into_owned_32bytes());
        graph_bytes.extend_from_slice(&self.prepared_payload_digest);
        graph_bytes.extend_from_slice(&baseline_observation_digest);
        let digest = RealmImtMutationGraphDigest(digest(PREPARED_GRAPH_DOMAIN, &graph_bytes));
        Ok(SealedRealmImtMutationGraph {
            authority: self.authority,
            predecessor_checkpoint: self.predecessor_checkpoint,
            state_checkpoint: self.state_checkpoint,
            old_realm_root: self.old_realm_root,
            new_realm_root: self.new_realm_root,
            prepared_payload_digest: self.prepared_payload_digest,
            baseline_observation_digest,
            digest,
            counts: self.counts,
            _hasher: PhantomData,
        })
    }
}

#[derive(Clone, Copy)]
struct FinalImtLeaf<Hash> { tree_id: u64, contract_id: u64, leaf_index: u64, leaf_hash: Hash }

fn parse_global_nodes<Hash: Q256BitHash>(
    prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
    config: RealmImtMutationGraphConfig,
    realm_id: u64,
) -> Result<BTreeMap<RealmImtBaselineNodeKey, Hash>, RealmImtMutationGraphError> {
    parse_fixed_nodes(
        &prepared.update_global_user_tree_nodes_ffs,
        PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE,
        RealmImtMutationGraphError::MalformedGlobalNodes,
        |chunk| {
            let node = SimpleMerkleNode::<Hash>::ffs_try_from_slice(chunk)
                .map_err(|_| RealmImtMutationGraphError::MalformedGlobalNodes)?;
            validate_position(node.key.level, node.key.index, config.global_user_tree_height)?;
            if node.key.level < config.coordinator_tree_height
                || (node.key.index >> (node.key.level - config.coordinator_tree_height)) != realm_id
            {
                return Err(RealmImtMutationGraphError::GlobalNodeOutsideRealmSubtree);
            }
            Ok((RealmImtBaselineNodeKey::GlobalUser { level: node.key.level, index: node.key.index }, node.value))
        },
    )
}

fn parse_user_contract_nodes<Hash: Q256BitHash>(
    prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
    config: RealmImtMutationGraphConfig,
    realm_id: u64,
) -> Result<BTreeMap<RealmImtBaselineNodeKey, Hash>, RealmImtMutationGraphError> {
    parse_fixed_nodes(
        &prepared.update_user_contract_tree_nodes_ffs,
        QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
        RealmImtMutationGraphError::MalformedUserContractNodes,
        |chunk| {
            let node = QMerkleStoreSingleIdNode::<Hash>::ffs_try_from_slice(chunk)
                .map_err(|_| RealmImtMutationGraphError::MalformedUserContractNodes)?;
            validate_user(node.key.tree_id, realm_id, config)?;
            validate_position(node.key.level, node.key.index, config.user_contract_tree_height)?;
            Ok((RealmImtBaselineNodeKey::UserContract {
                user_id: node.key.tree_id, level: node.key.level, index: node.key.index,
            }, node.value))
        },
    )
}

fn parse_contract_state_nodes<Hash: Q256BitHash>(
    prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
    config: RealmImtMutationGraphConfig,
    realm_id: u64,
    heights: &BTreeMap<u64, u8>,
) -> Result<(MerkleNodeMap<Hash>, UsedContractHeightMap), RealmImtMutationGraphError> {
    let nodes = parse_fixed_nodes(
        &prepared.update_contract_state_tree_nodes_ffs,
        QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE,
        RealmImtMutationGraphError::MalformedContractStateNodes,
        |chunk| {
            let node = QMerkleStoreDoubleIdNode::<Hash>::ffs_try_from_slice(chunk)
                .map_err(|_| RealmImtMutationGraphError::MalformedContractStateNodes)?;
            validate_user(node.key.tree_id, realm_id, config)?;
            let height = require_contract_height(node.key.tree_sub_id, heights)?;
            validate_position(node.key.level, node.key.index, height)?;
            Ok((RealmImtBaselineNodeKey::ContractState {
                user_id: node.key.tree_id,
                contract_id: node.key.tree_sub_id,
                level: node.key.level,
                index: node.key.index,
            }, node.value))
        },
    )?;
    let mut used = BTreeMap::new();
    for key in nodes.keys() {
        if let RealmImtBaselineNodeKey::ContractState { user_id, contract_id, .. } = key {
            used.insert((*user_id, *contract_id), require_contract_height(*contract_id, heights)?);
        }
    }
    Ok((nodes, used))
}

fn parse_user_leaves<F: QFelt64, Hash: Q256BitHash>(
    prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
    config: RealmImtMutationGraphConfig,
    realm_id: u64,
) -> Result<BTreeMap<u64, PQEDUserLeaf<F, Hash>>, RealmImtMutationGraphError> {
    if prepared.update_user_leaves_ffs.is_empty()
        || !prepared.update_user_leaves_ffs.len().is_multiple_of(PSY_OBJECT_FFS_SIZE_USER_LEAF)
    {
        return Err(RealmImtMutationGraphError::MalformedUserLeaves);
    }
    let mut leaves = BTreeMap::new();
    for chunk in prepared.update_user_leaves_ffs.chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF) {
        let leaf = PQEDUserLeaf::<F, Hash>::ffs_try_from_slice(chunk)
            .map_err(|_| RealmImtMutationGraphError::MalformedUserLeaves)?;
        let user_id = leaf.user_id.to_u64_value();
        validate_user(user_id, realm_id, config)?;
        if leaves.insert(user_id, leaf).is_some() {
            return Err(RealmImtMutationGraphError::DuplicateUserLeaf(user_id));
        }
    }
    Ok(leaves)
}

fn parse_final_imt_leaves<F, Hash, Hasher>(
    prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
    config: RealmImtMutationGraphConfig,
    realm_id: u64,
    heights: &BTreeMap<u64, u8>,
) -> Result<FinalImtLeafMap<Hash>, RealmImtMutationGraphError>
where
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
{
    let bytes = &prepared.update_contract_state_imt_leaves_ffs;
    if bytes.is_empty() || !bytes.len().is_multiple_of(IMT_LEAF_FFS_ENTRY_SIZE_V2) {
        return Err(RealmImtMutationGraphError::MalformedImtLeaves);
    }
    let mut leaves = BTreeMap::new();
    for chunk in bytes.chunks_exact(IMT_LEAF_FFS_ENTRY_SIZE_V2) {
        if chunk[160] > 1 { return Err(RealmImtMutationGraphError::NonCanonicalImtNewKeyFlag(chunk[160])); }
        let (tree_id, contract_id, leaf_index, leaf_hash_bytes, key, value, next_key, next_index, _) =
            deserialize_imt_leaf_ffs_entry_v2(chunk).map_err(|_| RealmImtMutationGraphError::MalformedImtLeaves)?;
        validate_user(tree_id, realm_id, config)?;
        let height = require_contract_height(contract_id, heights)?;
        validate_position(height, leaf_index, height)?;
        let leaf_hash = Hash::from_owned_32bytes(leaf_hash_bytes);
        let preimage = IMTContractStateLeaf::<F, Hash> {
            key: Hash::from_owned_32bytes(key),
            value: Hash::from_owned_32bytes(value),
            next_key: Hash::from_owned_32bytes(next_key),
            next_index: F::from_u64_value(next_index),
        };
        if preimage.qfhash::<Hasher>() != leaf_hash {
            return Err(RealmImtMutationGraphError::ImtLeafHashMismatch { tree_id, contract_id, leaf_index });
        }
        leaves.entry((tree_id, contract_id, leaf_index)).or_insert(FinalImtLeaf { tree_id, contract_id, leaf_index, leaf_hash });
    }
    Ok(leaves)
}

#[allow(clippy::too_many_arguments)]
fn validate_graph_edges<F, Hash, Hasher>(
    prepared: &PsyPreparedRealmBlockStateUpdates<Hash>,
    config: RealmImtMutationGraphConfig,
    realm_id: u64,
    global: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    user_contract: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    contract_state: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    users: &BTreeMap<u64, PQEDUserLeaf<F, Hash>>,
    imt: &BTreeMap<(u64, u64, u64), FinalImtLeaf<Hash>>,
    contract_heights: &BTreeMap<(u64, u64), u8>,
) -> Result<(), RealmImtMutationGraphError>
where
    F: QFelt64,
    Hash: QFHashBase<F>,
    Hasher: FieldQHasher<F, Hash>,
{
    let global_root_key = RealmImtBaselineNodeKey::GlobalUser { level: config.coordinator_tree_height, index: realm_id };
    if global.get(&global_root_key) != Some(&prepared.new_realm_root) {
        return Err(RealmImtMutationGraphError::RealmRootMutationMismatch);
    }

    let user_ids = users.keys().copied().collect::<BTreeSet<_>>();
    let uct_users = user_contract.keys().filter_map(|key| match key {
        RealmImtBaselineNodeKey::UserContract { user_id, .. } => Some(*user_id), _ => None,
    }).collect::<BTreeSet<_>>();
    let cst_users = contract_heights.keys().map(|(user_id, _)| *user_id).collect::<BTreeSet<_>>();
    if user_ids != uct_users || user_ids != cst_users {
        return Err(RealmImtMutationGraphError::UserCoverageMismatch);
    }

    for leaf in imt.values() {
        let height = contract_heights[&(leaf.tree_id, leaf.contract_id)];
        let key = RealmImtBaselineNodeKey::ContractState {
            user_id: leaf.tree_id, contract_id: leaf.contract_id, level: height, index: leaf.leaf_index,
        };
        if contract_state.get(&key) != Some(&leaf.leaf_hash) {
            return Err(RealmImtMutationGraphError::ImtToContractStateMismatch {
                tree_id: leaf.tree_id, contract_id: leaf.contract_id, leaf_index: leaf.leaf_index,
            });
        }
    }
    for &(user_id, contract_id) in contract_heights.keys() {
        let cst_root = contract_state.get(&RealmImtBaselineNodeKey::ContractState {
            user_id, contract_id, level: 0, index: 0,
        }).ok_or(RealmImtMutationGraphError::ContractStateRootMissing { user_id, contract_id })?;
        let uct_leaf = user_contract.get(&RealmImtBaselineNodeKey::UserContract {
            user_id, level: config.user_contract_tree_height, index: contract_id,
        }).ok_or(RealmImtMutationGraphError::UserContractLeafMissing { user_id, contract_id })?;
        if cst_root != uct_leaf {
            return Err(RealmImtMutationGraphError::ContractStateToUserContractMismatch { user_id, contract_id });
        }
    }
    for (&user_id, leaf) in users {
        let uct_root = user_contract.get(&RealmImtBaselineNodeKey::UserContract { user_id, level: 0, index: 0 })
            .ok_or(RealmImtMutationGraphError::UserContractRootMissing(user_id))?;
        if uct_root != &leaf.user_state_tree_root {
            return Err(RealmImtMutationGraphError::UserContractToUserLeafMismatch(user_id));
        }
        let global_leaf = global.get(&RealmImtBaselineNodeKey::GlobalUser { level: config.global_user_tree_height, index: user_id })
            .ok_or(RealmImtMutationGraphError::GlobalUserLeafMissing(user_id))?;
        if global_leaf != &leaf.qfhash::<Hasher>() {
            return Err(RealmImtMutationGraphError::UserLeafToGlobalTreeMismatch(user_id));
        }
    }
    Ok(())
}

fn validate_path_closure<Hash>(
    global: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    user_contract: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    contract_state: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    config: RealmImtMutationGraphConfig,
) -> Result<(), RealmImtMutationGraphError> {
    for key in global.keys() {
        if let RealmImtBaselineNodeKey::GlobalUser { level, index } = *key {
            if level > config.coordinator_tree_height {
                let parent = RealmImtBaselineNodeKey::GlobalUser { level: level - 1, index: index >> 1 };
                if !global.contains_key(&parent) { return Err(RealmImtMutationGraphError::MutationPathNotClosed(*key)); }
            }
        }
    }
    for key in user_contract.keys() {
        if let RealmImtBaselineNodeKey::UserContract { user_id, level, index } = *key {
            if level > 0 {
                let parent = RealmImtBaselineNodeKey::UserContract { user_id, level: level - 1, index: index >> 1 };
                if !user_contract.contains_key(&parent) { return Err(RealmImtMutationGraphError::MutationPathNotClosed(*key)); }
            }
        }
    }
    for key in contract_state.keys() {
        if let RealmImtBaselineNodeKey::ContractState { user_id, contract_id, level, index } = *key {
            if level > 0 {
                let parent = RealmImtBaselineNodeKey::ContractState { user_id, contract_id, level: level - 1, index: index >> 1 };
                if !contract_state.contains_key(&parent) { return Err(RealmImtMutationGraphError::MutationPathNotClosed(*key)); }
            }
        }
    }
    Ok(())
}

fn build_baseline_requests<Hash>(
    realm_id: u64,
    config: RealmImtMutationGraphConfig,
    global: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    user_contract: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    contract_state: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    contract_heights: &BTreeMap<(u64, u64), u8>,
) -> Vec<RealmImtBaselineNodeKey> {
    let mut requests = BTreeSet::new();
    requests.insert(RealmImtBaselineNodeKey::GlobalUser { level: config.coordinator_tree_height, index: realm_id });
    add_missing_children(global, config.global_user_tree_height, &mut requests);
    add_missing_children(user_contract, config.user_contract_tree_height, &mut requests);
    for (&(user_id, contract_id), &height) in contract_heights {
        let tree = contract_state.iter()
            .filter(|(key, _)| matches!(key, RealmImtBaselineNodeKey::ContractState { user_id: u, contract_id: c, .. } if *u == user_id && *c == contract_id))
            .map(|(key, value)| (*key, value))
            .collect::<BTreeMap<_, _>>();
        add_missing_children(&tree, height, &mut requests);
    }
    requests.into_iter().collect()
}

fn add_missing_children<Hash>(
    nodes: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    height: u8,
    requests: &mut BTreeSet<RealmImtBaselineNodeKey>,
) {
    for key in nodes.keys().copied() {
        let level = key_level(key);
        if level >= height { continue; }
        for child in [left_child(key), right_child(key)] {
            if !nodes.contains_key(&child) { requests.insert(child); }
        }
    }
}

fn verify_tree<Hash: Q256BitHash, Hasher: MerkleHasher<Hash>>(
    nodes: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
    height: u8,
    baseline: &BTreeMap<RealmImtBaselineNodeKey, Hash>,
) -> Result<(), RealmImtMutationGraphError> {
    for (&key, &parent) in nodes {
        if key_level(key) >= height { continue; }
        let left_key = left_child(key);
        let right_key = right_child(key);
        let left = nodes.get(&left_key).or_else(|| baseline.get(&left_key))
            .ok_or(RealmImtMutationGraphError::BaselineCoverageMismatch { missing: Some(left_key), unexpected: None })?;
        let right = nodes.get(&right_key).or_else(|| baseline.get(&right_key))
            .ok_or(RealmImtMutationGraphError::BaselineCoverageMismatch { missing: Some(right_key), unexpected: None })?;
        if Hasher::two_to_one(left, right) != parent {
            return Err(RealmImtMutationGraphError::MerkleParentMismatch(key));
        }
    }
    Ok(())
}

fn parse_fixed_nodes<Hash, Parse>(
    bytes: &[u8],
    width: usize,
    malformed: RealmImtMutationGraphError,
    mut parse: Parse,
) -> Result<BTreeMap<RealmImtBaselineNodeKey, Hash>, RealmImtMutationGraphError>
where
    Hash: Copy,
    Parse: FnMut(&[u8]) -> Result<(RealmImtBaselineNodeKey, Hash), RealmImtMutationGraphError>,
{
    if bytes.is_empty() || !bytes.len().is_multiple_of(width) { return Err(malformed); }
    let mut nodes = BTreeMap::new();
    for chunk in bytes.chunks_exact(width) {
        let (key, value) = parse(chunk)?;
        if nodes.insert(key, value).is_some() { return Err(RealmImtMutationGraphError::DuplicateMerkleMutation(key)); }
    }
    Ok(nodes)
}

fn validate_user(
    user_id: u64,
    realm_id: u64,
    config: RealmImtMutationGraphConfig,
) -> Result<(), RealmImtMutationGraphError> {
    let realm_height = config.global_user_tree_height - config.coordinator_tree_height;
    if (user_id >> realm_height) != realm_id { return Err(RealmImtMutationGraphError::UserOutsideRealm { user_id, realm_id }); }
    Ok(())
}

fn validate_position(level: u8, index: u64, height: u8) -> Result<(), RealmImtMutationGraphError> {
    if level > height || index >= (1u64 << level) {
        return Err(RealmImtMutationGraphError::MerklePositionOutOfRange { level, index, height });
    }
    Ok(())
}

fn require_contract_height(contract_id: u64, heights: &BTreeMap<u64, u8>) -> Result<u8, RealmImtMutationGraphError> {
    let height = *heights.get(&contract_id).ok_or(RealmImtMutationGraphError::ContractHeightMissing(contract_id))?;
    if height == 0 || height >= 64 { return Err(RealmImtMutationGraphError::InvalidContractHeight { contract_id, height }); }
    Ok(height)
}

fn key_level(key: RealmImtBaselineNodeKey) -> u8 {
    match key {
        RealmImtBaselineNodeKey::GlobalUser { level, .. }
        | RealmImtBaselineNodeKey::UserContract { level, .. }
        | RealmImtBaselineNodeKey::ContractState { level, .. } => level,
    }
}

fn left_child(key: RealmImtBaselineNodeKey) -> RealmImtBaselineNodeKey {
    match key {
        RealmImtBaselineNodeKey::GlobalUser { level, index } => RealmImtBaselineNodeKey::GlobalUser { level: level + 1, index: index << 1 },
        RealmImtBaselineNodeKey::UserContract { user_id, level, index } => RealmImtBaselineNodeKey::UserContract { user_id, level: level + 1, index: index << 1 },
        RealmImtBaselineNodeKey::ContractState { user_id, contract_id, level, index } => RealmImtBaselineNodeKey::ContractState { user_id, contract_id, level: level + 1, index: index << 1 },
    }
}

fn right_child(key: RealmImtBaselineNodeKey) -> RealmImtBaselineNodeKey {
    let mut child = left_child(key);
    match &mut child {
        RealmImtBaselineNodeKey::GlobalUser { index, .. }
        | RealmImtBaselineNodeKey::UserContract { index, .. }
        | RealmImtBaselineNodeKey::ContractState { index, .. } => *index += 1,
    }
    child
}

fn encode_authority(authority: AuthorityScope, output: &mut Vec<u8>) {
    match authority {
        AuthorityScope::Coordinator => output.push(0),
        AuthorityScope::Realm { realm_id, realm_sub_id } => {
            output.push(1);
            output.extend_from_slice(&realm_id.to_le_bytes());
            output.extend_from_slice(&realm_sub_id.to_le_bytes());
        }
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmImtMutationGraphError {
    RealmAuthorityRequired,
    PreparedAuthorityMismatch,
    InvalidCheckpointOrder,
    ChangedRealmStateRequired,
    InvalidGlobalUserTreeHeight(u8),
    InvalidCoordinatorTreeHeight(u8),
    InvalidUserContractTreeHeight(u8),
    RealmIndexOutOfRange,
    MalformedGlobalNodes,
    MalformedUserContractNodes,
    MalformedContractStateNodes,
    MalformedUserLeaves,
    MalformedImtLeaves,
    NonCanonicalImtNewKeyFlag(u8),
    GlobalNodeOutsideRealmSubtree,
    UserOutsideRealm { user_id: u64, realm_id: u64 },
    MerklePositionOutOfRange { level: u8, index: u64, height: u8 },
    ContractHeightMissing(u64),
    InvalidContractHeight { contract_id: u64, height: u8 },
    DuplicateMerkleMutation(RealmImtBaselineNodeKey),
    DuplicateUserLeaf(u64),
    ImtLeafHashMismatch { tree_id: u64, contract_id: u64, leaf_index: u64 },
    RealmRootMutationMismatch,
    UserCoverageMismatch,
    ImtToContractStateMismatch { tree_id: u64, contract_id: u64, leaf_index: u64 },
    ContractStateRootMissing { user_id: u64, contract_id: u64 },
    UserContractLeafMissing { user_id: u64, contract_id: u64 },
    ContractStateToUserContractMismatch { user_id: u64, contract_id: u64 },
    UserContractRootMissing(u64),
    UserContractToUserLeafMismatch(u64),
    GlobalUserLeafMissing(u64),
    UserLeafToGlobalTreeMismatch(u64),
    MutationPathNotClosed(RealmImtBaselineNodeKey),
    DuplicateBaselineObservation(RealmImtBaselineNodeKey),
    BaselineCoverageMismatch { missing: Option<RealmImtBaselineNodeKey>, unexpected: Option<RealmImtBaselineNodeKey> },
    PredecessorRealmRootMismatch,
    MerkleParentMismatch(RealmImtBaselineNodeKey),
    PreparedSerializationFailed,
}

impl fmt::Display for RealmImtMutationGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}

impl Error for RealmImtMutationGraphError {}
