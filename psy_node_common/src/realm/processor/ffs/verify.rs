//! Read-only history verification and baseline FFS replay.

use std::collections::HashMap;

use anyhow::Context;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher},
    data::hash::fast_node_serializer::{
        QMerkleStoreFastDoubleNodeSerializer, QMerkleStoreFastSingleNodeSerializer,
        QMS_FAST_SERIALIZER_DOUBLE_ID_NODE_SIZE, QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE,
    },
    felt::ToU64Value,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    p2p::{Proposal, RealmTransition},
    prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate},
    v1::qdata::{
        contract::{deserialize_imt_leaf_ffs_entry_v2, IMT_LEAF_FFS_ENTRY_SIZE_V2},
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
    realm::processor::{
        consensus::{
            decode_proposal_state_updates, require_declared_roots_match_zk_output,
            validator_tree_root_matches_proof_base, verify_proposal_submission,
        },
        db::PsyRealmDatabaseProcessor,
        proposal_backup::{ProposalBackup, StagedProposal},
    },
};

use super::{
    decode_double_id_node_ffs, double_id_leaves_at_level, history_error, load_previous_contract_heights,
    missing_local_state, replay_double_id_nodes_from_leaves, replay_state_updates_into_tree,
    require_previous_contract_height, seed_tree_from_merkle_proof, CheckpointIdentity, RecoveryError,
    VerifiedHistoryCandidate,
};

const ZERO_SENTINEL_KEY: [u8; 32] = [0u8; 32];
const UNWRITTEN_CST_LEAF: [u8; 32] = [0u8; 32];

fn is_empty_imt_zero_key_sentinel(
    has_previous_imt_preimage: bool,
    previous_cst_leaf: [u8; 32],
    key: [u8; 32],
) -> bool {
    !has_previous_imt_preimage && previous_cst_leaf == UNWRITTEN_CST_LEAF && key == ZERO_SENTINEL_KEY
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
        let changed_leaves_on_imt_indexed_trees = crate::realm::processor::db::load_changed_leaves_on_imt_indexed_trees::<S, N::F, N::QHash>(self.db.as_ref(), previous_checkpoint_id, updates)
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
            &changed_leaves_on_imt_indexed_trees,
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
            } else if let Some(old_index) = old_index {
                anyhow::ensure!(
                    old_index == *leaf_index,
                    "InvalidStateUpdates: IMT key index moved user={tree_id} contract={tree_sub_id}"
                );
            } else {
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
                let previous_cst = self
                    .db
                    .contract_state_tree_get_leaf_hash(
                        previous_checkpoint_id,
                        *tree_id,
                        *tree_sub_id,
                        height,
                        *leaf_index,
                    )
                    .await
                    .map_err(|error| anyhow::anyhow!("MissingAuthenticatedState: IMT previous contract-state leaf user={tree_id} contract={tree_sub_id} index={leaf_index}: {error}"))?;
                anyhow::ensure!(
                    is_empty_imt_zero_key_sentinel(
                        previous_at_index.is_some(),
                        previous_cst.into_owned_32bytes(),
                        *leaf_key,
                    ),
                    "InvalidStateUpdates: IMT key is not new but has no authenticated index user={tree_id} contract={tree_sub_id} index={leaf_index}"
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
                == included.checkpoint_leaf_hash,
            "MissingHistoryProof at C={}: coordinator leaf hash does not match included.checkpoint_leaf_hash",
            included.checkpoint_id
        );
        let authenticated_leaf = self
            .checkpoint_tree_backup_manager
            .checkpoint_tree
            .get_leaf(included.checkpoint_id);
        if authenticated_leaf.value.into_owned_32bytes() != included.checkpoint_leaf_hash {
            return Err(missing_local_state(
                included.checkpoint_id,
                "included.checkpoint_leaf_hash does not match the authenticated checkpoint tree leaf",
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
        let previous = included.checkpoint_id
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

    pub async fn verify_history_transition(
        &self,
        included: &CheckpointIdentity,
        transition: RealmTransition,
        staged: Option<&StagedProposal>,
        proposal_backup: &ProposalBackup,
    ) -> anyhow::Result<Option<VerifiedHistoryCandidate<N::F, N::QHash>>> {
        let loaded = match staged {
            Some(staged) => Some(proposal_backup.read_staged(staged).await?),
            None => proposal_backup
                .load_proposal(&transition.old_root, &transition.new_root)
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
                    "history verify rejected C={} transition=({},{}) proposal={} error={error:#}",
                    included.checkpoint_id,
                    hex::encode(transition.old_root),
                    hex::encode(transition.new_root),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_imt_zero_key_sentinel_only_when_all_three_hold() {
        assert!(is_empty_imt_zero_key_sentinel(false, UNWRITTEN_CST_LEAF, ZERO_SENTINEL_KEY));
        assert!(!is_empty_imt_zero_key_sentinel(true, UNWRITTEN_CST_LEAF, ZERO_SENTINEL_KEY));
        let mut key = ZERO_SENTINEL_KEY;
        key[0] = 1;
        assert!(!is_empty_imt_zero_key_sentinel(false, UNWRITTEN_CST_LEAF, key));
        let mut cst = UNWRITTEN_CST_LEAF;
        cst[0] = 1;
        assert!(!is_empty_imt_zero_key_sentinel(false, cst, ZERO_SENTINEL_KEY));
    }
}
