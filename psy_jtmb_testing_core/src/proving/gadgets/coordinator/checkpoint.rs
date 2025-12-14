use parth_core::{
    crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, tag_tree::hash_tag_tree_node_single, traits::QFieldHashable}, felt::FromPrimitiveValuesFelt
};
use psy_core::constants::protocol::DA_CHALLENGE_WINDOW;
use psy_data::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf};

use crate::{proving::{gadgets::merkle::{verify_delta_merkle_proof_append_only, verify_merkle_proof}, utils::connect::{jtmb_connect, jtmb_connect_ref}}, utils::jtmb_standard_circuit::JTMBCircuitConfig};

pub fn verify_checkpoint_transition_core<C: JTMBCircuitConfig>(
    append_proof: &DeltaMerkleProofCore<C::Hash>,
    previous_proof: &MerkleProofCore<C::Hash>,
    checkpoint_tree_height: usize,
) -> anyhow::Result<()> {
    // 1. Verify Append Proof is Append Only (Old value 0)
    // 2. Verify chain: append old root == previous root
    // 3. Verify index: append index == previous index + 1
    
    jtmb_connect_ref(&append_proof.old_root, &previous_proof.root, "checkpoint root chain mismatch")?;
    jtmb_connect(append_proof.index, previous_proof.index + 1, "checkpoint index chain mismatch")?;
    
    verify_merkle_proof::<C::Hash, C::F, C::Hasher>(
        previous_proof,
        previous_proof.root,
        previous_proof.value,
        previous_proof.index,
        checkpoint_tree_height,
    )?;

    verify_delta_merkle_proof_append_only::<C::Hash, C::F, C::Hasher>(
        append_proof,
        previous_proof.root,
        append_proof.new_root,
        append_proof.new_value,
        append_proof.index,
        checkpoint_tree_height,
    )?;

    Ok(())
}

pub fn construct_new_checkpoint_leaf<C: JTMBCircuitConfig>(
    _old_state_roots: &PQEDCheckpointGlobalStateRoots<C::Hash>,
    new_state_roots: &PQEDCheckpointGlobalStateRoots<C::Hash>,
    old_leaf: &PQEDCheckpointLeaf<C::F, C::Hash>,
    part_1_reward_root: C::Hash,
    worker_reward_tag: C::Hash,
    // Delta values
    fees_delta: C::F,
    ops_delta: C::F,
    txs_delta: C::F,
    slots_delta: C::F,
    pm_jobs_delta: psy_data::v1::qdata::pm_jobs_completed_stats::PPMJobsCompletedStats<C::F>,
    block_time: C::F,
    random_seed_contrib: C::Hash,
) -> PQEDCheckpointLeaf<C::F, C::Hash> {
    let rewards_root = hash_tag_tree_node_single::<C::Hash, C::Hasher>(&part_1_reward_root, &worker_reward_tag);
    let zero = C::F::from_u64_value(0);
    
    let new_stats = psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafStats {
        fees_collected: old_leaf.stats.fees_collected + fees_delta,
        user_ops_processed: old_leaf.stats.user_ops_processed + ops_delta,
        total_transactions: old_leaf.stats.total_transactions + txs_delta,
        slots_modified: old_leaf.stats.slots_modified + slots_delta,
        pm_jobs_completed: old_leaf.stats.pm_jobs_completed.combine(&pm_jobs_delta),
        block_time,
        random_seed: random_seed_contrib,
        pm_rewards_commitment: psy_data::v1::qdata::pm_rewards_commitment::PPMRewardCommitment {
            register_users_root: rewards_root,
            gutas_root: rewards_root,
            deploy_contracts_root: rewards_root,
        },
        da_challenges_claimed: [zero; DA_CHALLENGE_WINDOW], 
    };

    PQEDCheckpointLeaf {
        global_chain_root: new_state_roots.qfhash::<C::Hasher>(),
        stats: new_stats,
    }
}