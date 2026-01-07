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
    new_state_roots: &PQEDCheckpointGlobalStateRoots<C::Hash>,
    part_1_reward_root: C::Hash,
    worker_reward_tag: C::Hash,
    // These parameters represent the total stats for the current block, not deltas.
    guta_fees_for_block: C::F,
    da_fees_for_block: C::F,
    ops_for_block: C::F,
    txs_for_block: C::F,
    slots_for_block: C::F,
    pm_jobs_for_block: psy_data::v1::qdata::pm_jobs_completed_stats::PPMJobsCompletedStats<C::F>,
    block_time: C::F,
    random_seed_contrib: C::Hash,
) -> PQEDCheckpointLeaf<C::F, C::Hash> {
    let rewards_root = hash_tag_tree_node_single::<C::Hash, C::Hasher>(&part_1_reward_root, &worker_reward_tag);
    let zero = C::F::from_u64_value(0);
    
    // FIX: The circuit logic does not accumulate stats from the previous block.
    // It directly assigns the totals for the current block.
    // To match the circuit, we must do the same here.
    let new_stats = psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafStats {
        guta_fees_collected: guta_fees_for_block,
        da_fees_collected: da_fees_for_block,
        user_ops_processed: ops_for_block,
        total_transactions: txs_for_block,
        slots_modified: slots_for_block,
        pm_jobs_completed: pm_jobs_for_block, // This is also a direct assignment, not a combination.
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