use parth_core::{
    crypto::hash::merkle_proof::DeltaMerkleProofCore,
    felt::{FromPrimitiveValuesFelt, ToU64Value},
    utils::math::log2_ceil,
};
use psy_data::guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition};
use crate::{proving::utils::connect::{jtmb_connect, jtmb_connect_ref}, utils::jtmb_standard_circuit::JTMBCircuitConfig};

/// Replicates DualVariableHeightStateTransitionGadget constraints
pub fn verify_dual_variable_height_state_transition<C: JTMBCircuitConfig>(
    a_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
    b_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
    child_a_proof: &DeltaMerkleProofCore<C::Hash>,
    child_b_proof: &DeltaMerkleProofCore<C::Hash>,
    max_merkle_proof_height: usize,
    tree_height: usize,
) -> anyhow::Result<GlobalUserTreeAggregatorHeader<C::F, C::Hash>> {

    // 1. Context Matching
    jtmb_connect_ref(&a_header.checkpoint_tree_root, &b_header.checkpoint_tree_root, "checkpoint root mismatch")?;
    jtmb_connect_ref(&a_header.guta_circuit_whitelist, &b_header.guta_circuit_whitelist, "whitelist mismatch")?;
    jtmb_connect(a_header.state_transition.node_level, b_header.state_transition.node_level, "node level mismatch")?;

    // 2. Validate Delta Proofs
    let proof_height = child_a_proof.siblings.len();
    jtmb_connect(proof_height, child_b_proof.siblings.len(), "delta proofs must have same height")?;
    
    if proof_height > max_merkle_proof_height {
        anyhow::bail!("proof height exceeds max");
    }

    if !child_a_proof.verify::<C::Hasher>() {
        anyhow::bail!("child A delta proof invalid");
    }
    if !child_b_proof.verify::<C::Hasher>() {
        anyhow::bail!("child B delta proof invalid");
    }

    // 3. Connect Proofs to Headers
    jtmb_connect_ref(&child_a_proof.old_value, &a_header.state_transition.old_node_value, "child A old value mismatch")?;
    jtmb_connect_ref(&child_a_proof.new_value, &a_header.state_transition.new_node_value, "child A new value mismatch")?;
    jtmb_connect_ref(&child_b_proof.old_value, &b_header.state_transition.old_node_value, "child B old value mismatch")?;
    jtmb_connect_ref(&child_b_proof.new_value, &b_header.state_transition.new_node_value, "child B new value mismatch")?;

    // 4. Validate Indices relative to Header Index (Parent Index)
    let parent_index_a = child_a_proof.index >> proof_height;
    let parent_index_b = child_b_proof.index >> proof_height;
    
    jtmb_connect(parent_index_a, parent_index_b, "proofs do not share common parent index")?;
    jtmb_connect(C::F::from_u64_value(parent_index_a), a_header.state_transition.node_index, "header index mismatch")?;

    // 5. Chain Connectivity
    jtmb_connect_ref(&child_a_proof.new_root, &child_b_proof.old_root, "chain broken: A.new_root != B.old_root")?;

    // 6. Compute New Header
    let current_level = a_header.state_transition.node_level.to_u64_value();
    if current_level < proof_height as u64 {
        anyhow::bail!("node level underflow");
    }
    let new_level_val = current_level - proof_height as u64;
    
    if new_level_val > log2_ceil(tree_height) as u64 {
        anyhow::bail!("new level exceeds tree height");
    }

    let mut new_stats = a_header.stats.clone();
    new_stats.add_from_mut(&b_header.stats);
    let one = C::F::from_u64_value(1);

    Ok(GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: a_header.guta_circuit_whitelist,
        checkpoint_tree_root: a_header.checkpoint_tree_root,
        state_transition: SubTreeNodeStateTransition {
            old_node_value: child_a_proof.old_root,
            new_node_value: child_b_proof.new_root,
            node_index: C::F::from_u64_value(parent_index_a),
            node_level: C::F::from_u64_value(new_level_val),
        },
        stats: new_stats,
        total_aggregation_proofs_generated: a_header.total_aggregation_proofs_generated + b_header.total_aggregation_proofs_generated + one,
    })
}