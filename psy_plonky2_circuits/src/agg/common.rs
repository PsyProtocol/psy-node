
use plonky2::{
    field::extension::Extendable,
    hash::
        hash_types::{HashOut, HashOutTarget, RichField}
    ,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::AlgebraicHasher,
    },
};
use psy_plonky2_basic_helpers::builder::hash::core::CircuitBuilderHashCore;


pub fn compute_agg_state_trackable_final_public_inputs<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    allowed_circuit_hashes_root: HashOutTarget,
    state_transition_hash: HashOutTarget,
    tag_tree_value: HashOutTarget,
    total_proofs_generated: Target,
) -> HashOutTarget {
    let allowed_and_state_transition_hash = builder.hash_two_to_one::<H>(
        allowed_circuit_hashes_root,
        state_transition_hash,
    );
    let public_inputs_without_reward_tag = builder.hash_n_to_hash_no_pad::<H>(
        vec![
            allowed_and_state_transition_hash.elements[0],
            allowed_and_state_transition_hash.elements[1],
            allowed_and_state_transition_hash.elements[2],
            allowed_and_state_transition_hash.elements[3],
            total_proofs_generated,
        ]
    );
    builder.hash_two_to_one::<H>(public_inputs_without_reward_tag, tag_tree_value)
}



pub fn compute_agg_state_trackable_final_public_inputs_leaf<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    allowed_circuit_hashes_root: HashOutTarget,
    state_transition_hash: HashOutTarget,
    worker_reward_tag: HashOutTarget,
) -> HashOutTarget {


    let total_proofs_generated = builder.one();


    let zero_hash = builder.constant_hash(HashOut::ZERO);

    let rewards_tree_value_combo = builder.hash_two_to_one::<H>(
        zero_hash,
        zero_hash,
    );
    let rewards_tree_final_new_value = builder.hash_two_to_one::<H>(
        rewards_tree_value_combo,
        worker_reward_tag,
    );
    
    let allowed_and_state_transition_hash = builder.hash_two_to_one::<H>(
        allowed_circuit_hashes_root,
        state_transition_hash,
    );
    let public_inputs_without_reward_tag = builder.hash_n_to_hash_no_pad::<H>(
        vec![
            allowed_and_state_transition_hash.elements[0],
            allowed_and_state_transition_hash.elements[1],
            allowed_and_state_transition_hash.elements[2],
            allowed_and_state_transition_hash.elements[3],
            total_proofs_generated,
        ]
    );
    builder.hash_two_to_one::<H>(public_inputs_without_reward_tag, rewards_tree_final_new_value)
}