use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_plonky2_basic_helpers::builder::hash::core::CircuitBuilderHashCore;

pub fn hash_tag_tree_node_circuit<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left_child_proof_tag_tree_value: HashOutTarget,
    right_child_proof_tag_tree_value: HashOutTarget,
    worker_rewards_tree_tag: HashOutTarget,
) -> HashOutTarget {
    let left_right_children_tag_tree_value_hash = builder.hash_two_to_one::<H>(
        left_child_proof_tag_tree_value,
        right_child_proof_tag_tree_value,
    );
    builder.hash_two_to_one::<H>(left_right_children_tag_tree_value_hash, worker_rewards_tree_tag)
}

pub fn hash_tag_tree_node_single_circuit<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left_child_proof_tag_tree_value: HashOutTarget,
    worker_rewards_tree_tag: HashOutTarget,
) -> HashOutTarget {
    let zero = builder.zero();
    let right_child_proof_tag_tree_value = HashOutTarget { elements: [
        zero,
        zero,
        zero,
        zero,
    ] };
    let left_right_children_tag_tree_value_hash = builder.hash_two_to_one::<H>(
        left_child_proof_tag_tree_value,
        right_child_proof_tag_tree_value,
    );
    builder.hash_two_to_one::<H>(left_right_children_tag_tree_value_hash, worker_rewards_tree_tag)
}

pub fn hash_tag_tree_node_three_circuit<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    first_child_proof_tag_tree_value: HashOutTarget,
    second_child_proof_tag_tree_value: HashOutTarget,
    third_child_proof_tag_tree_value: HashOutTarget,
    worker_rewards_tree_tag: HashOutTarget,
) -> HashOutTarget {
    let first_value = hash_tag_tree_node_circuit::<H, F, D>(
        builder,
        first_child_proof_tag_tree_value,
        second_child_proof_tag_tree_value,
        worker_rewards_tree_tag,
    );
    hash_tag_tree_node_circuit::<H, F, D>(
        builder,
        first_value,
        third_child_proof_tag_tree_value,
        worker_rewards_tree_tag,
    )
}