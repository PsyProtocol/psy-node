use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::guta::header::GlobalUserTreeAggregatorHeader;

/// Computes the public inputs hash for a GUTA proof.
/// Corresponds to GlobalUserTreeAggregatorHeaderGadget::get_expected_public_inputs_hash
pub fn compute_guta_public_inputs_hash<F: QFelt64, Hash: Q256BitHash + QFHashBase<F>, Hasher: FieldQHasher<F, Hash>>(
    header: &GlobalUserTreeAggregatorHeader<F, Hash>,
    rewards_tree_value: Hash,
) -> Hash {
    // 1. Hash the header fields
    let header_hash = header.qfhash::<Hasher>();
    
    // 2. Hash(Header, Rewards)
    Hasher::two_to_one(&header_hash, &rewards_tree_value)
}

/// Computes public inputs when combining two children reward values.
/// Corresponds to GlobalUserTreeAggregatorHeaderGadget::get_public_inputs_hash_two_children
pub fn compute_guta_public_inputs_hash_two_children<F: QFelt64, Hash: Q256BitHash + QFHashBase<F>, Hasher: FieldQHasher<F, Hash>>(
    header: &GlobalUserTreeAggregatorHeader<F, Hash>,
    left_child_rewards: Hash,
    right_child_rewards: Hash,
    worker_reward_tag: Hash,
) -> Hash {
    // 1. Combine Children Rewards
    let children_combined = Hasher::two_to_one(&left_child_rewards, &right_child_rewards);
    // 2. Combine with Tag
    let final_rewards = Hasher::two_to_one(&children_combined, &worker_reward_tag);
    
    compute_guta_public_inputs_hash::<F, Hash, Hasher>(header, final_rewards)
}