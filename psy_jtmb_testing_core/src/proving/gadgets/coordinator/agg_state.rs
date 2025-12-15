use parth_core::{
    protocol::core_types::{Q256BitHash, QFHashBase},
    felt::QFelt64,
    crypto::hash::traits::FieldQHasher,
};
use psy_data::agg::AggStateTransition;

pub fn verify_agg_state_transition<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: FieldQHasher<F, Hash>>(
    left: &AggStateTransition<Hash>,
    right: &AggStateTransition<Hash>,
) -> anyhow::Result<AggStateTransition<Hash>> {
    // End of left must equal start of right
    if left.state_transition_end != right.state_transition_start {
        anyhow::bail!("agg state transition mismatch: left end != right start");
    }
    
    Ok(AggStateTransition {
        state_transition_start: left.state_transition_start,
        state_transition_end: right.state_transition_end,
    })
}

pub fn compute_agg_public_inputs<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: FieldQHasher<F, Hash>>(
    allowed_circuit_hashes_root: Hash,
    state_transition: &AggStateTransition<Hash>,
    total_proofs: F,
    rewards_tree_value: Hash,
) -> Hash {
    let trans_hash = state_transition.get_combined_hash::<Hasher>();
    
    let allowed_and_state = Hasher::two_to_one(&allowed_circuit_hashes_root, &trans_hash).to_4_felts();
    
    let pi_no_rewards = Hasher::q_hash_many(&[
        allowed_and_state[0],
        allowed_and_state[1],
        allowed_and_state[2],
        allowed_and_state[3],
        total_proofs,
    ]);
    
    Hasher::two_to_one(&pi_no_rewards, &rewards_tree_value)
}