use parth_core::crypto::hash::{
    merkle_proof::{compute_historical_and_current_merkle_roots_core_gt, MerkleProofCore},
    traits::MerkleZeroHasher,
};
use crate::utils::jtmb_standard_circuit::JTMBCircuitConfig;

// Corresponds to HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt
pub fn verify_historical_root_proof_gt<C: JTMBCircuitConfig>(
    proof: &MerkleProofCore<C::Hash>,
) -> anyhow::Result<(C::Hash, C::Hash)> 
where C::Hasher: MerkleZeroHasher<C::Hash>
{
    Ok(compute_historical_and_current_merkle_roots_core_gt::<C::Hash, C::Hasher>(proof))
}