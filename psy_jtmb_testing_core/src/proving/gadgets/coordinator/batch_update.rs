use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}
};
use psy_data::protocol::circuit_inputs::update_contracts::QCBatchUpdateContractsCircuitInput;
use crate::proving::gadgets::coordinator::spiderman::verify_spiderman_update_proof;

// Batch update logic connects spiderman replaced leaves to old/new contract leaf hashes.
pub fn verify_batch_update<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: FieldQHasher<F, Hash> + MerkleZeroHasher<Hash>>(
    input: &QCBatchUpdateContractsCircuitInput<F, Hash>,
    contract_tree_height: usize,
    batch_sub_tree_height: usize,
) -> anyhow::Result<()> {
    let top_line_height = contract_tree_height.checked_sub(batch_sub_tree_height)
        .ok_or_else(|| anyhow::anyhow!("contract batch subtree exceeds contract tree height"))?;
    anyhow::ensure!(contract_tree_height < 64, "contract tree height must be below 64");
    let spiderman_proof = &input.spiderman_update_proof;
    verify_spiderman_update_proof::<Hash, F, Hasher>(spiderman_proof, top_line_height, batch_sub_tree_height)?;
    anyhow::ensure!(spiderman_proof.top_line_proof.index < (1u64 << top_line_height), "contract update window out of range");
    // Shared validation binds every changed position to its global contract ID
    // and leaf preimages, and rejects missing or extra declared changes.
    input.validate::<Hasher>()
}
