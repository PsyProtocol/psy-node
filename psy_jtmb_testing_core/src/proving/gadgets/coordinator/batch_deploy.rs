use parth_core::{
    crypto::hash::{spiderman::SpidermanUpdateProof, traits::{FieldQHasher, QFieldHashable}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}
};
use psy_data::v1::qdata::contract::PQEDContractLeaf;
use crate::proving::{gadgets::coordinator::spiderman::verify_spiderman_append_proof, utils::connect::jtmb_connect_ref};

// Batch deploy logic connects spiderman new leaves to contract leaf hashes if added
pub fn verify_batch_deploy<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: FieldQHasher<F, Hash>>(
    spiderman_proof: &SpidermanUpdateProof<Hash>,
    contract_leaves: &[PQEDContractLeaf<F, Hash>],
    contract_tree_height: usize,
    batch_sub_tree_height: usize,
) -> anyhow::Result<()> {
    let top_line_height = contract_tree_height - batch_sub_tree_height;
    verify_spiderman_append_proof::<Hash, F, Hasher>(spiderman_proof, top_line_height, batch_sub_tree_height)?;

    let zero = Hash::get_zero_value();
    
    if contract_leaves.len() > spiderman_proof.web_proof_new_leaves.len() {
        anyhow::bail!("too many contract leaves for batch size");
    }

    for (i, (old, new)) in spiderman_proof.web_proof_old_leaves.iter().zip(spiderman_proof.web_proof_new_leaves.iter()).enumerate() {
        let is_added = *old == zero && *new != zero;
        
        if is_added {
            if i >= contract_leaves.len() {
                anyhow::bail!("missing contract leaf input for added index {}", i);
            }
            let leaf_hash = contract_leaves[i].qfhash::<Hasher>();
            jtmb_connect_ref(&leaf_hash, new, "contract leaf hash mismatch")?;
        }
    }

    Ok(())
}
