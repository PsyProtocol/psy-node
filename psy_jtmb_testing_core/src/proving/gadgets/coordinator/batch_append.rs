use parth_core::{
    crypto::hash::{spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher},
    protocol::core_types::{Q256BitHash, QFHashBase},
    felt::QFelt64,
};
use crate::proving::{gadgets::coordinator::spiderman::verify_spiderman_append_proof, utils::connect::jtmb_connect_ref};

pub struct BatchAppendResult<Hash> {
    pub old_root: Hash,
    pub new_root: Hash,
}

pub fn verify_batch_append<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: MerkleZeroHasher<Hash>>(
    proofs: &[SpidermanUpdateProof<Hash>],
    user_registration_tree_height: usize,
    batch_sub_tree_height: usize,
    max_sub_trees: usize,
) -> anyhow::Result<BatchAppendResult<Hash>> {
    let top_line_height = user_registration_tree_height - batch_sub_tree_height;
    
    if proofs.len() == 0 || proofs.len() > max_sub_trees {
        anyhow::bail!("invalid number of batch append proofs");
    }

    // Verify first proof
    verify_spiderman_append_proof::<Hash, F, Hasher>(&proofs[0], top_line_height, batch_sub_tree_height)?;
    let old_root = proofs[0].top_line_proof.old_root;
    let mut current_root = proofs[0].top_line_proof.new_root;

    // Verify chain
    for i in 1..proofs.len() {
        verify_spiderman_append_proof::<Hash, F, Hasher>(&proofs[i], top_line_height, batch_sub_tree_height)?;
        jtmb_connect_ref(&current_root, &proofs[i].top_line_proof.old_root, "batch append chain broken")?;
        current_root = proofs[i].top_line_proof.new_root;
    }

    Ok(BatchAppendResult {
        old_root,
        new_root: current_root,
    })
}