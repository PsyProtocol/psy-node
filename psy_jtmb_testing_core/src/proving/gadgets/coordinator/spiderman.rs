use parth_core::{
    crypto::hash::{spiderman::SpidermanUpdateProof, traits::{MerkleLeafHasher, MerkleZeroHasher}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}
};
use crate::proving::utils::connect::jtmb_connect_ref;

// Structural checks shared by append and update: top line proof, heights, and
// web-root-to-top-line connection. No leaf-transition semantics.
pub fn verify_spiderman_structure<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: MerkleZeroHasher<Hash>>(
    proof: &SpidermanUpdateProof<Hash>,
    top_line_height: usize,
    web_tree_height: usize,
) -> anyhow::Result<()> {
    if !proof.top_line_proof.verify::<Hasher>() {
        anyhow::bail!("spiderman top line proof verification failed");
    }
    if proof.top_line_proof.siblings.len() != top_line_height {
        anyhow::bail!("spiderman top line height mismatch");
    }
    if !proof.verify::<Hasher>() {
        anyhow::bail!("spiderman web proof verification failed");
    }

    let expected_leaves_count = 1 << web_tree_height;
    if proof.web_proof_new_leaves.len() != expected_leaves_count {
        anyhow::bail!("spiderman web proof new leaves count mismatch: expected {}, got {}", expected_leaves_count, proof.web_proof_new_leaves.len());
    }
    if proof.web_proof_old_leaves.len() != expected_leaves_count {
        anyhow::bail!("spiderman web proof old leaves count mismatch: expected {}, got {}", expected_leaves_count, proof.web_proof_old_leaves.len());
    }

    let computed_old_web_root = Hasher::compute_root_from_leaves(&proof.web_proof_old_leaves)?;
    let computed_new_web_root = Hasher::compute_root_from_leaves(&proof.web_proof_new_leaves)?;

    jtmb_connect_ref(&computed_old_web_root, &proof.top_line_proof.old_value, "spiderman old web root mismatch")?;
    jtmb_connect_ref(&computed_new_web_root, &proof.top_line_proof.new_value, "spiderman new web root mismatch")?;

    Ok(())
}

// Update allows in-place replacement of non-zero leaves, so only the
// structure is enforced; leaf-transition semantics are checked by the caller.
pub fn verify_spiderman_update_proof<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: MerkleZeroHasher<Hash>>(
    proof: &SpidermanUpdateProof<Hash>,
    top_line_height: usize,
    web_tree_height: usize,
) -> anyhow::Result<()> {
    verify_spiderman_structure::<Hash, F, Hasher>(proof, top_line_height, web_tree_height)
}

pub fn verify_spiderman_append_proof<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: MerkleZeroHasher<Hash>>(
    proof: &SpidermanUpdateProof<Hash>,
    top_line_height: usize,
    web_tree_height: usize,
) -> anyhow::Result<()> {
    
    // 1. Verify Top Line Proof
    if !proof.top_line_proof.verify::<Hasher>() {
        anyhow::bail!("spiderman top line proof verification failed");
    }
    if proof.top_line_proof.siblings.len() != top_line_height {
        anyhow::bail!("spiderman top line height mismatch");
    }
    if !proof.verify::<Hasher>() {
        anyhow::bail!("spiderman web proof verification failed");
    }

    // 2. Verify Web Proof Heights
    let expected_leaves_count = 1 << web_tree_height;
    if proof.web_proof_new_leaves.len() != expected_leaves_count {
        anyhow::bail!("spiderman web proof new leaves count mismatch: expected {}, got {}", expected_leaves_count, proof.web_proof_new_leaves.len());
    }
    if proof.web_proof_old_leaves.len() != expected_leaves_count {
        anyhow::bail!("spiderman web proof old leaves count mismatch: expected {}, got {}", expected_leaves_count, proof.web_proof_old_leaves.len());
    }

    // 3. Verify Web Proof Roots
    let computed_old_web_root = Hasher::compute_root_from_leaves(&proof.web_proof_old_leaves)?;
    let computed_new_web_root = Hasher::compute_root_from_leaves(&proof.web_proof_new_leaves)?;

    // 4. Connect Web to Top Line
    jtmb_connect_ref(&computed_old_web_root, &proof.top_line_proof.old_value, "spiderman old web root mismatch")?;
    jtmb_connect_ref(&computed_new_web_root, &proof.top_line_proof.new_value, "spiderman new web root mismatch")?;

    // 5. Verify Append Logic (Zero checks & Contiguous)
    let zero = Hash::get_zero_value();
    let mut encountered_end_of_data = false;

    for (i, (old, new)) in proof.web_proof_old_leaves.iter().zip(proof.web_proof_new_leaves.iter()).enumerate() {
        // If old leaf is non-zero, it must not change (no overwrite)
        if *old != zero {
            jtmb_connect_ref(old, new, "spiderman overwrite detected on non-zero leaf")?;
        }

        // Logic for contiguous append:
        // A "slot" is considered used if new != zero.
        // If old==0 and new==0, this slot is empty/unused.
        let is_empty_slot = *old == zero && *new == zero;
        
        if encountered_end_of_data {
            if !is_empty_slot {
                anyhow::bail!("spiderman non-contiguous append detected at index {}", i);
            }
        }

        if is_empty_slot {
            encountered_end_of_data = true;
        }
    }

    Ok(())
}