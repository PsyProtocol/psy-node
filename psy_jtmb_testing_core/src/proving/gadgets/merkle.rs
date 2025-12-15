use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{MerkleHasher, MerkleZeroHasher},
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use crate::proving::utils::connect::{jtmb_connect, jtmb_connect_ref};

/// Replicates MerkleProofGadget constraints
pub fn verify_merkle_proof<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: MerkleHasher<Hash>>(
    proof: &MerkleProofCore<Hash>,
    expected_root: Hash,
    expected_value: Hash,
    expected_index: u64,
    height: usize,
) -> anyhow::Result<()> {
    // Constraint: Height matches config
    jtmb_connect(proof.siblings.len(), height, "merkle proof height mismatch")?;
    
    // Constraint: Input root matches computed proof root (implicitly checked by verify(), but explicit connect in circuit)
    jtmb_connect_ref(&proof.root, &expected_root, "merkle proof root mismatch")?;
    
    // Constraint: Input value matches proof value
    jtmb_connect_ref(&proof.value, &expected_value, "merkle proof value mismatch")?;
    
    // Constraint: Input index matches proof index
    jtmb_connect(proof.index, expected_index, "merkle proof index mismatch")?;

    // Constraint: The cryptographic hash path is valid
    if !proof.verify::<Hasher>() {
        anyhow::bail!("merkle proof verification failed");
    }
    Ok(())
}

/// Replicates DeltaMerkleProofGadget constraints
pub fn verify_delta_merkle_proof<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: MerkleHasher<Hash>>(
    proof: &DeltaMerkleProofCore<Hash>,
    expected_old_root: Hash,
    expected_new_root: Hash,
    expected_old_value: Hash,
    expected_new_value: Hash,
    expected_index: u64,
    height: usize,
) -> anyhow::Result<()> {
    jtmb_connect(proof.siblings.len(), height, "delta merkle proof height mismatch")?;
    
    jtmb_connect_ref(&proof.old_root, &expected_old_root, "delta old root mismatch")?;
    jtmb_connect_ref(&proof.new_root, &expected_new_root, "delta new root mismatch")?;
    jtmb_connect_ref(&proof.old_value, &expected_old_value, "delta old value mismatch")?;
    jtmb_connect_ref(&proof.new_value, &expected_new_value, "delta new value mismatch")?;
    jtmb_connect(proof.index, expected_index, "delta index mismatch")?;

    if !proof.verify::<Hasher>() {
        anyhow::bail!("delta merkle proof verification failed");
    }
    Ok(())
}

/// Replicates DeltaMerkleProofGadget::add_virtual_to_append_only constraints
pub fn verify_delta_merkle_proof_append_only<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: MerkleZeroHasher<Hash>>(
    proof: &DeltaMerkleProofCore<Hash>,
    expected_old_root: Hash,
    expected_new_root: Hash,
    expected_new_value: Hash,
    expected_index: u64,
    height: usize,
) -> anyhow::Result<()> {
    let zero_hash = Hash::get_zero_value();
    
    // Constraint: Old value must be zero for append-only
    jtmb_connect_ref(&proof.old_value, &zero_hash, "append only: old value must be zero")?;

    // Constraint: Strict Append Logic. 
    // If the path goes Left (bit=0), the Right Sibling must be empty (Zero Hash).
    for (i, sibling) in proof.siblings.iter().enumerate() {
        let bit = (proof.index >> i) & 1;
        if bit == 0 {
            let expected_zero_sibling = Hasher::get_zero_hash(i);
            jtmb_connect_ref(sibling, &expected_zero_sibling, &format!("append only: non-zero right sibling at level {}", i))?;
        }
    }

    verify_delta_merkle_proof::<Hash, F, Hasher>(
        proof,
        expected_old_root,
        expected_new_root,
        zero_hash,
        expected_new_value,
        expected_index,
        height,
    )
}