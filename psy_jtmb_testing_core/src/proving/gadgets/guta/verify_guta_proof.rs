use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{MerkleHasher, QFieldHashable},
    },
};
use psy_data::guta::header::GlobalUserTreeAggregatorHeader;

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::utils::connect::{jtmb_connect, jtmb_connect_ref},
    utils::jtmb_standard_circuit::JTMBCircuitConfig,
};

/// Replicates VerifyGUTAProofGadget logic
pub fn verify_guta_proof<C: JTMBCircuitConfig>(
    known_guta_whitelist_height: u8,
    guta_whitelist_merkle_proof: &MerkleProofCore<C::Hash>,
    guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
    child_proof: &PsyTestJTMBProof<C::Hash>,
    child_verifier_data: &PsyTestJTMBProofVerifierData,
    child_rewards_tree_value: C::Hash,
) -> anyhow::Result<()> {
    
    // Constraint: Whitelist Merkle Proof Height
    jtmb_connect(
        guta_whitelist_merkle_proof.siblings.len(),
        known_guta_whitelist_height as usize,
        "guta whitelist proof height mismatch",
    )?;

    // Constraint: Header's whitelist root must match the proof's root
    jtmb_connect_ref(
        &guta_proof_header.guta_circuit_whitelist,
        &guta_whitelist_merkle_proof.root,
        "guta header whitelist root mismatch",
    )?;

    // Constraint: Whitelist proof must be valid
    if !guta_whitelist_merkle_proof.verify::<C::Hasher>() {
        anyhow::bail!("guta whitelist merkle proof verification failed");
    }

    // Constraint: The leaf of the whitelist proof must match the Child Proof's Circuit Fingerprint
    let calculated_fingerprint = child_verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
    jtmb_connect_ref(
        &calculated_fingerprint,
        &guta_whitelist_merkle_proof.value,
        "child proof fingerprint not found in whitelist",
    )?;

    //println!("input guta header: {:#?}", guta_proof_header);
    //println!("input child rewards tree value: {:?}", child_rewards_tree_value);

    // Constraint: The Child Proof's Public Inputs must match Hash(Header, Rewards)
    let guta_header_hash = guta_proof_header.qfhash::<C::Hasher>();
    let expected_child_public_inputs = C::Hasher::two_to_one(&guta_header_hash, &child_rewards_tree_value);
    
    jtmb_connect_ref(
        &expected_child_public_inputs,
        &child_proof.public_inputs_hash,
        "child proof public inputs mismatch",
    )?;

    // Constraint: The Child Proof itself must be cryptographically valid
    child_verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(child_proof)?;

    Ok(())
}