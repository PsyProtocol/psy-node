use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::ups::verify_previous_ups_step::VerifyPreviousUPSStepProofInProofTreeInput;
use psy_common_circuit::{
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget, traits::WitnessValueFor,
    treeprover::qrecursion::standard::gadgets::attest_tree_aware_proof_in_tree::AttestTreeAwareProofInTreeGadget,
};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;

use crate::gadgets::qdata::ups_context_input::UserProvingSessionHeaderGadget;

#[derive(Debug, Clone)]
pub struct VerifyPreviousUPSStepProofInProofTreeGadget {
    // start need witness
    pub proof_attestation_gadget: AttestTreeAwareProofInTreeGadget,
    pub previous_step_header_gadget: UserProvingSessionHeaderGadget,
    pub ups_circuit_whitelist_merkle_proof: MerkleProofGadget,

    // start computed
    pub current_proof_tree_root: HashOutTarget,
    pub ups_step_circuit_whitelist_root: HashOutTarget,
}

impl VerifyPreviousUPSStepProofInProofTreeGadget {
    pub fn add_virtual_to<H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        ups_session_proof_tree_height: usize,
        ups_circuit_whitelist_tree_height: usize,
    ) -> Self {
        let proof_attestation_gadget = AttestTreeAwareProofInTreeGadget::add_virtual_to::<H, F, D>(builder, ups_session_proof_tree_height);

        let previous_step_header_gadget = UserProvingSessionHeaderGadget::add_virtual_to::<H, F, D>(builder);

        let ups_circuit_whitelist_merkle_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, ups_circuit_whitelist_tree_height);
        let ups_step_circuit_whitelist_root = ups_circuit_whitelist_merkle_proof.root;

        let current_proof_tree_root = proof_attestation_gadget.inclusion_proof.root;

        // ensure the fingerprint in the ups circuit whitelist matches that in the
        // attestaion
        builder.connect_hashes(proof_attestation_gadget.fingerprint, ups_circuit_whitelist_merkle_proof.value);

        // ensure the current proof header has the same ups circuit whitelist root as
        // our merkle proof
        builder.connect_hashes(
            previous_step_header_gadget.ups_step_circuit_whitelist_root,
            ups_step_circuit_whitelist_root,
        );

        // ensure the previous proof header matches the public inputs of the proof we
        // are verifying
        let expected_inner_public_inputs_hash = previous_step_header_gadget.to_hash::<H, F, D>(builder);
        tracing::debug!(
            "🔗 VerifyPreviousUPSStep - expected_inner_public_inputs_hash: {:?}, actual_inner_hash: {:?}",
            expected_inner_public_inputs_hash,
            proof_attestation_gadget.inner_public_inputs_hash
        );

        builder.connect_hashes(proof_attestation_gadget.inner_public_inputs_hash, expected_inner_public_inputs_hash);

        Self {
            proof_attestation_gadget,
            ups_circuit_whitelist_merkle_proof,
            previous_step_header_gadget,
            current_proof_tree_root,
            ups_step_circuit_whitelist_root,
        }
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        target: &VerifyPreviousUPSStepProofInProofTreeInput<F>,
    ) -> anyhow::Result<()> {
        self.proof_attestation_gadget.set_witness(witness, &target.proof_attestation_witness)?;
        self.previous_step_header_gadget.set_witness(witness, &target.previous_step_header)?;
        self.ups_circuit_whitelist_merkle_proof
            .set_witness_core_proof_q_generic(witness, &target.ups_circuit_whitelist_merkle_proof)
    }
}

impl<F: RichField> WitnessValueFor<VerifyPreviousUPSStepProofInProofTreeGadget, F, true> for VerifyPreviousUPSStepProofInProofTreeInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &VerifyPreviousUPSStepProofInProofTreeGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<VerifyPreviousUPSStepProofInProofTreeGadget, F, false> for VerifyPreviousUPSStepProofInProofTreeInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &VerifyPreviousUPSStepProofInProofTreeGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
