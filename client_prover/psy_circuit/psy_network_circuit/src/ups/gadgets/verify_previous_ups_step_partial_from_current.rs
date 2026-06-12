use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::ups::verify_previous_ups_step::VerifyPreviousUPSStepProofInProofTreePartialInput;
use psy_common_circuit::{
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget, traits::WitnessValueFor,
    treeprover::qrecursion::standard::gadgets::attest_tree_aware_proof_in_tree::AttestTreeAwareProofInTreeGadget,
};
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;

use crate::gadgets::qdata::ups_context_input::{UserProvingSessionCurrentStateGadget, UserProvingSessionHeaderGadget};

#[derive(Debug, Clone)]
pub struct VerifyPreviousUPSStepProofInProofTreePartialFromCurrentGadget {
    // start need witness
    pub proof_attestation_gadget: AttestTreeAwareProofInTreeGadget,
    pub previous_step_state: UserProvingSessionCurrentStateGadget,
    pub ups_circuit_whitelist_merkle_proof: MerkleProofGadget,

    // start computed
    pub previous_step_header_gadget: UserProvingSessionHeaderGadget,
    pub current_proof_tree_root: HashOutTarget,
}

impl VerifyPreviousUPSStepProofInProofTreePartialFromCurrentGadget {
    pub fn add_virtual_to<H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        current_header: &UserProvingSessionHeaderGadget,
        ups_session_proof_tree_height: usize,
        ups_circuit_whitelist_tree_height: usize,
    ) -> Self {
        let proof_attestation_gadget = AttestTreeAwareProofInTreeGadget::add_virtual_to::<H, F, D>(builder, ups_session_proof_tree_height);

        let previous_step_state = UserProvingSessionCurrentStateGadget::add_virtual_to(builder);

        let ups_circuit_whitelist_merkle_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, ups_circuit_whitelist_tree_height);
        let ups_step_circuit_whitelist_root = ups_circuit_whitelist_merkle_proof.root;
        let session_start_context = current_header.session_start_context.clone();

        let previous_step_header_gadget = UserProvingSessionHeaderGadget::new_from_existing_ups_context::<H, F, D>(
            builder,
            ups_step_circuit_whitelist_root,
            session_start_context,
            previous_step_state,
        );

        let current_proof_tree_root = proof_attestation_gadget.inclusion_proof.root;

        // ensure the fingerprint in the ups circuit whitelist matches that in the
        // attestaion
        builder.connect_hashes(proof_attestation_gadget.fingerprint, ups_circuit_whitelist_merkle_proof.value);

        // ensure the current proof header has the same ups circuit whitelist root as
        // our merkle proof
        builder.connect_hashes(current_header.ups_step_circuit_whitelist_root, ups_step_circuit_whitelist_root);

        // ensure the previous proof header matches the public inputs of the proof we
        // are verifying
        let expected_inner_public_inputs_hash = previous_step_header_gadget.to_hash::<H, F, D>(builder);
        builder.connect_hashes(proof_attestation_gadget.inner_public_inputs_hash, expected_inner_public_inputs_hash);

        Self {
            proof_attestation_gadget,
            previous_step_state,
            ups_circuit_whitelist_merkle_proof,
            previous_step_header_gadget,
            current_proof_tree_root,
        }
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        target: &VerifyPreviousUPSStepProofInProofTreePartialInput<F>,
    ) -> anyhow::Result<()> {
        self.proof_attestation_gadget.set_witness(witness, &target.proof_attestation_witness)?;
        self.previous_step_state.set_witness(witness, &target.previous_step_state)?;
        self.ups_circuit_whitelist_merkle_proof
            .set_witness_core_proof_q_generic(witness, &target.ups_circuit_whitelist_merkle_proof)
    }
}

impl<F: RichField> WitnessValueFor<VerifyPreviousUPSStepProofInProofTreePartialFromCurrentGadget, F, true>
    for VerifyPreviousUPSStepProofInProofTreePartialInput<F>
{
    fn set_for_witness(
        &self,
        witness: &mut impl Witness<F>,
        target: &VerifyPreviousUPSStepProofInProofTreePartialFromCurrentGadget,
    ) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<VerifyPreviousUPSStepProofInProofTreePartialFromCurrentGadget, F, false>
    for VerifyPreviousUPSStepProofInProofTreePartialInput<F>
{
    fn set_for_witness(
        &self,
        witness: &mut impl Witness<F>,
        target: &VerifyPreviousUPSStepProofInProofTreePartialFromCurrentGadget,
    ) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
