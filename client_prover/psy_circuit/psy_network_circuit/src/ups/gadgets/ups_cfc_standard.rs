use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::ups::ups_standard_cfc_input::UPSVerifyCFCStandardStepInput;
use psy_common_circuit::traits::WitnessValueFor;
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;

use super::{
    correct_header_hashes::CorrectUPSHeaderHashesGadget, ups_cfc_verify_inclusion::UPSVerifyCFCProofExistsAndValidGadget,
    ups_standard_cfc_state_delta::UPSCFCStandardStateDeltaGadget,
};
use crate::gadgets::qdata::ups_context_input::UserProvingSessionHeaderGadget;

#[derive(Clone, Debug)]
pub struct UPSVerifyCFCStandardStepGadget {
    // start require witness
    pub verify_cfc_exists_and_valid_gadget: UPSVerifyCFCProofExistsAndValidGadget,
    pub process_cfc_state_delta_gadget: UPSCFCStandardStateDeltaGadget,

    // start computed
    pub new_header_gadget: UserProvingSessionHeaderGadget,
}
impl UPSVerifyCFCStandardStepGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        previous_step_header_gadget: &UserProvingSessionHeaderGadget,
        current_proof_tree_root: HashOutTarget,
        ups_session_proof_tree_height: usize,
    ) -> Self {
        let corrections = CorrectUPSHeaderHashesGadget::from_previous_step(previous_step_header_gadget);
        Self::add_virtual_to_with_corrections::<H, F, D>(
            builder,
            previous_step_header_gadget,
            &corrections,
            current_proof_tree_root,
            ups_session_proof_tree_height,
        )
    }
    pub fn add_virtual_to_with_corrections<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        previous_step_header_gadget: &UserProvingSessionHeaderGadget,
        corrections: &CorrectUPSHeaderHashesGadget,
        current_proof_tree_root: HashOutTarget,
        ups_session_proof_tree_height: usize,
    ) -> Self {
        tracing::debug!(
            "⚙️ UPS CFC Standard - current_proof_tree_root: {:?}, user_leaf: {:?}",
            current_proof_tree_root,
            previous_step_header_gadget.current_state.user_leaf
        );
        // start require witness
        let verify_cfc_exists_and_valid_gadget: UPSVerifyCFCProofExistsAndValidGadget =
            UPSVerifyCFCProofExistsAndValidGadget::add_virtual_to::<H, F, D>(builder, ups_session_proof_tree_height);
        let contract_state_tree_height = verify_cfc_exists_and_valid_gadget
            .cfc_inclusion_proof_gadget
            .contract_inclusion_proof
            .contract_leaf
            .state_tree_height;

        let (process_cfc_state_delta_gadget, new_header_gadget) =
            UPSCFCStandardStateDeltaGadget::add_virtual_to::<H, F, D>(builder, previous_step_header_gadget, corrections, contract_state_tree_height);

        // constrain verify with previous
        // ensure the cfc proof verifier gadget is using the correct proof tree root
        // (ie. so we know this proof actually exists if UPS is later to believed)
        builder.connect_hashes(verify_cfc_exists_and_valid_gadget.attested_proof_tree_root, current_proof_tree_root);

        // ensure the cfc proof verifier is working with the correct checkpoint leaf
        // hash (ie. so the contract function tree is correct)
        builder.connect_hashes(
            verify_cfc_exists_and_valid_gadget.checkpoint_leaf_hash,
            previous_step_header_gadget.session_start_context.checkpoint_leaf_hash,
        );

        // constraint process_cfc_state_delta
        // ensure that the verifier and state processor agree on contract id
        builder.connect(
            verify_cfc_exists_and_valid_gadget.cfc_contract_id,
            process_cfc_state_delta_gadget.cfc_contract_id,
        );

        // ensure that the verifier and state processor agree on method id
        builder.connect(
            verify_cfc_exists_and_valid_gadget.cfc_method_id,
            process_cfc_state_delta_gadget.cfc_method_id,
        );

        // ensure that the verifier and state processor agree on number of inputs
        builder.connect(
            verify_cfc_exists_and_valid_gadget.cfc_num_inputs,
            process_cfc_state_delta_gadget.cfc_num_inputs,
        );

        // ensure that the verifier and state processor agree on number of outputs
        builder.connect(
            verify_cfc_exists_and_valid_gadget.cfc_num_outputs,
            process_cfc_state_delta_gadget.cfc_num_outputs,
        );

        // ensure that the verifier and state processor agree on the
        // inner_public_inputs_hash
        builder.connect_hashes(
            verify_cfc_exists_and_valid_gadget.cfc_inner_public_inputs_hash,
            process_cfc_state_delta_gadget.cfc_inner_public_inputs_hash,
        );

        Self {
            verify_cfc_exists_and_valid_gadget,
            process_cfc_state_delta_gadget,
            new_header_gadget,
        }
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &UPSVerifyCFCStandardStepInput<F>) -> anyhow::Result<()> {
        tracing::debug!(
            "⚙️ UPS CFC Standard set_witness - checkpoint_state: {}, cfc_inclusion_proof: {}",
            serde_json::to_string_pretty(&target.checkpoint_state).unwrap(),
            serde_json::to_string_pretty(&target.cfc_inclusion_proof.contract_inclusion_proof.contract_leaf).unwrap()
        );

        self.verify_cfc_exists_and_valid_gadget.set_witness_params(
            witness,
            &target.checkpoint_state,
            &target.verify_cfc_proof_input,
            &target.cfc_inclusion_proof,
        )?;

        self.process_cfc_state_delta_gadget
            .set_witness(witness, &target.process_cfc_state_delta_input)
    }
}

impl<F: RichField> WitnessValueFor<UPSVerifyCFCStandardStepGadget, F, true> for UPSVerifyCFCStandardStepInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSVerifyCFCStandardStepGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<UPSVerifyCFCStandardStepGadget, F, false> for UPSVerifyCFCStandardStepInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSVerifyCFCStandardStepGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
