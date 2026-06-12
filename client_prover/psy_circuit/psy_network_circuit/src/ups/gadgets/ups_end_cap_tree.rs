use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::ups::{ups_end_cap::UPSEndCapFromProofTreeGadgetInput, verify_previous_ups_step::VerifyPreviousUPSStepProofInProofTreeInput};
use psy_common_circuit::treeprover::qrecursion::standard::gadgets::attest_proof_in_tree::AttestProofInTreeGadget;
use psy_config::network_constants::{DEFERRED_TRANSACTION_TREE_HEIGHT, INLINE_TRANSACTION_TREE_HEIGHT};
use psy_crypto::{common::witnesses::qrecursion::header::AttestProofInTreeInput, hash::traits::hasher::MerkleZeroHasher};

use super::{ups_end_cap::UPSEndCapCoreGadget, verify_previous_ups_step::VerifyPreviousUPSStepProofInProofTreeGadget};
use crate::ups::gadgets::ups_end_cap_result::UPSEndCapResultCompactGadget;

#[derive(Clone, Debug)]
pub struct UPSEndCapFromProofTreeGadget {
    // software defined signature
    // pub user_contract_state: UserContractStateGadget,

    // start require witness
    pub verify_previous_ups_step_gadget: VerifyPreviousUPSStepProofInProofTreeGadget,
    pub verify_zk_signature_proof_gadget: AttestProofInTreeGadget,
    pub user_public_key_param: HashOutTarget,
    pub nonce: Target,
    pub slots_modified: Target,
    pub second_to_last_tx_hash_stack: HashOutTarget,

    // start computed
    pub end_cap_core_gadget: UPSEndCapCoreGadget,
    pub current_proof_tree_root: HashOutTarget,
}
impl UPSEndCapFromProofTreeGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        ups_session_proof_tree_height: usize,
        ups_circuit_whitelist_tree_height: usize,
        network_magic: u64,
    ) -> Self {
        let user_public_key_param = builder.add_virtual_hash();
        let nonce = builder.add_virtual_target();
        let slots_modified = builder.add_virtual_target();
        let second_to_last_tx_hash_stack = builder.add_virtual_hash();

        let verify_previous_ups_step_gadget = VerifyPreviousUPSStepProofInProofTreeGadget::add_virtual_to::<H, F, D>(
            builder,
            ups_session_proof_tree_height,
            ups_circuit_whitelist_tree_height,
        );

        let current_proof_tree_root = verify_previous_ups_step_gadget.current_proof_tree_root;

        let verify_zk_signature_proof_gadget = AttestProofInTreeGadget::add_virtual_to::<H, F, D>(builder, ups_session_proof_tree_height);

        tracing::debug!(
            "🏁 UPSEndCapFromProofTree - current_proof_tree_root: {:?}, attested_proof_tree_root: {:?}",
            current_proof_tree_root,
            verify_zk_signature_proof_gadget.attested_proof_tree_root
        );
        // ensure our zk signature is in the same proof tree as our previous ups step
        builder.connect_hashes(verify_zk_signature_proof_gadget.attested_proof_tree_root, current_proof_tree_root);

        let empty_deferred_tx_debt_tree_root = builder.constant_hash(H::get_zero_hash(DEFERRED_TRANSACTION_TREE_HEIGHT as usize));
        let empty_inline_tx_debt_tree_root = builder.constant_hash(H::get_zero_hash(INLINE_TRANSACTION_TREE_HEIGHT as usize));

        let tx_count = verify_previous_ups_step_gadget.previous_step_header_gadget.current_state.tx_count;
        tracing::debug!(
            "🏁 UPSEndCapFromProofTree - tx_count: {:?}, nonce: {:?}, slots_modified: {:?}",
            tx_count,
            nonce,
            slots_modified
        );
        tracing::debug!(
            "🏁 UPSEndCapFromProofTree - user_public_key: {:?}, network_magic: {}",
            user_public_key_param,
            network_magic
        );
        tracing::debug!(
            "🏁 UPSEndCapFromProofTree - zk_signature: public_inputs={:?}, fingerprint={:?}",
            verify_zk_signature_proof_gadget.public_inputs_hash,
            verify_zk_signature_proof_gadget.fingerprint
        );

        let end_cap_core_gadget = UPSEndCapCoreGadget::enforce_signature_constraints::<H, F, D>(
            builder,
            &verify_previous_ups_step_gadget.previous_step_header_gadget,
            verify_zk_signature_proof_gadget.public_inputs_hash,
            verify_zk_signature_proof_gadget.fingerprint,
            user_public_key_param,
            nonce,
            slots_modified,
            network_magic,
            empty_deferred_tx_debt_tree_root,
            empty_inline_tx_debt_tree_root,
            second_to_last_tx_hash_stack,
        );

        Self {
            verify_previous_ups_step_gadget,
            verify_zk_signature_proof_gadget,
            user_public_key_param,
            nonce,
            slots_modified,
            second_to_last_tx_hash_stack,

            end_cap_core_gadget,
            current_proof_tree_root,
        }
    }

    pub fn get_state_transition_pi_hash<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let start_state_leaf_hash_with_potential_register_user = self
            .verify_previous_ups_step_gadget
            .previous_step_header_gadget
            .session_start_context
            .get_end_cap_start_session_user_leaf_hash_with_potential_register_user::<H, F, D>(builder);
        let end_cap_core_result_compact_modified_gadget = UPSEndCapResultCompactGadget {
            start_user_leaf_hash: start_state_leaf_hash_with_potential_register_user,
            end_user_leaf_hash: self.end_cap_core_gadget.end_cap_result_gadget.end_user_leaf_hash,
            checkpoint_tree_root_hash: self.end_cap_core_gadget.end_cap_result_gadget.checkpoint_tree_root_hash,
            user_id: self.end_cap_core_gadget.end_cap_result_gadget.user_id,
        };
        end_cap_core_result_compact_modified_gadget.to_hash::<H, F, D>(builder)
    }

    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        verify_previous_ups_step_input: &VerifyPreviousUPSStepProofInProofTreeInput<F>,
        verify_zk_signature_proof_input: &AttestProofInTreeInput<F>,
        user_public_key_param: QHashOut<F>,
        nonce: F,
        slots_modified: F,
        second_to_last_tx_hash_stack: QHashOut<F>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.user_public_key_param, user_public_key_param.0)?;
        witness.set_target(self.nonce, nonce)?;

        self.verify_previous_ups_step_gadget
            .set_witness(witness, verify_previous_ups_step_input)?;
        self.verify_zk_signature_proof_gadget
            .set_witness(witness, verify_zk_signature_proof_input)?;
        witness.set_target(self.slots_modified, slots_modified)?;
        witness.set_hash_target(self.second_to_last_tx_hash_stack, second_to_last_tx_hash_stack.0)
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &UPSEndCapFromProofTreeGadgetInput<F>) -> anyhow::Result<()> {
        self.set_witness_params(
            witness,
            &target.verify_previous_ups_step_input,
            &target.verify_zk_signature_proof_input,
            target.user_public_key_param,
            target.nonce,
            target.slots_modified,
            target.second_to_last_tx_hash_stack,
        )
    }
}
