use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::qdata::ups_signature::PsyUserProvingSessionSignatureDataCompact;
use psy_common_circuit::{
    builder::{core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore},
    traits::{AlgebraicHashableTarget, WitnessValueFor},
};
use psy_config::network_constants::PSY_SIG_ACTION_SIGN_UPS_END_CAP;

use crate::gadgets::{
    qdata::user_contract_state::SignContextGadget,
    sig_action::{compute_sig_action_hash_circuit, SimplePsySigAction},
};

#[derive(Clone, Debug)]
pub struct PsyUserProvingSessionSignatureDataCompactGadget {
    // start require witness
    pub start_user_leaf_hash: HashOutTarget,
    pub end_user_leaf_hash: HashOutTarget,
    pub checkpoint_leaf_hash: HashOutTarget,
    pub tx_stack_hash: HashOutTarget,
    pub tx_count: Target,
    // start computed
}
impl PsyUserProvingSessionSignatureDataCompactGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let start_user_leaf_hash = builder.add_virtual_hash();
        let end_user_leaf_hash = builder.add_virtual_hash();
        let checkpoint_leaf_hash = builder.add_virtual_hash();
        let tx_stack_hash = builder.add_virtual_hash();
        let tx_count = builder.add_virtual_target();

        Self {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_leaf_hash,
            tx_stack_hash,
            tx_count,
        }
    }
    pub fn new_from_known(
        start_user_leaf_hash: HashOutTarget,
        end_user_leaf_hash: HashOutTarget,
        checkpoint_leaf_hash: HashOutTarget,
        tx_stack_hash: HashOutTarget,
        tx_count: Target,
    ) -> Self {
        Self {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_leaf_hash,
            tx_stack_hash,
            tx_count,
        }
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        target: &PsyUserProvingSessionSignatureDataCompact<F>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.start_user_leaf_hash, target.start_user_leaf_hash.0)?;
        witness.set_hash_target(self.end_user_leaf_hash, target.end_user_leaf_hash.0)?;
        witness.set_hash_target(self.checkpoint_leaf_hash, target.checkpoint_leaf_hash.0)?;
        witness.set_hash_target(self.tx_stack_hash, target.tx_stack_hash.0)?;
        witness.set_target(self.tx_count, target.tx_count)
    }

    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let user_leaf_change_combo = builder.hash_two_to_one::<H>(self.start_user_leaf_hash, self.end_user_leaf_hash);
        let tx_sized_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            self.tx_count,
            self.tx_stack_hash.elements[0],
            self.tx_stack_hash.elements[1],
            self.tx_stack_hash.elements[2],
            self.tx_stack_hash.elements[3],
        ]);

        let state_context_combo = builder.hash_two_to_one::<H>(self.checkpoint_leaf_hash, user_leaf_change_combo);

        builder.hash_two_to_one::<H>(state_context_combo, tx_sized_hash)
    }
    pub fn get_sig_action_with_user_info<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        network_magic: u64,
        user_id: Target,
        nonce: Target,
        sign_context: &SignContextGadget,
    ) -> SimplePsySigAction {
        let network_magic_target = builder.constant_u64(network_magic);
        let sig_action = builder.constant_u64(PSY_SIG_ACTION_SIGN_UPS_END_CAP);
        let ups_end_data_hash = self.to_hash::<H, F, D>(builder);

        let mut action_arguments = ups_end_data_hash.elements.to_vec();
        action_arguments.extend_from_slice(&sign_context.to_targets());

        let sig_action_hash =
            compute_sig_action_hash_circuit::<H, F, D>(builder, network_magic_target, user_id, sig_action, nonce, &action_arguments);

        SimplePsySigAction {
            network_magic: network_magic_target,
            user: user_id,
            sig_action,
            nonce,
            action_arguments,
            sig_action_hash,
        }
    }
}
impl AlgebraicHashableTarget for PsyUserProvingSessionSignatureDataCompactGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<PsyUserProvingSessionSignatureDataCompactGadget, F, true> for PsyUserProvingSessionSignatureDataCompact<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyUserProvingSessionSignatureDataCompactGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyUserProvingSessionSignatureDataCompactGadget, F, false> for PsyUserProvingSessionSignatureDataCompact<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyUserProvingSessionSignatureDataCompactGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
