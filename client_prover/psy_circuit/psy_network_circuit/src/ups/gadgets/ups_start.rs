use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::ups::start_step::UPSStartStepInput;
use psy_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore,
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
    traits::{CreatableTarget, CreatableWithHasherTarget, WitnessValueFor},
};
use psy_config::network_constants::{
    CHECKPOINT_TREE_HEIGHT, DEFERRED_TRANSACTION_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, INLINE_TRANSACTION_TREE_HEIGHT,
};
use psy_crypto::hash::traits::hasher::iterate_merkle_hasher_alg;

use crate::gadgets::qdata::{
    checkpoint::PsyCheckpointLeafGadget, checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget,
    ups_context_input::UserProvingSessionHeaderGadget,
};

#[derive(Clone, Debug)]
pub struct UPSStartStepGadget {
    pub header_gadget: UserProvingSessionHeaderGadget,
    pub checkpoint_leaf_gadget: PsyCheckpointLeafGadget,
    pub state_roots_gadget: PsyCheckpointGlobalStateRootsGadget,
    pub checkpoint_tree_proof: MerkleProofGadget,
    pub user_tree_proof: MerkleProofGadget,
}
pub fn get_empty_tree_root_for_tx_debt_trees<H: AlgebraicHasher<F>, F: RichField>() -> (QHashOut<F>, QHashOut<F>) {
    let base_zero_hash = QHashOut::ZERO;
    let deferred_tx_debt_tree_root = iterate_merkle_hasher_alg::<H, F>(base_zero_hash, DEFERRED_TRANSACTION_TREE_HEIGHT as usize);
    let inline_tx_debt_tree_root = iterate_merkle_hasher_alg::<H, F>(base_zero_hash, INLINE_TRANSACTION_TREE_HEIGHT as usize);

    (deferred_tx_debt_tree_root, inline_tx_debt_tree_root)
}
impl UPSStartStepGadget {
    fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let header_gadget = UserProvingSessionHeaderGadget::add_virtual_to::<H, F, D>(builder);
        let checkpoint_leaf_gadget = PsyCheckpointLeafGadget::create_virtual::<F, D>(builder);
        let state_roots_gadget = PsyCheckpointGlobalStateRootsGadget::create_virtual::<F, D>(builder);
        let checkpoint_tree_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, CHECKPOINT_TREE_HEIGHT as usize);
        let user_tree_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, GLOBAL_USER_TREE_HEIGHT as usize);

        tracing::debug!(
            "🏁 UPS Start - header_gadget: {:?}, checkpoint_leaf_gadget: {:?}, state_roots_gadget: {:?}",
            header_gadget,
            checkpoint_leaf_gadget,
            state_roots_gadget
        );

        let gadget = Self {
            header_gadget,
            checkpoint_leaf_gadget,
            state_roots_gadget,
            checkpoint_tree_proof,
            user_tree_proof,
        };
        gadget.ensure_start_session_ctx_properly_constrainted::<H, F, D>(builder);
        gadget.ensure_current_state_properly_constrainted::<H, F, D>(builder);
        gadget
    }
    fn ensure_start_session_ctx_properly_constrainted<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // START: ensure that the data in header_gadget.session_start_context matches
        // the checkpoint_tree_proof
        let expected_checkpoint_tree_root = self.checkpoint_tree_proof.root;
        let expected_checkpoint_leaf_hash = self.checkpoint_tree_proof.value;
        let expected_checkpoint_id = self.checkpoint_tree_proof.index;

        let header_checkpoint_tree_root = self.header_gadget.session_start_context.checkpoint_tree_root;
        let header_checkpoint_leaf_hash = self.header_gadget.session_start_context.checkpoint_leaf_hash;
        let header_checkpoint_id = self.header_gadget.session_start_context.checkpoint_id;

        builder.connect_hashes(expected_checkpoint_tree_root, header_checkpoint_tree_root);
        builder.connect_hashes(expected_checkpoint_leaf_hash, header_checkpoint_leaf_hash);
        builder.connect(expected_checkpoint_id, header_checkpoint_id);
        // END: ensure that the data in header_gadget.session_start_context matches the
        // checkpoint_tree_proof

        /*
            We have now proven that in a checkpoint tree with root hash <header_checkpoint_tree_root>,
            there exists checkpoint with id <header_checkpoint_id> which has:
                - [NEW] A checkpoint leaf hash of <header_checkpoint_leaf_hash>
        */
        // START: ensure that the data in checkpoint_leaf_gadget/state_roots_gadget
        // match our header/checkpoint_tree_proof
        let computed_checkpoint_leaf_hash = self.checkpoint_leaf_gadget.to_hash::<H, F, D>(builder);
        let computed_global_chain_root = self.state_roots_gadget.to_hash::<H, F, D>(builder);
        let checkpoint_leaf_gadget_global_chain_root = self.checkpoint_leaf_gadget.global_chain_root;

        builder.connect_hashes(computed_checkpoint_leaf_hash, header_checkpoint_leaf_hash);
        builder.connect_hashes(computed_global_chain_root, checkpoint_leaf_gadget_global_chain_root);
        // END: ensure that the data in checkpoint_leaf_gadget/state_roots_gadget match
        // our header/checkpoint_tree_proof

        /*
            We have now proven that in a checkpoint tree with root hash <header_checkpoint_tree_root>,
            there exists checkpoint with id <header_checkpoint_id> which has:
                - A checkpoint leaf hash of <header_checkpoint_leaf_hash>
                - [NEW] State Roots <self.state_roots_gadget>
                - [NEW] A global user tree with root <self.state_roots_gadget.user_tree_root>
        */

        // START: ensure that the user_tree_proof.root matches the user tree root in
        // state_roots_gadget
        let user_tree_proof_root = self.user_tree_proof.root;
        let state_roots_user_tree_root = self.state_roots_gadget.user_tree_root;

        builder.connect_hashes(user_tree_proof_root, state_roots_user_tree_root);
        // END: ensure that the user_tree_proof.root matches the user tree root in
        // state_roots_gadget

        // START: ensure that the user leaf hash in the merkle proof matches the user
        // leaf hash in the header
        let user_tree_proof_user_leaf_hash = self.user_tree_proof.value;
        let header_start_session_user_leaf_hash = self.header_gadget.session_start_context.start_session_user_leaf_hash;

        builder.connect_hashes(user_tree_proof_user_leaf_hash, header_start_session_user_leaf_hash);
        // END: ensure that the user leaf hash in the merkle proof matches the user leaf
        // hash in the header

        // START: ensure that the user_id in the header matches the index of
        // user_tree_proof
        let header_user_id = self.header_gadget.session_start_context.start_session_user_leaf.user_id;
        let expected_user_id = self.user_tree_proof.index;

        builder.connect(header_user_id, expected_user_id);
        // END: ensure that the user_id in the header matches the index of
        // user_tree_proof

        /*
            We have now proven that in a checkpoint tree with root hash <header_checkpoint_tree_root>,
            there exists checkpoint with id <header_checkpoint_id> which has:
                - A checkpoint leaf hash of <header_checkpoint_leaf_hash>
                - State Roots <self.state_roots_gadget>
                - A global user tree with root <self.state_roots_gadget.user_tree_root>
                - [NEW] A User with id <header_user_id> that has:
                    * [NEW] A user leaf hash of <header_start_session_user_leaf_hash>
                    * [NEW] A user leaf of <self.header_gadget.session_start_context.start_session_user_leaf>
                    * [NEW] A user state tree with root <self.header_gadget.session_start_context.start_session_user_leaf.user_state_tree_root>
        */
    }
    fn ensure_current_state_properly_constrainted<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // START: ensure that the user leaf in current state is the same, except for an
        // updated checkpoint id, as the user leaf in start session
        let mut header_new_current_user_leaf = self.header_gadget.session_start_context.start_session_user_leaf.clone();

        header_new_current_user_leaf.last_checkpoint_id = self.header_gadget.session_start_context.checkpoint_id;

        // make it immutable to keep things keep/safe
        let header_new_current_user_leaf = header_new_current_user_leaf;

        let header_new_current_user_leaf_hash = header_new_current_user_leaf.to_hash::<H, F, D>(builder);

        let header_current_state_user_leaf_hash = self.header_gadget.current_state.user_leaf.to_hash::<H, F, D>(builder);
        builder.connect_hashes(header_new_current_user_leaf_hash, header_current_state_user_leaf_hash);
        // END: ensure that the user leaf in current state is the same as the user leaf
        // in start session

        // START: ensure that deferred_tx_debt_tree_root and inline_tx_debt_tree_root
        // are initialized to their starting values TODO/PERF: make
        // deferred_tx_debt_tree_root_const and inline_tx_debt_tree_root_const constants
        // instead of computing them each time
        let (deferred_tx_debt_tree_root_const, inline_tx_debt_tree_root_const) = get_empty_tree_root_for_tx_debt_trees::<H, F>();

        let correct_deferred_tx_debt_tree_root = builder.constant_qhash(deferred_tx_debt_tree_root_const);
        let correct_inline_tx_debt_tree_root = builder.constant_qhash(inline_tx_debt_tree_root_const);
        let current_state_deferred_tx_debt_tree_root = self.header_gadget.current_state.deferred_tx_debt_tree_root;
        let current_state_inline_tx_debt_tree_root = self.header_gadget.current_state.inline_tx_debt_tree_root;

        builder.connect_hashes(current_state_deferred_tx_debt_tree_root, correct_deferred_tx_debt_tree_root);
        builder.connect_hashes(current_state_inline_tx_debt_tree_root, correct_inline_tx_debt_tree_root);
        // END: ensure that deferred_tx_debt_tree_root and inline_tx_debt_tree_root are
        // initialized to their starting values

        // START: ensure that tx_hash_stack and tx_count are initialized to zero
        let zero_hash = builder.constant_hash(HashOut::ZERO);
        builder.connect_hashes(self.header_gadget.current_state.tx_hash_stack, zero_hash);

        let zero_target = builder.zero();
        builder.connect(self.header_gadget.current_state.tx_count, zero_target);
        // END: ensure that tx_hash_stack and tx_count are initialized to zero
    }

    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &UPSStartStepInput<F>) -> anyhow::Result<()> {
        tracing::debug!(
            "🏁 UPS Start set_witness - user_leaf: {}, checkpoint_leaf: {}, checkpoint_tree_root: {}",
            serde_json::to_string_pretty(&target.ups_header.current_state.user_leaf).unwrap(),
            serde_json::to_string_pretty(&target.checkpoint_leaf).unwrap(),
            serde_json::to_string_pretty(&target.ups_header.session_start_context.checkpoint_tree_root).unwrap()
        );

        self.header_gadget.set_witness(witness, &target.ups_header)?;
        self.checkpoint_leaf_gadget.set_witness(witness, &target.checkpoint_leaf)?;
        self.state_roots_gadget.set_witness(witness, &target.state_roots)?;
        self.checkpoint_tree_proof
            .set_witness_core_proof_q_generic(witness, &target.checkpoint_tree_proof)?;
        self.user_tree_proof.set_witness_core_proof_q_generic(witness, &target.user_tree_proof)
    }
}
impl CreatableWithHasherTarget for UPSStartStepGadget {
    fn create_virtual_with_hasher<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<UPSStartStepGadget, F, true> for UPSStartStepInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSStartStepGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<UPSStartStepGadget, F, false> for UPSStartStepInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSStartStepGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
