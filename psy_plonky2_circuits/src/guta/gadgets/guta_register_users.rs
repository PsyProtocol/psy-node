use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_data::proof_input::guta::GUTARegisterUserFullInput;
use psy_plonky2_basic_helpers::{builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, core::CircuitBuilderHelpersCore, select::CircuitBuilderSelectHelpers}};


use crate::treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget;

use super::guta_register_user_full::GUTARegisterUserFullGadget;




#[derive(Clone, Debug)]
pub struct GUTARegisterUsersGadget {
    pub register_user_gadgets: Vec<GUTARegisterUserFullGadget>,
    pub register_user_count: Target,

    pub global_user_tree_height: usize,


    // computed
    pub user_registration_tree_root: HashOutTarget,
    pub global_user_tree_proof_height: Target,

    pub state_transition: SubTreeNodeStateTransitionGadget,
}

impl GUTARegisterUsersGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        group_realm_height: usize,
        default_user_state_tree_root: QHashOut<F>,
        input_height_target: Option<Target>,
        max_users: usize,
    ) -> Self {

        assert!(max_users > 0, "must have non-zero number of users");

        let mut register_user_gadgets = Vec::with_capacity(max_users);

        let first_user = GUTARegisterUserFullGadget::add_virtual_to::<H,F,D>(
            builder,
            global_user_tree_realm_height,
            global_user_tree_height,
            group_realm_height,
            default_user_state_tree_root,
            input_height_target
        );

        let register_user_count = builder.add_virtual_target();

        builder.assert_non_zero(register_user_count);



        let mut state_transition = first_user.get_state_transition(builder);

        tracing::debug!("🔄 GUTA Register Users - initial state_transition: {:?}", state_transition);

        let global_user_tree_proof_height = first_user.global_user_tree_proof_height;
        let user_registration_tree_root = first_user.user_registration_tree_root;

        let new_input_height_target = Some(global_user_tree_proof_height);

        let mut is_disabled = builder._false();

        register_user_gadgets.push(first_user);

        for i in 1..max_users {
            let user = GUTARegisterUserFullGadget::add_virtual_to::<H,F,D>(
                builder,
                global_user_tree_realm_height,
                global_user_tree_height,
                group_realm_height,
                default_user_state_tree_root,
                new_input_height_target
            );
            builder.connect(user.global_user_tree_proof_height, global_user_tree_proof_height);

            let current_user_count = builder.constant_u64(i as u64);
            let is_pivot_disabled_user = builder.is_equal(current_user_count, register_user_count);


            is_disabled = builder.or(is_disabled, is_pivot_disabled_user);

            builder.connect_hashes_if_false(
                is_disabled,
                user.old_global_user_tree_root,
                state_transition.new_node_value,
            );

            state_transition.new_node_value = builder.select_hash(
                is_disabled,
                state_transition.new_node_value,
                user.new_global_user_tree_root,
            );

            // builder.connect_hashes_if_false(
            //     is_disabled,
            //     user_registration_tree_root,
            //     user.user_registration_tree_root,
            // );

            // TODO: do we need this?
            let computed_root_index = user.register_user_core_gadget.global_user_tree_update_proof.bit_info.get_root_parent_index(builder);
            builder.connect_if_false(
                is_disabled,
                computed_root_index,
                state_transition.node_index
            );

            register_user_gadgets.push(user);
        }

        tracing::debug!("🔄 GUTA Register Users - final state_transition: {:?}", state_transition);

        Self {
            register_user_gadgets,
            register_user_count,
            user_registration_tree_root,
            global_user_tree_proof_height,
            global_user_tree_height,
            state_transition,
        }
    }

    pub fn get_state_transition(
        &self,
    ) -> SubTreeNodeStateTransitionGadget {
        self.state_transition
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        guta_register_user_inputs: &[GUTARegisterUserFullInput<QHashOut<F>>],
        dummy_public_key: QHashOut<F>,
        dummy_user_leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<()> {

        let inputs_len = guta_register_user_inputs.len();
        
        tracing::debug!("🔄 GUTA Register Users set_witness - inputs_len: {}, state_transition: {:?}", 
            inputs_len, self.state_transition);

        if inputs_len == 0 {
            anyhow::bail!("must provide at least one guta_register_user_input");
        }else if inputs_len > self.register_user_gadgets.len() {
            anyhow::bail!("provided too many guta_register_user_inputs");
        }else if inputs_len == self.register_user_gadgets.len() {
            for (input, g) in guta_register_user_inputs.iter().zip(self.register_user_gadgets.iter()) {
                g.set_witness_params(
                    witness,
                    &input.user_registration_tree_merkle_proof,
                    &input.global_user_tree_update_proof
                )?;
            }
            witness.set_target(
                self.register_user_count,
                F::from_canonical_usize(inputs_len),
            )?;
            return Ok(());
        }


        let dummy_value = GUTARegisterUserFullInput::new_dummy(
            self.global_user_tree_height,
            guta_register_user_inputs[0].global_user_tree_update_proof.siblings.len(),
            dummy_user_leaf_hash,
            dummy_public_key,
        );


        for (i, g) in self.register_user_gadgets.iter().enumerate() {
            if i < inputs_len {
                g.set_witness_params(
                    witness,
                    &guta_register_user_inputs[i].user_registration_tree_merkle_proof,
                    &guta_register_user_inputs[i].global_user_tree_update_proof,
                )?;
            }else{
                g.set_witness_params(
                    witness,
                    &dummy_value.user_registration_tree_merkle_proof,
                    &dummy_value.global_user_tree_update_proof
                )?;
            }
        }
        witness.set_target(
            self.register_user_count,
            F::from_canonical_usize(inputs_len),
        )
    }

}
