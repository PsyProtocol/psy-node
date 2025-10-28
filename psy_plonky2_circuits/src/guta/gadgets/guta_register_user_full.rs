use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_plonky2_basic_helpers::{builder::comparison::CircuitBuilderComparison};
use parth_core::{crypto::hash::merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, pgoldilocks::QHashOut};
use psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;


use crate::{treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget, user_id::circuit_user_registration_tree_index_bits_to_user_id};

use super::guta_register_user_core::GUTARegisterUserCoreGadget;




#[derive(Clone, Debug)]
pub struct GUTARegisterUserFullGadget {
    pub user_registration_tree_merkle_proof: MerkleProofGadget,
    pub register_user_core_gadget: GUTARegisterUserCoreGadget,


    // computed
    pub user_registration_tree_root: HashOutTarget,
    pub old_global_user_tree_root: HashOutTarget,
    pub new_global_user_tree_root: HashOutTarget,

    pub global_user_tree_proof_height: Target,
}

impl GUTARegisterUserFullGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        group_realm_height: usize,
        default_user_state_tree_root: QHashOut<F>,
        input_height_target: Option<Target>,
    ) -> Self {

        assert!(global_user_tree_height > global_user_tree_realm_height);
        let realm_user_tree_height = global_user_tree_realm_height;
        let coordinator_user_tree_height = global_user_tree_height - realm_user_tree_height;


        let (
            user_registration_tree_merkle_proof,
            user_registration_tree_index_bits,
        ) = MerkleProofGadget::add_virtual_to_get_index_bits::<H,F,D>(
            builder,
            global_user_tree_height,
        );

        let expected_user_id = circuit_user_registration_tree_index_bits_to_user_id::<H,F,D>(
            builder,
            user_registration_tree_merkle_proof.index,
            &user_registration_tree_index_bits,
            coordinator_user_tree_height as u8,
            realm_user_tree_height as u8,
            group_realm_height as u8,
        );

        let public_key = user_registration_tree_merkle_proof.value;

        builder.assert_non_zero_hash(public_key);


        let register_user_core_gadget = GUTARegisterUserCoreGadget::add_virtual_to_with_public_key::<H,F,D>(
            builder,
            global_user_tree_realm_height,
            global_user_tree_height,
            default_user_state_tree_root,
            input_height_target,
            public_key,
        );

        builder.connect(
            register_user_core_gadget.user_id,
            expected_user_id,
        );


        let user_registration_tree_root = user_registration_tree_merkle_proof.root;
        let old_global_user_tree_root = register_user_core_gadget.global_user_tree_update_proof.old_root;
        let new_global_user_tree_root = register_user_core_gadget.global_user_tree_update_proof.new_root;

        let global_user_tree_proof_height = register_user_core_gadget.global_user_tree_update_proof.height;

        Self {
            user_registration_tree_merkle_proof,
            register_user_core_gadget,
            user_registration_tree_root,
            old_global_user_tree_root,
            new_global_user_tree_root,
            global_user_tree_proof_height,
        }
    }

    pub fn get_state_transition<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> SubTreeNodeStateTransitionGadget {
        self.register_user_core_gadget.get_state_transition(builder)
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        user_registration_tree_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        global_user_tree_update_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.user_registration_tree_merkle_proof.set_witness_core_proof_q_generic(
            witness,
            user_registration_tree_merkle_proof,
        )?;
        self.register_user_core_gadget.set_witness_params_no_public_key(
            witness,
            global_user_tree_update_proof,
        )
    }

}
