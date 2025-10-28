use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_plonky2_basic_helpers::{builder::{comparison::CircuitBuilderComparison, core::CircuitBuilderHelpersCore}};
use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut};
use psy_plonky2_common_circuits::hash::merkle::gadgets::variable_height_delta_merkle_proof_opt::VariableHeightDeltaMerkleProofOptGadget;

use crate::{gadgets::qdata::user::QEDUserLeafGadget, treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget};






#[derive(Clone, Debug)]
pub struct GUTARegisterUserCoreGadget {
    pub global_user_tree_update_proof: VariableHeightDeltaMerkleProofOptGadget,
    pub public_key: HashOutTarget,

    // computed
    pub user_id: Target,
    pub user_leaf_gadget: QEDUserLeafGadget,
    pub user_leaf_hash: HashOutTarget,

    pub needs_public_key_witness: bool,
    //global_user_tree_realm_height: usize,
    global_user_tree_height: usize,
}

impl GUTARegisterUserCoreGadget {
    pub fn add_virtual_to_with_public_key<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        default_user_state_tree_root: QHashOut<F>,
        input_height_target: Option<Target>,
        public_key: HashOutTarget,
    ) -> Self {

        let global_user_tree_update_proof = VariableHeightDeltaMerkleProofOptGadget::add_virtual_to_full::<H,F,D>(
            builder,
            global_user_tree_realm_height,
            input_height_target,
        );

        builder.assert_zero_hash(global_user_tree_update_proof.old_value);

        let user_id = global_user_tree_update_proof.index;

        let user_leaf_gadget = QEDUserLeafGadget::create_new_user_default::<F,D>(
            builder,
            user_id,
            public_key,
            default_user_state_tree_root,
        );

        let user_leaf_hash = user_leaf_gadget.to_hash::<H,F,D>(builder);


        builder.connect_hashes(
            global_user_tree_update_proof.new_value,
            user_leaf_hash
        );

        Self {
            global_user_tree_update_proof,
            public_key,
            user_leaf_gadget,
            user_leaf_hash,
            user_id,
            needs_public_key_witness: false,
            //global_user_tree_realm_height,
            global_user_tree_height,
        }
    }

    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        default_user_state_tree_root: QHashOut<F>,
        input_height_target: Option<Target>,
    ) -> Self {
        let public_key = builder.add_virtual_hash();

        let mut gadget = Self::add_virtual_to_with_public_key::<H,F,D>(
            builder,
            global_user_tree_realm_height,
            global_user_tree_height,
            default_user_state_tree_root,
            input_height_target,
            public_key
        );

        gadget.needs_public_key_witness = true;

        gadget
    }

    pub fn get_state_transition<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> SubTreeNodeStateTransitionGadget {
        let leaf_level = builder.constant_u64(self.global_user_tree_height as u64);
        let node_level = builder.sub(leaf_level, self.global_user_tree_update_proof.height);
        // leaf level will always be >= than the proof tree height
        let node_index = self.global_user_tree_update_proof.bit_info.get_root_parent_index(builder);

        SubTreeNodeStateTransitionGadget {
            old_node_value: self.global_user_tree_update_proof.old_root,
            new_node_value: self.global_user_tree_update_proof.new_root,
            node_index,
            node_level,
        }

    }
    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        public_key: QHashOut<F>,
        global_user_tree_update_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.global_user_tree_update_proof.set_witness(
            witness,
            global_user_tree_update_proof,
        )?;
        if self.needs_public_key_witness{
            witness.set_hash_target(
                self.public_key,
                public_key.0
            )?;
        }
        Ok(())
    }

    pub fn set_witness_params_no_public_key<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        global_user_tree_update_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        if self.needs_public_key_witness {
            anyhow::bail!("This instance of GUTARegisterUserCoreGadget needs a public key witness!");
        }
        self.global_user_tree_update_proof.set_witness(
            witness,
            global_user_tree_update_proof,
        )
    }
    pub fn set_witness_detailed_params_no_public_key<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        index: F,
        user_leaf_hash: QHashOut<F>,
        siblings: &[QHashOut<F>],
    ) -> anyhow::Result<()> {
        if self.needs_public_key_witness {
            anyhow::bail!("This instance of GUTARegisterUserCoreGadget needs a public key witness!");
        }
        self.global_user_tree_update_proof.set_witness_params(
            witness,
            index,
            QHashOut::ZERO,
            user_leaf_hash,
            siblings
        )
    }

}
