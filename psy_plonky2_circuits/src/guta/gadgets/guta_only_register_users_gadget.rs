use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_core::constants::protocol::get_default_worker_public_key;
use psy_data::{proof_input::guta::GUTARegisterUserFullInput, v1::qdata::user::PQEDUserLeaf};

use crate::{guta::gadgets::guta_stats::GUTAStatsGadget, utils::alghash::AlgHashable};

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, guta_register_users::GUTARegisterUsersGadget, helpers::ToGUTAHeader};





#[derive(Clone, Debug)]
pub struct GUTAOnlyRegisterUsersGadget{
    pub register_users_gadget: GUTARegisterUsersGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl GUTAOnlyRegisterUsersGadget {

    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        guta_circuit_whitelist: HashOutTarget,
        checkpoint_tree_root: HashOutTarget,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        group_realm_height: usize,
        default_user_state_tree_root: QHashOut<F>,
        max_users: usize,
    ) -> Self
    {

        assert!(global_user_tree_realm_height <= global_user_tree_height, "global_user_tree_realm_height cannot be taller than global_user_tree_height");

        let register_users_gadget = GUTARegisterUsersGadget::add_virtual_to::<H, F, D>(
            builder,
            global_user_tree_realm_height,
            global_user_tree_height,
            group_realm_height,
            default_user_state_tree_root,
            None,
            max_users
        );



        let new_guta_header = GlobalUserTreeAggregatorHeaderGadget{
            guta_circuit_whitelist: guta_circuit_whitelist,
            checkpoint_tree_root: checkpoint_tree_root,
            state_transition: register_users_gadget.get_state_transition(),
            stats: GUTAStatsGadget::add_virtual_to_zero(builder),
        };


        Self {
            new_guta_header,
            register_users_gadget,
        }
    }

    pub fn set_witness_params<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        witness: &mut impl Witness<F>,
        guta_register_user_inputs: &[GUTARegisterUserFullInput<QHashOut<F>>],
        default_user_state_tree_root: QHashOut<F>,
    ) -> anyhow::Result<()> {
        let dummy_public_key = get_default_worker_public_key();
        let dummy_user_leaf_hash = PQEDUserLeaf::new_user_default_with_zero(F::ZERO, F::ZERO, dummy_public_key, default_user_state_tree_root).p2_q_alghash::<H>();

        self.register_users_gadget.set_witness_params(
            witness,
            guta_register_user_inputs,
            dummy_public_key,
            dummy_user_leaf_hash,
        )
    }

}

impl <const D: usize> ToGUTAHeader<D> for GUTAOnlyRegisterUsersGadget{
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
        self.new_guta_header
    }
}
