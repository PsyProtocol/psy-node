use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CommonCircuitData, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::ProofWithPublicInputs}};
use psy_core::constants::protocol::get_default_worker_public_key;
use psy_data::{guta::header::GlobalUserTreeAggregatorHeader, proof_input::guta::GUTARegisterUserFullInput, v1::qdata::user::PQEDUserLeaf};

use crate::{treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget, utils::alghash::AlgHashable};

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, guta_register_users::GUTARegisterUsersGadget, helpers::ToGUTAHeader, verify_guta_proof_to_line::VerifyGUTAProofToLineGadget};





#[derive(Clone, Debug)]
pub struct GUTARegisterUsersBatchGadget<const D: usize> {
    pub verify_to_line_gadget: VerifyGUTAProofToLineGadget<D>,
    pub register_users_gadget: GUTARegisterUsersGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl<const D: usize> GUTARegisterUsersBatchGadget<D> {

    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        proof_common_data: &CommonCircuitData<F, D>,
        verifier_data_cap_height: usize,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        group_realm_height: usize,
        default_user_state_tree_root: QHashOut<F>,
        max_users: usize,
        guta_circuit_whitelist_tree_height: u8,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: MerkleZeroHasher<HashOut<F>> +AlgebraicHasher<F>,
    {
        println!("GUTARegisterUsersBatchGadget::add_virtual_to: verifier_data_cap_height: {}, global_user_tree_realm_height: {}, global_user_tree_height: {}, max_users: {}", verifier_data_cap_height, global_user_tree_realm_height, global_user_tree_height, max_users);

        assert!(global_user_tree_realm_height <= global_user_tree_height, "global_user_tree_realm_height cannot be taller than global_user_tree_height");
        let verify_to_line_gadget = VerifyGUTAProofToLineGadget::<D>::add_virtual_to::<C, F>(
            builder,
            proof_common_data,
            verifier_data_cap_height,
            global_user_tree_realm_height,
            global_user_tree_height,
            guta_circuit_whitelist_tree_height,
        );
        let register_users_gadget = GUTARegisterUsersGadget::add_virtual_to::<C::Hasher, C::F, D>(
            builder,
            global_user_tree_realm_height,
            global_user_tree_height,
            group_realm_height,
            default_user_state_tree_root,
            None,
            max_users
        );

        let line_guta_header = verify_to_line_gadget.get_guta_header_line();
        let line_state_transition = line_guta_header.state_transition;
        let register_users_state_transiton = register_users_gadget.get_state_transition();

        builder.connect(
            line_state_transition.node_index,
            register_users_state_transiton.node_index,
        );
        builder.connect(
            line_state_transition.node_level,
            register_users_state_transiton.node_level,
        );
        builder.connect_hashes(
            line_state_transition.new_node_value,
            register_users_state_transiton.old_node_value,
        );


        let new_guta_header = GlobalUserTreeAggregatorHeaderGadget{
            guta_circuit_whitelist: line_guta_header.guta_circuit_whitelist,
            checkpoint_tree_root: line_guta_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransitionGadget {
                old_node_value: line_state_transition.old_node_value,
                new_node_value: register_users_state_transiton.new_node_value,
                node_index: line_state_transition.node_index,
                node_level: line_state_transition.node_level,
            },
            stats: line_guta_header.stats,
        };


        Self {
            new_guta_header,
            verify_to_line_gadget,
            register_users_gadget,
        }
    }

    pub fn set_witness_params<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        top_line_siblings: &[QHashOut<F>],
        guta_register_user_inputs: &[GUTARegisterUserFullInput<QHashOut<F>>],
        default_user_state_tree_root: QHashOut<F>,
    ) -> anyhow::Result<()> where
    <C as GenericConfig<D>>::Hasher:AlgebraicHasher<F>, {
        self.verify_to_line_gadget.set_witness(witness, guta_whitelist_merkle_proof, guta_proof_header, proof, verifier_data, top_line_siblings)?;
        let dummy_public_key = get_default_worker_public_key();
        let dummy_user_leaf_hash = PQEDUserLeaf::new_user_default_with_zero(F::ZERO, F::ZERO, dummy_public_key, default_user_state_tree_root).p2_q_alghash::<C::Hasher>();

        self.register_users_gadget.set_witness_params(
            witness,
            guta_register_user_inputs,
            dummy_public_key,
            dummy_user_leaf_hash,
        )
    }

}

impl <const D: usize> ToGUTAHeader<D> for GUTARegisterUsersBatchGadget<D> {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
        self.new_guta_header
    }
}
