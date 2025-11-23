use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, nca::nca_proof::{PartialUpdateNearestCommonAncestorProof, UpdateNearestCommonAncestorProof}}, pgoldilocks::QHashOut, utils::math::log2_ceil};
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_plonky2_common_circuits::hash::merkle::gadgets::dual_variable_height_delta_merkle_proof::DualVariableHeightDeltaMerkleProofGadget;

use crate::treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget;

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, helpers::ToGUTAHeader};



#[derive(Clone, Debug)]
pub struct DualVariableHeightStateTransitionGadget {
    pub dvh_delta_merkle_proof_gadget: DualVariableHeightDeltaMerkleProofGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl DualVariableHeightStateTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a_header: GlobalUserTreeAggregatorHeaderGadget,
        b_header: GlobalUserTreeAggregatorHeaderGadget,
        max_merkle_proof_height: usize,
        tree_height: usize,
    ) -> Self {
        tracing::debug!("🔗 a_header: {:?}, b_header: {:?}", a_header, b_header);

        let dvh_delta_merkle_proof_gadget = DualVariableHeightDeltaMerkleProofGadget::add_virtual_to::<H,F,D>(
            builder, 
            max_merkle_proof_height,
            tree_height,
            None,
            Some(a_header.state_transition.old_node_value),
            Some(a_header.state_transition.new_node_value),
            Some(a_header.state_transition.node_index),
            Some(b_header.state_transition.old_node_value),
            Some(b_header.state_transition.new_node_value),
            Some(b_header.state_transition.node_index),
        );

        builder.connect_hashes(
            a_header.checkpoint_tree_root,
            b_header.checkpoint_tree_root,
        );

        builder.connect_hashes(
            a_header.guta_circuit_whitelist,
            b_header.guta_circuit_whitelist,
        );

        // for dual variable height delta merkle proofs, the height of the proofs is variable, but both left and right must have the same height
        builder.connect(
            a_header.state_transition.node_level,
            b_header.state_transition.node_level,
        );
        // ensure dvh_delta_merkle_proof_gadget.height is greater than or equal to node_level
        let node_level = a_header.state_transition.node_level;
        // the "height" of the merkle proof, aka, how many levels the sub-root is above a_header and b_header 
        let transition_height = dvh_delta_merkle_proof_gadget.height;

        // compute the new level of the transition node by subtracting the transition height from the current node level
        let new_node_level = builder.sub(
            node_level,
            transition_height,
        );
        // range check this to ensure node_level >= transition_height
        builder.range_check(new_node_level, log2_ceil(tree_height));

        // the index of the new node is equal to a_header.state_transition.node_index >> transition_height
        // this is already computed in dvh
        let new_node_index = dvh_delta_merkle_proof_gadget.parent_index;

        let old_node_value = dvh_delta_merkle_proof_gadget.old_root;
        let new_node_value = dvh_delta_merkle_proof_gadget.new_root;


        let new_stats = a_header.stats.combine_with(builder, &b_header.stats);



        let total_aggregation_proofs_generated = builder.add(a_header.total_aggregation_proofs_generated, b_header.total_aggregation_proofs_generated);
        let one = builder.one();
        let total_aggregation_proofs_generated = builder.add(total_aggregation_proofs_generated, one);

        let new_guta_header = GlobalUserTreeAggregatorHeaderGadget{
            guta_circuit_whitelist: a_header.guta_circuit_whitelist,
            checkpoint_tree_root: a_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransitionGadget {
                old_node_value,
                new_node_value,
                node_index: new_node_index,
                node_level: new_node_level
            },
            stats: new_stats,
            total_aggregation_proofs_generated,
        };

        tracing::debug!("📊 new_guta_header: {:?}", new_guta_header);








        Self {
            dvh_delta_merkle_proof_gadget,
            new_guta_header,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        child_a: &DeltaMerkleProofCore<QHashOut<F>>,
        child_b: &DeltaMerkleProofCore<QHashOut<F>>,

    ) -> anyhow::Result<()> {
        self.dvh_delta_merkle_proof_gadget.set_witness(witness,
            child_a,
            child_b,
        )
    }
    pub fn set_witness_partial<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.dvh_delta_merkle_proof_gadget.set_witness(
            witness,
            &input.child_a,
            &input.child_b,
        )
    }
    pub fn set_witness_full<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &UpdateNearestCommonAncestorProof<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.dvh_delta_merkle_proof_gadget.set_witness(
            witness,
            &input.child_a,
            &input.child_b,
        )
    }
}


impl<const D: usize> ToGUTAHeader<D> for DualVariableHeightStateTransitionGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
       self.new_guta_header.to_owned()
    }
}