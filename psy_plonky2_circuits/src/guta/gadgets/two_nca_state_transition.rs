use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, nca::nca_proof::{PartialUpdateNearestCommonAncestorProof, UpdateNearestCommonAncestorProof}}, pgoldilocks::QHashOut};
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_plonky2_common_circuits::hash::merkle::gadgets::sub_tree_update_proof_opt::UpdateNearestCommonAncestorProofOptGadget;

use crate::treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget;

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, helpers::ToGUTAHeader};



#[derive(Clone, Debug)]
pub struct TwoNCAStateTransitionGadget {
    pub update_nca_proof_gadget: UpdateNearestCommonAncestorProofOptGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl TwoNCAStateTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a_header: GlobalUserTreeAggregatorHeaderGadget,
        b_header: GlobalUserTreeAggregatorHeaderGadget,
        global_user_tree_height: u8,
    ) -> Self {
        tracing::debug!("🔗 a_header: {:?}, b_header: {:?}", a_header, b_header);

        let update_nca_proof_gadget = UpdateNearestCommonAncestorProofOptGadget::add_virtual_to_full::<H,F,D>(builder, global_user_tree_height as usize);

        // TODO: WHY WAS THIS REMOVED, I am adding back!?!!, we need to make sure a and b have the same checkpoint root
        builder.connect_hashes(
            a_header.checkpoint_tree_root,
            b_header.checkpoint_tree_root,
        );

        builder.connect_hashes(
            a_header.guta_circuit_whitelist,
            b_header.guta_circuit_whitelist,
        );


        builder.connect_hashes(
            a_header.state_transition.old_node_value,
            update_nca_proof_gadget.child_a.old_value,
        );
        builder.connect_hashes(
            a_header.state_transition.new_node_value,
            update_nca_proof_gadget.child_a.new_value,
        );
        builder.connect(
            a_header.state_transition.node_index,
            update_nca_proof_gadget.child_a.index,
        );

        builder.connect(
            a_header.state_transition.node_level,
            update_nca_proof_gadget.level_a,
        );


        builder.connect_hashes(
            b_header.state_transition.old_node_value,
            update_nca_proof_gadget.child_b.old_value,
        );
        builder.connect_hashes(
            b_header.state_transition.new_node_value,
            update_nca_proof_gadget.child_b.new_value,
        );
        builder.connect(
            b_header.state_transition.node_index,
            update_nca_proof_gadget.child_b.index,
        );

        builder.connect(
            b_header.state_transition.node_level,
            update_nca_proof_gadget.level_b,
        );

        let new_stats = a_header.stats.combine_with(builder, &b_header.stats);



        let new_guta_header = GlobalUserTreeAggregatorHeaderGadget{
            guta_circuit_whitelist: a_header.guta_circuit_whitelist,
            checkpoint_tree_root: a_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransitionGadget {
                old_node_value: update_nca_proof_gadget.old_nearest_common_ancestor_value,
                new_node_value: update_nca_proof_gadget.new_nearest_common_ancestor_value,
                node_index: update_nca_proof_gadget.nearest_common_ancestor_index,
                node_level: update_nca_proof_gadget.nearest_common_ancestor_level
            },
            stats: new_stats,
        };

        tracing::debug!("📊 new_guta_header: {:?}", new_guta_header);








        Self {
            update_nca_proof_gadget,
            new_guta_header,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        child_a: &DeltaMerkleProofCore<QHashOut<F>>,
        child_b: &DeltaMerkleProofCore<QHashOut<F>>,
        nearest_common_ancestor_level: u8

    ) -> anyhow::Result<()> {
        self.update_nca_proof_gadget.set_witness_params(witness,
            child_a,
            child_b,
            nearest_common_ancestor_level
        )
    }
    pub fn set_witness_partial<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.update_nca_proof_gadget.set_witness_partial(
            witness,
            input,
        )
    }
    pub fn set_witness_full<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        input: &UpdateNearestCommonAncestorProof<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.update_nca_proof_gadget.set_witness_full(
            witness,
            input,
        )
    }
}


impl<const D: usize> ToGUTAHeader<D> for TwoNCAStateTransitionGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
       self.new_guta_header.to_owned()
    }
}
/*
impl CreatableWithHasherTarget for TwoNCAStateTransitionGadget {
    fn create_virtual_with_hasher<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}
impl AlgebraicHashableTarget for TwoNCAStateTransitionGadget {
    fn to_hash_target<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<TwoNCAStateTransitionGadget, F, true>
    for UserProvingSessionHeader<F>
{
    fn set_for_witness(
        &self,
        witness: &mut impl Witness<F>,
        target: &TwoNCAStateTransitionGadget,
    ) {
        target.set_witness(witness, self);
    }
}

impl<F: RichField> WitnessValueFor<TwoNCAStateTransitionGadget, F, false>
    for UserProvingSessionHeader<F>
{
    fn set_for_witness(
        &self,
        witness: &mut impl Witness<F>,
        target: &TwoNCAStateTransitionGadget,
    ) {
        target.set_witness(witness, self);
    }
}
*/
