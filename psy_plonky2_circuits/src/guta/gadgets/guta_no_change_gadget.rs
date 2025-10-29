
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};
use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafCompactWithStateRoots;
use psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;
use crate::{
    gadgets::qdata::checkpoint_compact_with_state::QEDCheckpointLeafCompactWithStateRootsGadget, guta::gadgets::guta_stats::GUTAStatsGadget, treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget
};

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, helpers::ToGUTAHeader};

#[derive(Clone, Debug)]
pub struct GUTANoChangeGadget {
    pub checkpoint_tree_proof: MerkleProofGadget,
    pub checkpoint_leaf_gadget: QEDCheckpointLeafCompactWithStateRootsGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl GUTANoChangeGadget {
    pub fn add_virtual_to<
        H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        guta_circuit_whitelist: HashOutTarget,
        checkpoint_tree_height: usize,
    ) -> Self {
        let checkpoint_tree_proof = MerkleProofGadget::add_virtual_to_append_only::<H, F, D>(
            builder,
            checkpoint_tree_height,
        );

        let checkpoint_leaf_gadget =
            QEDCheckpointLeafCompactWithStateRootsGadget::add_virtual_to::<H, F, D>(builder);

        let computed_checkpoint_leaf_hash = checkpoint_leaf_gadget.to_hash::<H, F, D>(builder);
        let expected_checkpoint_leaf_hash = checkpoint_tree_proof.value;

        // ensure that the checkpoint tree leaf has the state transition we want
        builder.connect_hashes(computed_checkpoint_leaf_hash, expected_checkpoint_leaf_hash);

        let zero = builder.zero();

        // value does not change and node index is the root
        let new_guta_header = GlobalUserTreeAggregatorHeaderGadget {
            guta_circuit_whitelist: guta_circuit_whitelist,
            checkpoint_tree_root: checkpoint_tree_proof.root,
            state_transition: SubTreeNodeStateTransitionGadget {
                old_node_value: checkpoint_leaf_gadget.global_state_roots.user_tree_root,
                new_node_value: checkpoint_leaf_gadget.global_state_roots.user_tree_root,
                node_index: zero,
                node_level: zero,
            },
            stats: GUTAStatsGadget {
                fees_collected: zero,
                user_ops_processed: zero,
                total_transactions: zero,
                slots_modified: zero,
            },
        };

        Self {
            checkpoint_tree_proof,
            checkpoint_leaf_gadget,

            new_guta_header,
        }
    }

    pub fn set_witness_params<
        W: Witness<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        witness: &mut W,
        checkpoint_tree_proof: &MerkleProofCore<QHashOut<F>>,
        checkpoint_leaf: &PQEDCheckpointLeafCompactWithStateRoots<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.checkpoint_tree_proof
            .set_witness_core_proof_q_generic(witness, checkpoint_tree_proof)?;

        self.checkpoint_leaf_gadget
            .set_witness(witness, checkpoint_leaf)?;

        Ok(())
    }
}

impl<const D: usize> ToGUTAHeader<D> for GUTANoChangeGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
        _default_guta_circuit_whitelist: HashOutTarget,
    ) -> GlobalUserTreeAggregatorHeaderGadget {
        self.new_guta_header
    }
}
