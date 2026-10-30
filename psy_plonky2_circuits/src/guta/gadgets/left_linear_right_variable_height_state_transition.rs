use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_plonky2_common_circuits::hash::merkle::gadgets::q_variable_height_delta_merkle_proof::QVariableHeightDeltaMerkleProofGadget;

use crate::treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget;

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, helpers::ToGUTAHeader};



#[derive(Clone, Debug)]
pub struct LeftLinearRightVariableHeightStateTransitionGadget {
    pub right_delta_merkle_proof_gadget: QVariableHeightDeltaMerkleProofGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl LeftLinearRightVariableHeightStateTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a_header: GlobalUserTreeAggregatorHeaderGadget,
        b_header: GlobalUserTreeAggregatorHeaderGadget,
        max_merkle_proof_height: usize,
        tree_height: usize,
    ) -> Self {
        tracing::debug!("🔗 a_header: {:?}, b_header: {:?}", a_header, b_header);

        let right_delta_merkle_proof_gadget = QVariableHeightDeltaMerkleProofGadget::add_virtual_to::<H,F,D>(
            builder, 
            max_merkle_proof_height,
            tree_height,
            None,
            Some(b_header.state_transition.old_node_value),
            Some(b_header.state_transition.new_node_value),
            Some(b_header.state_transition.node_index),
        );
        let right_parent_level = right_delta_merkle_proof_gadget.get_parent_level::<F, D>(
            builder,
            b_header.state_transition.node_level,
        );

        builder.connect_hashes(
            a_header.checkpoint_tree_root,
            b_header.checkpoint_tree_root,
        );

        builder.connect_hashes(
            a_header.guta_circuit_whitelist,
            b_header.guta_circuit_whitelist,
        );
        // the left aggregation's end root is the subtree state the right proof starts from
        builder.connect_hashes(
            a_header.state_transition.new_node_value,
            right_delta_merkle_proof_gadget.old_root,
        );
        // ensure that the node for a_header matches the parent node of the right delta merkle proof
        builder.connect(
            a_header.state_transition.node_index,
            right_delta_merkle_proof_gadget.parent_index,
        );
        builder.connect(
            a_header.state_transition.node_level,
            right_parent_level,
        );
        let new_node_index = a_header.state_transition.node_index;
        // ensure dvh_delta_merkle_proof_gadget.height is greater than or equal to node_level
        let new_node_level = a_header.state_transition.node_level;
        // the "height" of the merkle proof, aka, how many levels the sub-root is above a_header and b_header 
        
        let old_node_value = a_header.state_transition.old_node_value;
        let new_node_value = right_delta_merkle_proof_gadget.new_root;


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









        Self {
            right_delta_merkle_proof_gadget,
            new_guta_header,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        right_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.right_delta_merkle_proof_gadget.set_witness(witness,
            right_delta_merkle_proof,
        )
    }
}


impl<const D: usize> ToGUTAHeader<D> for LeftLinearRightVariableHeightStateTransitionGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
       self.new_guta_header.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::merkle_proof::DeltaMerkleProofCore,
        data::hash::merkle_node_key::SimpleMerkleNodeKey,
        pgoldilocks::{PoseidonHasher, QHashOut},
    };
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        field::types::Field,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::super::guta_header::GlobalUserTreeAggregatorHeaderGadget;
    use super::LeftLinearRightVariableHeightStateTransitionGadget;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    type H = <C as GenericConfig<D>>::Hasher;

    fn chain_witness(forged: bool) -> anyhow::Result<()> {
        let tree_height = 2usize;
        let mut store = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, QHashOut<F>>::new(tree_height as u8);
        let index = 1u64;
        let old_value = QHashOut::from_values(1, 2, 3, 4);
        let new_value = QHashOut::from_values(9, 8, 7, 6);
        store.set_leaf_no_proof(index, old_value);
        let start = store.get_leaf_in_subtree(1, 2, index);
        store.set_node_value(SimpleMerkleNodeKey::new(2, index), new_value);
        store.rehash_from_node_to_level(SimpleMerkleNodeKey::new(2, index), 1);
        let end = store.get_leaf_in_subtree(1, 2, index);
        let dmp = DeltaMerkleProofCore {
            old_root: start.root,
            old_value: start.value,
            new_root: end.root,
            new_value,
            index,
            siblings: start.siblings,
        };

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let a_header = GlobalUserTreeAggregatorHeaderGadget::add_virtual_to(&mut builder);
        let b_header = GlobalUserTreeAggregatorHeaderGadget::add_virtual_to(&mut builder);
        let gadget = LeftLinearRightVariableHeightStateTransitionGadget::add_virtual_to::<H, F, D>(
            &mut builder,
            a_header,
            b_header,
            tree_height,
            tree_height,
        );

        let mut pw = PartialWitness::new();
        let checkpoint_tree_root = QHashOut::from_values(7, 7, 7, 7);
        let whitelist = QHashOut::from_values(8, 8, 8, 8);
        let end_root = if forged { QHashOut::ZERO } else { dmp.old_root };
        set_header_witness(&mut pw, &a_header, whitelist, checkpoint_tree_root, QHashOut::ZERO, end_root, index >> 1, 1)?;
        set_header_witness(&mut pw, &b_header, whitelist, checkpoint_tree_root, old_value, new_value, index, 2)?;
        gadget.set_witness_params(&mut pw, &dmp)?;

        let data = builder.build::<C>();
        match data.prove(pw) {
            Err(_) => assert!(forged, "honest chain must be provable"),
            Ok(proof) => {
                if forged {
                    assert!(data.verify(proof).is_err(), "a spliced transition must not verify");
                } else {
                    data.verify(proof)?;
                }
            }
        }
        Ok(())
    }

    fn set_header_witness(
        witness: &mut PartialWitness<F>,
        header: &GlobalUserTreeAggregatorHeaderGadget,
        whitelist: QHashOut<F>,
        checkpoint_tree_root: QHashOut<F>,
        old_node_value: QHashOut<F>,
        new_node_value: QHashOut<F>,
        node_index: u64,
        node_level: u64,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(header.guta_circuit_whitelist, whitelist.0)?;
        witness.set_hash_target(header.checkpoint_tree_root, checkpoint_tree_root.0)?;
        witness.set_hash_target(header.state_transition.old_node_value, old_node_value.0)?;
        witness.set_hash_target(header.state_transition.new_node_value, new_node_value.0)?;
        witness.set_target(header.state_transition.node_index, F::from_noncanonical_u64(node_index))?;
        witness.set_target(header.state_transition.node_level, F::from_noncanonical_u64(node_level))?;
        for target in [
            header.stats.guta_fees_collected,
            header.stats.da_fees_collected,
            header.stats.user_ops_processed,
            header.stats.total_transactions,
            header.stats.slots_modified,
            header.total_aggregation_proofs_generated,
        ] {
            witness.set_target(target, F::ZERO)?;
        }
        Ok(())
    }

    #[test]
    fn accepts_a_chained_transition() -> Result<()> {
        chain_witness(false)
    }

    #[test]
    fn rejects_splicing_two_unrelated_transitions() -> Result<()> {
        chain_witness(true)
    }
}