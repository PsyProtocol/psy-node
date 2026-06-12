use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleZeroHasher},
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafCompactWithStateRoots;
use psy_plonky2_common_circuits::hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget;

use crate::gadgets::qdata::checkpoint_compact_with_state::QEDCheckpointLeafCompactWithStateRootsGadget;

pub const BRIDGE_AGG_BATCH_SIZE: usize = 10;

#[derive(Debug, Clone)]
pub struct BridgeAggDeltaMerkleChainGadget {
    pub delta_merkle_proofs: Vec<DeltaMerkleProofGadget>,
    pub final_leaf_preimage: QEDCheckpointLeafCompactWithStateRootsGadget,
}

impl BridgeAggDeltaMerkleChainGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        checkpoint_tree_height: usize,
    ) -> Self {
        // Create 10 append-only delta merkle proofs
        let delta_merkle_proofs: Vec<DeltaMerkleProofGadget> = (0..BRIDGE_AGG_BATCH_SIZE)
            .map(|_| DeltaMerkleProofGadget::add_virtual_to_append_only::<H, F, D>(builder, checkpoint_tree_height))
            .collect();

        // Constraint: sequential chaining
        let one = builder.one();
        for i in 1..BRIDGE_AGG_BATCH_SIZE {
            // new_root[i-1] == old_root[i]
            builder.connect_hashes(delta_merkle_proofs[i - 1].new_root, delta_merkle_proofs[i].old_root);
            // index[i] == index[i-1] + 1
            let prev_index_plus_one = builder.add(delta_merkle_proofs[i - 1].index, one);
            builder.connect(delta_merkle_proofs[i].index, prev_index_plus_one);
        }

        // Create leaf preimage gadget for the final checkpoint
        let final_leaf_preimage = QEDCheckpointLeafCompactWithStateRootsGadget::add_virtual_to::<H, F, D>(builder);

        // Constraint: Poseidon(leaf_preimage) == delta_merkle_proofs[9].new_value
        builder.connect_hashes(
            final_leaf_preimage.checkpoint_leaf_hash,
            delta_merkle_proofs[BRIDGE_AGG_BATCH_SIZE - 1].new_value,
        );

        Self {
            delta_merkle_proofs,
            final_leaf_preimage,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        delta_merkle_proofs: &[DeltaMerkleProofCore<QHashOut<F>>],
        final_leaf_preimage: &PQEDCheckpointLeafCompactWithStateRoots<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        assert_eq!(
            delta_merkle_proofs.len(),
            BRIDGE_AGG_BATCH_SIZE,
            "expected {} delta merkle proofs, got {}",
            BRIDGE_AGG_BATCH_SIZE,
            delta_merkle_proofs.len()
        );

        for (i, proof) in delta_merkle_proofs.iter().enumerate() {
            self.delta_merkle_proofs[i].set_witness_core_proof_q(witness, proof)?;
        }

        self.final_leaf_preimage.set_witness(witness, final_leaf_preimage)?;

        Ok(())
    }
}
