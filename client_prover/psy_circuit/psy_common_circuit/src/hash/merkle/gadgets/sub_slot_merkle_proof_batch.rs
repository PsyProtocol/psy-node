use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::Target,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use super::{merkle_array_gen::enforce_merkle_array_helper_new_values_2_bit, merkle_proof::MerkleProofGadget};
use crate::builder::{math::core::CircuitBuilderCoreMathHelpers, select::CircuitBuilderSelectHelpers};

#[derive(Debug, Clone)]
pub struct SubSlotMerkleProofBatchGadget {
    pub root: HashOutTarget,
    pub merkle_proof_gadgets: Vec<MerkleProofGadget>,

    // computed
    pub values: Vec<Target>,
    pub sub_slot_index: Target,
    pub start_slot_index: Target,
    pub sub_slot_index_mod_4: Target,

    pub sub_slot_length: usize,
}
impl SubSlotMerkleProofBatchGadget {
    // calculate the normal merkle root + a historical merkle root where all the
    // leaves with index >= `gadget.index` set to zero
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
        sub_slot_length: usize,
        sub_slot_index: Target,
        force_four_align: bool,
    ) -> Self {
        let (start_slot_index, sub_slot_index_mod_4) = builder.div_rem4(sub_slot_index);

        if sub_slot_length == 1 {
            let mp = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);

            let value = builder.select_in_hash(mp.value, sub_slot_index_mod_4);

            Self {
                root: mp.root,
                merkle_proof_gadgets: vec![mp],
                values: vec![value],
                sub_slot_index,
                start_slot_index,
                sub_slot_index_mod_4,
                sub_slot_length,
            }
        } else {
            let n_proofs = (sub_slot_length + 6) / 4;

            let first_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);

            builder.connect(start_slot_index, first_proof.index);

            let root = first_proof.root;
            let mut last_slot_index_target = first_proof.index;
            let one = builder.one();

            let mut mps = Vec::with_capacity(n_proofs);
            mps.push(first_proof);
            for _ in 1..(n_proofs - 1) {
                let mp = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
                let expected_index = builder.add(last_slot_index_target, one);

                // ensure the proofs are for a contiguous portion of the tree
                builder.connect(mp.index, expected_index);

                // connect old root to previous slot's new root
                builder.connect_hashes(mp.root, root);
                last_slot_index_target = expected_index;
                mps.push(mp);
            }

            // handle last proof edge case

            let last_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
            let expected_last_proof_index = builder.add(last_slot_index_target, one);

            // ensure the proofs are for a contiguous portion of the tree
            builder.connect(last_proof.index, expected_last_proof_index);

            // connect old root to previous slot's new root
            builder.connect_hashes(last_proof.root, root);

            mps.push(last_proof);

            // TODO: figure out a better way to handle non-four aligned writes
            let values = if force_four_align {
                (0..sub_slot_length)
                    .map(|i| {
                        let mp_index = i / 4;
                        let mp_sub_index = i % 4;
                        mps[mp_index].value.elements[mp_sub_index]
                    })
                    .collect::<Vec<_>>()
            } else {
                enforce_merkle_array_helper_new_values_2_bit::<F, D>(builder, sub_slot_index_mod_4, sub_slot_length, &mps)
            };

            Self {
                root,
                merkle_proof_gadgets: mps,
                values,
                sub_slot_index,
                start_slot_index,
                sub_slot_index_mod_4,
                sub_slot_length,
            }
        }
    }
}
