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
                // The element-0 start of the values wiring below assumes the
                // read is four-aligned; mirror the write gadget and the read
                // helper in state_readers and reject misaligned indices.
                builder.assert_zero(sub_slot_index_mod_4);
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

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::{hash_types::HashOut, poseidon::PoseidonHash},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::{Hasher, PoseidonGoldilocksConfig}},
    };
    use psy_client_common::data::qhashout::QHashOut;

    use super::SubSlotMerkleProofBatchGadget;

    type F = GoldilocksField;
    const D: usize = 2;

    fn leaf(seed: u64) -> HashOut<F> {
        HashOut {
            elements: [
                F::from_canonical_u64(seed),
                F::from_canonical_u64(seed * 7 + 1),
                F::from_canonical_u64(seed * 13 + 2),
                F::from_canonical_u64(seed * 29 + 3),
            ],
        }
    }

    fn siblings_for(leaves: &[HashOut<F>], index: usize) -> Vec<HashOut<F>> {
        let mut level = leaves.to_vec();
        let mut sibs = vec![];
        let mut idx = index;
        while level.len() > 1 {
            sibs.push(level[idx ^ 1]);
            level = level.chunks(2).map(|c| PoseidonHash::two_to_one(c[0], c[1])).collect();
            idx >>= 1;
        }
        sibs
    }

    /// force_four_align asserts the read is four-aligned: r == 0 proves and
    /// verifies against the tree root, a misaligned r != 0 is rejected, and
    /// the non-aligned path is unaffected.
    #[test]
    fn force_four_align_read_rejects_misaligned_index() {
        let height = 4usize;
        let leaves: Vec<HashOut<F>> = (0..16u64).map(|i| leaf(100 + i)).collect();
        let len = 6usize;
        let n_proofs = (len + 6) / 4;

        let run = |r: u64, align: bool| -> Option<Vec<GoldilocksField>> {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let sub_slot_index = builder.constant(F::from_canonical_u64(r));
            let gadget = SubSlotMerkleProofBatchGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, height, len, sub_slot_index, align);
            assert_eq!(gadget.merkle_proof_gadgets.len(), n_proofs);
            builder.register_public_inputs(&gadget.root.elements);
            let data = builder.build::<PoseidonGoldilocksConfig>();

            let mut pw = PartialWitness::new();
            let q = |h: HashOut<F>| QHashOut(h);
            for (p, mp) in gadget.merkle_proof_gadgets.iter().enumerate() {
                let sibs: Vec<QHashOut<F>> = siblings_for(&leaves, p).into_iter().map(q).collect();
                mp.set_witness(&mut pw, F::from_canonical_usize(p), q(leaves[p]), &sibs).unwrap();
            }
            let proof = data.prove(pw).ok()?;
            data.verify(proof.clone()).ok()?;
            Some(proof.public_inputs)
        };

        let root_pi = run(0, true).expect("aligned read proves and verifies");
        let mut level = leaves.clone();
        while level.len() > 1 {
            level = level.chunks(2).map(|c| PoseidonHash::two_to_one(c[0], c[1])).collect();
        }
        assert_eq!(root_pi, level[0].elements, "read root must commit the tree");

        assert!(run(1, true).is_none(), "force_four_align read with r != 0 must be rejected");

        run(1, false).expect("non-aligned path is unaffected");
    }
}
