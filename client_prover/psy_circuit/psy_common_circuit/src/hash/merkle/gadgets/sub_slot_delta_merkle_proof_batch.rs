use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use super::delta_merkle_proof::DeltaMerkleProofGadget;
use crate::builder::{
    comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore,
    math::core::CircuitBuilderCoreMathHelpers,
};

/*
this gadget helps you prove that an append only merkle tree with a current root `current_root` once had a root of `historical_root`
another way to think of this gadget is that it proves that, if you take a tree with root X and set all the leaves with index >= `gadget.index` to zero, the tree will have a new root Y
*/
#[derive(Debug, Clone)]
pub struct SubSlotDeltaMerkleProofBatchGadget {
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
    pub delta_merkle_proof_gadgets: Vec<DeltaMerkleProofGadget>,

    // computed
    pub values: Vec<Target>,
    pub sub_slot_index: Target,
    pub start_slot_index: Target,
    pub sub_slot_index_mod_4: Target,

    pub sub_slot_length: usize,
}

#[derive(Debug, Clone)]
pub struct SubSlotStartGadget {
    pub is_sub_slot_index_mod_4_eq_0: BoolTarget,
    pub is_sub_slot_index_mod_4_eq_1: BoolTarget,
    pub is_sub_slot_index_mod_4_eq_2: BoolTarget,
    pub is_sub_slot_index_mod_4_eq_3: BoolTarget,
    pub is_ssim4_eq_1_or_2: BoolTarget,
    pub is_ssim4_eq_1_or_2_or_3: BoolTarget,
    pub sub_slot_index_mod_4: Target,

    pub sub_slot_length: usize,
}
/*

const SLOT_MASK_TABLE: [[u8; 4]; 7] = [
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [1, 0, 0, 0],
    [1, 1, 0, 0],
    [1, 1, 1, 0],
    [1, 1, 1, 1],
];
*/
impl SubSlotStartGadget {
    fn enforce_targets_from_dmps<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        dmps: &[DeltaMerkleProofGadget],
        targets: &[Target],
        condition: Option<BoolTarget>,
    ) {
        self.enforce_targets_from_dmps_with_offset::<H, F, D>(builder, self.is_sub_slot_index_mod_4_eq_0, dmps, targets, 0, condition);
        self.enforce_targets_from_dmps_with_offset::<H, F, D>(builder, self.is_sub_slot_index_mod_4_eq_1, dmps, targets, 1, condition);
        self.enforce_targets_from_dmps_with_offset::<H, F, D>(builder, self.is_sub_slot_index_mod_4_eq_2, dmps, targets, 2, condition);
        self.enforce_targets_from_dmps_with_offset::<H, F, D>(builder, self.is_sub_slot_index_mod_4_eq_3, dmps, targets, 3, condition);
    }
    fn enforce_targets_from_dmps_with_offset<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        dmps: &[DeltaMerkleProofGadget],
        targets: &[Target],
        offset: usize,
        write_condition: Option<BoolTarget>,
    ) {
        for (i, t) in targets.iter().enumerate() {
            let dmp_index = (i + offset) / 4;
            let dmp_sub_index = (i + offset) % 4;
            match write_condition {
                Some(write_condition) => {
                    let enabled = builder.and(condition, write_condition);
                    builder.connect_if_true(enabled, *t, dmps[dmp_index].new_value.elements[dmp_sub_index]);
                }
                None => {
                    builder.connect_if_true(condition, *t, dmps[dmp_index].new_value.elements[dmp_sub_index]);
                }
            }
        }
    }
    fn enforce_final_mask<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        old_last_value: HashOutTarget,
        new_last_value: HashOutTarget,
    ) {
        let len_minus_2_mod_4 = (self.sub_slot_length - 2) % 4;
        if len_minus_2_mod_4 == 0 {
            /*
                [0, 0, 0, 0], // self.sub_slot_index_mod_4 == 0
                [0, 0, 0, 0], // self.sub_slot_index_mod_4 == 1
                [0, 0, 0, 0], // self.sub_slot_index_mod_4 == 2
                [1, 0, 0, 0], // self.sub_slot_index_mod_4 == 3
            */
            builder.connect_if_false(self.is_sub_slot_index_mod_4_eq_3, old_last_value.elements[0], new_last_value.elements[0]);

            builder.connect(old_last_value.elements[1], new_last_value.elements[1]);

            builder.connect(old_last_value.elements[2], new_last_value.elements[2]);

            builder.connect(old_last_value.elements[3], new_last_value.elements[3]);
        } else if len_minus_2_mod_4 == 1 {
            /*
                [0, 0, 0, 0], // self.sub_slot_index_mod_4 == 0
                [0, 0, 0, 0], // self.sub_slot_index_mod_4 == 1
                [1, 0, 0, 0], // self.sub_slot_index_mod_4 == 2
                [1, 1, 0, 0], // self.sub_slot_index_mod_4 == 3
            */
            let is_ssim4_eq_2_or_3 = builder.or(self.is_sub_slot_index_mod_4_eq_2, self.is_sub_slot_index_mod_4_eq_3);

            builder.connect_if_false(is_ssim4_eq_2_or_3, old_last_value.elements[0], new_last_value.elements[0]);

            builder.connect_if_false(self.is_sub_slot_index_mod_4_eq_3, old_last_value.elements[1], new_last_value.elements[1]);

            builder.connect(old_last_value.elements[2], new_last_value.elements[2]);

            builder.connect(old_last_value.elements[3], new_last_value.elements[3]);
        } else if len_minus_2_mod_4 == 2 {
            /*
                [0, 0, 0, 0], // self.sub_slot_index_mod_4 == 0
                [1, 0, 0, 0], // self.sub_slot_index_mod_4 == 1
                [1, 1, 0, 0], // self.sub_slot_index_mod_4 == 2
                [1, 1, 1, 0], // self.sub_slot_index_mod_4 == 3
            */
            let is_ssim4_eq_2_or_3 = builder.or(self.is_sub_slot_index_mod_4_eq_2, self.is_sub_slot_index_mod_4_eq_3);

            // connect if self.sub_slot_index_mod_4 == 0
            builder.connect_if_false(self.is_ssim4_eq_1_or_2_or_3, old_last_value.elements[0], new_last_value.elements[0]);

            // connect if 2 or 3
            builder.connect_if_false(is_ssim4_eq_2_or_3, old_last_value.elements[1], new_last_value.elements[1]);

            // connect if not 3
            builder.connect_if_false(self.is_sub_slot_index_mod_4_eq_3, old_last_value.elements[2], new_last_value.elements[2]);

            builder.connect(old_last_value.elements[3], new_last_value.elements[3]);
        } else {
            //else if len_minus_2_mod_4 == 3 {
            /*
                [1, 0, 0, 0], // self.sub_slot_index_mod_4 == 0
                [1, 1, 0, 0], // self.sub_slot_index_mod_4 == 0
                [1, 1, 1, 0], // self.sub_slot_index_mod_4 == 0
                [1, 1, 1, 1], // self.sub_slot_index_mod_4 == 0
            */
            let is_ssim4_eq_2_or_3 = builder.or(self.is_sub_slot_index_mod_4_eq_2, self.is_sub_slot_index_mod_4_eq_3);

            // connect if zero
            builder.connect_if_false(self.is_ssim4_eq_1_or_2_or_3, old_last_value.elements[1], new_last_value.elements[1]);

            // connect if not 2 or 3
            builder.connect_if_false(is_ssim4_eq_2_or_3, old_last_value.elements[2], new_last_value.elements[2]);

            // connect if not 3
            builder.connect_if_false(self.is_sub_slot_index_mod_4_eq_3, old_last_value.elements[3], new_last_value.elements[3]);
        }
    }
}
fn connect_sub_slot_start_mask_4_delta_merkle_proof<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    sub_slot_index_mod_4: Target,
    old_value: HashOutTarget,
    new_value: HashOutTarget,
    sub_slot_length: usize,
) -> SubSlotStartGadget {
    let is_sub_slot_index_mod_4_eq_1 = builder.is_equal_to_u64(sub_slot_index_mod_4, 1);
    let is_sub_slot_index_mod_4_eq_2 = builder.is_equal_to_u64(sub_slot_index_mod_4, 2);
    let is_sub_slot_index_mod_4_eq_3 = builder.is_equal_to_u64(sub_slot_index_mod_4, 3);
    let is_ssim4_eq_1_or_2 = builder.or(is_sub_slot_index_mod_4_eq_1, is_sub_slot_index_mod_4_eq_2);
    let is_ssim4_eq_1_or_2_or_3 = builder.or(is_ssim4_eq_1_or_2, is_sub_slot_index_mod_4_eq_3);

    let is_sub_slot_index_mod_4_eq_0 = builder.not(is_ssim4_eq_1_or_2_or_3);

    // if sub_slot_index_mod_4 == 1, mask is [0,1,1,1]
    builder.connect_if_true(is_sub_slot_index_mod_4_eq_1, old_value.elements[0], new_value.elements[0]);

    // if sub_slot_index_mod_4 == 2, mask is [0,0,1,1]
    builder.connect_if_true(is_sub_slot_index_mod_4_eq_2, old_value.elements[0], new_value.elements[0]);
    builder.connect_if_true(is_sub_slot_index_mod_4_eq_2, old_value.elements[1], new_value.elements[1]);

    // if sub_slot_index_mod_4 == 3, mask is [0,0,0,1]
    builder.connect_if_true(is_sub_slot_index_mod_4_eq_3, old_value.elements[0], new_value.elements[0]);
    builder.connect_if_true(is_sub_slot_index_mod_4_eq_3, old_value.elements[1], new_value.elements[1]);
    builder.connect_if_true(is_sub_slot_index_mod_4_eq_3, old_value.elements[2], new_value.elements[2]);

    SubSlotStartGadget {
        is_sub_slot_index_mod_4_eq_0,
        is_sub_slot_index_mod_4_eq_1,
        is_sub_slot_index_mod_4_eq_2,
        is_sub_slot_index_mod_4_eq_3,
        is_ssim4_eq_1_or_2,
        is_ssim4_eq_1_or_2_or_3,
        sub_slot_length,
        sub_slot_index_mod_4,
    }
}

impl SubSlotDeltaMerkleProofBatchGadget {
    // calculate the normal merkle root + a historical merkle root where all the
    // leaves with index >= `gadget.index` set to zero
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
        sub_slot_index: Target,
        values: Vec<Target>,
        force_four_align: bool,
        write_condition: Option<BoolTarget>,
    ) -> Self {
        let sub_slot_length = values.len();

        let (start_slot_index, sub_slot_index_mod_4) = builder.div_rem4(sub_slot_index);

        if sub_slot_length == 1 {
            let dmp = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
            let expected_new_value = builder.set_target_in_hash(dmp.old_value, sub_slot_index_mod_4, values[0]);
            builder.connect_hashes(dmp.new_value, expected_new_value);

            // ensure the proof starts at the correct slot index
            builder.connect(start_slot_index, dmp.index);

            Self {
                old_root: dmp.old_root,
                new_root: dmp.new_root,
                delta_merkle_proof_gadgets: vec![dmp],
                values,
                sub_slot_index,
                start_slot_index,
                sub_slot_index_mod_4,
                sub_slot_length,
            }
        } else if sub_slot_length < 6 {
            let dmp_0 = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
            let dmp_1 = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);

            if force_four_align {
                builder.assert_zero(sub_slot_index_mod_4);
            }

            // ensure the delta merkle proofs are back to back
            builder.connect_hashes(dmp_0.new_root, dmp_1.old_root);

            // ensure the proof starts at the correct slot index
            builder.connect(start_slot_index, dmp_0.index);

            let one = builder.one();
            let end_index = builder.add(start_slot_index, one);

            // ensure the proof ends at the start_slot_index + 1
            builder.connect(dmp_1.index, end_index);

            let first_gadget = connect_sub_slot_start_mask_4_delta_merkle_proof::<H, F, D>(
                builder,
                sub_slot_index_mod_4,
                dmp_0.old_value,
                dmp_0.new_value,
                sub_slot_length,
            );

            // dmp_0 tail mask: elements of the first proof outside the write
            // window [sub_slot_index, sub_slot_index + sub_slot_length) must
            // stay unchanged. Element e stays unchanged iff
            // sub_slot_index_mod_4 <= e - sub_slot_length. The gap exists for
            // len in 2..3 with r + len < 4 ((2,0), (2,1), (3,0)); for len >= 4
            // this adds no constraints (the window always covers [r, 4)).
            let is_mod4_eq_2_or_3 = builder.or(first_gadget.is_sub_slot_index_mod_4_eq_2, first_gadget.is_sub_slot_index_mod_4_eq_3);
            for e in 0..4isize {
                let c = e - sub_slot_length as isize;
                // unchanged iff sub_slot_index_mod_4 <= c
                if c < 0 {
                    continue;
                }
                let cond = if c >= 3 {
                    None
                } else if c == 2 {
                    Some(builder.not(first_gadget.is_sub_slot_index_mod_4_eq_3))
                } else if c == 1 {
                    Some(builder.not(is_mod4_eq_2_or_3))
                } else {
                    Some(first_gadget.is_sub_slot_index_mod_4_eq_0)
                };
                match cond {
                    Some(cond) => builder.connect_if_true(cond, dmp_0.old_value.elements[e as usize], dmp_0.new_value.elements[e as usize]),
                    None => builder.connect(dmp_0.old_value.elements[e as usize], dmp_0.new_value.elements[e as usize]),
                }
            }

            let old_root = dmp_0.old_root;
            let new_root = dmp_1.new_root;

            first_gadget.enforce_final_mask::<H, F, D>(builder, dmp_1.old_value, dmp_1.new_value);
            let dmps = vec![dmp_0, dmp_1];
            if force_four_align {
                for (i, t) in values.iter().enumerate() {
                    let dmp_index = i / 4;
                    let dmp_sub_index = i % 4;
                    match write_condition {
                        Some(condition) => builder.connect_if_true(condition, *t, dmps[dmp_index].new_value.elements[dmp_sub_index]),
                        None => builder.connect(*t, dmps[dmp_index].new_value.elements[dmp_sub_index]),
                    }
                }
            } else {
                first_gadget.enforce_targets_from_dmps::<H, F, D>(builder, &dmps, &values, write_condition);
            }

            Self {
                old_root,
                new_root,
                delta_merkle_proof_gadgets: dmps,
                values,
                sub_slot_index,
                start_slot_index,
                sub_slot_index_mod_4,
                sub_slot_length,
            }
        } else {
            let n_proofs = (sub_slot_length + 6) / 4;

            let first_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);

            builder.connect(start_slot_index, first_proof.index);

            let first_gadget = connect_sub_slot_start_mask_4_delta_merkle_proof::<H, F, D>(
                builder,
                sub_slot_index_mod_4,
                first_proof.old_value,
                first_proof.new_value,
                sub_slot_length,
            );
            let start_root = first_proof.old_root;
            let mut last_slot_index_target = first_proof.index;
            let mut last_slot_new_root = first_proof.new_root;
            let one = builder.one();

            let mut dmps = Vec::with_capacity(n_proofs);
            dmps.push(first_proof);
            let is_mod4_eq_2_or_3 = builder.or(first_gadget.is_sub_slot_index_mod_4_eq_2, first_gadget.is_sub_slot_index_mod_4_eq_3);
            for proof_i in 1..(n_proofs - 1) {
                let dmp = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
                let expected_index = builder.add(last_slot_index_target, one);

                // ensure the proofs are for a contiguous portion of the tree
                builder.connect(dmp.index, expected_index);

                // connect old root to previous slot's new root
                builder.connect_hashes(dmp.old_root, last_slot_new_root);

                // Elements of this proof outside the write window
                // [sub_slot_index, sub_slot_index + sub_slot_length) must stay
                // unchanged. Since sub_slot_index_mod_4 < 4 <= 4 * proof_i, the
                // write always starts at element 0 of a middle proof, so only
                // the tail needs masking: element e stays unchanged iff
                // sub_slot_index_mod_4 <= e - (sub_slot_length - 4 * proof_i).
                let tail_start = sub_slot_length as isize - 4 * proof_i as isize;
                for e in 0..4isize {
                    let c = e - tail_start;
                    // unchanged iff sub_slot_index_mod_4 <= c
                    if c < 0 {
                        continue;
                    }
                    let cond = if c >= 3 {
                        None
                    } else if c == 2 {
                        Some(builder.not(first_gadget.is_sub_slot_index_mod_4_eq_3))
                    } else if c == 1 {
                        Some(builder.not(is_mod4_eq_2_or_3))
                    } else {
                        Some(first_gadget.is_sub_slot_index_mod_4_eq_0)
                    };
                    match cond {
                        Some(cond) => builder.connect_if_true(cond, dmp.old_value.elements[e as usize], dmp.new_value.elements[e as usize]),
                        None => builder.connect(dmp.old_value.elements[e as usize], dmp.new_value.elements[e as usize]),
                    }
                }

                last_slot_new_root = dmp.new_root;
                last_slot_index_target = expected_index;
                dmps.push(dmp);
            }

            // handle last proof edge case

            let last_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
            let expected_last_proof_index = builder.add(last_slot_index_target, one);

            // ensure the proofs are for a contiguous portion of the tree
            builder.connect(last_proof.index, expected_last_proof_index);

            // connect old root to previous slot's new root
            builder.connect_hashes(last_proof.old_root, last_slot_new_root);

            // enforce the last proof edge constraints
            first_gadget.enforce_final_mask::<H, F, D>(builder, last_proof.old_value, last_proof.new_value);

            let old_root = start_root;
            let new_root = last_proof.new_root;

            dmps.push(last_proof);

            // TODO: figure out a better way to handle non-four aligned writes
            if force_four_align {
                // The element-0 start of the values wiring below assumes the
                // write is four-aligned; mirror the < 6 branch and the read
                // helper and reject misaligned indices outright.
                builder.assert_zero(sub_slot_index_mod_4);
                for (i, t) in values.iter().enumerate() {
                    let dmp_index = i / 4;
                    let dmp_sub_index = i % 4;
                    match write_condition {
                        Some(condition) => builder.connect_if_true(condition, *t, dmps[dmp_index].new_value.elements[dmp_sub_index]),
                        None => builder.connect(*t, dmps[dmp_index].new_value.elements[dmp_sub_index]),
                    }
                }
            } else {
                first_gadget.enforce_targets_from_dmps::<H, F, D>(builder, &dmps, &values, write_condition);
            }

            Self {
                old_root,
                new_root,
                delta_merkle_proof_gadgets: dmps,
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

    use super::SubSlotDeltaMerkleProofBatchGadget;

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

    fn tree_root(leaves: &[HashOut<F>]) -> HashOut<F> {
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            level = level.chunks(2).map(|c| PoseidonHash::two_to_one(c[0], c[1])).collect();
        }
        level[0]
    }

    // siblings bottom-up for `index`, matching compute_root_bits (bit=1: node is the right child)
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

    /// Regression for the middle-proof mask fix (audit H1): elements of any
    /// proof that fall outside the write window
    /// [sub_slot_index, sub_slot_index + sub_slot_length) are pinned to
    /// old == new. An honest witness proves and verifies; a witness that
    /// smuggles an unauthorized value into a middle proof's uncovered tail —
    /// with every delta proof and the whole root chain recomputed so the
    /// witness is fully self-consistent and no generator is involved — must
    /// be rejected by the constraint system itself.
    #[test]
    fn middle_proof_tail_elements_outside_write_window_are_pinned() {
        let height = 4usize;
        let leaves0: Vec<HashOut<F>> = (0..16u64).map(|i| leaf(100 + i)).collect();

        // (len, r, tampered (proof, element) outside the write window, force_four_align)
        let cases: Vec<(usize, u64, Option<(usize, usize)>, bool)> = vec![
            (6, 0, Some((1, 2)), false), // original H1 gap: len%4==2, r<=1
            (6, 1, Some((1, 3)), false), // len%4==2, r==1
            (7, 0, Some((1, 3)), false), // len%4==3, r==0
            (10, 0, Some((2, 2)), false),
            (10, 1, Some((2, 3)), false),
            // < 6 two-proof branch: dmp_0 tail gap when the window ends inside dmp_0
            (2, 0, Some((0, 2)), false), // window [0,2): dmp_0 elements 2,3 exposed
            (2, 1, Some((0, 3)), false), // window [1,3): dmp_0 element 3 exposed
            (3, 0, Some((0, 3)), false), // window [0,3): dmp_0 element 3 exposed
            (6, 0, None, false), // honest control
            (7, 3, None, false), // honest: write ends inside the last proof
            (9, 3, None, false), // honest: middles fully covered, r==3
            (12, 0, None, false), // honest: len%4==0, write ends on a proof boundary
            (2, 2, None, false), // honest <6: window ends exactly at dmp_0 tail
            (4, 0, None, false), // honest <6: dmp_0 fully written, dmp_1 fully frozen
            (5, 0, None, false), // honest <6: dmp_1 element 0 written only
            (5, 3, None, false), // honest <6: window spans into dmp_1 fully
            // force_four_align: aligned writes pass in both branches, a
            // misaligned index must be rejected outright
            (6, 0, None, true),
            (5, 0, None, true),
            (6, 1, None, true), // misaligned: must fail
        ];

        for &(len, r, tamper, align) in &cases {
            let write: Vec<u64> = (0..len).map(|i| 500 + i as u64).collect();
            let n_proofs = (len + 6) / 4;
            assert!(n_proofs >= 2, "len >= 6 expected");

            // Final slot values: elements inside [r, r+len) get the write
            // values; a tampered (proof, element) outside the window gets an
            // unauthorized value instead of staying unchanged.
            let mut slots_final: Vec<HashOut<F>> = leaves0.clone();
            for p in 0..n_proofs {
                for e in 0..4usize {
                    let g = 4 * p + e;
                    if g as u64 >= r && (g as u64) < r + len as u64 {
                        slots_final[p].elements[e] = F::from_canonical_u64(write[g - r as usize]);
                    } else if tamper == Some((p, e)) {
                        slots_final[p].elements[e] = F::from_canonical_u64(0xDEAD_BEEF);
                    }
                }
            }

            // Cumulative tree states: state s = leaves after applying slots 0..s.
            let mut states: Vec<Vec<HashOut<F>>> = Vec::with_capacity(n_proofs + 1);
            states.push(leaves0.clone());
            for p in 0..n_proofs {
                let mut st = states[p].clone();
                st[p] = slots_final[p];
                states.push(st);
            }

            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let sub_slot_index = builder.constant(F::from_canonical_u64(r));
            let values: Vec<_> = (0..len).map(|_| builder.add_virtual_target()).collect();
            let gadget =
                SubSlotDeltaMerkleProofBatchGadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, height, sub_slot_index, values.clone(), align, None);
            assert_eq!(gadget.delta_merkle_proof_gadgets.len(), n_proofs, "n_proofs = (len+6)/4");
            builder.register_public_inputs(&gadget.old_root.elements);
            builder.register_public_inputs(&gadget.new_root.elements);
            let data = builder.build::<PoseidonGoldilocksConfig>();

            let mut pw = PartialWitness::new();
            for (i, v) in values.iter().enumerate() {
                pw.set_target(*v, F::from_canonical_u64(write[i])).unwrap();
            }
            let q = |h: HashOut<F>| QHashOut(h);
            for (p, dmp) in gadget.delta_merkle_proof_gadgets.iter().enumerate() {
                let sibs: Vec<QHashOut<F>> = siblings_for(&states[p], p).into_iter().map(q).collect();
                dmp.set_witness(&mut pw, F::from_canonical_usize(p), q(states[p][p]), q(slots_final[p]), &sibs).unwrap();
            }

            let proved = match data.prove(pw) {
                Ok(proof) => {
                    assert!(data.verify(proof.clone()).is_ok(), "proved witness must verify (len={len}, r={r})");
                    let new_root: Vec<GoldilocksField> = proof.public_inputs[4..8].to_vec();
                    assert_eq!(new_root, tree_root(&states[n_proofs]).elements, "verified new root must commit the final tree (len={len}, r={r})");
                    true
                }
                Err(_) => false,
            };

            match (tamper, align && r != 0) {
                (None, false) => assert!(proved, "honest witness must prove and verify (len={len}, r={r}, align={align})"),
                (Some((p, e)), _) => assert!(!proved, "tampered middle-proof element ({p},{e}) outside the write window must be rejected (len={len}, r={r})"),
                (None, true) => assert!(!proved, "force_four_align with a misaligned sub_slot_index must be rejected (len={len}, r={r})"),
            }
        }
    }
}
