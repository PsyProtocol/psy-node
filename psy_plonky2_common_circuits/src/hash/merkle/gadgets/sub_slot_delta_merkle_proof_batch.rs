use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers,
    hash::core::CircuitBuilderHashCore, math::core::CircuitBuilderCoreMathHelpers,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::
        target::{BoolTarget, Target}
    ,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

use super::delta_merkle_proof::DeltaMerkleProofGadget;

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
    fn enforce_targets_from_dmps<
        H:  AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        dmps: &[DeltaMerkleProofGadget],
        targets: &[Target]
    ) {
        self.enforce_targets_from_dmps_with_offset::<H,F,D>(
            builder,
            self.is_sub_slot_index_mod_4_eq_0,
            dmps,
            targets,
            0
        );
        self.enforce_targets_from_dmps_with_offset::<H,F,D>(
            builder,
            self.is_sub_slot_index_mod_4_eq_1,
            dmps,
            targets,
            1
        );
        self.enforce_targets_from_dmps_with_offset::<H,F,D>(
            builder,
            self.is_sub_slot_index_mod_4_eq_2,
            dmps,
            targets,
            2
        );
        self.enforce_targets_from_dmps_with_offset::<H,F,D>(
            builder,
            self.is_sub_slot_index_mod_4_eq_3,
            dmps,
            targets,
            3
        );


    }
    fn enforce_targets_from_dmps_with_offset<
        H:  AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        dmps: &[DeltaMerkleProofGadget],
        targets: &[Target],
        offset: usize,
    ) {
        for (i, t) in targets.iter().enumerate() {
            let dmp_index = (i+offset)/4;
            let dmp_sub_index = (i+offset)%4;
            builder.connect_if_true(condition, *t, dmps[dmp_index].new_value.elements[dmp_sub_index]);
        }
    }
    fn enforce_final_mask<
        H:  AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
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
            builder.connect_if_false(
                self.is_sub_slot_index_mod_4_eq_3,
                old_last_value.elements[0],
                new_last_value.elements[0],
            );

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
            let is_ssim4_eq_2_or_3 = builder.or(
                self.is_sub_slot_index_mod_4_eq_2,
                self.is_sub_slot_index_mod_4_eq_3,
            );

            builder.connect_if_false(
                is_ssim4_eq_2_or_3,
                old_last_value.elements[0],
                new_last_value.elements[0],
            );

            builder.connect_if_false(
                self.is_sub_slot_index_mod_4_eq_3,
                old_last_value.elements[1],
                new_last_value.elements[1],
            );

            builder.connect(old_last_value.elements[2], new_last_value.elements[2]);

            builder.connect(old_last_value.elements[3], new_last_value.elements[3]);
        } else if len_minus_2_mod_4 == 2 {
            /*
                [0, 0, 0, 0], // self.sub_slot_index_mod_4 == 0
                [1, 0, 0, 0], // self.sub_slot_index_mod_4 == 1
                [1, 1, 0, 0], // self.sub_slot_index_mod_4 == 2
                [1, 1, 1, 0], // self.sub_slot_index_mod_4 == 3
            */
            let is_ssim4_eq_2_or_3 = builder.or(
                self.is_sub_slot_index_mod_4_eq_2,
                self.is_sub_slot_index_mod_4_eq_3,
            );

            // connect if self.sub_slot_index_mod_4 == 0
            builder.connect_if_false(
                self.is_ssim4_eq_1_or_2_or_3,
                old_last_value.elements[0],
                new_last_value.elements[0],
            );

            // connect if 2 or 3
            builder.connect_if_false(
                is_ssim4_eq_2_or_3,
                old_last_value.elements[1],
                new_last_value.elements[1],
            );

            // connect if not 3
            builder.connect_if_false(
                self.is_sub_slot_index_mod_4_eq_3,
                old_last_value.elements[2],
                new_last_value.elements[2],
            );

            builder.connect(old_last_value.elements[3], new_last_value.elements[3]);
        } else {
            //else if len_minus_2_mod_4 == 3 {
            /*
                [1, 0, 0, 0], // self.sub_slot_index_mod_4 == 0
                [1, 1, 0, 0], // self.sub_slot_index_mod_4 == 0
                [1, 1, 1, 0], // self.sub_slot_index_mod_4 == 0
                [1, 1, 1, 1], // self.sub_slot_index_mod_4 == 0
            */
            let is_ssim4_eq_2_or_3 = builder.or(
                self.is_sub_slot_index_mod_4_eq_2,
                self.is_sub_slot_index_mod_4_eq_3,
            );

            // connect if zero
            builder.connect_if_false(
                self.is_ssim4_eq_1_or_2_or_3,
                old_last_value.elements[1],
                new_last_value.elements[1],
            );

            // connect if not 2 or 3
            builder.connect_if_false(
                is_ssim4_eq_2_or_3,
                old_last_value.elements[2],
                new_last_value.elements[2],
            );

            // connect if not 3
            builder.connect_if_false(
                self.is_sub_slot_index_mod_4_eq_3,
                old_last_value.elements[3],
                new_last_value.elements[3],
            );
        }
    }
}
fn connect_sub_slot_start_mask_4_delta_merkle_proof<
    H:  AlgebraicHasher<F>,
    F: RichField + Extendable<D>,
    const D: usize,
>(
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
    builder.connect_if_true(
        is_sub_slot_index_mod_4_eq_1,
        old_value.elements[0],
        new_value.elements[0],
    );

    // if sub_slot_index_mod_4 == 2, mask is [0,0,1,1]
    builder.connect_if_true(
        is_sub_slot_index_mod_4_eq_2,
        old_value.elements[0],
        new_value.elements[0],
    );
    builder.connect_if_true(
        is_sub_slot_index_mod_4_eq_2,
        old_value.elements[1],
        new_value.elements[1],
    );

    // if sub_slot_index_mod_4 == 3, mask is [0,0,0,1]
    builder.connect_if_true(
        is_sub_slot_index_mod_4_eq_3,
        old_value.elements[0],
        new_value.elements[0],
    );
    builder.connect_if_true(
        is_sub_slot_index_mod_4_eq_3,
        old_value.elements[1],
        new_value.elements[1],
    );
    builder.connect_if_true(
        is_sub_slot_index_mod_4_eq_3,
        old_value.elements[2],
        new_value.elements[2],
    );

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
    // calculate the normal merkle root + a historical merkle root where all the leaves with index >= `gadget.index` set to zero
    pub fn add_virtual_to<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
        sub_slot_index: Target,
        values: Vec<Target>,
        force_four_align: bool,
    ) -> Self {
        let sub_slot_length = values.len();

        let (start_slot_index, sub_slot_index_mod_4) = builder.div_rem4(sub_slot_index);

        if sub_slot_length == 1 {
            let dmp = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
            let expected_new_value =
                builder.set_target_in_hash(dmp.old_value, sub_slot_index_mod_4, values[0]);
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

            if force_four_align{
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
            let old_root = dmp_0.old_root;
            let new_root = dmp_1.new_root;

            first_gadget.enforce_final_mask::<H, F, D>(builder, dmp_1.old_value, dmp_1.new_value);
            let dmps = vec![dmp_0, dmp_1];
            if force_four_align {
                for (i, t) in values.iter().enumerate() {
                    let dmp_index = i/4;
                    let dmp_sub_index = i%4;
                    builder.connect( *t, dmps[dmp_index].new_value.elements[dmp_sub_index]);
                }
            }else{
                first_gadget.enforce_targets_from_dmps::<H,F,D>(builder, &dmps, &values);
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
            for _ in 1..(n_proofs-1) {
                let dmp = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
                let expected_index = builder.add(last_slot_index_target, one);

                // ensure the proofs are for a contiguous portion of the tree
                builder.connect(
                    dmp.index,
                    expected_index,
                );

                // connect old root to previous slot's new root
                builder.connect_hashes(
                    dmp.old_root,
                    last_slot_new_root,
                );

                last_slot_new_root = dmp.new_root;
                last_slot_index_target = expected_index;
                dmps.push(dmp);
            }

            // handle last proof edge case

            let last_proof = DeltaMerkleProofGadget::add_virtual_to::<H, F, D>(builder, height);
            let expected_last_proof_index = builder.add(last_slot_index_target, one);

            // ensure the proofs are for a contiguous portion of the tree
            builder.connect(
                last_proof.index,
                expected_last_proof_index
            );


            // connect old root to previous slot's new root
            builder.connect_hashes(
                last_proof.old_root,
                last_slot_new_root,
            );


            // enforce the last proof edge constraints
            first_gadget.enforce_final_mask::<H,F,D>(
                builder,
                last_proof.old_value,
                last_proof.new_value,
            );

            let old_root = start_root;
            let new_root = last_proof.new_root;

            dmps.push(last_proof);

            // TODO: figure out a better way to handle non-four aligned writes
            if force_four_align {
                for (i, t) in values.iter().enumerate() {
                    let dmp_index = i/4;
                    let dmp_sub_index = i%4;
                    builder.connect( *t, dmps[dmp_index].new_value.elements[dmp_sub_index]);
                }
            }else{
                first_gadget.enforce_targets_from_dmps::<H,F,D>(builder, &dmps, &values);
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

