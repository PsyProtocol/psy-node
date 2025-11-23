use parth_core::utils::math::log2_ceil;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, core::CircuitBuilderHelpersCore
};


#[derive(Debug, Clone)]
pub struct VariableHeightMerkleProofIndexBitInfoGadget {
    pub is_bit_not_within_height: Vec<BoolTarget>,
    pub is_first_bit_outside_height: Vec<BoolTarget>,
    pub height: Target,
    pub parent_index: Target,
}
impl VariableHeightMerkleProofIndexBitInfoGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_merkle_proof_height: usize,
        tree_height: usize,
        height: Target,
        left_index_bits: &[BoolTarget],
        right_index_bits: &[BoolTarget],
    ) -> Self {
        assert!(tree_height > 0, "tree height must be > 0");
        assert!(left_index_bits.len() > 0, "left index bits length must be > 0");
        assert!(right_index_bits.len() > 0, "right index bits length must be > 0");
        assert!(tree_height >= max_merkle_proof_height, "tree height must be >= max merkle proof height");

        assert_eq!(left_index_bits.len(), tree_height, "left index bits length must equal tree height");
        assert_eq!(right_index_bits.len(), tree_height, "right index bits length must equal tree height");

        let max_merkle_proof_height_target = builder.constant_u64(max_merkle_proof_height as u64);
        let max_merkle_proof_height_minus_height_target = builder.sub(max_merkle_proof_height_target, height);
        // ensure height <= tree_height
        builder.range_check(max_merkle_proof_height_minus_height_target, log2_ceil(max_merkle_proof_height));

        let is_height_zero = builder.is_zero(height);

        let mut is_bit_not_within_height = Vec::with_capacity(max_merkle_proof_height);
        let mut is_first_bit_outside_height = Vec::with_capacity(max_merkle_proof_height);
        is_bit_not_within_height.push(is_height_zero);
        is_first_bit_outside_height.push(is_height_zero);

        let mut is_not_within_height = is_height_zero;
        builder.conditional_assert_eq(is_not_within_height.target, left_index_bits[0].target, right_index_bits[0].target);

        let one = builder.one();
        let two = builder.constant_u32(2);

        let mut reverse_counter = height;
        for i in 1..max_merkle_proof_height {
            reverse_counter = builder.sub(reverse_counter, one);
            let is_at_tree_height = builder.is_zero(reverse_counter);
            is_first_bit_outside_height.push(is_at_tree_height);
            is_not_within_height = builder.or(is_not_within_height, is_at_tree_height);
            is_bit_not_within_height.push(is_not_within_height);
            builder.conditional_assert_eq(is_not_within_height.target, left_index_bits[i].target, right_index_bits[i].target);
            /*if i < max_merkle_proof_height - 1 {
                let add_bit = builder.mul(is_not_within_height.target, left_index_bits[left_index_bits.len() - 1 - i].target);
                parent_index = builder.mul_add(parent_index, two, add_bit);
            }*/
        }
        // if we are are still not within height at the end of the max merkle proof height, then the reverse counter should be 1
        // ie. max_merkle_proof_height == height
        builder.connect_if_false(is_not_within_height, reverse_counter, one);


        // 1. Initialize with Upper Bits (if they exist)
        // This sums the bits above `max_merkle_proof_height`.
        let mut parent_index = if max_merkle_proof_height < tree_height {
            let true_target = builder._true();
            let false_target = builder._false();
            for i in max_merkle_proof_height..tree_height {
                // Upper bits are always outside the proof window, so they must match
                builder.connect(left_index_bits[i].target, right_index_bits[i].target);
                
                is_bit_not_within_height.push(true_target);
                if i == max_merkle_proof_height {
                    // If mask was false until now, this is the transition point
                    is_first_bit_outside_height.push(builder.not(is_not_within_height));
                } else {
                    is_first_bit_outside_height.push(false_target);
                }
            }
            builder.le_sum(left_index_bits[max_merkle_proof_height..tree_height].iter())
        } else {
            builder.zero()
        };

        // 2. Consume Lower Bits Backwards (MSB -> LSB)
        // This loop performs `acc = acc * 2 + bit` whenever `mask` is true.
        // This effectively shifts the `parent_index` (including the Upper Bits loaded above)
        // to the left and appends the active bits from the "Lower" section.
        // When `mask` becomes false (we are inside the sub-tree), we stop updating.
        for i in (0..max_merkle_proof_height).rev() {
            let bit = left_index_bits[i].target;

            let shifted_val = builder.mul_add(parent_index, two, bit);
            
            
            // If mask is true, we take the new shifted value.
            // If mask is false, we keep the previous value (effectively behaving as `>> height`)
            parent_index = builder.select(is_bit_not_within_height[i], shifted_val, parent_index);
        }


        /* 
        let zero = builder.zero();
        let mut parent_index = zero;
        if max_merkle_proof_height == tree_height {
            for i in (0..max_merkle_proof_height).rev() {
                let bit = left_index_bits[i].target;
                let mask = is_bit_not_within_height[i].target;
                // parent_index = (left_index_bits[i] & is_bit_not_within_height[i]) | (parent_index << 1)
                // aka: parent_index = parent_index * 2 + (left_index_bits[i] * is_bit_not_within_height[i])
                parent_index = builder.arithmetic(F::ONE, F::TWO, bit, mask, parent_index);
            }
        }else{
            parent_index = builder.le_sum(left_index_bits[max_merkle_proof_height..tree_height].iter());
            let true_value = builder._true();
            let false_value = builder._false();
            is_first_bit_outside_height.push(builder.not(is_not_within_height));
            is_first_bit_outside_height.extend_from_slice(&vec![false_value; tree_height - max_merkle_proof_height - 1]);
            is_bit_not_within_height.extend_from_slice(&vec![true_value; tree_height - max_merkle_proof_height]);
            for i in (0..max_merkle_proof_height).rev() {
                let bit = left_index_bits[i].target;
                let mask = is_bit_not_within_height[i].target;
                // parent_index = (left_index_bits[i] & is_bit_not_within_height[i]) | (parent_index << 1)
                // aka: parent_index = parent_index * 2 + (left_index_bits[i] * is_bit_not_within_height[i])
                parent_index = builder.arithmetic(F::ONE, F::TWO, bit, mask, parent_index);
            }

        }*/
        Self {
            height,
            is_bit_not_within_height,
            is_first_bit_outside_height,
            parent_index,
        }
    }
}
