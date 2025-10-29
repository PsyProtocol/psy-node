use parth_core::pgoldilocks::QHashOut;
use plonky2::iop::target::Target;
use plonky2::hash::hash_types::HashOut;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::BoolTarget,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use plonky2::hash::hashing::PlonkyPermutation;

use crate::builder::comparison::CircuitBuilderComparison;
use crate::builder::core::CircuitBuilderHelpersCore;
const NUM_HASH_OUT_ELEMENTS: usize = 4;
pub trait CircuitBuilderHashCore<F: RichField + Extendable<D>, const D: usize> {
    fn ensure_hash_is_zero(&mut self, hash: HashOutTarget);
    fn ensure_hash_is_non_zero(&mut self, hash: HashOutTarget);
    fn constant_qhash(&mut self, value: QHashOut<F>) -> HashOutTarget;
    fn constant_hash_str(&mut self, value: &str) -> HashOutTarget;
    fn two_to_one_swapped<H:AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
        swap: BoolTarget,
    ) -> HashOutTarget;
    fn hash_two_to_one<H:AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
    ) -> HashOutTarget;


    fn safe_hash_fixed_length<H:AlgebraicHasher<F>>(&mut self, targets: &[Target]) -> HashOutTarget;


    fn ensure_hash_not_equal(&mut self, x: HashOutTarget, y: HashOutTarget);
    fn ensure_hash_not_equal_if(
        &mut self,
        condition: BoolTarget,
        x: HashOutTarget,
        y: HashOutTarget,
    );

    // sets the n-th element of a hash to a value
    // index is assumed to be range checked where: 0 <= index <= 3
    fn set_target_in_hash(&mut self, hash: HashOutTarget, index: Target, value: Target) -> HashOutTarget;

    fn set_target_in_hash_bit_indexed(&mut self, hash: HashOutTarget, index_low_bit: BoolTarget, index_high_bit: BoolTarget, value: Target) -> HashOutTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashCore<F, D>
    for CircuitBuilder<F, D>
{
    /*fn constant_hash(&mut self, value: HashOut<F>) -> HashOutTarget {
        let a = self.cons
    }*/

    fn constant_qhash(&mut self, value: QHashOut<F>) -> HashOutTarget {
        self.constant_hash(value.0)
    }

    fn constant_hash_str(&mut self, value: &str) -> HashOutTarget {
        self.constant_qhash(QHashOut::from_string_or_panic(value))
    }

    fn two_to_one_swapped<H:AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
        swap: BoolTarget,
    ) -> HashOutTarget {

        /*
        let real_left = self.select_hash(swap,right, left);
        let real_right = self.select_hash(swap,left, right);

        self.hash_two_to_one::<H>(real_left, real_right)

        */

        let zero = self.zero();
        let mut state = H::AlgebraicPermutation::new(std::iter::repeat(zero));

        state.set_from_slice(&left.elements, 0);
        state.set_from_slice(&right.elements, NUM_HASH_OUT_ELEMENTS);
        state = H::permute_swapped(state, swap, self);

        HashOutTarget {
            elements: state.squeeze()[0..NUM_HASH_OUT_ELEMENTS]
                .try_into()
                .unwrap(),
        }
    }
    fn hash_two_to_one<H:AlgebraicHasher<F>>(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
    ) -> HashOutTarget {
        self.hash_n_to_hash_no_pad::<H>(vec![
            left.elements[0],
            left.elements[1],
            left.elements[2],
            left.elements[3],
            right.elements[0],
            right.elements[1],
            right.elements[2],
            right.elements[3],
        ])
    }

    fn ensure_hash_not_equal(&mut self, x: HashOutTarget, y: HashOutTarget) {
        let is_eq_target = self.is_equal_hash(x, y).target;
        let false_target = self._false().target;
        self.connect(is_eq_target, false_target);
    }

    fn ensure_hash_not_equal_if(
        &mut self,
        condition: BoolTarget,
        x: HashOutTarget,
        y: HashOutTarget,
    ) {
        let is_eq = self.is_equal_hash(x, y);
        let is_eq_and_enabled_target = self.and(is_eq, condition).target;
        let false_target = self._false().target;
        self.connect(is_eq_and_enabled_target, false_target);
    }

    fn ensure_hash_is_zero(&mut self, hash: HashOutTarget) {
        let zero_hash = self.constant_hash(HashOut::ZERO);
        self.connect_hashes(hash, zero_hash);
    }

    fn ensure_hash_is_non_zero(&mut self, hash: HashOutTarget) {
        let zero_hash = self.constant_hash(HashOut::ZERO);
        self.ensure_hash_not_equal(hash, zero_hash)
    }

    fn set_target_in_hash(&mut self, hash: HashOutTarget, index: Target, value: Target) -> HashOutTarget {

        /*
        TODO/OPT: is using the bitsplit method more efficient?

        let results = self.split_le(index, 2);
        self.set_target_in_hash_bit_indexed(hash, results[0], results[1], value)
        */

        let constant_0 = self.constant_u64(0);
        let constant_1 = self.constant_u64(1);
        let constant_2 = self.constant_u64(2);
        let constant_3 = self.constant_u64(3);

        let index_is_0 = self.is_equal(index, constant_0);
        let index_is_1 = self.is_equal(index, constant_1);
        let index_is_2 = self.is_equal(index, constant_2);
        let index_is_3 = self.is_equal(index, constant_3);


        let elements_0 = self.select(index_is_0, value, hash.elements[0]);
        let elements_1 = self.select(index_is_1, value, hash.elements[1]);
        let elements_2 = self.select(index_is_2, value, hash.elements[2]);
        let elements_3 = self.select(index_is_3, value, hash.elements[3]);

        HashOutTarget {
            elements: [
                elements_0,
                elements_1,
                elements_2,
                elements_3,
            ]
        }
    }

    fn set_target_in_hash_bit_indexed(&mut self, hash: HashOutTarget, index_low_bit: BoolTarget, index_high_bit: BoolTarget, value: Target) -> HashOutTarget {


        let not_high_bit = self.not(index_high_bit);
        let not_low_bit = self.not(index_high_bit);

        let index_is_0 = self.and(not_low_bit, not_high_bit);
        let index_is_1 = self.and(index_low_bit, not_high_bit);
        let index_is_2 = self.and(not_low_bit, index_high_bit);
        let index_is_3 = self.and(index_low_bit, index_high_bit);

        let elements_0 = self.select(index_is_0, value, hash.elements[0]);
        let elements_1 = self.select(index_is_1, value, hash.elements[1]);
        let elements_2 = self.select(index_is_2, value, hash.elements[2]);
        let elements_3 = self.select(index_is_3, value, hash.elements[3]);

        HashOutTarget {
            elements: [
                elements_0,
                elements_1,
                elements_2,
                elements_3,
            ]
        }



    }

    fn safe_hash_fixed_length<H:AlgebraicHasher<F>>(&mut self, targets: &[Target]) -> HashOutTarget {

        let targets_length = targets.len();
        let targets_length_target = self.constant_u64(targets_length as u64);

        let mut targets_hash_preimage = Vec::with_capacity(targets_length + 2);

        targets_hash_preimage.push(targets_length_target);
        targets_hash_preimage.extend_from_slice(targets);
        targets_hash_preimage.push(targets_length_target);
        let targets_hash = self.hash_n_to_hash_no_pad::<H>(targets_hash_preimage);
        targets_hash
    }
}
