use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::u32::multiple_comparison::list_lte_circuit;

use super::core::CircuitBuilderHelpersCore;

pub trait CircuitBuilderComparison<F: RichField + Extendable<D>, const D: usize> {
    fn is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_less_than_or_equal_split(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_less_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_greater_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget;
    fn is_not_equal(&mut self, x: Target, y: Target) -> BoolTarget;
    fn is_not_equal_bool(&mut self, x: BoolTarget, y: BoolTarget) -> BoolTarget;
    fn is_zero(&mut self, x: Target) -> BoolTarget;
    fn is_equal_to_u64(&mut self, x: Target, value: u64) -> BoolTarget;
    fn is_equal_hash(
        &mut self,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> BoolTarget;
    fn is_not_equal_hash(
        &mut self,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> BoolTarget;
    fn is_zero_hash(&mut self, x: HashOutTarget) -> BoolTarget;
    fn is_not_zero(&mut self, x: Target) -> BoolTarget;

    fn ensure_is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target);
    fn ensure_is_less_than(&mut self, num_bits: usize, x: Target, y: Target);
    fn ensure_is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target);
    fn ensure_is_greater_than(&mut self, num_bits: usize, x: Target, y: Target);
    fn ensure_not_equal(&mut self, x: Target, y: Target);
    fn ensure_not_equal_bool(&mut self, x: BoolTarget, y: BoolTarget);
    fn assert_zero_hash(&mut self, hash: HashOutTarget);
    fn assert_non_zero_hash(&mut self, hash: HashOutTarget);
    fn assert_non_zero(&mut self, x: Target);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderComparison<F, D>
    for CircuitBuilder<F, D>
{
    fn is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        //list_lte_circuit(self, vec![x], vec![y], num_bits)
        self.is_less_than_or_equal_split(num_bits, x, y)
    }

    fn is_less_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        let is_lte = self.is_less_than_or_equal(num_bits, x, y);
        let is_equal = self.is_equal(x, y);
        let is_not_equal = self.not(is_equal);
        self.and(is_lte, is_not_equal)
    }

    fn is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        let is_gt = self.is_greater_than(num_bits, x, y);
        let is_equal = self.is_equal(x, y);
        self.or(is_gt, is_equal)
    }

    fn is_greater_than(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        let is_lte = self.is_less_than_or_equal(num_bits, x, y);
        self.not(is_lte)
    }

    fn ensure_is_less_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_less_than_or_equal(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn ensure_is_less_than(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_less_than(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn ensure_is_greater_than_or_equal(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_greater_than_or_equal(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn ensure_is_greater_than(&mut self, num_bits: usize, x: Target, y: Target) {
        let test_target = self.is_greater_than(num_bits, x, y).target;
        let true_target = self._true().target;
        self.connect(test_target, true_target);
    }

    fn is_not_equal(&mut self, x: Target, y: Target) -> BoolTarget {
        let is_eq = self.is_equal(x, y);
        self.not(is_eq)
    }

    fn ensure_not_equal(&mut self, x: Target, y: Target) {
        let is_eq = self.is_equal(x, y);
        let zero = self.zero();
        self.connect(is_eq.target, zero);
    }


    fn is_less_than_or_equal_split(&mut self, num_bits: usize, x: Target, y: Target) -> BoolTarget {
        if num_bits <= 32 {
            list_lte_circuit(self, vec![x], vec![y], num_bits)
        }else{
            // x_low = x & 0xffffffff, x_high = x >> 32
            let (x_low_target, x_high_target) = self.split_low_high(x, 32, 64);
            // y_low = x & 0xffffffff, y_high = y >> 32
            let (y_low_target, y_high_target) = self.split_low_high(y, 32, 64);

            // is_gt = (x_high > y_high) || (x_high == y_high && x_low > y_low)
            // is_leq = !is_gt

            // high_leq_target = (x_high <= y_high)
            let high_leq_target = list_lte_circuit(self, vec![x_high_target], vec![y_high_target], 32);

            // low_leq_target = (x_low <= y_low)
            let low_leq_target = list_lte_circuit(self, vec![x_low_target], vec![y_low_target], 32);

            // high_gt_target = (x_high > y_high) = !(x_high <= y_high)
            let high_gt_target = self.not(high_leq_target);

            // low_gt_target = (x_low > y_low) = !(x_low <= y_low)
            let low_gt_target = self.not(low_leq_target);

            // high_eq_target = x_high == y_high
            let high_eq_target = self.is_equal(x_high_target, y_high_target);

            // equal_high_bits_case_target = (x_high == y_high && x_low > y_low)
            let equal_high_bits_case_target = self.and(high_eq_target, low_gt_target);

            // is_gt = (x_high > y_high) || (x_high == y_high && x_low > y_low)

            let is_gt = self.or(high_gt_target, equal_high_bits_case_target);

            // is_leq = !is_gt = !((x_high > y_high) || (x_high == y_high && x_low > y_low))
            let is_leq = self.not(is_gt);
            is_leq
        }
    }

    fn is_zero(&mut self, x: Target) -> BoolTarget {
        let zero = self.zero();
        self.is_equal(x, zero)

    }

    fn is_not_zero(&mut self, x: Target) -> BoolTarget {
        let is_z = self.is_zero(x);
        self.not(is_z)
    }

    fn is_zero_hash(&mut self, x: HashOutTarget) -> BoolTarget {
        let is_elem_0_zero = self.is_zero(x.elements[0]);
        let is_elem_1_zero = self.is_zero(x.elements[1]);
        let is_elem_2_zero = self.is_zero(x.elements[2]);
        let is_elem_3_zero = self.is_zero(x.elements[3]);

        let is_elem_01_zero = self.and(is_elem_0_zero, is_elem_1_zero);
        let is_elem_23_zero = self.and(is_elem_2_zero, is_elem_3_zero);



        self.and(is_elem_01_zero, is_elem_23_zero)

    }

    fn ensure_not_equal_bool(&mut self, x: BoolTarget, y: BoolTarget) {
        let not_x = self.not(x);
        self.connect(not_x.target, y.target);
    }

    fn is_not_equal_bool(&mut self, x: BoolTarget, y: BoolTarget) -> BoolTarget {
        // x xor y = (x+y-2*x*y)
        let x_plus_y = self.add(x.target, y.target);
        let x_times_y = self.mul(x.target, y.target);
        let x_times_y_2 = self.add(x_times_y, x_times_y);
        BoolTarget::new_unsafe(self.sub(x_plus_y, x_times_y_2))
    }

    fn is_equal_to_u64(&mut self, x: Target, value: u64) -> BoolTarget {
        if value == 0 {
            self.is_zero(x)
        }else{
            let constant_u64 = self.constant_u64(value);
            self.is_equal(x, constant_u64)
        }
    }

    fn is_equal_hash(&mut self, x: HashOutTarget, y: HashOutTarget) -> BoolTarget {
        let mut result = self.constant_bool(true);
        for i in 0..x.elements.len() {
            let equal = self.is_equal(x.elements[i], y.elements[i]);
            result = self.and(equal, result);
        }
        result
    }

    fn is_not_equal_hash(&mut self, x: HashOutTarget, y: HashOutTarget) -> BoolTarget {
        let is_equal = self.is_equal_hash(x, y);
        self.not(is_equal)
    }


    fn assert_zero_hash(&mut self, hash: HashOutTarget) {
        self.assert_zero(hash.elements[0]);
        self.assert_zero(hash.elements[1]);
        self.assert_zero(hash.elements[2]);
        self.assert_zero(hash.elements[3]);
    }

    fn assert_non_zero(&mut self, x: Target) {
        let is_zero = self.is_zero(x);
        self.assert_zero(is_zero.target)
    }

    fn assert_non_zero_hash(&mut self, hash: HashOutTarget) {
        self.assert_non_zero(hash.elements[0]);
        self.assert_non_zero(hash.elements[1]);
        self.assert_non_zero(hash.elements[2]);
        self.assert_non_zero(hash.elements[3]);
    }
}
