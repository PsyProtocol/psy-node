use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};


use super::{comparison::CircuitBuilderComparison, core::CircuitBuilderHelpersCore};

pub trait CircuitBuilderSelectHelpers<F: RichField + Extendable<D>, const D: usize> {
    fn select_or_zero(
        &mut self,
        zero_condition: BoolTarget,
        condition: BoolTarget,
        true_value: Target,
        false_value: Target,
    ) -> Target;
    fn select_in_hash(
        &mut self,
        hash: HashOutTarget,
        index: Target,
    ) -> Target;
    fn select_in_array(
        &mut self,
        array: &[Target],
        index: Target,
    ) -> Target;
    fn select_in_hash_array(
        &mut self,
        array: &[HashOutTarget],
        index: Target,
    ) -> HashOutTarget;
    fn select_hash(
        &mut self,
        condition: BoolTarget,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> HashOutTarget;
    fn pick_from_hashes(
        &mut self,
        value: HashOutTarget,
        allowed_hashes: &[HashOutTarget],
    ) -> HashOutTarget;
    fn select_hash_or_zero(
        &mut self,
        zero_condition: BoolTarget,
        condition: BoolTarget,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> HashOutTarget;

}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSelectHelpers<F, D>
    for CircuitBuilder<F, D>
{
    fn select_or_zero(
        &mut self,
        zero_condition: BoolTarget,
        condition: BoolTarget,
        true_value: Target,
        false_value: Target,
    ) -> Target {
        let not_zero = self.not(zero_condition);
        let value = self.select(condition, true_value, false_value);
        self.mul(not_zero.target, value)
    }

    fn select_hash(
        &mut self,
        condition: BoolTarget,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> HashOutTarget {
        HashOutTarget {
            elements: core::array::from_fn(|i| {
                self.select(condition, true_value.elements[i], false_value.elements[i])
            }),
        }
    }

    fn select_hash_or_zero(
        &mut self,
        zero_condition: BoolTarget,
        condition: BoolTarget,
        true_value: HashOutTarget,
        false_value: HashOutTarget,
    ) -> HashOutTarget {
        let base = self.select_hash(condition, true_value, false_value);
        let not_zero = self.not(zero_condition).target;
        HashOutTarget {
            elements: core::array::from_fn(|i: usize| self.mul(not_zero, base.elements[i])),
        }
    }

    fn pick_from_hashes(
        &mut self,
        value: HashOutTarget,
        allowed_hashes: &[HashOutTarget],
    ) -> HashOutTarget {
        if allowed_hashes.len() == 0 {
            panic!("must pass at least one hash to select_from_hashes");
        }
        let mut last_allowed = allowed_hashes[0];

        for i in 1..allowed_hashes.len() {
            let equal = self.is_equal_hash(value, allowed_hashes[i]);
            last_allowed = self.select_hash(equal, value, last_allowed);
        }
        last_allowed
    }


    fn select_in_hash(
        &mut self,
        hash: HashOutTarget,
        index: Target,
    ) -> Target {


        let constant_0 = self.constant_u64(0);
        let constant_1 = self.constant_u64(1);
        let constant_2 = self.constant_u64(2);
        let constant_3 = self.constant_u64(3);

        let index_is_0 = self.is_equal(index, constant_0).target;
        let index_is_1 = self.is_equal(index, constant_1).target;
        let index_is_2 = self.is_equal(index, constant_2).target;
        let index_is_3 = self.is_equal(index, constant_3).target;

        let mut value = self.mul(hash.elements[0], index_is_0);
        value = self.mul_add(hash.elements[1], index_is_1, value);
        value = self.mul_add(hash.elements[2], index_is_2, value);
        value = self.mul_add(hash.elements[3], index_is_3, value);

        value
    }

    fn select_in_array(
        &mut self,
        array: &[Target],
        index: Target,
    ) -> Target {
        let mut running_sum = self.zero();

        for (i, val) in array.iter().enumerate() {
            let const_index = self.constant_u64(i as u64);
            let index_eq_i = self.is_equal(index, const_index).target;
            running_sum = self.mul_add(*val, index_eq_i, running_sum);
        }
        running_sum
    }

    fn select_in_hash_array(
        &mut self,
        array: &[HashOutTarget],
        index: Target,
    ) -> HashOutTarget {
        let zero = self.zero();
        let mut running_sum = [zero; 4];

        for (i, val) in array.iter().enumerate() {
            let const_index = self.constant_u64(i as u64);
            let index_eq_i = self.is_equal(index, const_index).target;
            running_sum[0] = self.mul_add(val.elements[0], index_eq_i, running_sum[0]);
            running_sum[1] = self.mul_add(val.elements[1], index_eq_i, running_sum[1]);
            running_sum[2] = self.mul_add(val.elements[2], index_eq_i, running_sum[2]);
            running_sum[3] = self.mul_add(val.elements[3], index_eq_i, running_sum[3]);
        }
        HashOutTarget {
            elements: running_sum,
        }
    }
}
