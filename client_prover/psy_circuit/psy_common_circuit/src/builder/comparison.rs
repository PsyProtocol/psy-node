use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use super::core::CircuitBuilderHelpersCore;
use crate::u32::multiple_comparison::list_lte_circuit;

/// A field element can also be represented by its value plus the modulus when
/// split into 64 bits. Exclude that alias before treating the limbs as an integer.
fn assert_canonical_64<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    low: Target,
    high: Target,
) {
    // RichField currently has only the Goldilocks implementation. Keep the
    // generic fallback correct for future RichField implementations.
    if F::ORDER == 0xffff_ffff_0000_0001 {
        // p - 1 has (high, low) = (0xffffffff, 0). Only larger
        // 64-bit representations need to be excluded.
        let max_high = builder.constant_u64(0xffff_ffff);
        let high_is_max = builder.is_equal(high, max_high);
        let zero = builder.zero();
        let low_is_zero = builder.is_equal(low, zero);
        let low_is_nonzero = builder.not(low_is_zero);
        let noncanonical = builder.and(high_is_max, low_is_nonzero);
        builder.assert_zero(noncanonical.target);
        return;
    }

    let modulus_high = builder.constant_u64(F::ORDER >> 32);
    let modulus_low = builder.constant_u64(F::ORDER & 0xffff_ffff);
    let high_le = list_lte_circuit(builder, vec![high], vec![modulus_high], 32);
    let high_eq = builder.is_equal(high, modulus_high);
    let high_ne = builder.not(high_eq);
    let high_lt = builder.and(high_le, high_ne);
    let low_le = list_lte_circuit(builder, vec![low], vec![modulus_low], 32);
    let low_eq = builder.is_equal(low, modulus_low);
    let low_ne = builder.not(low_eq);
    let low_lt = builder.and(low_le, low_ne);
    let at_modulus_high = builder.and(high_eq, low_lt);
    let canonical = builder.or(high_lt, at_modulus_high);
    builder.assert_one(canonical.target);
}

/// Split a field element into its unique canonical 64-bit integer limbs.
pub fn split_canonical_low_high_32bits<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
) -> (Target, Target) {
    let (low, high) = builder.split_low_high(x, 32, 64);
    assert_canonical_64(builder, low, high);
    (low, high)
}

/// Use this when individual bits, rather than 32-bit limbs, are consumed.
pub fn split_canonical_le_64<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
) -> Vec<BoolTarget> {
    let bits = builder.split_le(x, 64);
    let low = builder.le_sum(bits[..32].iter());
    let high = builder.le_sum(bits[32..].iter());
    assert_canonical_64(builder, low, high);
    bits
}

pub fn split_canonical_low_high<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
    low_bits: usize,
) -> (Target, Target) {
    assert!((1..=64).contains(&low_bits));
    let (low32, high32) = split_canonical_low_high_32bits(builder, x);
    if low_bits <= 32 {
        let (low, low_rest) = builder.split_low_high(low32, low_bits, 32);
        let high_scale = builder.constant_u64(1u64 << (32 - low_bits));
        let high = builder.mul_add(high32, high_scale, low_rest);
        (low, high)
    } else {
        let high_low_bits = low_bits - 32;
        let (high_low, high) = builder.split_low_high(high32, high_low_bits, 32);
        let two_to_32 = builder.constant_u64(1u64 << 32);
        let low = builder.mul_add(high_low, two_to_32, low32);
        (low, high)
    }
}

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
    fn is_equal_hash(&mut self, true_value: HashOutTarget, false_value: HashOutTarget) -> BoolTarget;
    fn is_not_equal_hash(&mut self, true_value: HashOutTarget, false_value: HashOutTarget) -> BoolTarget;
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

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderComparison<F, D> for CircuitBuilder<F, D> {
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
        } else {
            // x_low = x & 0xffffffff, x_high = x >> 32
            let (x_low_target, x_high_target) = split_canonical_low_high_32bits(self, x);
            // y_low = x & 0xffffffff, y_high = y >> 32
            let (y_low_target, y_high_target) = split_canonical_low_high_32bits(self, y);

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
        } else {
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
        let is_zero = self.is_zero_hash(hash);
        self.assert_zero(is_zero.target);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    use super::*;

    #[test]
    fn non_zero_hash_allows_zero_elements_but_rejects_zero_hash() {
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(CircuitConfig::standard_recursion_config());
        let hash = builder.add_virtual_hash();
        builder.assert_non_zero_hash(hash);
        let circuit = builder.build::<PoseidonGoldilocksConfig>();

        let mut one_zero_element = PartialWitness::new();
        one_zero_element
            .set_hash_target(hash, HashOut { elements: [GoldilocksField::ZERO, GoldilocksField::ONE, GoldilocksField::ONE, GoldilocksField::ONE] })
            .unwrap();
        assert!(circuit.prove(one_zero_element).is_ok());

        let mut all_zero = PartialWitness::new();
        all_zero.set_hash_target(hash, HashOut::ZERO).unwrap();
        assert!(circuit.prove(all_zero).is_err());
    }

    #[test]
    fn canonical_64_rejects_modulus_aliases() {
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(CircuitConfig::standard_recursion_config());
        let x = builder.add_virtual_target();
        let low = builder.add_virtual_target();
        let high = builder.add_virtual_target();
        let two_to_32 = builder.constant_u64(1 << 32);
        let recomposed = builder.mul_add(high, two_to_32, low);
        builder.connect(x, recomposed);
        assert_canonical_64(&mut builder, low, high);
        let circuit = builder.build::<PoseidonGoldilocksConfig>();

        for (value, low_value, high_value, valid) in [
            (0, 0, 0, true),
            (10, 10, 0, true),
            (0xffff_ffff_0000_0000, 0, 0xffff_ffff, true),
            (0, 1, 0xffff_ffff, false),
            (10, 11, 0xffff_ffff, false),
        ] {
            let mut witness = PartialWitness::new();
            witness.set_target(x, GoldilocksField::from_canonical_u64(value)).unwrap();
            witness.set_target(low, GoldilocksField::from_canonical_u64(low_value)).unwrap();
            witness.set_target(high, GoldilocksField::from_canonical_u64(high_value)).unwrap();
            assert_eq!(circuit.prove(witness).is_ok(), valid, "value={value}, high={high_value}, low={low_value}");
        }
    }

    #[test]
    fn canonical_64_blocks_false_less_than_or_equal_alias() {
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(CircuitConfig::standard_recursion_config());
        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let x_low = builder.add_virtual_target();
        let x_high = builder.add_virtual_target();
        let y_low = builder.add_virtual_target();
        let y_high = builder.add_virtual_target();
        let two_to_32 = builder.constant_u64(1 << 32);
        let x_recomposed = builder.mul_add(x_high, two_to_32, x_low);
        let y_recomposed = builder.mul_add(y_high, two_to_32, y_low);
        builder.connect(x, x_recomposed);
        builder.connect(y, y_recomposed);
        assert_canonical_64(&mut builder, x_low, x_high);
        assert_canonical_64(&mut builder, y_low, y_high);
        let lte = list_lte_circuit(&mut builder, vec![x_high, x_low], vec![y_high, y_low], 32);
        builder.assert_one(lte.target);
        let circuit = builder.build::<PoseidonGoldilocksConfig>();

        let mut witness = PartialWitness::new();
        witness.set_target(x, GoldilocksField::from_canonical_u64(11)).unwrap();
        witness.set_target(y, GoldilocksField::from_canonical_u64(10)).unwrap();
        witness.set_target(x_low, GoldilocksField::from_canonical_u64(11)).unwrap();
        witness.set_target(x_high, GoldilocksField::ZERO).unwrap();
        witness.set_target(y_low, GoldilocksField::from_canonical_u64(11)).unwrap();
        witness.set_target(y_high, GoldilocksField::from_canonical_u64(0xffff_ffff)).unwrap();
        assert!(circuit.prove(witness).is_err());
    }
}
