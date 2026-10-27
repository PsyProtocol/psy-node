use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use super::core::CircuitBuilderHelpersCore;
use crate::u32::multiple_comparison::list_lte_circuit;

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
        self.assert_non_zero(hash.elements[0]);
        self.assert_non_zero(hash.elements[1]);
        self.assert_non_zero(hash.elements[2]);
        self.assert_non_zero(hash.elements[3]);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{extension::Extendable, types::Field},
        hash::hash_types::RichField,
        iop::{
            generator::{GeneratedValues, WitnessGenerator, WitnessGeneratorRef},
            target::Target,
            wire::Wire,
            witness::{PartialWitness, PartitionWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CommonCircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
        util::serialization::{Buffer, IoResult},
    };

    use super::CircuitBuilderComparison;
    use crate::u32::multiple_comparison::list_lte_circuit;

    const BALANCE: u64 = 5;
    const AMOUNT: u64 = 100;
    const ALIAS_HIGH: u64 = 0xFFFF_FFFF;
    const ALIAS_LOW: u64 = 6;

    fn goldilocks_prime() -> u128 {
        (1u128 << 64) - (1u128 << 32) + 1
    }

    /// `(2^32 - 1) * 2^32 + 6 = 5 + p`, so the alias is another 64-bit
    /// decomposition of the field element 5.
    #[test]
    fn balance_five_alias_is_five_plus_prime() {
        const D: usize = 2;
        type F = <PoseidonGoldilocksConfig as GenericConfig<D>>::F;

        let prime = goldilocks_prime();
        let alias = ((ALIAS_HIGH as u128) << 32) + ALIAS_LOW as u128;
        assert_eq!(alias, BALANCE as u128 + prime);
        assert!(alias < (1u128 << 64));

        let high = F::from_canonical_u64(ALIAS_HIGH);
        let low = F::from_canonical_u64(ALIAS_LOW);
        let base = F::from_canonical_u64(1u64 << 32);
        let reconstructed = high * base + low;
        assert_eq!(reconstructed, F::from_canonical_u64(BALANCE));
    }

    /// Constraints copied from `split_low_high(x, 32, 64)` and
    /// `is_greater_than_or_equal(64, x, y)`. The balance split has no generator,
    /// so the test supplies the limbs itself.
    fn balance_ge_amount_with_split(high: u64, low: u64) -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let balance = builder.add_virtual_target();
        let amount = builder.constant(F::from_canonical_u64(AMOUNT));
        let low_target = builder.add_virtual_target();
        let high_target = builder.add_virtual_target();

        builder.range_check(low_target, 32);
        builder.range_check(high_target, 32);
        let base = builder.constant(F::from_canonical_u64(1u64 << 32));
        let reconstructed = builder.mul_add(high_target, base, low_target);
        builder.connect(balance, reconstructed);

        let (amount_low, amount_high) = builder.split_low_high(amount, 32, 64);
        let high_lte = list_lte_circuit(&mut builder, vec![high_target], vec![amount_high], 32);
        let low_lte = list_lte_circuit(&mut builder, vec![low_target], vec![amount_low], 32);
        let high_gt = builder.not(high_lte);
        let low_gt = builder.not(low_lte);
        let high_eq = builder.is_equal(high_target, amount_high);
        let equal_high_and_low_gt = builder.and(high_eq, low_gt);
        let is_gt = builder.or(high_gt, equal_high_and_low_gt);
        let is_lte = builder.not(is_gt);
        let balance_gt_amount = builder.not(is_lte);
        let values_equal = builder.is_equal(balance, amount);
        let is_gte = builder.or(balance_gt_amount, values_equal);
        let true_target = builder._true().target;
        builder.connect(is_gte.target, true_target);

        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        witness.set_target(balance, F::from_canonical_u64(BALANCE))?;
        witness.set_target(low_target, F::from_canonical_u64(low))?;
        witness.set_target(high_target, F::from_canonical_u64(high))?;
        let proof = data.prove(witness)?;
        data.verify(proof)
    }

    #[test]
    fn alias_split_accepts_balance_five_ge_one_hundred() {
        balance_ge_amount_with_split(ALIAS_HIGH, ALIAS_LOW).expect("alias split must satisfy 5 >= 100");
    }

    #[test]
    fn canonical_split_rejects_balance_five_ge_one_hundred() {
        assert!(
            balance_ge_amount_with_split(0, BALANCE).is_err(),
            "canonical split of 5 must not satisfy 5 >= 100"
        );
    }

    #[derive(Debug)]
    struct FinishedGenerator;

    impl<F: RichField + Extendable<D>, const D: usize> WitnessGenerator<F, D> for FinishedGenerator {
        fn id(&self) -> String {
            "FinishedGenerator".to_string()
        }

        fn watch_list(&self) -> Vec<Target> {
            Vec::new()
        }

        fn run(&self, _witness: &PartitionWitness<F>, _out_buffer: &mut GeneratedValues<F>) -> bool {
            true
        }

        fn serialize(&self, _dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
            Ok(())
        }

        fn deserialize(_src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
            Ok(FinishedGenerator)
        }
    }

    fn read_usize(bytes: &mut &[u8]) -> usize {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes[..8]);
        *bytes = &bytes[8..];
        u64::from_le_bytes(raw) as usize
    }

    fn read_target(bytes: &mut &[u8]) -> Target {
        let is_wire = bytes[0] != 0;
        *bytes = &bytes[1..];
        if is_wire {
            let row = read_usize(bytes);
            let column = read_usize(bytes);
            Target::Wire(Wire { row, column })
        } else {
            Target::VirtualTarget { index: read_usize(bytes) }
        }
    }

    /// `is_greater_than_or_equal` calls `split_low_high`. That generator writes the
    /// canonical limbs, so the alias case replaces it and supplies the other limbs
    /// to the comparison constraints.
    fn real_gte_with_balance_split(high: u64, low: u64, replace_balance_generator: bool) -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let balance = builder.add_virtual_target();
        let amount = builder.constant(F::from_canonical_u64(AMOUNT));
        let compared = builder.is_greater_than_or_equal(64, balance, amount);
        let true_target = builder._true().target;
        builder.connect(compared.target, true_target);
        let mut data = builder.build::<C>();

        let mut balance_limbs = None;
        for generator in &mut data.prover_only.generators {
            if generator.0.id() != "LowHighGenerator" {
                continue;
            }
            let mut encoded = Vec::new();
            generator.0.serialize(&mut encoded, &data.common).expect("serialize LowHighGenerator");
            let mut cursor = encoded.as_slice();
            let integer = read_target(&mut cursor);
            let n_log = read_usize(&mut cursor);
            let low_target = read_target(&mut cursor);
            let high_target = read_target(&mut cursor);
            if integer != balance || n_log != 32 {
                continue;
            }
            balance_limbs = Some((low_target, high_target));
            if replace_balance_generator {
                *generator = WitnessGeneratorRef::new(FinishedGenerator);
            }
        }
        let (low_target, high_target) = balance_limbs.expect("balance split_low_high generator");

        let mut witness = PartialWitness::new();
        witness.set_target(balance, F::from_canonical_u64(BALANCE))?;
        if replace_balance_generator {
            witness.set_target(low_target, F::from_canonical_u64(low))?;
            witness.set_target(high_target, F::from_canonical_u64(high))?;
        }
        let proof = data.prove(witness)?;
        data.verify(proof)
    }

    #[test]
    fn real_comparison_accepts_alias_split() {
        real_gte_with_balance_split(ALIAS_HIGH, ALIAS_LOW, true).expect("real >= must accept the alias split of 5");
    }

    #[test]
    fn real_comparison_rejects_canonical_split() {
        assert!(
            real_gte_with_balance_split(0, BALANCE, false).is_err(),
            "real >= must reject canonical 5 against 100"
        );
    }

    #[test]
    fn alias_comparison_then_field_sub_wraps_balance() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let balance = builder.add_virtual_target();
        let amount = builder.constant(F::from_canonical_u64(AMOUNT));
        let compared = builder.is_greater_than_or_equal(64, balance, amount);
        let true_target = builder._true().target;
        builder.connect(compared.target, true_target);
        let wrapped = builder.sub(balance, amount);
        builder.register_public_input(wrapped);
        let mut data = builder.build::<C>();

        let mut balance_limbs = None;
        for generator in &mut data.prover_only.generators {
            if generator.0.id() != "LowHighGenerator" {
                continue;
            }
            let mut encoded = Vec::new();
            generator.0.serialize(&mut encoded, &data.common).expect("serialize LowHighGenerator");
            let mut cursor = encoded.as_slice();
            let integer = read_target(&mut cursor);
            let n_log = read_usize(&mut cursor);
            let low_target = read_target(&mut cursor);
            let high_target = read_target(&mut cursor);
            if integer != balance || n_log != 32 {
                continue;
            }
            balance_limbs = Some((low_target, high_target));
            *generator = WitnessGeneratorRef::new(FinishedGenerator);
        }
        let (low_target, high_target) = balance_limbs.expect("balance split_low_high generator");

        let mut witness = PartialWitness::new();
        witness.set_target(balance, F::from_canonical_u64(BALANCE)).unwrap();
        witness.set_target(low_target, F::from_canonical_u64(ALIAS_LOW)).unwrap();
        witness.set_target(high_target, F::from_canonical_u64(ALIAS_HIGH)).unwrap();
        let proof = data.prove(witness).expect("aliased 5 >= 100 and field subtraction must prove");
        data.verify(proof.clone()).expect("proof must verify");

        let prime = goldilocks_prime();
        let wrapped_value = (prime - (AMOUNT as u128 - BALANCE as u128)) as u64;
        let expected = F::from_canonical_u64(BALANCE) - F::from_canonical_u64(AMOUNT);
        assert_eq!(expected, F::from_canonical_u64(wrapped_value));
        assert_eq!(proof.public_inputs[0], expected);
    }
}
