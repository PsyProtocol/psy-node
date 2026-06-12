use std::{any::TypeId, marker::PhantomData};

use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField},
    },
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::PartitionWitness,
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::{
    crypto::{
        bn254::{
            field::{bn128_base::Bn128Base, bn128_scalar::Bn128Scalar},
            gadgets::gates::{nonnative_add::NonnativeAddGate, nonnative_mul::NonnativeMulGate, u28_to_u32::U28ToU32Gate, u32_to_u28::U32ToU28Gate},
        },
        secp256k1::ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint, GeneratedValuesBigUint, WitnessBigUint},
    },
    u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target},
};

fn ceil_div_usize(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

#[derive(Clone, Debug)]
pub struct NonNativeTarget<FF: Field> {
    pub value: BigUintTarget,
    pub _phantom: PhantomData<FF>,
}

impl<FF: Field> NonNativeTarget<FF> {
    pub fn new(value: BigUintTarget) -> Self {
        Self {
            value,
            _phantom: PhantomData,
        }
    }
}

pub trait CircuitBuilderNonNative<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_nonnative_target<FF: Field>(&mut self) -> NonNativeTarget<FF>;

    fn constant_nonnative<FF: PrimeField>(&mut self, value: FF) -> NonNativeTarget<FF>;

    fn add_nonnative<FF: Field>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn sub_nonnative<FF: Field + PrimeField>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn mul_nonnative<FF: Field>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn inv_nonnative<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn div_nonnative<FF: Field + PrimeField>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn neg_nonnative<FF: Field + PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn is_equal_nonnative<FF: Field>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> BoolTarget;

    fn is_zero_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> BoolTarget;

    fn select_nonnative<FF: Field>(
        &mut self,
        condition: BoolTarget,
        true_value: &NonNativeTarget<FF>,
        false_value: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF>;

    fn zero_nonnative<FF: Field>(&mut self) -> NonNativeTarget<FF>;

    fn one_nonnative<FF: PrimeField>(&mut self) -> NonNativeTarget<FF>;

    fn bool_to_nonnative<FF: PrimeField>(&mut self, b: BoolTarget) -> NonNativeTarget<FF>;

    fn pow_nonnative<FF: PrimeField>(&mut self, base: &NonNativeTarget<FF>, exponent: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn square_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn cube_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn mul_by_nonresidue_nonnative<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn assert_valid_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>);

    fn reduce_nonnative<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF>;

    fn connect_nonnative<FF: Field>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>);

    fn mul_nonnative_by_bool<FF: Field>(&mut self, a: &NonNativeTarget<FF>, b: BoolTarget) -> NonNativeTarget<FF>;

    fn nonnative_conditional_neg<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>, condition: BoolTarget) -> NonNativeTarget<FF>;

    fn split_nonnative_to_bits<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> Vec<BoolTarget>;

    fn reduce<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF>;

    fn biguint_to_nonnative<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF>;

    fn nonnative_to_canonical_biguint<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> BigUintTarget;

    fn if_nonnative<FF: PrimeField>(&mut self, b: BoolTarget, x: &NonNativeTarget<FF>, y: &NonNativeTarget<FF>) -> NonNativeTarget<FF>;

    fn add_virtual_nonnative_target_sized<FF: Field>(&mut self, num_limbs: usize) -> NonNativeTarget<FF>;

    fn num_nonnative_limbs<FF: Field>() -> usize;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderNonNative<F, D> for CircuitBuilder<F, D> {
    fn add_virtual_nonnative_target<FF: Field>(&mut self) -> NonNativeTarget<FF> {
        let value = self.add_virtual_biguint_target(8);
        NonNativeTarget::new(value)
    }

    fn constant_nonnative<FF: PrimeField>(&mut self, value: FF) -> NonNativeTarget<FF> {
        let mut x_biguint = self.constant_biguint(&value.to_canonical_biguint());
        let num_limbs = FF::BITS / 32;
        for _ in 0..(num_limbs - x_biguint.num_limbs()) {
            x_biguint.limbs.push(self.constant_u32(0));
        }
        self.biguint_to_nonnative(&x_biguint)
    }

    fn add_nonnative<FF: Field>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let gate = NonnativeAddGate::<F, FF, D>::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);
        let mut targets = Vec::new();

        for i in 0..8 {
            self.connect(Target::wire(row, gate.wire_ith_input_x(copy, i)), lhs.value.limbs[i].0);
            self.connect(Target::wire(row, gate.wire_ith_input_y(copy, i)), rhs.value.limbs[i].0);
            targets.push(U32Target(Target::wire(row, gate.wire_ith_output_result(copy, i))));
        }

        NonNativeTarget::new(BigUintTarget { limbs: targets })
    }

    fn sub_nonnative<FF: Field + PrimeField>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let diff = self.add_virtual_nonnative_target::<FF>();
        self.add_simple_generator(NonNativeSubtractionGenerator::<F, D, FF> {
            a: lhs.clone(),
            b: rhs.clone(),
            diff: diff.clone(),
            _phantom: PhantomData,
        });

        use crate::u32::gadgets::range_check::range_check_u32_circuit;
        range_check_u32_circuit(self, diff.value.limbs.clone());

        let diff_plus_b = self.add_nonnative(&diff, rhs);
        self.connect_nonnative(lhs, &diff_plus_b);

        diff
    }

    fn mul_nonnative<FF: Field>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let gate = U32ToU28Gate::<F, D>::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);
        for i in 0..8 {
            self.connect(Target::wire(row, gate.wire_ith_input(copy, i)), lhs.value.limbs[i].0);
        }
        let mut a_targets = Vec::new();
        for i in 0..10 {
            a_targets.push(Target::wire(row, gate.wire_ith_output_result(copy, i)));
        }

        let gate = U32ToU28Gate::<F, D>::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);
        for i in 0..8 {
            self.connect(Target::wire(row, gate.wire_ith_input(copy, i)), rhs.value.limbs[i].0);
        }
        let mut b_targets = Vec::new();
        for i in 0..10 {
            b_targets.push(Target::wire(row, gate.wire_ith_output_result(copy, i)));
        }

        let mut xy = Vec::new();
        let gate = NonnativeMulGate::<F, FF, D>::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);
        for i in 0..10 {
            self.connect(Target::wire(row, gate.wire_ith_input_x(copy, i)), a_targets[i]);
            self.connect(Target::wire(row, gate.wire_ith_input_y(copy, i)), b_targets[i]);
            xy.push(Target::wire(row, gate.wire_ith_output_result(copy, i)));
        }

        let mut res = Vec::new();
        let gate = NonnativeMulGate::<F, FF, D>::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);

        // Choose Montgomery inverse based on field type
        let mont_inv_limbs = if TypeId::of::<FF>() == TypeId::of::<Bn128Base>() {
            // BN128 Base field Montgomery inverse in 28-bit limbs
            [
                0x14afa37, 0x84884a0, 0x8edf8ed, 0x2285027, 0x2d9eb20, 0xcfb7449, 0x9cf63e9, 0x59e5c63, 0xe671571, 0x2,
            ]
        } else if TypeId::of::<FF>() == TypeId::of::<Bn128Scalar>() {
            // BN128 Scalar field with MONTGOMERY_INV = 1 (disabled Montgomery)
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        } else {
            panic!("NonNative multiplication gate only supports Bn128Base and Bn128Scalar fields");
        };

        for i in 0..10 {
            self.connect(Target::wire(row, gate.wire_ith_input_x(copy, i)), xy[i]);
            let inv = self.constant(F::from_canonical_u32(mont_inv_limbs[i]));
            self.connect(Target::wire(row, gate.wire_ith_input_y(copy, i)), inv);
            res.push(Target::wire(row, gate.wire_ith_output_result(copy, i)));
        }

        let gate = U28ToU32Gate::<F, D>::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);
        for i in 0..10 {
            self.connect(Target::wire(row, gate.wire_ith_input(copy, i)), res[i]);
        }
        let mut targets = Vec::new();
        for i in 0..8 {
            targets.push(U32Target(Target::wire(row, gate.wire_ith_output_result(copy, i))));
        }

        NonNativeTarget::new(BigUintTarget { limbs: targets })
    }

    fn inv_nonnative<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        // Following ark-r1cs-std approach: allocate witness that is either inverse or
        // zero
        let num_limbs = x.value.num_limbs();
        let inv_biguint = self.add_virtual_biguint_target(num_limbs);

        // Check if x is zero
        let x_is_zero = self.is_zero_nonnative(x);

        // Add generator that computes inv = x.inverse() if x != 0, else 0
        self.add_simple_generator(NonNativeInverseGenerator::<F, D, FF> {
            x: x.clone(),
            inv: inv_biguint.clone(),
            _phantom: PhantomData,
        });

        // Add constraint: inv * x = !x_is_zero
        // This ensures inv is the inverse when x != 0, and is 0 when x = 0
        let product = self.mul_nonnative(
            &x,
            &NonNativeTarget {
                value: inv_biguint.clone(),
                _phantom: PhantomData,
            },
        );

        let one = self.one_nonnative();
        let zero = self.zero_nonnative();
        let not_zero = self.not(x_is_zero);
        let expected = self.select_nonnative(not_zero, &one, &zero);
        self.connect_nonnative(&product, &expected);

        NonNativeTarget::<FF> {
            value: inv_biguint,
            _phantom: PhantomData,
        }
    }

    fn div_nonnative<FF: Field + PrimeField>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let rhs_inv = self.inv_nonnative(rhs);
        self.mul_nonnative(lhs, &rhs_inv)
    }

    fn neg_nonnative<FF: Field + PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let zero = self.zero_nonnative();
        self.sub_nonnative(&zero, x)
    }

    fn is_equal_nonnative<FF: Field>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) -> BoolTarget {
        let mut all_equal = self._true();
        let (lhs_padded, rhs_padded) = self.pad_biguints(&lhs.value, &rhs.value);

        for (lhs_limb, rhs_limb) in lhs_padded.limbs.iter().zip(rhs_padded.limbs.iter()) {
            let limb_equal = self.is_equal(lhs_limb.0, rhs_limb.0);
            all_equal = self.and(all_equal, limb_equal);
        }

        all_equal
    }

    fn is_zero_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> BoolTarget {
        let zero = self.zero_biguint();
        self.is_equal_nonnative(&NonNativeTarget::new(zero), x)
    }

    fn select_nonnative<FF: Field>(
        &mut self,
        condition: BoolTarget,
        true_value: &NonNativeTarget<FF>,
        false_value: &NonNativeTarget<FF>,
    ) -> NonNativeTarget<FF> {
        let (true_padded, false_padded) = self.pad_biguints(&true_value.value, &false_value.value);
        let result_limbs: Vec<_> = true_padded
            .limbs
            .iter()
            .zip(false_padded.limbs.iter())
            .map(|(&true_limb, &false_limb)| {
                let selected = self.select(condition, true_limb.0, false_limb.0);
                crate::u32::gadgets::arithmetic_u32::U32Target(selected)
            })
            .collect();

        NonNativeTarget::new(BigUintTarget { limbs: result_limbs })
    }

    fn zero_nonnative<FF: Field>(&mut self) -> NonNativeTarget<FF> {
        let zero_limbs = vec![self.zero_u32(); 8];
        let zero = BigUintTarget { limbs: zero_limbs };
        NonNativeTarget::new(zero)
    }

    fn one_nonnative<FF: PrimeField>(&mut self) -> NonNativeTarget<FF> {
        self.constant_nonnative(FF::ONE)
    }

    fn bool_to_nonnative<FF: PrimeField>(&mut self, b: BoolTarget) -> NonNativeTarget<FF> {
        let one = self.one_nonnative();
        let zero = self.zero_nonnative();
        self.select_nonnative(b, &one, &zero)
    }

    fn pow_nonnative<FF: PrimeField>(&mut self, base: &NonNativeTarget<FF>, _exponent: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let mut _result = self.one_nonnative::<FF>();
        let base_power = base.clone();

        let squared = self.mul_nonnative(&base_power, &base_power);
        squared
    }

    fn square_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        self.mul_nonnative(x, x)
    }

    fn cube_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let x_squared = self.square_nonnative(x);
        self.mul_nonnative(x, &x_squared)
    }

    fn mul_by_nonresidue_nonnative<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        // Check if FF is Bn128Base
        use core::any::TypeId;

        use crate::crypto::bn254::field::bn128_base::Bn128Base;

        if TypeId::of::<FF>() == TypeId::of::<Bn128Base>() {
            // For Bn128Base in Fp, the nonresidue is -1
            self.neg_nonnative(x)
        } else {
            // For generic fields, multiply by FF::NONRESIDUE if available
            // Since we don't have FF::NONRESIDUE in the trait bounds, we use NEG_ONE
            self.neg_nonnative(x)
        }
    }

    fn assert_valid_nonnative<FF: Field>(&mut self, x: &NonNativeTarget<FF>) {
        let modulus = self.constant_biguint(&FF::characteristic());
        let is_valid = self.cmp_biguint(&x.value, &modulus);
        self.assert_one(is_valid.target);
    }

    fn reduce_nonnative<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF> {
        let modulus = self.constant_biguint(&FF::characteristic());

        let remainder = self.rem_biguint(x, &modulus);

        NonNativeTarget::new(remainder)
    }

    fn connect_nonnative<FF: Field>(&mut self, lhs: &NonNativeTarget<FF>, rhs: &NonNativeTarget<FF>) {
        self.connect_biguint(&lhs.value, &rhs.value);
    }

    fn mul_nonnative_by_bool<FF: Field>(&mut self, a: &NonNativeTarget<FF>, b: BoolTarget) -> NonNativeTarget<FF> {
        let result = self.mul_biguint_by_bool(&a.value, b);
        NonNativeTarget::new(result)
    }

    fn nonnative_conditional_neg<FF: PrimeField>(&mut self, x: &NonNativeTarget<FF>, condition: BoolTarget) -> NonNativeTarget<FF> {
        let neg = self.neg_nonnative(x);
        self.select_nonnative(condition, &neg, x)
    }

    fn split_nonnative_to_bits<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> Vec<BoolTarget> {
        let num_limbs = x.value.num_limbs();
        let mut result = Vec::with_capacity(num_limbs * 32);

        for i in 0..num_limbs {
            let limb = x.value.get_limb(i);
            let bit_targets = self.split_le_base::<2>(limb.0, 32);
            let bits: Vec<_> = bit_targets.iter().map(|&t| BoolTarget::new_unsafe(t)).collect();

            result.extend(bits);
        }

        result
    }

    fn reduce<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF> {
        self.reduce_nonnative(x)
    }

    fn biguint_to_nonnative<FF: Field>(&mut self, x: &BigUintTarget) -> NonNativeTarget<FF> {
        NonNativeTarget {
            value: x.clone(),
            _phantom: PhantomData,
        }
    }

    fn nonnative_to_canonical_biguint<FF: Field>(&mut self, x: &NonNativeTarget<FF>) -> BigUintTarget {
        x.value.clone()
    }

    fn if_nonnative<FF: PrimeField>(&mut self, b: BoolTarget, x: &NonNativeTarget<FF>, y: &NonNativeTarget<FF>) -> NonNativeTarget<FF> {
        let not_b = self.not(b);
        let maybe_x = self.mul_nonnative_by_bool(x, b);
        let maybe_y = self.mul_nonnative_by_bool(y, not_b);
        self.add_nonnative(&maybe_x, &maybe_y)
    }

    fn add_virtual_nonnative_target_sized<FF: Field>(&mut self, num_limbs: usize) -> NonNativeTarget<FF> {
        let value = self.add_virtual_biguint_target(num_limbs);
        NonNativeTarget {
            value,
            _phantom: PhantomData,
        }
    }

    fn num_nonnative_limbs<FF: Field>() -> usize {
        ceil_div_usize(FF::BITS, 32)
    }
}

#[derive(Debug)]
struct NonNativeSubtractionGenerator<F: RichField + Extendable<D>, const D: usize, FF: Field> {
    a: NonNativeTarget<FF>,
    b: NonNativeTarget<FF>,
    diff: NonNativeTarget<FF>,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> SimpleGenerator<F, D> for NonNativeSubtractionGenerator<F, D, FF> {
    fn id(&self) -> String {
        "NonNativeSubtractionGenerator".to_string()
    }

    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> Result<(), plonky2::util::serialization::IoError> {
        use plonky2::util::serialization::Write;
        dst.write_usize(self.a.value.limbs.len())?;
        for limb in &self.a.value.limbs {
            dst.write_target(limb.0)?;
        }
        for limb in &self.b.value.limbs {
            dst.write_target(limb.0)?;
        }
        for limb in &self.diff.value.limbs {
            dst.write_target(limb.0)?;
        }
        Ok(())
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> Result<Self, plonky2::util::serialization::IoError> {
        use plonky2::util::serialization::Read;
        let limb_count = src.read_usize()?;

        let mut a_limbs = Vec::with_capacity(limb_count);
        for _ in 0..limb_count {
            a_limbs.push(U32Target(src.read_target()?));
        }

        let mut b_limbs = Vec::with_capacity(limb_count);
        for _ in 0..limb_count {
            b_limbs.push(U32Target(src.read_target()?));
        }

        let mut diff_limbs = Vec::with_capacity(limb_count);
        for _ in 0..limb_count {
            diff_limbs.push(U32Target(src.read_target()?));
        }

        Ok(Self {
            a: NonNativeTarget::new(BigUintTarget { limbs: a_limbs }),
            b: NonNativeTarget::new(BigUintTarget { limbs: b_limbs }),
            diff: NonNativeTarget::new(BigUintTarget { limbs: diff_limbs }),
            _phantom: PhantomData,
        })
    }

    fn dependencies(&self) -> Vec<Target> {
        self.a
            .value
            .limbs
            .iter()
            .cloned()
            .chain(self.b.value.limbs.clone())
            .map(|l| l.0)
            .collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) -> Result<(), anyhow::Error> {
        let a_biguint = witness.get_biguint_target(&self.a.value);
        let b_biguint = witness.get_biguint_target(&self.b.value);
        let p = FF::order();

        let a_mod_p = a_biguint % &p;
        let b_mod_p = b_biguint % &p;

        let diff_biguint = if a_mod_p >= b_mod_p { a_mod_p - b_mod_p } else { a_mod_p + &p - b_mod_p };

        out_buffer.set_biguint_target(&self.diff.value, &diff_biguint)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NonNativeInverseGenerator<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> {
    pub x: NonNativeTarget<FF>,
    pub inv: BigUintTarget,
    pub _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize, FF: PrimeField> SimpleGenerator<F, D> for NonNativeInverseGenerator<F, D, FF> {
    fn id(&self) -> String {
        "NonNativeInverseGenerator".to_string()
    }

    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> Result<(), plonky2::util::serialization::IoError> {
        use plonky2::util::serialization::Write;
        dst.write_usize(self.x.value.limbs.len())?;
        dst.write_usize(self.inv.limbs.len())?;
        let x_targets: Vec<Target> = self.x.value.limbs.iter().map(|l| l.0).collect();
        let inv_targets: Vec<Target> = self.inv.limbs.iter().map(|l| l.0).collect();
        dst.write_target_vec(&x_targets)?;
        dst.write_target_vec(&inv_targets)?;
        Ok(())
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> Result<Self, plonky2::util::serialization::IoError> {
        use plonky2::util::serialization::Read;
        let limb_count_x = src.read_usize()?;
        let limb_count_inv = src.read_usize()?;
        let mut limbs_x = Vec::with_capacity(limb_count_x);
        for _ in 0..limb_count_x {
            limbs_x.push(U32Target(src.read_target()?));
        }
        let mut limbs_inv = Vec::with_capacity(limb_count_inv);
        for _ in 0..limb_count_inv {
            limbs_inv.push(U32Target(src.read_target()?));
        }
        Ok(Self {
            x: NonNativeTarget {
                value: BigUintTarget { limbs: limbs_x },
                _phantom: PhantomData,
            },
            inv: BigUintTarget { limbs: limbs_inv },
            _phantom: PhantomData,
        })
    }

    fn dependencies(&self) -> Vec<Target> {
        self.x.value.limbs.iter().map(|&l| l.0).collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) -> Result<(), anyhow::Error> {
        let x = FF::from_noncanonical_biguint(witness.get_biguint_target(&self.x.value));
        let inv_biguint = if x.is_zero() {
            // If x is zero, set inv to zero
            num::BigUint::from(0u32)
        } else {
            // Otherwise, compute the inverse
            let inv = x.inverse();
            inv.to_canonical_biguint()
        };
        out_buffer.set_biguint_target(&self.inv, &inv_biguint)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Field,
        iop::witness::PartialWitness,
        plonk::{
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::*;
    use crate::crypto::bn254::field::bn128_base::Bn128Base;

    type FF = Bn128Base;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_constant_nonnative() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x_ff = FF::from_canonical_u64(12345);
        let x_target = builder.constant_nonnative(x_ff);

        let y_target = builder.constant_nonnative(x_ff);

        builder.connect_nonnative(&x_target, &y_target);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_nonnative_addition() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a_ff = FF::from_canonical_u64(100);
        let b_ff = FF::from_canonical_u64(200);
        let sum_ff = a_ff + b_ff;

        let a = builder.constant_nonnative(a_ff);
        let b = builder.constant_nonnative(b_ff);
        let sum = builder.add_nonnative(&a, &b);

        let sum_expected = builder.constant_nonnative(sum_ff);
        builder.connect_nonnative(&sum, &sum_expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_nonnative_subtraction() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            num_routed_wires: 80,
            num_constants: 2,
            use_base_arithmetic_gate: true,
            security_bits: 100,
            num_challenges: 2,
            zero_knowledge: false,
            max_quotient_degree_factor: 8,
            fri_config: plonky2::fri::FriConfig {
                rate_bits: 3,
                cap_height: 4,
                proof_of_work_bits: 16,
                reduction_strategy: plonky2::fri::reduction_strategies::FriReductionStrategy::ConstantArityBits(4, 5),
                num_query_rounds: 28,
            },
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a_ff = FF::from_canonical_u64(300);
        let b_ff = FF::from_canonical_u64(100);
        let _diff_ff = a_ff - b_ff;

        let a = builder.constant_nonnative(a_ff);
        let b = builder.constant_nonnative(b_ff);
        let diff = builder.sub_nonnative(&a, &b);

        let sum = builder.add_nonnative(&diff, &b);
        builder.connect_nonnative(&sum, &a);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_nonnative_multiplication() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a_ff = FF::from_canonical_u64(7);
        let b_ff = FF::from_canonical_u64(13);
        let product_ff = a_ff * b_ff;

        let a = builder.constant_nonnative(a_ff);
        let b = builder.constant_nonnative(b_ff);
        let product = builder.mul_nonnative(&a, &b);

        let product_expected = builder.constant_nonnative(product_ff);
        builder.connect_nonnative(&product, &product_expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_nonnative_negation() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x_ff = FF::from_canonical_u64(42);
        let neg_x_ff = -x_ff;

        let x = builder.constant_nonnative(x_ff);
        let neg_x = builder.neg_nonnative(&x);

        let neg_x_expected = builder.constant_nonnative(neg_x_ff);
        builder.connect_nonnative(&neg_x, &neg_x_expected);

        let sum = builder.add_nonnative(&x, &neg_x);
        let zero = builder.zero_nonnative();
        builder.connect_nonnative(&sum, &zero);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_safe_inverse_with_zero() {
        // Test that inverse of zero returns zero (ark-r1cs-std behavior)
        let config = CircuitConfig {
            num_wires: 400,
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let zero = builder.zero_nonnative::<FF>();
        let inv_zero = builder.inv_nonnative(&zero);

        // inv(0) should be 0
        let expected_zero = builder.zero_nonnative();
        builder.connect_nonnative(&inv_zero, &expected_zero);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_nonnative_inverse() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            num_routed_wires: 80,
            num_constants: 2,
            use_base_arithmetic_gate: true,
            security_bits: 100,
            num_challenges: 2,
            zero_knowledge: false,
            max_quotient_degree_factor: 8,
            fri_config: plonky2::fri::FriConfig {
                rate_bits: 3,
                cap_height: 4,
                proof_of_work_bits: 16,
                reduction_strategy: plonky2::fri::reduction_strategies::FriReductionStrategy::ConstantArityBits(4, 5),
                num_query_rounds: 28,
            },
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x_ff = FF::from_canonical_u64(7);
        let inv_x_ff = x_ff.inverse();

        let x = builder.constant_nonnative(x_ff);
        let inv_x = builder.inv_nonnative(&x);

        let inv_x_expected = builder.constant_nonnative(inv_x_ff);
        builder.connect_nonnative(&inv_x, &inv_x_expected);

        let product = builder.mul_nonnative(&x, &inv_x);
        let one = builder.constant_nonnative(FF::ONE);
        builder.connect_nonnative(&product, &one);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_bool_to_nonnative() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let true_val = builder._true();
        let false_val = builder._false();

        let true_nn = builder.bool_to_nonnative::<FF>(true_val);
        let false_nn = builder.bool_to_nonnative::<FF>(false_val);

        let one = builder.one_nonnative();
        let zero = builder.zero_nonnative();

        builder.connect_nonnative(&true_nn, &one);
        builder.connect_nonnative(&false_nn, &zero);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_mul_by_bool() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x_ff = FF::from_canonical_u64(42);
        let x = builder.constant_nonnative(x_ff);

        let true_val = builder._true();
        let false_val = builder._false();

        let x_times_true = builder.mul_nonnative_by_bool(&x, true_val);
        builder.connect_nonnative(&x_times_true, &x);

        let x_times_false = builder.mul_nonnative_by_bool(&x, false_val);
        let zero = builder.zero_nonnative();
        builder.connect_nonnative(&x_times_false, &zero);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_select_nonnative() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let a_ff = FF::from_canonical_u64(100);
        let b_ff = FF::from_canonical_u64(200);

        let a = builder.constant_nonnative(a_ff);
        let b = builder.constant_nonnative(b_ff);

        let true_val = builder._true();
        let false_val = builder._false();

        let selected_true = builder.select_nonnative(true_val, &a, &b);
        builder.connect_nonnative(&selected_true, &a);

        let selected_false = builder.select_nonnative(false_val, &a, &b);
        builder.connect_nonnative(&selected_false, &b);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_conditional_neg() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x_ff = FF::from_canonical_u64(42);
        let x = builder.constant_nonnative(x_ff);

        let true_val = builder._true();
        let false_val = builder._false();

        let neg_if_true = builder.nonnative_conditional_neg(&x, true_val);
        let neg_x = builder.neg_nonnative(&x);
        builder.connect_nonnative(&neg_if_true, &neg_x);

        let neg_if_false = builder.nonnative_conditional_neg(&x, false_val);
        builder.connect_nonnative(&neg_if_false, &x);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_nonnative_performance_batch_operations() {
        use std::time::Instant;

        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let values: Vec<FF> = (1..=10).map(|i| FF::from_canonical_u64(i as u64 * 123)).collect();
        let targets: Vec<_> = values.iter().map(|&v| builder.constant_nonnative(v)).collect();

        let mut result = targets[0].clone();
        for i in 1..targets.len() {
            result = builder.add_nonnative(&result, &targets[i]);
            let constant = builder.constant_nonnative(FF::from_canonical_u64(2));
            result = builder.mul_nonnative(&result, &constant);
        }

        let final_target = builder.add_virtual_nonnative_target();
        builder.connect_nonnative(&result, &final_target);

        let start = Instant::now();
        let data = builder.build::<C>();
        let build_time = start.elapsed();

        let pw = PartialWitness::new();

        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let prove_time = start.elapsed();

        let start = Instant::now();
        data.verify(proof).unwrap();
        let verify_time = start.elapsed();

        assert!(build_time.as_millis() < 5000, "Build time too long: {:?}", build_time);
        assert!(prove_time.as_millis() < 10000, "Prove time too long: {:?}", prove_time);
        assert!(verify_time.as_millis() < 1000, "Verify time too long: {:?}", verify_time);
    }

    #[test]
    fn test_nonnative_large_field_operations() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            num_routed_wires: 80,
            num_constants: 2,
            use_base_arithmetic_gate: true,
            security_bits: 100,
            num_challenges: 2,
            zero_knowledge: false,
            max_quotient_degree_factor: 8,
            fri_config: plonky2::fri::FriConfig {
                rate_bits: 3,
                cap_height: 4,
                proof_of_work_bits: 16,
                reduction_strategy: plonky2::fri::reduction_strategies::FriReductionStrategy::ConstantArityBits(4, 5),
                num_query_rounds: 28,
            },
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let large_val1 = FF::from_canonical_u64(u64::MAX - 1000);
        let large_val2 = FF::from_canonical_u64(u64::MAX - 2000);

        let target1 = builder.constant_nonnative(large_val1);
        let target2 = builder.constant_nonnative(large_val2);

        let _sum = builder.add_nonnative(&target1, &target2);
        let diff = builder.sub_nonnative(&target1, &target2);
        let _product = builder.mul_nonnative(&target1, &target2);
        let inv1 = builder.inv_nonnative(&target1);

        let diff_plus_b = builder.add_nonnative(&diff, &target2);
        builder.connect_nonnative(&diff_plus_b, &target1);

        let one = builder.constant_nonnative(FF::ONE);
        let product_inv = builder.mul_nonnative(&target1, &inv1);
        builder.connect_nonnative(&product_inv, &one);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_nonnative_edge_cases() {
        let config = CircuitConfig {
            num_wires: 400, // Enough for NonnativeMulGate (334) and some margin
            num_routed_wires: 80,
            num_constants: 2,
            use_base_arithmetic_gate: true,
            security_bits: 100,
            num_challenges: 2,
            zero_knowledge: false,
            max_quotient_degree_factor: 8,
            fri_config: plonky2::fri::FriConfig {
                rate_bits: 3,
                cap_height: 4,
                proof_of_work_bits: 16,
                reduction_strategy: plonky2::fri::reduction_strategies::FriReductionStrategy::ConstantArityBits(4, 5),
                num_query_rounds: 28,
            },
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let zero: NonNativeTarget<FF> = builder.zero_nonnative();
        let one = builder.constant_nonnative(FF::ONE);
        let value = builder.constant_nonnative(FF::from_canonical_u64(42));

        let zero_plus_value = builder.add_nonnative(&zero, &value);
        builder.connect_nonnative(&zero_plus_value, &value);

        let value_plus_zero = builder.add_nonnative(&value, &zero);
        builder.connect_nonnative(&value_plus_zero, &value);

        let zero_times_value = builder.mul_nonnative(&zero, &value);
        builder.connect_nonnative(&zero_times_value, &zero);

        let one_times_value = builder.mul_nonnative(&one, &value);
        builder.connect_nonnative(&one_times_value, &value);

        let value_times_one = builder.mul_nonnative(&value, &one);
        builder.connect_nonnative(&value_times_one, &value);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_bn128_scalar_operations() {
        use crate::crypto::bn254::field::bn128_scalar::Bn128Scalar;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test simple addition first
        let a = Bn128Scalar::from_canonical_u64(100);
        let b = Bn128Scalar::from_canonical_u64(200);
        let sum = a + b;

        let a_target = builder.constant_nonnative(a);
        let b_target = builder.constant_nonnative(b);
        let sum_target = builder.add_nonnative(&a_target, &b_target);

        let expected = builder.constant_nonnative(sum);
        builder.connect_nonnative(&sum_target, &expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_scalar_vs_base_field_operations() {
        use crate::crypto::bn254::field::bn128_scalar::Bn128Scalar;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with Scalar field (should use generic operations)
        let scalar_a = Bn128Scalar::from_canonical_u64(42);
        let scalar_b = Bn128Scalar::from_canonical_u64(17);
        let scalar_product = scalar_a * scalar_b;

        let scalar_a_target = builder.constant_nonnative(scalar_a);
        let scalar_b_target = builder.constant_nonnative(scalar_b);
        let scalar_product_target = builder.mul_nonnative(&scalar_a_target, &scalar_b_target);

        let expected_scalar = builder.constant_nonnative(scalar_product);
        builder.connect_nonnative(&scalar_product_target, &expected_scalar);

        // Test with Base field (should use specialized gates)
        let base_a = FF::from_canonical_u64(42);
        let base_b = FF::from_canonical_u64(17);
        let base_product = base_a * base_b;

        let base_a_target = builder.constant_nonnative(base_a);
        let base_b_target = builder.constant_nonnative(base_b);
        let base_product_target = builder.mul_nonnative(&base_a_target, &base_b_target);

        let expected_base = builder.constant_nonnative(base_product);
        builder.connect_nonnative(&base_product_target, &expected_base);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_bn128_scalar_multiplication() {
        use crate::crypto::bn254::field::bn128_scalar::Bn128Scalar;

        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test multiplication
        let x = Bn128Scalar::from_canonical_u64(7);
        let y = Bn128Scalar::from_canonical_u64(13);
        let product = x * y;

        let x_target = builder.constant_nonnative(x);
        let y_target = builder.constant_nonnative(y);
        let product_target = builder.mul_nonnative(&x_target, &y_target);

        let expected_product = builder.constant_nonnative(product);
        builder.connect_nonnative(&product_target, &expected_product);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_mul_by_nonresidue_nonnative() {
        let config = crate::crypto::bn254::pairing_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Test with specific values
        let x_ff = FF::from_canonical_u64(5);

        // For Bn128Base in Fp, mul_by_nonresidue should return -x
        let expected_ff = -x_ff;

        println!("Testing mul_by_nonresidue for Bn128Base in Fp");
        println!("x = {:?}", x_ff);
        println!("expected (-x) = {:?}", expected_ff);

        let x = builder.constant_nonnative(x_ff);
        let result = builder.mul_by_nonresidue_nonnative(&x);
        let expected = builder.constant_nonnative(expected_ff);

        builder.connect_nonnative(&result, &expected);

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();

        println!("✅ mul_by_nonresidue_nonnative test passed!");
    }
}
