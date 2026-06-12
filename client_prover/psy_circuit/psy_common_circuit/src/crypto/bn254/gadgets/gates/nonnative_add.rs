use core::marker::PhantomData;
use std::any::TypeId;

use num::BigUint;
use plonky2::{
    field::{extension::Extendable, packed::PackedField, types::Field},
    gates::{gate::Gate, packed_util::PackedEvaluableBase, util::StridedConstraintConsumer},
    hash::hash_types::RichField,
    iop::{
        ext_target::ExtensionTarget,
        generator::{GeneratedValues, SimpleGenerator, WitnessGeneratorRef},
        target::Target,
        wire::Wire,
        witness::{PartitionWitness, Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        vars::{EvaluationTargets, EvaluationVars, EvaluationVarsBase, EvaluationVarsBaseBatch, EvaluationVarsBasePacked},
    },
};

// Helper function to get field modulus as 32-bit limbs based on field type
fn get_field_modulus_32bit<F: Field>() -> [u32; 8] {
    use crate::crypto::bn254::field::{bn128_base::Bn128Base, bn128_scalar::Bn128Scalar};

    if TypeId::of::<F>() == TypeId::of::<Bn128Base>() {
        // BN128 Base field modulus in 32-bit limbs (little-endian)
        [
            0xd87cfd47, 0x3c208c16, 0x6871ca8d, 0x97816a91, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
        ]
    } else if TypeId::of::<F>() == TypeId::of::<Bn128Scalar>() {
        // BN128 Scalar field modulus in 32-bit limbs (little-endian)
        [
            0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
        ]
    } else {
        panic!("NonNative operations only support Bn128Base and Bn128Scalar fields");
    }
}

#[derive(Copy, Clone, Debug)]
pub struct NonnativeAddGate<F: RichField + Extendable<D>, FF: Field, const D: usize> {
    pub num_ops: usize,
    _phantom: PhantomData<(F, FF)>,
}

impl<F: RichField + Extendable<D>, FF: Field, const D: usize> NonnativeAddGate<F, FF, D> {
    pub fn new_from_config(config: &CircuitConfig) -> Self {
        Self {
            num_ops: Self::num_ops(config),
            _phantom: PhantomData,
        }
    }

    pub(crate) fn num_ops(config: &CircuitConfig) -> usize {
        let wires_per_op = 169;
        let routed_wires_per_op = 24;
        (config.num_wires / wires_per_op).min(config.num_routed_wires / routed_wires_per_op)
    }

    pub fn wire_ith_input_x(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < 8);
        24 * i + j
    }
    pub fn wire_ith_input_y(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < 8);
        24 * i + 8 + j
    }
    pub fn wire_ith_output_result(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < 8);
        24 * i + 16 + j
    }
    pub fn wire_ith_carry(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        24 * self.num_ops + 145 * i
    }
    pub fn wire_ith_carry_l(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < 8);
        24 * self.num_ops + 145 * i + 1 + j
    }
    pub fn wire_ith_carry_r(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < 8);
        24 * self.num_ops + 145 * i + 9 + j
    }
    pub fn wire_ith_output_jth_limb32_kth_limb2_bit(&self, i: usize, j: usize, k: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < 8);
        debug_assert!(k < 16);
        24 * self.num_ops + 145 * i + 17 + 16 * j + k
    }

    pub fn limb_bits() -> usize {
        2
    }
    pub fn num_limbs() -> usize {
        32 / Self::limb_bits()
    }
}

impl<F: RichField + Extendable<D>, FF: Field, const D: usize> Gate<F, D> for NonnativeAddGate<F, FF, D> {
    fn id(&self) -> String {
        format!("{self:?}")
    }

    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        use plonky2::util::serialization::Write;
        dst.write_usize(self.num_ops)
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self> {
        use plonky2::util::serialization::Read;
        let num_ops = src.read_usize()?;
        Ok(Self {
            num_ops,
            _phantom: PhantomData,
        })
    }

    fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let mut constraints = Vec::with_capacity(self.num_constraints());

        let modulus_limbs = get_field_modulus_32bit::<FF>();

        for i in 0..self.num_ops {
            let mut input_x = vec![F::Extension::ZERO; 8];
            let mut input_y = vec![F::Extension::ZERO; 8];
            let mut output_result = vec![F::Extension::ZERO; 8];
            let mut carry_l = vec![F::Extension::ZERO; 8];
            let mut carry_r = vec![F::Extension::ZERO; 8];
            let carry = vars.local_wires[self.wire_ith_carry(i)];

            for j in 0..8 {
                input_x[j] = vars.local_wires[self.wire_ith_input_x(i, j)];
                input_y[j] = vars.local_wires[self.wire_ith_input_y(i, j)];
                output_result[j] = vars.local_wires[self.wire_ith_output_result(i, j)];
                carry_l[j] = vars.local_wires[self.wire_ith_carry_l(i, j)];
                carry_r[j] = vars.local_wires[self.wire_ith_carry_r(i, j)];
            }

            let base = F::Extension::from_canonical_u64(1 << 32u64);
            let mut last_carry_l = F::Extension::ZERO;
            let mut last_carry_r = F::Extension::ZERO;

            for j in 0..8 {
                let results_l = input_x[j] + input_y[j] + (F::Extension::ONE - carry_l[j]) * base + last_carry_l;
                let results_r = output_result[j]
                    + carry * F::Extension::from_canonical_u32(modulus_limbs[j])
                    + (F::Extension::ONE - carry_r[j]) * base
                    + last_carry_r;
                constraints.push(results_r - results_l);
                constraints.push(carry_l[j] * (F::Extension::ONE - carry_l[j]));
                constraints.push(carry_r[j] * (F::Extension::ONE - carry_r[j]));
                last_carry_l = carry_l[j];
                last_carry_r = carry_r[j];
            }
            constraints.push(carry * (F::Extension::ONE - carry));

            for j in 0..8 {
                let mut combined_limbs = F::Extension::ZERO;
                let limb_base = F::Extension::from_canonical_u64(1u64 << Self::limb_bits());
                for k in (0..Self::num_limbs()).rev() {
                    let this_limb = vars.local_wires[self.wire_ith_output_jth_limb32_kth_limb2_bit(i, j, k)];
                    let max_limb = 1 << Self::limb_bits();
                    let product = (0..max_limb).map(|x| this_limb - F::Extension::from_canonical_usize(x)).product();
                    constraints.push(product);

                    combined_limbs = limb_base * combined_limbs + this_limb;
                }
                constraints.push(combined_limbs - output_result[j]);
            }
        }

        constraints
    }

    fn eval_unfiltered_base_one(&self, _vars: EvaluationVarsBase<F>, _yield_constr: StridedConstraintConsumer<F>) {
        panic!("use eval_unfiltered_base_packed instead");
    }

    fn eval_unfiltered_base_batch(&self, vars_base: EvaluationVarsBaseBatch<F>) -> Vec<F> {
        self.eval_unfiltered_base_batch_packed(vars_base)
    }

    fn eval_unfiltered_circuit(&self, _builder: &mut CircuitBuilder<F, D>, _vars: EvaluationTargets<D>) -> Vec<ExtensionTarget<D>> {
        todo!("eval_unfiltered_circuit")
    }

    fn generators(&self, row: usize, _local_constants: &[F]) -> Vec<WitnessGeneratorRef<F, D>> {
        (0..self.num_ops)
            .map(|i| {
                WitnessGeneratorRef::new(
                    NonnativeAddGenerator::<F, FF, D> {
                        gate: *self,
                        row,
                        i,
                        _phantom: PhantomData,
                    }
                    .adapter(),
                )
            })
            .collect()
    }

    fn num_wires(&self) -> usize {
        169
    }

    fn num_constants(&self) -> usize {
        0
    }

    fn degree(&self) -> usize {
        1 << Self::limb_bits()
    }

    fn num_constraints(&self) -> usize {
        self.num_ops * (33 + 16 * 8)
    }
}

impl<F: RichField + Extendable<D>, FF: Field, const D: usize> PackedEvaluableBase<F, D> for NonnativeAddGate<F, FF, D> {
    fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>>(
        &self,
        vars: EvaluationVarsBasePacked<P>,
        mut yield_constr: StridedConstraintConsumer<P>,
    ) {
        let modulus_limbs = get_field_modulus_32bit::<FF>();

        for i in 0..self.num_ops {
            let mut input_x = vec![P::ZEROS; 8];
            let mut input_y = vec![P::ZEROS; 8];
            let mut output_result = vec![P::ZEROS; 8];
            let mut carry_l = vec![P::ZEROS; 8];
            let mut carry_r = vec![P::ZEROS; 8];
            let carry = vars.local_wires[self.wire_ith_carry(i)];

            for j in 0..8 {
                input_x[j] = vars.local_wires[self.wire_ith_input_x(i, j)];
                input_y[j] = vars.local_wires[self.wire_ith_input_y(i, j)];
                output_result[j] = vars.local_wires[self.wire_ith_output_result(i, j)];
                carry_l[j] = vars.local_wires[self.wire_ith_carry_l(i, j)];
                carry_r[j] = vars.local_wires[self.wire_ith_carry_r(i, j)];
            }

            let base = F::from_canonical_u64(1 << 32u64);
            let mut last_carry_l = P::ZEROS;
            let mut last_carry_r = P::ZEROS;

            for j in 0..8 {
                let results_l = input_x[j] + input_y[j] + (P::ONES - carry_l[j]) * base.clone() + last_carry_l;
                let results_r =
                    output_result[j] + carry * F::from_canonical_u32(modulus_limbs[j]) + (P::ONES - carry_r[j]) * base.clone() + last_carry_r;
                yield_constr.one(results_r - results_l);
                yield_constr.one(carry_l[j] * (P::ONES - carry_l[j]));
                yield_constr.one(carry_r[j] * (P::ONES - carry_r[j]));
                last_carry_l = carry_l[j];
                last_carry_r = carry_r[j];
            }
            yield_constr.one(carry * (P::ONES - carry));

            for j in 0..8 {
                let mut combined_limbs = P::ZEROS;
                let limb_base = F::from_canonical_u64(1u64 << Self::limb_bits());
                for k in (0..Self::num_limbs()).rev() {
                    let this_limb = vars.local_wires[self.wire_ith_output_jth_limb32_kth_limb2_bit(i, j, k)];
                    let max_limb = 1 << Self::limb_bits();
                    let product = (0..max_limb).map(|x| this_limb - F::from_canonical_usize(x)).product();
                    yield_constr.one(product);

                    combined_limbs = combined_limbs * limb_base.clone() + this_limb;
                }
                yield_constr.one(combined_limbs - output_result[j]);
            }
        }
    }
}

#[derive(Clone, Debug)]
struct NonnativeAddGenerator<F: RichField + Extendable<D>, FF: Field, const D: usize> {
    gate: NonnativeAddGate<F, FF, D>,
    row: usize,
    i: usize,
    _phantom: PhantomData<(F, FF)>,
}

impl<F: RichField + Extendable<D>, FF: Field, const D: usize> SimpleGenerator<F, D> for NonnativeAddGenerator<F, FF, D> {
    fn id(&self) -> String {
        "NonnativeAddGenerator".to_string()
    }

    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        use plonky2::util::serialization::Write;
        dst.write_usize(self.row)?;
        dst.write_usize(self.i)?;
        dst.write_usize(self.gate.num_ops)
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self> {
        use plonky2::util::serialization::Read;
        let row = src.read_usize()?;
        let i = src.read_usize()?;
        let num_ops = src.read_usize()?;
        Ok(Self {
            gate: NonnativeAddGate {
                num_ops,
                _phantom: PhantomData,
            },
            row,
            i,
            _phantom: PhantomData,
        })
    }

    fn dependencies(&self) -> Vec<Target> {
        let local_target = |column| Target::wire(self.row, column);

        let x_range: Vec<_> = (0..8).map(|i| local_target(self.gate.wire_ith_input_x(self.i, i))).collect();
        let y_range: Vec<_> = (0..8).map(|i| local_target(self.gate.wire_ith_input_y(self.i, i))).collect();

        [x_range, y_range].concat()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) -> Result<(), anyhow::Error> {
        let local_wire = |column| Wire { row: self.row, column };

        let get_local_wire = |column| witness.get_wire(local_wire(column));

        let mut input_x = vec![F::ZERO; 8];
        let mut input_y = vec![F::ZERO; 8];
        let mut input_x_u32s = vec![0u32; 8];
        let mut input_y_u32s = vec![0u32; 8];

        for j in 0..8 {
            input_x[j] = get_local_wire(self.gate.wire_ith_input_x(self.i, j));
            input_y[j] = get_local_wire(self.gate.wire_ith_input_y(self.i, j));
            input_x_u32s[j] = input_x[j].to_canonical_u64() as u32;
            input_y_u32s[j] = input_y[j].to_canonical_u64() as u32;
        }

        let input_x_biguint = BigUint::from_slice(&input_x_u32s);
        let input_y_biguint = BigUint::from_slice(&input_y_u32s);

        let sum_biguint = input_x_biguint + input_y_biguint;

        // Get the appropriate field modulus based on the field type
        let modulus_limbs = get_field_modulus_32bit::<FF>();
        let nonnative_base_biguint = BigUint::from_slice(&modulus_limbs);

        let carry = if sum_biguint >= nonnative_base_biguint { F::ONE } else { F::ZERO };
        let output_result_bigutint = if sum_biguint >= nonnative_base_biguint {
            sum_biguint - nonnative_base_biguint
        } else {
            sum_biguint
        };
        let mut output_result_u32s = output_result_bigutint.to_u32_digits();
        output_result_u32s.resize(8, 0u32);

        let base = F::from_canonical_u64(1 << 32u64);
        out_buffer.set_wire(local_wire(self.gate.wire_ith_carry(self.i)), carry.clone())?;
        let mut last_carry_l = F::ZERO;
        let mut last_carry_r = F::ZERO;
        for j in 0..8 {
            let output_result = F::from_canonical_u32(output_result_u32s[j]);
            out_buffer.set_wire(local_wire(self.gate.wire_ith_output_result(self.i, j)), output_result.clone())?;
            let carry_l = if (input_x[j].clone() + input_y[j].clone() + last_carry_l).to_canonical_u64() >= base.to_canonical_u64() {
                F::ONE
            } else {
                F::ZERO
            };
            out_buffer.set_wire(local_wire(self.gate.wire_ith_carry_l(self.i, j)), carry_l.clone())?;
            let modulus_limbs = get_field_modulus_32bit::<FF>();
            let carry_r = if (output_result.clone() + F::from_canonical_u32(modulus_limbs[j]) * carry + last_carry_r).to_canonical_u64()
                >= base.to_canonical_u64()
            {
                F::ONE
            } else {
                F::ZERO
            };
            out_buffer.set_wire(local_wire(self.gate.wire_ith_carry_r(self.i, j)), carry_r.clone())?;
            last_carry_l = carry_l.clone();
            last_carry_r = carry_r.clone();
        }

        for j in 0..8 {
            let num_limbs = NonnativeAddGate::<F, FF, D>::num_limbs();
            let limb_base = 1 << NonnativeAddGate::<F, FF, D>::limb_bits();
            let output_limbs: Vec<_> = (0..num_limbs)
                .scan(output_result_u32s[j] as u64, |acc, _| {
                    let tmp = *acc % limb_base;
                    *acc /= limb_base;
                    Some(F::from_canonical_u64(tmp))
                })
                .collect();

            for k in 0..num_limbs {
                let wire = local_wire(self.gate.wire_ith_output_jth_limb32_kth_limb2_bit(self.i, j, k));
                out_buffer.set_wire(wire, output_limbs[k].clone())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{field::goldilocks_field::GoldilocksField, gates::gate_testing::test_low_degree};

    use super::*;
    use crate::crypto::bn254::field::bn128_base::Bn128Base;

    #[test]
    fn low_degree() {
        test_low_degree::<GoldilocksField, _, 4>(NonnativeAddGate::<GoldilocksField, Bn128Base, 4> {
            num_ops: 1,
            _phantom: PhantomData,
        })
    }
}
