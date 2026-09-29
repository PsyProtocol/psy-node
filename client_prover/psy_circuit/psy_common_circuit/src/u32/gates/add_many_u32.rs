use core::marker::PhantomData;

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
        circuit_data::{CircuitConfig, CommonCircuitData},
        vars::{EvaluationTargets, EvaluationVars, EvaluationVarsBase, EvaluationVarsBaseBatch, EvaluationVarsBasePacked},
    },
    util::serialization::{Buffer, IoResult, Read, Write},
};
use psy_client_common::utils::math::ceil_div_usize;

const LOG2_MAX_NUM_ADDENDS: usize = 4;
const MAX_NUM_ADDENDS: usize = 24;

/// A gate to perform addition on `num_addends` different 32-bit values, plus a
/// small carry
#[derive(Copy, Clone, Debug)]
pub struct U32AddManyGate<F: RichField + Extendable<D>, const D: usize> {
    pub num_addends: usize,
    pub num_ops: usize,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> U32AddManyGate<F, D> {
    pub fn new_from_config(config: &CircuitConfig, num_addends: usize) -> Self {
        Self {
            num_addends,
            num_ops: Self::num_ops(num_addends, config),
            _phantom: PhantomData,
        }
    }

    pub(crate) fn num_ops(num_addends: usize, config: &CircuitConfig) -> usize {
        debug_assert!(num_addends <= MAX_NUM_ADDENDS);
        let wires_per_op = (num_addends + 3) + Self::num_limbs();
        let routed_wires_per_op = num_addends + 3;
        (config.num_wires / wires_per_op).min(config.num_routed_wires / routed_wires_per_op)
    }

    pub fn wire_ith_op_jth_addend(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < self.num_addends);
        (self.num_addends + 3) * i + j
    }
    pub fn wire_ith_carry(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        (self.num_addends + 3) * i + self.num_addends
    }

    pub fn wire_ith_output_result(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        (self.num_addends + 3) * i + self.num_addends + 1
    }
    pub fn wire_ith_output_carry(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        (self.num_addends + 3) * i + self.num_addends + 2
    }

    pub const fn limb_bits() -> usize {
        2
    }
    pub const fn num_result_limbs() -> usize {
        ceil_div_usize(32, Self::limb_bits())
    }
    pub const fn num_carry_limbs() -> usize {
        ceil_div_usize(LOG2_MAX_NUM_ADDENDS, Self::limb_bits())
    }
    pub const fn num_limbs() -> usize {
        Self::num_result_limbs() + Self::num_carry_limbs()
    }

    // Compile-time values of the limb helpers above. The packed evaluation uses these so that no
    // `ceil_div_usize` call (a non-inlined function in another crate) is made per row.
    const LIMB_BITS: usize = Self::limb_bits();
    const NUM_RESULT_LIMBS: usize = Self::num_result_limbs();
    const NUM_LIMBS: usize = Self::num_limbs();

    /// Same value as `wire_ith_output_jth_limb(i, 0)`, computed from the compile-time limb count.
    fn wire_ith_output_first_limb(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        (self.num_addends + 3) * self.num_ops + Self::NUM_LIMBS * i
    }

    pub fn wire_ith_output_jth_limb(&self, i: usize, j: usize) -> usize {
        debug_assert!(i < self.num_ops);
        debug_assert!(j < Self::num_limbs());
        (self.num_addends + 3) * self.num_ops + Self::num_limbs() * i + j
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for U32AddManyGate<F, D> {
    fn id(&self) -> String {
        format!("{self:?}")
    }

    fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let mut constraints = Vec::with_capacity(self.num_constraints());
        for i in 0..self.num_ops {
            let addends: Vec<F::Extension> = (0..self.num_addends)
                .map(|j| vars.local_wires[self.wire_ith_op_jth_addend(i, j)])
                .collect();
            let carry = vars.local_wires[self.wire_ith_carry(i)];

            let computed_output = addends.iter().fold(F::Extension::ZERO, |x, &y| x + y) + carry;

            let output_result = vars.local_wires[self.wire_ith_output_result(i)];
            let output_carry = vars.local_wires[self.wire_ith_output_carry(i)];

            let base = F::Extension::from_canonical_u64(1 << 32u64);
            let combined_output = output_carry * base + output_result;

            constraints.push(combined_output - computed_output);

            let mut combined_result_limbs = F::Extension::ZERO;
            let mut combined_carry_limbs = F::Extension::ZERO;
            let base = F::Extension::from_canonical_u64(1u64 << Self::limb_bits());
            for j in (0..Self::num_limbs()).rev() {
                let this_limb = vars.local_wires[self.wire_ith_output_jth_limb(i, j)];
                let max_limb = 1 << Self::limb_bits();
                let product = (0..max_limb).map(|x| this_limb - F::Extension::from_canonical_usize(x)).product();
                constraints.push(product);

                if j < Self::num_result_limbs() {
                    combined_result_limbs = base * combined_result_limbs + this_limb;
                } else {
                    combined_carry_limbs = base * combined_carry_limbs + this_limb;
                }
            }
            constraints.push(combined_result_limbs - output_result);
            constraints.push(combined_carry_limbs - output_carry);
        }

        constraints
    }

    fn eval_unfiltered_base_one(&self, vars: EvaluationVarsBase<F>, mut yield_constr: StridedConstraintConsumer<F>) {
        for i in 0..self.num_ops {
            let addends: Vec<F> = (0..self.num_addends)
                .map(|j| vars.local_wires[self.wire_ith_op_jth_addend(i, j)])
                .collect();
            let carry = vars.local_wires[self.wire_ith_carry(i)];

            let computed_output = addends.iter().fold(F::ZERO, |x, &y| x + y) + carry;

            let output_result = vars.local_wires[self.wire_ith_output_result(i)];
            let output_carry = vars.local_wires[self.wire_ith_output_carry(i)];

            let base = F::from_canonical_u64(1 << 32u64);
            let combined_output = output_carry * base + output_result;

            yield_constr.one(combined_output - computed_output);

            let mut combined_result_limbs = F::ZERO;
            let mut combined_carry_limbs = F::ZERO;
            let base = F::from_canonical_u64(1u64 << Self::limb_bits());
            for j in (0..Self::num_limbs()).rev() {
                let this_limb = vars.local_wires[self.wire_ith_output_jth_limb(i, j)];
                let max_limb = 1 << Self::limb_bits();
                let product = (0..max_limb).map(|x| this_limb - F::from_canonical_usize(x)).product();
                yield_constr.one(product);

                if j < Self::num_result_limbs() {
                    combined_result_limbs = base * combined_result_limbs + this_limb;
                } else {
                    combined_carry_limbs = base * combined_carry_limbs + this_limb;
                }
            }
            yield_constr.one(combined_result_limbs - output_result);
            yield_constr.one(combined_carry_limbs - output_carry);
        }
    }

    fn eval_unfiltered_base_batch(&self, vars_base: EvaluationVarsBaseBatch<F>) -> Vec<F> {
        self.eval_unfiltered_base_batch_packed(vars_base)
    }

    fn eval_unfiltered_circuit(&self, builder: &mut CircuitBuilder<F, D>, vars: EvaluationTargets<D>) -> Vec<ExtensionTarget<D>> {
        let mut constraints = Vec::with_capacity(self.num_constraints());

        for i in 0..self.num_ops {
            let addends: Vec<ExtensionTarget<D>> = (0..self.num_addends)
                .map(|j| vars.local_wires[self.wire_ith_op_jth_addend(i, j)])
                .collect();
            let carry = vars.local_wires[self.wire_ith_carry(i)];

            let mut computed_output = carry;
            for addend in addends {
                computed_output = builder.add_extension(computed_output, addend);
            }

            let output_result = vars.local_wires[self.wire_ith_output_result(i)];
            let output_carry = vars.local_wires[self.wire_ith_output_carry(i)];

            let base: F::Extension = F::from_canonical_u64(1 << 32u64).into();
            let base_target = builder.constant_extension(base);
            let combined_output = builder.mul_add_extension(output_carry, base_target, output_result);

            constraints.push(builder.sub_extension(combined_output, computed_output));

            let mut combined_result_limbs = builder.zero_extension();
            let mut combined_carry_limbs = builder.zero_extension();
            let base = builder.constant_extension(F::Extension::from_canonical_u64(1u64 << Self::limb_bits()));
            for j in (0..Self::num_limbs()).rev() {
                let this_limb = vars.local_wires[self.wire_ith_output_jth_limb(i, j)];
                let max_limb = 1 << Self::limb_bits();

                let mut product = builder.one_extension();
                for x in 0..max_limb {
                    let x_target = builder.constant_extension(F::Extension::from_canonical_usize(x));
                    let diff = builder.sub_extension(this_limb, x_target);
                    product = builder.mul_extension(product, diff);
                }
                constraints.push(product);

                if j < Self::num_result_limbs() {
                    combined_result_limbs = builder.mul_add_extension(base, combined_result_limbs, this_limb);
                } else {
                    combined_carry_limbs = builder.mul_add_extension(base, combined_carry_limbs, this_limb);
                }
            }
            constraints.push(builder.sub_extension(combined_result_limbs, output_result));
            constraints.push(builder.sub_extension(combined_carry_limbs, output_carry));
        }

        constraints
    }

    fn generators(&self, row: usize, _local_constants: &[F]) -> Vec<WitnessGeneratorRef<F, D>> {
        (0..self.num_ops)
            .map(|i| {
                let g = WitnessGeneratorRef::new(
                    U32AddManyGenerator {
                        gate: *self,
                        row,
                        i,
                        _phantom: PhantomData,
                    }
                    .adapter(),
                );
                g
            })
            .collect()
    }

    fn num_wires(&self) -> usize {
        (self.num_addends + 3) * self.num_ops + Self::num_limbs() * self.num_ops
    }

    fn num_constants(&self) -> usize {
        0
    }

    fn degree(&self) -> usize {
        1 << Self::limb_bits()
    }

    fn num_constraints(&self) -> usize {
        self.num_ops * (3 + Self::num_limbs())
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_usize(self.num_addends)?;
        dst.write_usize(self.num_ops)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self>
    where
        Self: Sized,
    {
        let num_addends = src.read_usize()?;
        let num_ops = src.read_usize()?;
        Ok(Self {
            num_addends,
            num_ops,
            _phantom: PhantomData,
        })
    }
}

impl<F: RichField + Extendable<D>, const D: usize> PackedEvaluableBase<F, D> for U32AddManyGate<F, D> {
    /// Packed counterpart of `eval_unfiltered_base_one`. It yields exactly the same constraints,
    /// in the same order, for every lane; only the evaluation strategy differs (no per-row
    /// allocation, limb counts are compile-time constants, and the limb range check uses two
    /// multiplications instead of four).
    fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>>(
        &self,
        vars: EvaluationVarsBasePacked<P>,
        mut yield_constr: StridedConstraintConsumer<P>,
    ) {
        let output_base = F::from_canonical_u64(1 << 32u64);
        let limb_base = F::from_canonical_u64(1u64 << Self::LIMB_BITS);
        let max_limb = 1usize << Self::LIMB_BITS;

        for i in 0..self.num_ops {
            // Same summation order as the scalar fold: 0 + a_0 + ... + a_{n-1}, then + carry.
            let mut computed_output = P::ZEROS;
            for j in 0..self.num_addends {
                computed_output += vars.local_wires[self.wire_ith_op_jth_addend(i, j)];
            }
            computed_output += vars.local_wires[self.wire_ith_carry(i)];

            let output_result = vars.local_wires[self.wire_ith_output_result(i)];
            let output_carry = vars.local_wires[self.wire_ith_output_carry(i)];

            let combined_output = output_carry * output_base + output_result;

            yield_constr.one(combined_output - computed_output);

            let mut combined_result_limbs = P::ZEROS;
            let mut combined_carry_limbs = P::ZEROS;
            let first_limb = self.wire_ith_output_first_limb(i);
            for j in (0..Self::NUM_LIMBS).rev() {
                let this_limb = vars.local_wires[first_limb + j];
                // prod_{x < max_limb} (limb - x), the same polynomial as the scalar product.
                let product = if max_limb == 4 {
                    // t (t - 1) (t - 2) (t - 3) = u (u + 2) with u = t (t - 3).
                    let u = this_limb * (this_limb - F::from_canonical_usize(3));
                    u * (u + F::TWO)
                } else {
                    let mut product = P::ONES;
                    for x in 0..max_limb {
                        product *= this_limb - F::from_canonical_usize(x);
                    }
                    product
                };
                yield_constr.one(product);

                if j < Self::NUM_RESULT_LIMBS {
                    combined_result_limbs = combined_result_limbs * limb_base + this_limb;
                } else {
                    combined_carry_limbs = combined_carry_limbs * limb_base + this_limb;
                }
            }
            yield_constr.one(combined_result_limbs - output_result);
            yield_constr.one(combined_carry_limbs - output_carry);
        }
    }
}

#[derive(Clone, Debug)]
struct U32AddManyGenerator<F: RichField + Extendable<D>, const D: usize> {
    gate: U32AddManyGate<F, D>,
    row: usize,
    i: usize,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for U32AddManyGenerator<F, D> {
    fn dependencies(&self) -> Vec<Target> {
        let local_target = |column| Target::wire(self.row, column);

        (0..self.gate.num_addends)
            .map(|j| local_target(self.gate.wire_ith_op_jth_addend(self.i, j)))
            .chain([local_target(self.gate.wire_ith_carry(self.i))])
            .collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) -> anyhow::Result<()> {
        let local_wire = |column| Wire { row: self.row, column };

        let get_local_wire = |column| witness.get_wire(local_wire(column));

        let addends: Vec<_> = (0..self.gate.num_addends)
            .map(|j| get_local_wire(self.gate.wire_ith_op_jth_addend(self.i, j)))
            .collect();
        let carry = get_local_wire(self.gate.wire_ith_carry(self.i));

        let output = addends.iter().fold(F::ZERO, |x, &y| x + y) + carry;
        let output_u64 = output.to_canonical_u64();

        let output_carry_u64 = output_u64 >> 32;
        let output_result_u64 = output_u64 & ((1 << 32) - 1);

        let output_carry = F::from_canonical_u64(output_carry_u64);
        let output_result = F::from_canonical_u64(output_result_u64);

        let output_carry_wire = local_wire(self.gate.wire_ith_output_carry(self.i));
        let output_result_wire = local_wire(self.gate.wire_ith_output_result(self.i));

        out_buffer.set_wire(output_carry_wire, output_carry)?;
        out_buffer.set_wire(output_result_wire, output_result)?;

        let num_result_limbs = U32AddManyGate::<F, D>::num_result_limbs();
        let num_carry_limbs = U32AddManyGate::<F, D>::num_carry_limbs();
        let limb_base = 1 << U32AddManyGate::<F, D>::limb_bits();

        let split_to_limbs = |mut val, num| {
            std::iter::from_fn(move || {
                let ret = val % limb_base;
                val /= limb_base;
                Some(ret)
            })
            .take(num)
            .map(F::from_canonical_u64)
        };

        let result_limbs = split_to_limbs(output_result_u64, num_result_limbs);
        let carry_limbs = split_to_limbs(output_carry_u64, num_carry_limbs);

        for (j, limb) in result_limbs.chain(carry_limbs).enumerate() {
            let wire = local_wire(self.gate.wire_ith_output_jth_limb(self.i, j));
            out_buffer.set_wire(wire, limb)?;
        }
        anyhow::Ok(())
    }

    fn id(&self) -> String {
        "U32AddManyGenerator".to_string()
    }

    fn serialize(&self, dst: &mut Vec<u8>, common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        self.gate.serialize(dst, common_data)?;
        dst.write_usize(self.row)?;
        dst.write_usize(self.i)
    }

    fn deserialize(src: &mut Buffer, common_data: &CommonCircuitData<F, D>) -> IoResult<Self>
    where
        Self: Sized,
    {
        let gate = U32AddManyGate::<F, D>::deserialize(src, common_data)?;
        let row = src.read_usize()?;
        let i = src.read_usize()?;
        Ok(Self {
            gate,
            row,
            i,
            _phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use itertools::unfold;
    use plonky2::{
        field::{
            extension::quartic::QuarticExtension,
            goldilocks_field::GoldilocksField,
            packable::Packable,
            types::{Field64, PrimeField64, Sample},
        },
        gates::gate_testing::{test_eval_fns, test_low_degree},
        hash::hash_types::HashOut,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use rand::{rngs::OsRng, Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    fn low_degree() {
        test_low_degree::<GoldilocksField, _, 4>(U32AddManyGate::<GoldilocksField, 4> {
            num_addends: 4,
            num_ops: 3,
            _phantom: PhantomData,
        })
    }

    #[test]
    fn eval_fns() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        test_eval_fns::<F, C, _, D>(U32AddManyGate::<GoldilocksField, D> {
            num_addends: 4,
            num_ops: 3,
            _phantom: PhantomData,
        })
    }

    #[test]
    fn test_gate_constraint() {
        type F = GoldilocksField;
        type FF = QuarticExtension<GoldilocksField>;
        const D: usize = 4;
        const NUM_ADDENDS: usize = 10;
        const NUM_U32_ADD_MANY_OPS: usize = 3;

        fn get_wires(addends: Vec<Vec<u64>>, carries: Vec<u64>) -> Vec<FF> {
            let mut v0 = Vec::new();
            let mut v1 = Vec::new();

            let num_result_limbs = U32AddManyGate::<F, D>::num_result_limbs();
            let num_carry_limbs = U32AddManyGate::<F, D>::num_carry_limbs();
            let limb_base = 1 << U32AddManyGate::<F, D>::limb_bits();
            for op in 0..NUM_U32_ADD_MANY_OPS {
                let adds = &addends[op];
                let ca = carries[op];

                let output = adds.iter().sum::<u64>() + ca;
                let output_result = output & ((1 << 32) - 1);
                let output_carry = output >> 32;

                let split_to_limbs = |mut val, num| {
                    unfold((), move |_| {
                        let ret = val % limb_base;
                        val /= limb_base;
                        Some(ret)
                    })
                    .take(num)
                    .map(F::from_canonical_u64)
                };

                let mut result_limbs: Vec<_> = split_to_limbs(output_result, num_result_limbs).collect();
                let mut carry_limbs: Vec<_> = split_to_limbs(output_carry, num_carry_limbs).collect();

                for a in adds {
                    v0.push(F::from_canonical_u64(*a));
                }
                v0.push(F::from_canonical_u64(ca));
                v0.push(F::from_canonical_u64(output_result));
                v0.push(F::from_canonical_u64(output_carry));
                v1.append(&mut result_limbs);
                v1.append(&mut carry_limbs);
            }

            v0.iter().chain(v1.iter()).map(|&x| x.into()).collect()
        }

        let mut rng = OsRng;
        let addends: Vec<Vec<_>> = (0..NUM_U32_ADD_MANY_OPS)
            .map(|_| (0..NUM_ADDENDS).map(|_| rng.gen::<u32>() as u64).collect())
            .collect();
        let carries: Vec<_> = (0..NUM_U32_ADD_MANY_OPS).map(|_| rng.gen::<u32>() as u64).collect();

        let gate = U32AddManyGate::<F, D> {
            num_addends: NUM_ADDENDS,
            num_ops: NUM_U32_ADD_MANY_OPS,
            _phantom: PhantomData,
        };

        let vars = EvaluationVars {
            local_constants: &[],
            local_wires: &get_wires(addends, carries),
            public_inputs_hash: &HashOut::rand(),
        };

        assert!(
            gate.eval_unfiltered(vars).iter().all(|x| x.is_zero()),
            "Gate constraints are not satisfied."
        );
    }
    /// Row-by-row reference: a verbatim copy of the default `Gate::eval_unfiltered_base_batch`,
    /// which calls `eval_unfiltered_base_one` once per row.
    fn eval_base_batch_row_by_row<F: RichField + Extendable<D>, G: Gate<F, D>, const D: usize>(
        gate: &G,
        vars_base: EvaluationVarsBaseBatch<F>,
    ) -> Vec<F> {
        let mut res = vec![F::ZERO; vars_base.len() * gate.num_constraints()];
        for (i, vars_base_one) in vars_base.iter().enumerate() {
            gate.eval_unfiltered_base_one(vars_base_one, StridedConstraintConsumer::new(&mut res, vars_base.len(), i));
        }
        res
    }

    /// Every configuration exercised by the equivalence tests: the ones the circuit builder
    /// derives from the standard and a wide config for each supported addend count, plus the
    /// hand-built shapes used by the other tests.
    fn gate_configs<const D: usize>() -> Vec<U32AddManyGate<GoldilocksField, D>>
    where
        GoldilocksField: Extendable<D>,
    {
        let standard = CircuitConfig::standard_recursion_config();
        let wide = CircuitConfig {
            num_wires: 400,
            num_routed_wires: 200,
            ..CircuitConfig::standard_recursion_config()
        };
        let mut gates = Vec::new();
        for num_addends in 1..=MAX_NUM_ADDENDS {
            for config in [&standard, &wide] {
                let gate = U32AddManyGate::<GoldilocksField, D>::new_from_config(config, num_addends);
                assert!(gate.num_ops > 0);
                gates.push(gate);
            }
        }
        for (num_addends, num_ops) in [(1, 1), (4, 3), (10, 3), (24, 1)] {
            gates.push(U32AddManyGate {
                num_addends,
                num_ops,
                _phantom: PhantomData,
            });
        }
        gates
    }

    fn batch_sizes() -> Vec<usize> {
        let width = <GoldilocksField as Packable>::Packing::WIDTH;
        let mut sizes = vec![1, 2, 3, width, width + 1, 3 * width + 2, 32, 33, 64];
        sizes.sort_unstable();
        sizes.dedup();
        sizes
    }

    /// Edge values (0, 1, small limb values, 2^32 boundaries, p - 1, and non-canonical
    /// representatives >= p) mixed with uniform values.
    fn random_value(rng: &mut ChaCha8Rng, edge_only: bool) -> GoldilocksField {
        const P: u64 = GoldilocksField::ORDER;
        let edges = [
            0,
            1,
            2,
            3,
            4,
            (1 << 32) - 1,
            1 << 32,
            P - 1,
            P,
            P + 1,
            P + 3,
            u64::MAX - 1,
            u64::MAX,
        ];
        if edge_only || rng.gen_range(0..3) == 0 {
            GoldilocksField(edges[rng.gen_range(0..edges.len())])
        } else {
            GoldilocksField(rng.gen_range(0..P))
        }
    }

    fn assert_batch_paths_match<const D: usize>(gate: &U32AddManyGate<GoldilocksField, D>, vars: EvaluationVarsBaseBatch<GoldilocksField>, context: &str)
    where
        GoldilocksField: Extendable<D>,
    {
        let batch_size = vars.len();
        let expected = eval_base_batch_row_by_row(gate, vars);
        assert_eq!(expected.len(), gate.num_constraints() * batch_size, "{context}");
        for (path, actual) in [
            ("eval_unfiltered_base_batch", gate.eval_unfiltered_base_batch(vars)),
            ("eval_unfiltered_base_batch_packed", gate.eval_unfiltered_base_batch_packed(vars)),
        ] {
            assert_eq!(actual.len(), expected.len(), "{path} {context}");
            for (idx, (a, e)) in actual.iter().zip(&expected).enumerate() {
                assert_eq!(
                    a.to_canonical_u64(),
                    e.to_canonical_u64(),
                    "{path} {context}: constraint {} of row {} differs",
                    idx / batch_size,
                    idx % batch_size
                );
            }
            assert_eq!(actual, expected, "{path} {context}");
        }
    }

    #[test]
    fn limb_constants_and_wire_layout() {
        type G = U32AddManyGate<GoldilocksField, 2>;
        assert_eq!(G::LIMB_BITS, G::limb_bits());
        assert_eq!(G::NUM_RESULT_LIMBS, G::num_result_limbs());
        assert_eq!(G::NUM_LIMBS, G::num_limbs());
        assert_eq!(G::NUM_LIMBS, G::num_result_limbs() + G::num_carry_limbs());
        for gate in gate_configs::<2>() {
            for i in 0..gate.num_ops {
                for j in 0..G::num_limbs() {
                    assert_eq!(gate.wire_ith_output_first_limb(i) + j, gate.wire_ith_output_jth_limb(i, j));
                }
            }
        }
    }

    fn packed_batch_matches_row_by_row_for<const D: usize>()
    where
        GoldilocksField: Extendable<D>,
    {
        let width = <GoldilocksField as Packable>::Packing::WIDTH;
        let mut rng = ChaCha8Rng::seed_from_u64(0x0032_add0 + D as u64);
        for gate in gate_configs::<D>() {
            for &batch_size in &batch_sizes() {
                for trial in 0..4 {
                    let edge_only = trial == 0;
                    let wires: Vec<_> = (0..gate.num_wires() * batch_size)
                        .map(|_| random_value(&mut rng, edge_only))
                        .collect();
                    // Extra constants model the selector columns that the gate does not read.
                    let constants: Vec<_> = (0..(gate.num_constants() + 2) * batch_size)
                        .map(|_| random_value(&mut rng, edge_only))
                        .collect();
                    let public_inputs_hash = HashOut {
                        elements: core::array::from_fn(|_| random_value(&mut rng, edge_only)),
                    };
                    let vars = EvaluationVarsBaseBatch::new(batch_size, &constants, &wires, &public_inputs_hash);
                    let context = format!(
                        "D={D} width={width} num_addends={} num_ops={} batch_size={batch_size} trial={trial}",
                        gate.num_addends, gate.num_ops
                    );
                    assert_batch_paths_match(&gate, vars, &context);
                }
            }
        }
    }

    #[test]
    fn packed_batch_matches_row_by_row() {
        packed_batch_matches_row_by_row_for::<2>();
        packed_batch_matches_row_by_row_for::<4>();
    }

    /// Valid witnesses must give all-zero constraints on both paths.
    #[test]
    fn packed_batch_is_zero_on_valid_witness() {
        type F = GoldilocksField;
        const D: usize = 2;
        let mut rng = ChaCha8Rng::seed_from_u64(0x0032_add1);
        // n addends plus a carry give a carry-out of at most n, and the carry output has two
        // 2-bit limbs (at most 15), so up to 15 addends have valid witnesses.
        for num_addends in 1..=15 {
            let gate = U32AddManyGate::<F, D>::new_from_config(&CircuitConfig::standard_recursion_config(), num_addends);
            for &batch_size in &batch_sizes() {
                let mut wires = vec![F::ZERO; gate.num_wires() * batch_size];
                let mut set = |column: usize, row: usize, value: u64| wires[column * batch_size + row] = F::from_canonical_u64(value);
                for row in 0..batch_size {
                    for i in 0..gate.num_ops {
                        let mut output = 0u64;
                        for j in 0..num_addends {
                            let addend = rng.gen::<u32>() as u64;
                            output += addend;
                            set(gate.wire_ith_op_jth_addend(i, j), row, addend);
                        }
                        let carry = rng.gen::<u32>() as u64;
                        output += carry;
                        set(gate.wire_ith_carry(i), row, carry);
                        let (result, carry_out) = (output & 0xffff_ffff, output >> 32);
                        set(gate.wire_ith_output_result(i), row, result);
                        set(gate.wire_ith_output_carry(i), row, carry_out);
                        let num_result_limbs = U32AddManyGate::<F, D>::num_result_limbs();
                        for j in 0..U32AddManyGate::<F, D>::num_limbs() {
                            let limb = if j < num_result_limbs { (result >> (2 * j)) & 3 } else { (carry_out >> (2 * (j - num_result_limbs))) & 3 };
                            set(gate.wire_ith_output_jth_limb(i, j), row, limb);
                        }
                    }
                }
                let public_inputs_hash = HashOut::rand();
                let vars = EvaluationVarsBaseBatch::new(batch_size, &[], &wires, &public_inputs_hash);
                assert_batch_paths_match(&gate, vars, &format!("num_addends={num_addends} batch_size={batch_size}"));
                assert!(gate.eval_unfiltered_base_batch(vars).iter().all(|c| c.is_zero()));
            }
        }
    }

    /// Timing comparison of the row-by-row path and the packed batch path, on 2^14 rows in
    /// batches of 32 as in quotient polynomial computation. Run with
    /// `cargo test --release -p psy_common_circuit u32::gates::add_many_u32::tests::bench -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bench_packed_vs_row_by_row() {
        use std::{
            hint::black_box,
            time::{Duration, Instant},
        };

        type F = GoldilocksField;
        const NUM_ROWS: usize = 1 << 14;
        const BATCH_SIZE: usize = 32;
        const ROUNDS: usize = 30;

        let summarize = |mut samples: Vec<Duration>| {
            samples.sort();
            (samples[0], samples[samples.len() / 2])
        };

        for num_addends in [3, 4, 5, 8] {
            let gate = U32AddManyGate::<F, 2>::new_from_config(&CircuitConfig::standard_recursion_config(), num_addends);
            let batches: Vec<Vec<F>> = (0..NUM_ROWS / BATCH_SIZE).map(|_| F::rand_vec(gate.num_wires() * BATCH_SIZE)).collect();
            let constants = F::rand_vec(2 * BATCH_SIZE);
            let public_inputs_hash = HashOut::rand();
            let run = |packed: bool| {
                let start = Instant::now();
                for wires in &batches {
                    let vars = EvaluationVarsBaseBatch::new(BATCH_SIZE, &constants, wires, &public_inputs_hash);
                    if packed {
                        black_box(gate.eval_unfiltered_base_batch(black_box(vars)));
                    } else {
                        black_box(eval_base_batch_row_by_row(&gate, black_box(vars)));
                    }
                }
                start.elapsed()
            };
            run(false);
            run(true);
            let (mut row_by_row, mut batch) = (Vec::new(), Vec::new());
            for _ in 0..ROUNDS {
                row_by_row.push(run(false));
                batch.push(run(true));
            }
            let (r_min, r_med) = summarize(row_by_row);
            let (b_min, b_med) = summarize(batch);
            println!(
                "U32AddManyGate num_addends={num_addends} num_ops={}: {NUM_ROWS} rows in batches of {BATCH_SIZE}, packing width {}",
                gate.num_ops,
                <F as Packable>::Packing::WIDTH
            );
            println!("  row_by_row                 min {r_min:>10.3?}  median {r_med:>10.3?}");
            println!("  eval_unfiltered_base_batch min {b_min:>10.3?}  median {b_med:>10.3?}");
            println!(
                "  speedup (min) {:.2}x  (median) {:.2}x",
                r_min.as_secs_f64() / b_min.as_secs_f64(),
                r_med.as_secs_f64() / b_med.as_secs_f64()
            );
        }
    }
}
