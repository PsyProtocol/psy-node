use core::marker::PhantomData;

use plonky2::{
    field::{
        extension::Extendable,
        secp256k1_base::Secp256K1Base,
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field, PrimeField},
    },
    hash::hash_types::RichField,
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::{BoolTarget, Target},
        witness::{PartitionWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
    util::serialization::{Read, Write},
};
use psy_crypto::signature::secp256k1::curve::{
    glv::{decompose_secp256k1_scalar, GLV_BETA, GLV_S},
    secp256k1::Secp256K1,
};

use super::{
    super::gadgets::{
        biguint::{GeneratedValuesBigUint, WitnessBigUint},
        curve::{AffinePointTarget, CircuitBuilderCurve},
        curve_msm::curve_msm_circuit,
        nonnative::{CircuitBuilderNonNative, NonNativeTarget},
    },
    biguint::BigUintTarget,
};
use crate::u32::arithmetic_u32::U32Target;

pub trait CircuitBuilderGlv<F: RichField + Extendable<D>, const D: usize> {
    fn secp256k1_glv_beta(&mut self) -> NonNativeTarget<Secp256K1Base>;

    fn decompose_secp256k1_scalar(
        &mut self,
        k: &NonNativeTarget<Secp256K1Scalar>,
    ) -> (NonNativeTarget<Secp256K1Scalar>, NonNativeTarget<Secp256K1Scalar>, BoolTarget, BoolTarget);

    fn glv_mul(&mut self, p: &AffinePointTarget<Secp256K1>, k: &NonNativeTarget<Secp256K1Scalar>) -> AffinePointTarget<Secp256K1>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderGlv<F, D> for CircuitBuilder<F, D> {
    fn secp256k1_glv_beta(&mut self) -> NonNativeTarget<Secp256K1Base> {
        self.constant_nonnative(GLV_BETA)
    }

    fn decompose_secp256k1_scalar(
        &mut self,
        k: &NonNativeTarget<Secp256K1Scalar>,
    ) -> (NonNativeTarget<Secp256K1Scalar>, NonNativeTarget<Secp256K1Scalar>, BoolTarget, BoolTarget) {
        let k1 = self.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
        let k2 = self.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
        let k1_neg = self.add_virtual_bool_target_unsafe();
        let k2_neg = self.add_virtual_bool_target_unsafe();
        self.assert_bool(k1_neg);
        self.assert_bool(k2_neg);

        self.add_simple_generator(GLVDecompositionGenerator::<F, D> {
            k: k.clone(),
            k1: k1.clone(),
            k2: k2.clone(),
            k1_neg,
            k2_neg,
            _phantom: PhantomData,
        });

        // Check that `k1_raw + GLV_S * k2_raw == k`.
        let k1_raw = self.nonnative_conditional_neg(&k1, k1_neg);
        let k2_raw = self.nonnative_conditional_neg(&k2, k2_neg);
        let s = self.constant_nonnative(GLV_S);
        let mut should_be_k = self.mul_nonnative(&s, &k2_raw);
        should_be_k = self.add_nonnative(&should_be_k, &k1_raw);
        self.connect_nonnative(&should_be_k, k);

        (k1, k2, k1_neg, k2_neg)
    }

    fn glv_mul(&mut self, p: &AffinePointTarget<Secp256K1>, k: &NonNativeTarget<Secp256K1Scalar>) -> AffinePointTarget<Secp256K1> {
        let (k1, k2, k1_neg, k2_neg) = self.decompose_secp256k1_scalar(k);

        let beta = self.secp256k1_glv_beta();
        let beta_px = self.mul_nonnative(&beta, &p.x);
        let sp = AffinePointTarget::<Secp256K1> { x: beta_px, y: p.y.clone() };

        let p_neg = self.curve_conditional_neg(p, k1_neg);
        let sp_neg = self.curve_conditional_neg(&sp, k2_neg);
        curve_msm_circuit(self, &p_neg, &sp_neg, &k1, &k2)
    }
}

#[derive(Debug)]
struct GLVDecompositionGenerator<F: RichField + Extendable<D>, const D: usize> {
    k: NonNativeTarget<Secp256K1Scalar>,
    k1: NonNativeTarget<Secp256K1Scalar>,
    k2: NonNativeTarget<Secp256K1Scalar>,
    k1_neg: BoolTarget,
    k2_neg: BoolTarget,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for GLVDecompositionGenerator<F, D> {
    fn dependencies(&self) -> Vec<Target> {
        self.k.value.limbs.iter().map(|l| l.0).collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) -> anyhow::Result<()> {
        let k = Secp256K1Scalar::from_noncanonical_biguint(witness.get_biguint_target(&self.k.value));

        let (k1, k2, k1_neg, k2_neg) = decompose_secp256k1_scalar(k);

        out_buffer.set_biguint_target(&self.k1.value, &k1.to_canonical_biguint())?;
        out_buffer.set_biguint_target(&self.k2.value, &k2.to_canonical_biguint())?;
        out_buffer.set_bool_target(self.k1_neg, k1_neg)?;
        out_buffer.set_bool_target(self.k2_neg, k2_neg)?;

        anyhow::Ok(())
    }

    fn id(&self) -> String {
        "GLVDecompositionGenerator".to_string()
    }

    fn serialize(
        &self,
        dst: &mut Vec<u8>,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<()> {
        let k_targets = self.k.value.limbs.iter().map(|x| x.0).collect::<Vec<Target>>();
        let k1_targets = self.k1.value.limbs.iter().map(|x| x.0).collect::<Vec<Target>>();
        let k2_targets = self.k2.value.limbs.iter().map(|x| x.0).collect::<Vec<Target>>();
        dst.write_target_vec(&k_targets)?;
        dst.write_target_vec(&k1_targets)?;
        dst.write_target_vec(&k2_targets)?;
        dst.write_target_bool(self.k1_neg)?;
        dst.write_target_bool(self.k2_neg)
    }

    fn deserialize(
        src: &mut plonky2::util::serialization::Buffer,
        _common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> plonky2::util::serialization::IoResult<Self>
    where
        Self: Sized,
    {
        let k_targets = src.read_target_vec()?;
        let k1_targets = src.read_target_vec()?;
        let k2_targets = src.read_target_vec()?;
        let k1_neg = src.read_target_bool()?;
        let k2_neg = src.read_target_bool()?;

        let k = NonNativeTarget {
            value: BigUintTarget {
                limbs: k_targets.iter().map(|&x| U32Target(x)).collect(),
            },
            _phantom: PhantomData,
        };
        let k1 = NonNativeTarget {
            value: BigUintTarget {
                limbs: k1_targets.iter().map(|&x| U32Target(x)).collect(),
            },
            _phantom: PhantomData,
        };
        let k2 = NonNativeTarget {
            value: BigUintTarget {
                limbs: k2_targets.iter().map(|&x| U32Target(x)).collect(),
            },
            _phantom: PhantomData,
        };

        Ok(Self {
            k,
            k1,
            k2,
            k1_neg,
            k2_neg,
            _phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::{
        field::{
            secp256k1_scalar::Secp256K1Scalar,
            types::{Field, PrimeField, Sample},
        },
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use psy_crypto::signature::secp256k1::curve::{
        curve_types::{Curve, CurveScalar},
        glv::{decompose_secp256k1_scalar, glv_mul, GLV_S},
        secp256k1::Secp256K1,
    };

    use super::super::super::gadgets::{
        biguint::WitnessBigUint, curve::CircuitBuilderCurve, glv::CircuitBuilderGlv, nonnative::CircuitBuilderNonNative,
    };

    /// Probe for the unasserted GLV negation flags: `k1_neg`/`k2_neg` are
    /// `add_virtual_bool_target_unsafe` with no `assert_bool`, and
    /// `nonnative_conditional_neg` computes `(1-2b)·x` linearly. This replica
    /// reproduces the decomposition constraints of
    /// `decompose_secp256k1_scalar` WITHOUT its generator, so the witness is
    /// fully hand-crafted and a passing prove is a constraint-level fact.
    ///
    /// - honest: the native GLV decomposition proves and verifies.
    /// - malicious: `k1 = 7, k1_neg = 2` (non-boolean) gives
    ///   `k1_raw = (1-2·2)·7 = -21 mod n`; with `k2 = 0, k2_neg = 0` and
    ///   `k = n - 21` the scalar equation `S·k2_raw + k1_raw == k` holds
    ///   exactly. Whether the circuit accepts it is the empirical question
    ///   this test answers (attribute any rejection: "set twice" would be a
    ///   generator artifact, but this replica has no GLV generator).
    #[test]
    fn glv_decomposition_flag_probe() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let k = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let k1 = builder.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
        let k2 = builder.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
        let k1_neg = builder.add_virtual_bool_target_unsafe();
        let k2_neg = builder.add_virtual_bool_target_unsafe();

        // exact constraint lines from decompose_secp256k1_scalar, minus the generator
        let k1_raw = builder.nonnative_conditional_neg(&k1, k1_neg);
        let k2_raw = builder.nonnative_conditional_neg(&k2, k2_neg);
        let s = builder.constant_nonnative(GLV_S);
        let mut should_be_k = builder.mul_nonnative(&s, &k2_raw);
        should_be_k = builder.add_nonnative(&should_be_k, &k1_raw);
        builder.connect_nonnative(&should_be_k, &k);

        let data = builder.build::<C>();

        // honest: native decomposition of a deterministic scalar
        let scalar = Secp256K1Scalar::from_noncanonical_biguint(num::BigUint::from(0x0042_0000_0000_0001u64) << 200);
        let mut pw = PartialWitness::new();
        pw.set_biguint_target(&k.value, &scalar.to_canonical_biguint()).unwrap();
        let (h1, h2, b1, b2) = decompose_secp256k1_scalar(scalar);
        pw.set_biguint_target(&k1.value, &h1.to_canonical_biguint()).unwrap();
        pw.set_biguint_target(&k2.value, &h2.to_canonical_biguint()).unwrap();
        pw.set_bool_target(k1_neg, b1).unwrap();
        pw.set_bool_target(k2_neg, b2).unwrap();
        println!("proving honest case...");
        let proof = data.prove(pw).expect("honest decomposition proves");
        data.verify(proof).expect("honest decomposition verifies");
        println!("honest case ok");

        // malicious: non-boolean k1_neg = 2, k1 = 7 => k1_raw = -21 mod n
        let n = Secp256K1Scalar::order();
        let k_mal = Secp256K1Scalar::from_noncanonical_biguint(n.clone() - 21u32);
        assert_eq!(k_mal.to_canonical_biguint(), n - 21u32);
        let mut pw = PartialWitness::new();
        pw.set_biguint_target(&k.value, &k_mal.to_canonical_biguint()).unwrap();
        pw.set_biguint_target(&k1.value, &num::BigUint::from(7u32)).unwrap();
        pw.set_biguint_target(&k2.value, &num::BigUint::from(0u32)).unwrap();
        pw.set_target(k1_neg.target, F::from_canonical_u64(2)).unwrap();
        pw.set_target(k2_neg.target, F::ZERO).unwrap();
        println!("proving malicious case (k1_neg = 2)...");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| data.prove(pw)));
        match outcome {
            Ok(Ok(proof)) => {
                data.verify(proof).expect("malicious proof must verify if it proves");
                println!("GLV FLAG REPRODUCED: non-boolean k1_neg=2 (k1_raw = -3*k1) satisfies the decomposition constraints");
            }
            Ok(Err(err)) => println!("malicious flag prove error: {err:#}"),
            Err(_) => println!(
                "malicious flag dies at WITNESS GENERATION: NonNativeAdditionGenerator panics converting the \
                 residue-inflated limbs (limb*2 >= 2^32 makes get_biguint_target assemble >256 bits). This is a \
                 prover-side generator artifact with ZERO soundness evidence; an attacker hand-supplying the full \
                 intermediate witness never runs this generator. Constraint-level acceptance is undetermined."
            ),
        }
    }

    #[test]
    #[ignore]
    fn test_glv_gadget() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let rando = (CurveScalar(Secp256K1Scalar::rand()) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
        let randot = builder.constant_affine_point(rando);

        let scalar = Secp256K1Scalar::rand();
        let scalar_target = builder.constant_nonnative(scalar);

        let rando_glv_scalar = glv_mul(rando.to_projective(), scalar);
        let expected = builder.constant_affine_point(rando_glv_scalar.to_affine());
        let actual = builder.glv_mul(&randot, &scalar_target);
        builder.connect_affine_point(&expected, &actual);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof)
    }
}

/// H3: the GLV negation flags `k1_neg`/`k2_neg` (glv.rs:57-58) were
/// `add_virtual_bool_target_unsafe` with no `assert_bool`.
///
/// POST-FIX NOTE: `decompose_secp256k1_scalar` now asserts both flags are
/// boolean (`assert_bool(k1_neg); assert_bool(k2_neg);`, glv.rs:59-60).
/// Tests 1 and 2 below are POST-FIX REGRESSION tests: their circuits include
/// the same `assert_bool` and the non-boolean-flag witnesses must be REJECTED
/// at the constraint level (vanishing-poly failure — no generator artifact).
/// Test 3 deliberately builds the PRE-FIX chain (no `assert_bool`) to keep
/// testing the second line of defense, the MSM output binding. The paragraphs
/// below are kept as pre-fix documentation of the mechanism.
///
/// Pre-fix documentation: `nonnative_conditional_neg(x, b)`
/// (nonnative.rs:360-367) computes `t*x_neg + (1-t)*x` limb-wise, which for a
/// non-boolean integer flag `t` yields `(1-2t)*x mod modulus` — provided the
/// internal `add_nonnative` ripple stays non-negative per limb (the add
/// gate's carry is confined to 4 bits, so any limb position where the running
/// signed total goes negative is unsatisfiable; see `cond_neg_admission`).
///
/// The honest `NonNativeAdditionGenerator` cannot produce such witnesses: it
/// re-assembles the inflated limbs (`t*neg_i >= 2^32`) into a >256-bit
/// BigUint and panics in `from_noncanonical_biguint` — a prover-side
/// artifact with zero soundness content. These tests therefore pre-seed the
/// conditional-neg outputs and run a watch-list scheduler replica that
/// catches the panic and skips exactly those generators, then prove via
/// `prove_with_partition_witness` and `verify`. A passing verify is a
/// constraint-level fact (same evidence standard as the h2_ bypass tests).
///
/// Pre-fix empirical results (recorded before the fix landed):
/// - test 1 malicious (t=2): verify PASSED — the constraint system admitted
///   the non-boolean flag on a single `nonnative_conditional_neg`;
/// - test 2 malicious (t1=2, full glv_mul chain incl. production MSM): verify
///   PASSED — the MSM performs no on-curve checks and happily scalar-multiplies
///   the off-curve point (P.x, -3*P.y);
/// - test 3 malicious (output connected to (n-21)*P): verify REJECTED — the
///   MSM output binding was the semantic backstop.
#[cfg(test)]
mod h3 {
    use num::BigUint;
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            secp256k1_base::Secp256K1Base,
            secp256k1_scalar::Secp256K1Scalar,
            types::{Field, PrimeField},
        },
        iop::{
            generator::GeneratedValues,
            target::{BoolTarget, Target},
            witness::{PartialWitness, PartitionWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
            prover::prove_with_partition_witness,
        },
        util::{
            serialization::{Buffer, Read},
            timing::TimingTree,
        },
    };
    use psy_crypto::signature::secp256k1::curve::{
        curve_types::{AffinePoint, Curve, CurveScalar},
        glv::{decompose_secp256k1_scalar, GLV_S},
        secp256k1::Secp256K1,
    };

    use crate::crypto::secp256k1::ecdsa::gadgets::{
        biguint::WitnessBigUint,
        curve::{AffinePointTarget, CircuitBuilderCurve},
        curve_msm::curve_msm_circuit,
        glv::CircuitBuilderGlv,
        nonnative::{CircuitBuilderNonNative, NonNativeTarget},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    fn limbs8(v: &BigUint) -> [u64; 8] {
        let d = v.to_u32_digits();
        core::array::from_fn(|i| d.get(i).copied().unwrap_or(0) as u64)
    }

    /// Exact gate-level model of `nonnative_conditional_neg(x, t)` for an
    /// integer flag `t`, over 8 limbs: limb-wise the add gate computes
    /// `T_i = t*neg_i - (t-1)*x_i + carry_i (mod p_gold)`, where
    /// `neg = modulus - x`. The gate confines `out_i < 2^32` and
    /// `carry_{i+1} < 16`, and `out_i + 2^32*carry_{i+1} < 2^36 < p_gold`,
    /// so the congruence is an equality and `T_i` must be a NON-NEGATIVE
    /// integer (a negative signed total would require `out + 2^32*carry`
    /// near `p_gold`, i.e. `carry ~ 2^32`, violating the 4-bit confinement).
    /// Returns `((1-2t)*x mod modulus, overflow)` when admissible.
    fn cond_neg_admission(x: &BigUint, t: u64, modulus: &BigUint) -> Option<(BigUint, u64)> {
        assert!(*x > BigUint::from(0u8) && *x < *modulus);
        assert!(t >= 1 && t <= 3, "model assumes t*x_i and t*neg_i stay < 2^34");
        let neg = modulus - x;
        let neg_limbs = limbs8(&neg);
        let x_limbs = limbs8(x);
        let mut carry: u128 = 0;
        for i in 0..8 {
            let a_i = (t as u128) * (neg_limbs[i] as u128);
            let signed = a_i as i128 - ((t - 1) as i128) * (x_limbs[i] as i128) + carry as i128;
            if signed < 0 {
                return None;
            }
            let t_i = signed as u128;
            carry = t_i >> 32;
            if carry >= 16 {
                return None;
            }
        }
        let v_l = BigUint::from(t) * &neg - BigUint::from(t - 1) * x;
        let out = &v_l % modulus;
        let ov = ((&v_l - &out) / modulus).to_u64_digits().first().copied().unwrap_or(0);
        Some((out, ov))
    }

    struct H3Report {
        rounds: usize,
        unfinished: usize,
        unset_partitions: usize,
        conflicts: Vec<(String, Target, F, F)>,
        panicked: Vec<String>,
    }

    /// Faithful replica of plonky2's watch-list scheduler
    /// (`generate_partial_witness`) with two changes: conflicts are logged and
    /// resolved keep-first (input partitions are seeded before any generator
    /// runs, so held values win), and a panicking generator is caught,
    /// recorded, and skipped (its outputs must have been pre-seeded).
    fn generate_bypass<'a>(inputs: &PartialWitness<F>, data: &'a CircuitData<F, C, D>) -> (PartitionWitness<'a, F>, H3Report) {
        let prover = &data.prover_only;
        let common = &data.common;
        let num_wires = common.config.num_wires;
        let degree = common.degree();
        let mut witness = PartitionWitness::new(num_wires, degree, &prover.representative_map);
        for (t, v) in inputs.target_values.iter() {
            witness.set_target(*t, *v).unwrap();
        }
        let gens = &prover.generators;
        let mut buffer = GeneratedValues::empty();
        let mut report = H3Report { rounds: 0, unfinished: 0, unset_partitions: 0, conflicts: vec![], panicked: vec![] };
        let mut pending: Vec<usize> = (0..gens.len()).collect();
        let mut expired = vec![false; gens.len()];
        let mut remaining = gens.len();
        while !pending.is_empty() {
            report.rounds += 1;
            assert!(report.rounds <= 100000, "scheduler failed to converge");
            let mut next_pending = Vec::new();
            for &i in &pending {
                if expired[i] {
                    continue;
                }
                let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gens[i].0.run(&witness, &mut buffer)));
                match ran {
                    Ok(true) => {
                        expired[i] = true;
                        remaining -= 1;
                    }
                    Ok(false) => {}
                    Err(_) => {
                        report.panicked.push(gens[i].0.id());
                        expired[i] = true;
                        remaining -= 1;
                        buffer.target_values.clear();
                    }
                }
                let mut new_reps = Vec::new();
                for (t, v) in buffer.target_values.drain(..) {
                    let rep = prover.representative_map[t.index(num_wires, degree)];
                    match witness.values[rep] {
                        None => {
                            witness.values[rep] = Some(v);
                            new_reps.push(rep);
                        }
                        Some(old) if old == v => {}
                        Some(old) => {
                            if report.conflicts.len() < 40 {
                                report.conflicts.push((gens[i].0.id(), t, old, v));
                            }
                        }
                    }
                }
                for rep in new_reps {
                    if let Some(watchers) = prover.generator_indices_by_watches.get(&rep) {
                        for &w in watchers {
                            if !expired[w] {
                                next_pending.push(w);
                            }
                        }
                    }
                }
            }
            pending = next_pending;
        }
        report.unfinished = remaining;
        report.unset_partitions = witness.values.iter().filter(|v| v.is_none()).count();
        (witness, report)
    }

    /// Parse every `NonNativeAdditionGenerator` in the circuit into
    /// (a, b, sum, overflow) targets via its public serialize format
    /// (nonnative.rs:413-421).
    fn addition_generators(data: &CircuitData<F, C, D>) -> Vec<(Vec<Target>, Vec<Target>, Vec<Target>, BoolTarget)> {
        let mut out = Vec::new();
        for g in &data.prover_only.generators {
            if g.0.id() != "NonNativeAdditionGenerator" {
                continue;
            }
            let mut bytes = Vec::new();
            g.0.serialize(&mut bytes, &data.common).unwrap();
            let mut buf = Buffer::new(&bytes);
            let a = buf.read_target_vec().unwrap();
            let b = buf.read_target_vec().unwrap();
            let sum = buf.read_target_vec().unwrap();
            let overflow = buf.read_target_bool().unwrap();
            out.push((a, b, sum, overflow));
        }
        out
    }

    fn find_add_overflow(data: &CircuitData<F, C, D>, sum: &NonNativeTarget<impl plonky2::field::types::Field>) -> BoolTarget {
        let sum_targets: Vec<Target> = sum.value.limbs.iter().map(|l| l.0).collect();
        addition_generators(data)
            .into_iter()
            .find(|(_, _, s, _)| *s == sum_targets)
            .map(|(_, _, _, ov)| ov)
            .expect("conditional-neg addition generator must be locatable by its sum targets")
    }

    fn seed_biguint(pw: &mut PartialWitness<F>, target: &BigUintTargetForSeed, value: &BigUint) {
        let digits = value.to_u32_digits();
        assert!(digits.len() <= target.len());
        for (i, t) in target.iter().enumerate() {
            pw.set_target(*t, F::from_canonical_u32(digits.get(i).copied().unwrap_or(0))).unwrap();
        }
    }
    type BigUintTargetForSeed = Vec<Target>;

    fn limbs_of<FF: plonky2::field::types::Field>(x: &NonNativeTarget<FF>) -> Vec<Target> {
        x.value.limbs.iter().map(|l| l.0).collect()
    }

    /// Run the bypass harness, print diagnostics, prove and verify.
    /// Returns (verify_ok, report).
    fn bypass_prove_verify(pw: &PartialWitness<F>, data: &CircuitData<F, C, D>, label: &str) -> (bool, H3Report) {
        let (witness, report) = generate_bypass(pw, data);
        println!(
            "[{label}] rounds={} unfinished={} unset_partitions={} conflicts={} panicked={:?}",
            report.rounds,
            report.unfinished,
            report.unset_partitions,
            report.conflicts.len(),
            report.panicked
        );
        for (gen, t, old, new) in &report.conflicts {
            println!("[{label}] conflict: gen={gen} target={t:?} old={old:?} new={new:?}");
        }
        assert_eq!(report.unfinished, 0, "[{label}] all generators must run or be accounted for");
        // Note: unset partitions are normal — padding wires are never written
        // by any generator and default to zero in `full_witness()`, exactly as
        // in stock `data.prove`. Only a verify failure can indict them.
        let proof = prove_with_partition_witness(&data.prover_only, &data.common, witness, &mut TimingTree::default())
            .unwrap_or_else(|e| panic!("[{label}] prove from hand-driven witness failed: {e:#}"));
        match data.verify(proof) {
            Ok(()) => {
                println!("[{label}] VERIFY PASSED");
                (true, report)
            }
            Err(e) => {
                println!("[{label}] verify rejected: {e:#}");
                (false, report)
            }
        }
    }

    /// Test 1 (POST-FIX REGRESSION): a single `nonnative_conditional_neg` with
    /// a non-boolean flag, connected to its semantic output, plus the same
    /// `assert_bool` the fix added at glv.rs:59-60. The malicious witness
    /// (t=2) must now be REJECTED at the constraint level: the rejection must
    /// come from the proof's vanishing polynomial, not from a generator
    /// conflict or panic (the bypass harness never emits "set twice", and the
    /// only skipped generator is the pre-seeded conditional-neg add).
    ///
    /// Pre-fix, this exact malicious witness PROVED and VERIFIED (H3 core
    /// admission).
    #[test]
    fn h3_conditional_neg_nonboolean_flag_constraint_level() {
        let n = Secp256K1Scalar::order();

        let build = |expected: &BigUint| {
            let config = CircuitConfig::standard_ecc_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let k1 = builder.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
            let t = builder.add_virtual_bool_target_unsafe();
            builder.assert_bool(t); // post-fix constraint set (glv.rs:59-60)
            let k1_raw = builder.nonnative_conditional_neg(&k1, t);
            let expected_t = builder.constant_nonnative(Secp256K1Scalar::from_noncanonical_biguint(expected.clone()));
            builder.connect_nonnative(&k1_raw, &expected_t);
            let data = builder.build::<C>();
            (k1, t, k1_raw, data)
        };

        // Honest control: t = 1, k1 = 7 -> k1_raw = -7 mod n, plain prover.
        {
            let (k1, t, _k1_raw, data) = build(&(n.clone() - 7u32));
            let mut pw = PartialWitness::new();
            pw.set_biguint_target(&k1.value, &BigUint::from(7u32)).unwrap();
            pw.set_target(t.target, F::ONE).unwrap();
            let proof = data.prove(pw).expect("honest conditional-neg proves");
            data.verify(proof).expect("honest conditional-neg verifies");
            println!("[h3-t1-honest] control ok");
        }

        // Malicious: t = 2, k1 = 7 -> k1_raw = (1-2*2)*7 = -21 mod n.
        let (k1_raw_val, ov) = cond_neg_admission(&BigUint::from(7u32), 2, &n).expect("scalar-side candidate must be admissible");
        assert_eq!(k1_raw_val, n.clone() - 21u32);
        assert_eq!(ov, 1);
        let (k1, t, k1_raw, data) = build(&k1_raw_val);
        let ov_target = find_add_overflow(&data, &k1_raw);

        let mut pw = PartialWitness::new();
        pw.set_biguint_target(&k1.value, &BigUint::from(7u32)).unwrap();
        pw.set_target(t.target, F::TWO).unwrap();
        seed_biguint(&mut pw, &limbs_of(&k1_raw), &k1_raw_val);
        pw.set_target(ov_target.target, F::ONE).unwrap();

        let (ok, report) = bypass_prove_verify(&pw, &data, "h3-t1-malicious-t2");
        assert_eq!(report.panicked, vec!["NonNativeAdditionGenerator".to_string()], "only the conditional-neg add generator may panic-skip");
        // The ONLY disagreement must be the fix's boolean gate itself:
        // assert_bool computes z = t*t - t = 2 and copy-ties it to the
        // constant-zero partition, so its generator writes 2 over the 0.
        assert_eq!(report.conflicts.len(), 1, "the boolean gate must be the only firing constraint");
        assert_eq!(report.conflicts[0].0, "ArithmeticBaseGenerator");
        assert_eq!(report.conflicts[0].2, F::ZERO, "the conflicted partition holds the zero constant");
        assert_eq!(report.conflicts[0].3, F::TWO, "the boolean gate computes t*t - t = 2 != 0");
        assert!(
            !ok,
            "POST-FIX REGRESSION: assert_bool(t) must reject the non-boolean flag at the constraint level \
             (pre-fix this witness proved and verified)"
        );
    }

    struct FullChain {
        data: CircuitData<F, C, D>,
        k: NonNativeTarget<Secp256K1Scalar>,
        k1: NonNativeTarget<Secp256K1Scalar>,
        k2: NonNativeTarget<Secp256K1Scalar>,
        t1: BoolTarget,
        t2: BoolTarget,
        k1_raw: NonNativeTarget<Secp256K1Scalar>,
        p_neg_y: NonNativeTarget<Secp256K1Base>,
    }

    /// Replica of `glv_mul` (glv.rs:82-92) and `decompose_secp256k1_scalar`
    /// (glv.rs:71-77) with the GLVDecompositionGenerator omitted (its outputs
    /// k1/k2/flags are seeded directly). All gadgets used are production code.
    /// `with_fix` adds the post-fix `assert_bool` on both flags (glv.rs:59-60);
    /// test 3 passes `false` to keep probing the pre-fix chain's second line
    /// of defense (the MSM output binding).
    fn build_full_chain(p: AffinePoint<Secp256K1>, expected: Option<AffinePoint<Secp256K1>>, with_fix: bool) -> FullChain {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let k = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let k1 = builder.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
        let k2 = builder.add_virtual_nonnative_target_sized::<Secp256K1Scalar>(4);
        let t1 = builder.add_virtual_bool_target_unsafe();
        let t2 = builder.add_virtual_bool_target_unsafe();
        if with_fix {
            builder.assert_bool(t1);
            builder.assert_bool(t2);
        }

        // decompose constraints (glv.rs:70-75), generator omitted
        let k1_raw = builder.nonnative_conditional_neg(&k1, t1);
        let k2_raw = builder.nonnative_conditional_neg(&k2, t2);
        let s = builder.constant_nonnative(GLV_S);
        let mut should_be_k = builder.mul_nonnative(&s, &k2_raw);
        should_be_k = builder.add_nonnative(&should_be_k, &k1_raw);
        builder.connect_nonnative(&should_be_k, &k);

        // glv_mul body (glv.rs:83-89)
        let p_t = builder.constant_affine_point(p);
        let beta = builder.secp256k1_glv_beta();
        let beta_px = builder.mul_nonnative(&beta, &p_t.x);
        let sp = AffinePointTarget::<Secp256K1> { x: beta_px, y: p_t.y.clone() };
        let p_neg = builder.curve_conditional_neg(&p_t, t1);
        let sp_neg = builder.curve_conditional_neg(&sp, t2);
        let result = curve_msm_circuit(&mut builder, &p_neg, &sp_neg, &k1, &k2);

        if let Some(exp) = expected {
            let exp_t = builder.constant_affine_point(exp);
            builder.connect_affine_point(&result, &exp_t);
        }

        let data = builder.build::<C>();
        FullChain { data, k, k1, k2, t1, t2, k1_raw, p_neg_y: p_neg.y }
    }

    /// Find the smallest m such that P = m*G admits the t=2 y-side ripple.
    fn find_admissible_point() -> (AffinePoint<Secp256K1>, BigUint, u64) {
        let p_secp = Secp256K1Base::order();
        for m in 1u64..100000 {
            let pa = (CurveScalar(Secp256K1Scalar::from_canonical_u64(m)) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
            let qy = pa.y.to_canonical_biguint();
            if let Some((y1, ov)) = cond_neg_admission(&qy, 2, &p_secp) {
                println!("[h3] admissible point: P = {m}*G, y1 = (1-2*2)*Qy mod p, ov = {ov}");
                return (pa, y1, ov);
            }
        }
        panic!("no admissible point found in 100000 tries (expected ~1 in 25)");
    }

    /// Test 2 (POST-FIX REGRESSION): the FULL glv_mul chain — scalar equation
    /// plus the production MSM — with a non-boolean flag t1 = 2, k1 = 7,
    /// k2 = 0, k = n - 21, built WITH the fix (`assert_bool` on both flags).
    /// The malicious witness must now be REJECTED at the constraint level by
    /// the flag's boolean gate (vanishing-poly failure; no generator artifact:
    /// zero conflicts, only the two pre-seeded conditional-neg add generators
    /// panic-skip).
    ///
    /// Pre-fix documentation: this exact witness PROVED and VERIFIED. The
    /// scalar equation is honestly satisfied (S*0 + (1-2*2)*7 = -21 == k mod
    /// n); the MSM consumes k1/k2 with the flag-scaled point (P.x, -3*P.y),
    /// which is OFF the curve (curve_msm_circuit performs no on-curve checks,
    /// curve_msm.rs:23-78).
    #[test]
    fn h3_glv_mul_nonboolean_flag_full_chain() {
        let n = Secp256K1Scalar::order();
        let (p_affine, y1, ov_y) = find_admissible_point();

        let chain = build_full_chain(p_affine, None, true);
        let ov_k1 = find_add_overflow(&chain.data, &chain.k1_raw);
        let ov_y_t = find_add_overflow(&chain.data, &chain.p_neg_y);

        let mut pw = PartialWitness::new();
        pw.set_biguint_target(&chain.k.value, &(n.clone() - 21u32)).unwrap();
        pw.set_biguint_target(&chain.k1.value, &BigUint::from(7u32)).unwrap();
        pw.set_biguint_target(&chain.k2.value, &BigUint::from(0u32)).unwrap();
        pw.set_target(chain.t1.target, F::TWO).unwrap();
        pw.set_target(chain.t2.target, F::ZERO).unwrap();
        seed_biguint(&mut pw, &limbs_of(&chain.k1_raw), &(n.clone() - 21u32));
        pw.set_target(ov_k1.target, F::ONE).unwrap();
        seed_biguint(&mut pw, &limbs_of(&chain.p_neg_y), &y1);
        pw.set_target(ov_y_t.target, F::from_canonical_u64(ov_y)).unwrap();

        let (ok, report) = bypass_prove_verify(&pw, &chain.data, "h3-fullchain-t1eq2");
        let mut expected_panics = vec!["NonNativeAdditionGenerator".to_string(); 2];
        expected_panics.sort();
        let mut got = report.panicked.clone();
        got.sort();
        assert_eq!(got, expected_panics, "exactly the two conditional-neg add generators may panic-skip");
        // The ONLY disagreement must be the fix's boolean gate itself:
        // assert_bool computes z = t1*t1 - t1 = 2 and copy-ties it to the
        // constant-zero partition, so its generator writes 2 over the 0.
        assert_eq!(report.conflicts.len(), 1, "the boolean gate must be the only firing constraint");
        assert_eq!(report.conflicts[0].0, "ArithmeticBaseGenerator");
        assert_eq!(report.conflicts[0].2, F::ZERO, "the conflicted partition holds the zero constant");
        assert_eq!(report.conflicts[0].3, F::TWO, "the boolean gate computes t1*t1 - t1 = 2 != 0");
        assert!(
            !ok,
            "POST-FIX REGRESSION: assert_bool(t1) must reject the non-boolean flag at the constraint level \
             (pre-fix this full-chain witness proved and verified)"
        );
    }

    /// Test 3: the semantic backstop, on the PRE-FIX chain (`with_fix=false`)
    /// — this deliberately keeps probing the second line of defense:
    /// `connect_affine_point(result, (n-21)*P)`, the analog of the signature
    /// circuit's `connect_nonnative(r, x)` binding the MSM output. The MSM
    /// computes 7*(P.x, -3*P.y) (off-curve input, no validity check), which is
    /// not the point (n-21)*P = -21*P w.h.p., so verify must REJECT. An honest
    /// control (real GLV decomposition, boolean flags, connected to k*P) must
    /// verify. (Post-fix, assert_bool rejects the malicious witness even
    /// earlier; the binding remains the defense for any future flag gadget.)
    #[test]
    fn h3_glv_mul_semantic_backstop() {
        let n = Secp256K1Scalar::order();
        let (p_affine, y1, ov_y) = find_admissible_point();

        // Honest control: real decomposition of a deterministic scalar.
        {
            let k0 = Secp256K1Scalar::from_noncanonical_biguint(num::BigUint::from(0x0042_0000_0000_0001u64) << 200);
            let expected = (CurveScalar(k0) * p_affine.to_projective()).to_affine();
            let chain = build_full_chain(p_affine, Some(expected), false);
            let (h1, h2, b1, b2) = decompose_secp256k1_scalar(k0);
            let mut pw = PartialWitness::new();
            pw.set_biguint_target(&chain.k.value, &k0.to_canonical_biguint()).unwrap();
            pw.set_biguint_target(&chain.k1.value, &h1.to_canonical_biguint()).unwrap();
            pw.set_biguint_target(&chain.k2.value, &h2.to_canonical_biguint()).unwrap();
            pw.set_target(chain.t1.target, if b1 { F::ONE } else { F::ZERO }).unwrap();
            pw.set_target(chain.t2.target, if b2 { F::ONE } else { F::ZERO }).unwrap();
            let (ok, report) = bypass_prove_verify(&pw, &chain.data, "h3-backstop-honest");
            assert!(report.panicked.is_empty(), "honest run must not panic any generator");
            assert!(report.conflicts.is_empty(), "honest run must be conflict-free");
            assert!(ok, "honest control: k*P must verify (harness correctness)");
        }

        // Malicious: t1 = 2 witness connected to (n-21)*P — must be REJECTED.
        {
            let expected = (CurveScalar(Secp256K1Scalar::from_noncanonical_biguint(n.clone() - 21u32)) * p_affine.to_projective()).to_affine();
            let chain = build_full_chain(p_affine, Some(expected), false);
            let ov_k1 = find_add_overflow(&chain.data, &chain.k1_raw);
            let ov_y_t = find_add_overflow(&chain.data, &chain.p_neg_y);
            let mut pw = PartialWitness::new();
            pw.set_biguint_target(&chain.k.value, &(n.clone() - 21u32)).unwrap();
            pw.set_biguint_target(&chain.k1.value, &BigUint::from(7u32)).unwrap();
            pw.set_biguint_target(&chain.k2.value, &BigUint::from(0u32)).unwrap();
            pw.set_target(chain.t1.target, F::TWO).unwrap();
            pw.set_target(chain.t2.target, F::ZERO).unwrap();
            seed_biguint(&mut pw, &limbs_of(&chain.k1_raw), &(n.clone() - 21u32));
            pw.set_target(ov_k1.target, F::ONE).unwrap();
            seed_biguint(&mut pw, &limbs_of(&chain.p_neg_y), &y1);
            pw.set_target(ov_y_t.target, F::from_canonical_u64(ov_y)).unwrap();

            let (ok, report) = bypass_prove_verify(&pw, &chain.data, "h3-backstop-malicious");
            assert_eq!(report.panicked.len(), 2, "same two panic-skips as the full-chain test");
            assert!(
                !ok,
                "BACKSTOP FAILED: the MSM output for the flag-scaled off-curve point matched (n-21)*P; \
                 non-boolean flags would let a prover alter the verified statement"
            );
            println!("[h3-backstop-malicious] verify rejected as expected: the MSM output binding is the semantic backstop");
        }
    }

    /// Fingerprint harness: prints the secp256k1 signature base circuit's
    /// digest, degree, gate-type histogram and generator count. Used to
    /// measure the delta of the H3 `assert_bool` hardening (pre-fix vs
    /// post-fix). Builds the exact circuit of
    /// `EthPersonalSignSecp256K1SignatureCircuit::new` (without the minifier
    /// chain, which is fingerprinted separately off the same common data).
    #[test]
    fn h3_signature_circuit_fingerprint_print() {
        use plonky2::hash::poseidon::PoseidonHash;

        use crate::crypto::secp256k1::gadget::{Secp256K1Gadget, EIP191_PREFIX_32};

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let gadget = Secp256K1Gadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, EIP191_PREFIX_32);
        builder.register_public_inputs(&gadget.combined_hash.elements);
        let data: CircuitData<F, C, D> = builder.build::<C>();

        let mut gate_counts = std::collections::BTreeMap::new();
        for g in &data.common.gates {
            *gate_counts.entry(g.0.id()).or_insert(0usize) += 1;
        }
        println!("fingerprint circuit_digest: {:?}", data.verifier_only.circuit_digest);
        println!("fingerprint degree: {}", data.common.degree());
        println!("fingerprint num gates: {}", data.common.gates.len());
        println!("fingerprint generators: {}", data.prover_only.generators.len());
        for (gate, count) in &gate_counts {
            println!("fingerprint gate: {count} x {gate}");
        }
    }
}
