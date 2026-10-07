//! Psy circuit serialization.
//!
//! Plonky2's `DefaultGateSerializer` / `DefaultGeneratorSerializer` only know
//! about stock plonky2 gates. Psy circuits that bake `ComparisonGate` into the
//! *serialized* circuit (e.g. anything built with
//! `add_psy_type_b_common_gates`, which covers the UPS network circuits) need a
//! serializer that also registers that custom gate and its generator.
//!
//! Existing gate tags remain stable. The gate registry also covers the client
//! secp256k1 and shared Keccak gates used by reward common-data serialization.
//! The generator registry remains limited to stock generators and Comparison;
//! this does not enable full secp256k1 prover-data serialization.

use core::marker::PhantomData;

use plonky2::{
    field::extension::Extendable,
    gadgets::{
        arithmetic::EqualityGenerator,
        arithmetic_extension::QuotientGeneratorExtension,
        range_check::LowHighGenerator,
        split_base::BaseSumGenerator,
        split_join::{SplitGenerator, WireSplitGenerator},
    },
    gates::{
        arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate},
        arithmetic_extension::{ArithmeticExtensionGate, ArithmeticExtensionGenerator},
        base_sum::{BaseSplitGenerator, BaseSumGate},
        constant::ConstantGate,
        coset_interpolation::{CosetInterpolationGate, InterpolationGenerator},
        exponentiation::{ExponentiationGate, ExponentiationGenerator},
        lookup::{LookupGate, LookupGenerator},
        lookup_table::{LookupTableGate, LookupTableGenerator},
        multiplication_extension::{MulExtensionGate, MulExtensionGenerator},
        noop::NoopGate,
        poseidon::{PoseidonGate, PoseidonGenerator},
        poseidon_mds::{PoseidonMdsGate, PoseidonMdsGenerator},
        public_input::PublicInputGate,
        random_access::{RandomAccessGate, RandomAccessGenerator},
        reducing::{ReducingGate, ReducingGenerator},
        reducing_extension::{ReducingExtensionGate, ReducingGenerator as ReducingExtensionGenerator},
    },
    get_gate_tag_impl, get_generator_tag_impl,
    hash::hash_types::RichField,
    impl_gate_serializer, impl_generator_serializer,
    iop::generator::{ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator},
    plonk::config::{AlgebraicHasher, GenericConfig},
    read_gate_impl, read_generator_impl,
    recursion::dummy_circuit::DummyProofGenerator,
    util::serialization::{GateSerializer, WitnessGeneratorSerializer},
};

use crate::u32::gates::comparison::{ComparisonGate, ComparisonGenerator};
use crate::u32::gates::{add_many_u32::U32AddManyGate, arithmetic_u32::U32ArithmeticGate, subtraction_u32::U32SubtractionGate, range_check_u32::U32RangeCheckGate};
use psy_plonky2_basic_helpers::u32::gates::{arithmetic_u32::U32ArithmeticGate as SharedU32ArithmeticGate, subtraction_u32::U32SubtractionGate as SharedU32SubtractionGate, interleave_u32::U32InterleaveGate, uninterleave_to_b32::UninterleaveToB32Gate, uninterleave_to_u32::UninterleaveToU32Gate};
use psy_plonky2_basic_helpers::u32::gates::comparison::ComparisonGate as SharedComparisonGate;

/// Append-only gate registry for existing UPS and reward common data.
#[derive(Debug)]
pub struct PsyGateSerializer;

impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for PsyGateSerializer {
    impl_gate_serializer! {
        PsyGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        ComparisonGate<F, D>,
        U32ArithmeticGate<F, D>,
        U32AddManyGate<F, D>,
        U32SubtractionGate<F, D>,
        U32RangeCheckGate<F, D>,
        SharedU32ArithmeticGate<F, D>,
        SharedU32SubtractionGate<F, D>,
        U32InterleaveGate,
        UninterleaveToB32Gate,
        UninterleaveToU32Gate,
        SharedComparisonGate<F, D>,
        BaseSumGate<4>
    }
}

/// Generator serializer: all plonky2 default generators + Psy
/// `ComparisonGenerator`.
#[derive(Debug, Default)]
pub struct PsyGeneratorSerializer<C: GenericConfig<D>, const D: usize> {
    pub _phantom: PhantomData<C>,
}

impl<F, C, const D: usize> WitnessGeneratorSerializer<F, D> for PsyGeneratorSerializer<C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    impl_generator_serializer! {
        PsyGeneratorSerializer,
        ArithmeticBaseGenerator<F, D>,
        ArithmeticExtensionGenerator<F, D>,
        BaseSplitGenerator<2>,
        BaseSumGenerator<2>,
        ConstantGenerator<F>,
        CopyGenerator,
        DummyProofGenerator<F, C, D>,
        EqualityGenerator,
        ExponentiationGenerator<F, D>,
        InterpolationGenerator<F, D>,
        LookupGenerator,
        LookupTableGenerator,
        LowHighGenerator,
        MulExtensionGenerator<F, D>,
        NonzeroTestGenerator,
        PoseidonGenerator<F, D>,
        PoseidonMdsGenerator<D>,
        QuotientGeneratorExtension<D>,
        RandomAccessGenerator<F, D>,
        RandomValueGenerator,
        ReducingGenerator<D>,
        ReducingExtensionGenerator<D>,
        SplitGenerator,
        WireSplitGenerator,
        ComparisonGenerator<F, D>
    }
}

// ---------------------------------------------------------------------------
// Compact serialization: omit the derivable parts of `prover_only` (the LDE
// Merkle leaves + internal digests + fft root table, ~70% of the bytes) and
// rebuild them from the stored polynomial coefficients on load via FFT+hashing.
// This is far more effective than any byte compressor on this (high-entropy)
// data, and the rebuild is pure-Rust (wasm-compatible).
// ---------------------------------------------------------------------------

use plonky2::{
    fri::oracle::PolynomialBatch,
    plonk::circuit_data::CircuitData,
    util::{serialization::IoError, timing::TimingTree},
};

/// Serialize `circuit_data`, omitting the derivable
/// `constants_sigmas_commitment` Merkle `leaves`/`digests` and the
/// `fft_root_table`. The polynomial coefficients and the Merkle `cap` are kept.
/// `circuit_data` is left unchanged (the stripped parts are restored before
/// returning).
pub fn to_bytes_compact<F, C, const D: usize>(
    circuit_data: &mut CircuitData<F, C, D>,
    gate_serializer: &impl GateSerializer<F, D>,
    generator_serializer: &impl WitnessGeneratorSerializer<F, D>,
) -> anyhow::Result<Vec<u8>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    let mt = &mut circuit_data.prover_only.constants_sigmas_commitment.merkle_tree;
    let leaves = core::mem::take(&mut mt.leaves);
    let digests = core::mem::take(&mut mt.digests);
    let fft = circuit_data.prover_only.fft_root_table.take();

    let bytes = circuit_data
        .to_bytes(gate_serializer, generator_serializer)
        .map_err(|e| anyhow::anyhow!("compact serialize failed: {e:?}"));

    // Restore so the circuit stays usable for proving.
    let mt = &mut circuit_data.prover_only.constants_sigmas_commitment.merkle_tree;
    mt.leaves = leaves;
    mt.digests = digests;
    circuit_data.prover_only.fft_root_table = fft;

    bytes
}

/// Inverse of [`to_bytes_compact`]: deserialize, then rebuild the omitted
/// Merkle tree from the stored polynomial coefficients via
/// `PolynomialBatch::from_coeffs`.
pub fn from_bytes_compact<F, C, const D: usize>(
    bytes: &[u8],
    gate_serializer: &impl GateSerializer<F, D>,
    generator_serializer: &impl WitnessGeneratorSerializer<F, D>,
) -> anyhow::Result<CircuitData<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    let mut circuit_data = CircuitData::<F, C, D>::from_bytes(bytes, gate_serializer, generator_serializer)
        .map_err(|e: IoError| anyhow::anyhow!("compact deserialize failed: {e:?}"))?;

    let commitment = &circuit_data.prover_only.constants_sigmas_commitment;
    let cap_height = circuit_data.common.config.fri_config.cap_height;
    let rate_bits = commitment.rate_bits;
    let blinding = commitment.blinding;
    let polynomials = commitment.polynomials.clone();

    let rebuilt = PolynomialBatch::<F, C, D>::from_coeffs(polynomials, rate_bits, blinding, cap_height, &mut TimingTree::default(), None)
        .map_err(|e| anyhow::anyhow!("rebuild constants_sigmas commitment failed: {e}"))?;

    circuit_data.prover_only.constants_sigmas_commitment.merkle_tree = rebuilt.merkle_tree;
    Ok(circuit_data)
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::PoseidonGoldilocksConfig,
        },
    };

    use super::{PsyGateSerializer, PsyGeneratorSerializer};
    use crate::builder::comparison::CircuitBuilderComparison;

    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    const D: usize = 2;

    /// Build a tiny circuit whose serialized `CircuitData` actually contains a
    /// `ComparisonGate`, then prove the Psy serializer round-trips it (which
    /// the stock `DefaultGateSerializer` cannot) and the restored circuit
    /// still proves.
    #[test]
    fn psy_serializer_round_trips_comparison_gate() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let le = builder.is_less_than_or_equal(32, x, y);
        builder.register_public_input(le.target);
        let data = builder.build::<C>();

        // Sanity: the gate the Default serializer chokes on is really present.
        assert!(
            data.common.gates.iter().any(|g| g.0.id().contains("ComparisonGate")),
            "expected a ComparisonGate; gates: {:?}",
            data.common.gates.iter().map(|g| g.0.id()).collect::<Vec<_>>()
        );

        let gate_ser = PsyGateSerializer;
        let gen_ser = PsyGeneratorSerializer::<C, D>::default();

        // serialize -> deserialize -> re-serialize must be byte-identical.
        let bytes = data.to_bytes(&gate_ser, &gen_ser).expect("serialize");
        let restored = CircuitData::<F, C, D>::from_bytes(&bytes, &gate_ser, &gen_ser).expect("deserialize");
        let bytes2 = restored.to_bytes(&gate_ser, &gen_ser).expect("re-serialize");
        assert_eq!(bytes, bytes2, "round-trip bytes differ");

        // The restored circuit can still prove & verify.
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::from_canonical_u64(3)).unwrap();
        pw.set_target(y, F::from_canonical_u64(7)).unwrap();
        let proof = restored.prove(pw).expect("prove");
        restored.verify(proof).expect("verify");
    }

    /// Compact serialization round-trip: strip the derivable Merkle data,
    /// deserialize, rebuild it from the polynomial coeffs, and confirm the
    /// rebuilt circuit still proves & verifies — i.e. the rebuilt
    /// commitment is correct. Also reports the size win vs full
    /// serialization.
    #[test]
    fn compact_serialization_rebuilds_and_proves() {
        use core::marker::PhantomData;

        use psy_client_common::data::qhashout::QHashOut;

        use super::{from_bytes_compact, to_bytes_compact};
        use crate::circuits::zk_signature3::core::PsyBasicZKSignatureInnerCircuit;

        let gate_ser = PsyGateSerializer;
        let gen_ser = PsyGeneratorSerializer::<C, D> { _phantom: PhantomData };

        let mut circuit = PsyBasicZKSignatureInnerCircuit::<C, D>::new();
        let full = circuit.circuit_data.to_bytes(&gate_ser, &gen_ser).expect("full serialize");
        let compact = to_bytes_compact(&mut circuit.circuit_data, &gate_ser, &gen_ser).expect("compact serialize");

        let restored = from_bytes_compact::<F, C, D>(&compact, &gate_ser, &gen_ser).expect("compact deserialize");

        // The rebuilt circuit must match the original's common/verifier data...
        assert_eq!(restored.common, circuit.circuit_data.common, "common mismatch after rebuild");
        assert_eq!(
            restored.verifier_only, circuit.circuit_data.verifier_only,
            "verifier mismatch after rebuild"
        );

        // ...and actually prove & verify (proves the rebuilt Merkle commitment is
        // correct). Targets are deterministic, so the original wrapper's
        // handles index the rebuilt data.
        let mut pw = PartialWitness::new();
        pw.set_hash_target(circuit.private_key, QHashOut::<F>::rand().0).unwrap();
        pw.set_hash_target(circuit.sig_hash, QHashOut::<F>::rand().0).unwrap();
        let proof = restored.prove(pw).expect("prove with rebuilt circuit");
        restored.verify(proof).expect("verify");

        println!(
            "zk-sign inner: full {} KiB -> compact {} KiB ({:.2}x smaller)",
            full.len() / 1024,
            compact.len() / 1024,
            full.len() as f64 / compact.len() as f64
        );
    }

    /// CROSS-VERIFICATION: a proof produced by the compact-rebuilt circuit must
    /// verify against a *freshly built* circuit's verifier (and vice
    /// versa). This is the strong correctness check — the rebuilt prover
    /// data is interchangeable with a native build. Also reports build vs
    /// compact-rebuild timing.
    #[test]
    fn compact_cross_verification_and_timing() {
        use core::marker::PhantomData;
        use std::time::Instant;

        use psy_client_common::data::qhashout::QHashOut;

        use super::{from_bytes_compact, to_bytes_compact};
        use crate::circuits::zk_signature3::core::PsyBasicZKSignatureInnerCircuit;

        let gate_ser = PsyGateSerializer;
        let gen_ser = PsyGeneratorSerializer::<C, D> { _phantom: PhantomData };

        // Freshly built circuit A.
        let t0 = Instant::now();
        let mut fresh = PsyBasicZKSignatureInnerCircuit::<C, D>::new();
        let build_time = t0.elapsed();

        let compact = to_bytes_compact(&mut fresh.circuit_data, &gate_ser, &gen_ser).expect("compact serialize");

        // Compact-rebuilt circuit B (timed).
        let t1 = Instant::now();
        let rebuilt = from_bytes_compact::<F, C, D>(&compact, &gate_ser, &gen_ser).expect("compact deserialize");
        let rebuild_time = t1.elapsed();

        let pk = QHashOut::<F>::rand();
        let sh = QHashOut::<F>::rand();
        let mut pw = || {
            let mut pw = PartialWitness::new();
            pw.set_hash_target(fresh.private_key, pk.0).unwrap();
            pw.set_hash_target(fresh.sig_hash, sh.0).unwrap();
            pw
        };

        // proof from REBUILT circuit, verified by FRESH circuit.
        let proof_from_rebuilt = rebuilt.prove(pw()).expect("rebuilt prove");
        fresh
            .circuit_data
            .verify(proof_from_rebuilt)
            .expect("fresh circuit must verify a proof produced by the rebuilt circuit");

        // proof from FRESH circuit, verified by REBUILT circuit.
        let proof_from_fresh = fresh.circuit_data.prove(pw()).expect("fresh prove");
        rebuilt
            .verify(proof_from_fresh)
            .expect("rebuilt circuit must verify a proof produced by the fresh circuit");

        let speedup = build_time.as_secs_f64() / rebuild_time.as_secs_f64();
        println!(
            "zk-sign inner timing: build() {:.3?} | compact rebuild {:.3?} ({:.2}x)",
            build_time, rebuild_time, speedup
        );
    }
}

#[cfg(test)]
mod reward_common_tests {
    use super::*;
    use plonky2::{field::goldilocks_field::GoldilocksField as F, gates::gate::GateRef, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CommonCircuitData}, config::PoseidonGoldilocksConfig as C}, util::serialization::Buffer};

    #[test]
    fn existing_gate_tags_remain_decodable() {
        let serializer = PsyGateSerializer;
        let config = CircuitConfig::standard_recursion_config();
        let common = CircuitBuilder::<F, 2>::new(config).build::<C>().common;
        for (gate, tag) in [(GateRef::new(NoopGate), 9u32), (GateRef::new(ComparisonGate::<F, 2>::new(32, 16)), 16u32)] {
            let mut bytes = Vec::new();
            serializer.write_gate(&mut bytes, &gate, &common).unwrap();
            assert_eq!(&bytes[..4], &tag.to_le_bytes());
            let restored = serializer.read_gate(&mut Buffer::new(&bytes), &common).unwrap();
            assert_eq!(restored, gate);
        }
    }

    #[test]
    fn shared_comparison_preserves_its_concrete_type() {
        let serializer = PsyGateSerializer;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        builder.add_gate(SharedComparisonGate::<F, 2>::new(32, 16), vec![]);
        let common = builder.build::<C>().common;
        let bytes = common.to_bytes(&serializer).unwrap();
        let restored = CommonCircuitData::<F, 2>::from_bytes(bytes.clone(), &serializer).unwrap();
        assert!(restored.gates.iter().any(|gate| gate.0.as_any().is::<SharedComparisonGate<F, 2>>()));
        assert_eq!(restored.to_bytes(&serializer).unwrap(), bytes);
        let shared = GateRef::new(SharedComparisonGate::<F, 2>::new(32, 16));
        let mut bytes = Vec::new();
        serializer.write_gate(&mut bytes, &shared, &common).unwrap();
        assert_eq!(&bytes[..4], &26u32.to_le_bytes());
        let decoded = serializer.read_gate(&mut Buffer::new(&bytes), &common).unwrap();
        assert!(decoded.0.as_any().is::<SharedComparisonGate<F, 2>>());
    }

    #[test]
    fn secp_and_keccak_common_data_round_trips() {
        use crate::crypto::secp256k1::gadget::Secp256K1Gadget;
        use plonky2::hash::poseidon::PoseidonHash;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        Secp256K1Gadget::add_virtual_to_eth_personal_sign::<PoseidonHash, F, 2>(&mut builder);
        let common = builder.build::<C>().common;
        let serializer = PsyGateSerializer;
        let bytes = common.to_bytes(&serializer).unwrap();
        let restored = CommonCircuitData::<F, 2>::from_bytes(bytes.clone(), &serializer).unwrap();
        assert_eq!(restored, common);
        assert_eq!(restored.to_bytes(&serializer).unwrap(), bytes);
    }
}
