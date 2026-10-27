use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    gates::gate::GateRef,
    hash::hash_types::{HashOut, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_common::utils::debug_timer::DebugTimer;

use super::{pm_core::get_circuit_fingerprint_generic, pm_custom::PMCircuitCustomizer};
use crate::builder::verify::CircuitBuilderVerifyProofHelpers;

#[derive(Debug)]
pub struct PsyProofMinifierDynamic<const D: usize, F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub circuit_data: CircuitData<F, C, D>,
    pub circuit_fingerprint: HashOut<F>,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: Option<VerifierCircuitTarget>,
    pub verifier_data: Option<VerifierOnlyCircuitData<C, D>>,
}

impl<const D: usize, F: RichField + Extendable<D>, C: GenericConfig<D, F = F>> PsyProofMinifierDynamic<D, F, C>
where
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    pub fn new(base_circuit_verifier_data: &VerifierOnlyCircuitData<C, D>, base_circuit_common_data: &CommonCircuitData<F, D>) -> Self {
        let standard_config = CircuitConfig::standard_recursion_config();
        Self::new_with_cfg(standard_config, base_circuit_verifier_data, base_circuit_common_data, None, false)
    }
    pub fn new_with_dynamic_constant_verifier(
        base_circuit_verifier_data: &VerifierOnlyCircuitData<C, D>,
        base_circuit_common_data: &CommonCircuitData<F, D>,
        is_constant_verifier_data: bool,
    ) -> Self {
        let standard_config = CircuitConfig::standard_recursion_config();
        Self::new_with_cfg(
            standard_config,
            base_circuit_verifier_data,
            base_circuit_common_data,
            None,
            is_constant_verifier_data,
        )
    }
    pub fn new_with_cfg(
        config: CircuitConfig,
        base_circuit_verifier_data: &VerifierOnlyCircuitData<C, D>,
        base_circuit_common_data: &CommonCircuitData<F, D>,
        add_gates: Option<&[GateRef<F, D>]>,
        is_constant_verifier_data: bool,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let verifier_data_target = if is_constant_verifier_data {
            builder.constant_verifier_data(base_circuit_verifier_data)
        } else {
            builder.add_virtual_verifier_data(base_circuit_verifier_data.constants_sigmas_cap.height())
        };
        let proof_target = builder.add_virtual_proof_with_pis(base_circuit_common_data);

        builder.register_public_inputs(&proof_target.public_inputs);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, base_circuit_common_data);
        if !is_constant_verifier_data {
            let fingerprint_target = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data_target);
            let known_fingerprint = builder.constant_hash(get_circuit_fingerprint_generic::<D, C::F, C>(base_circuit_verifier_data));
            builder.connect_hashes(fingerprint_target, known_fingerprint);
        }

        if add_gates.is_some() {
            add_gates.unwrap().iter().for_each(|g| {
                builder.add_gate_to_gate_set(g.clone());
            });
        }

        let circuit_data = builder.build::<C>();

        let circuit_fingerprint = get_circuit_fingerprint_generic(&circuit_data.verifier_only);

        Self {
            circuit_data,
            circuit_fingerprint,
            proof_target,
            verifier_data_target: if is_constant_verifier_data { None } else { Some(verifier_data_target) },
            verifier_data: if is_constant_verifier_data {
                None
            } else {
                Some(base_circuit_verifier_data.clone())
            },
        }
    }
    pub fn new_with_cfg_customizer<PMCC: PMCircuitCustomizer<F, D>>(
        config: CircuitConfig,
        base_circuit_verifier_data: &VerifierOnlyCircuitData<C, D>,
        base_circuit_common_data: &CommonCircuitData<F, D>,
        add_gates: Option<&[GateRef<F, D>]>,
        customizer: Option<&PMCC>,
        is_constant_verifier_data: bool,
    ) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let verifier_data_target = if is_constant_verifier_data {
            builder.constant_verifier_data(base_circuit_verifier_data)
        } else {
            builder.add_virtual_verifier_data(base_circuit_verifier_data.constants_sigmas_cap.height())
        };
        let proof_target = builder.add_virtual_proof_with_pis(base_circuit_common_data);

        builder.register_public_inputs(&proof_target.public_inputs);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, base_circuit_common_data);
        // Same binding as `new_with_cfg`: a witness-supplied (dynamic) VK is
        // only safe when the circuit pins it to the intended child circuit —
        // otherwise a prover could launder a proof of a foreign circuit
        // through this minifier.
        if !is_constant_verifier_data {
            let fingerprint_target = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data_target);
            let known_fingerprint = builder.constant_hash(get_circuit_fingerprint_generic::<D, C::F, C>(base_circuit_verifier_data));
            builder.connect_hashes(fingerprint_target, known_fingerprint);
        }

        if add_gates.is_some() {
            add_gates.unwrap().iter().for_each(|g| {
                builder.add_gate_to_gate_set(g.clone());
            });
        }
        if customizer.is_some() {
            customizer.unwrap().augment_circuit(&mut builder);
        }

        let circuit_data = builder.build::<C>();

        let circuit_fingerprint = get_circuit_fingerprint_generic(&circuit_data.verifier_only);

        Self {
            circuit_data,
            circuit_fingerprint,
            proof_target,
            verifier_data_target: if is_constant_verifier_data { None } else { Some(verifier_data_target) },
            verifier_data: if is_constant_verifier_data {
                None
            } else {
                Some(base_circuit_verifier_data.clone())
            },
        }
    }
    pub fn prove(
        &self,
        base_proof: &ProofWithPublicInputs<F, C, D>, /*verifier_data: &VerifierOnlyCircuitData<C, D>,
                                                      *proof: &ProofWithPublicInputs<F, C, D>, */
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        if self.verifier_data_target.is_some() {
            let verifier_data_target = self.verifier_data_target.as_ref().unwrap();
            let verifier_data = self.verifier_data.as_ref().unwrap();

            pw.set_verifier_data_target(verifier_data_target, verifier_data)?;
        }
        pw.set_proof_with_pis_target(&self.proof_target, base_proof)?;
        let mut timer = DebugTimer::new("compress");
        let result = self.circuit_data.prove(pw);
        timer.lap("proved compress");
        result
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        field::types::Field,
        iop::witness::WitnessWrite,
        plonk::config::PoseidonGoldilocksConfig,
    };

    use super::*;
    use crate::proof_minifier::pm_custom::PMCircuitCustomizer;

    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    struct NoopCustomizer;
    impl PMCircuitCustomizer<F, D> for NoopCustomizer {
        fn augment_circuit(&self, _builder: &mut CircuitBuilder<F, D>) {}
    }

    fn base_circuit_and_proof() -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let value = builder.add_virtual_target();
        builder.register_public_input(value);
        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        pw.set_target(value, F::ZERO);
        let proof = data.prove(pw).expect("base circuit must prove");
        (data, proof)
    }

    // The customizer path with a dynamic VK must bind the witness-supplied
    // verifier data to the intended child circuit, exactly like `new_with_cfg`:
    // a proof compressed under a foreign VK (same common data, different
    // circuit digest) must be unprovable.
    #[test]
    fn customizer_dynamic_vk_rejects_foreign_verifier_data() {
        let (base_data, base_proof) = base_circuit_and_proof();
        let minifier = PsyProofMinifierDynamic::<D, F, C>::new_with_cfg_customizer(
            CircuitConfig::standard_recursion_config(),
            &base_data.verifier_only,
            &base_data.common,
            None,
            Some(&NoopCustomizer),
            false,
        );

        // The intended VK still compresses and verifies.
        let compressed = minifier.prove(&base_proof).expect("minifier must prove with the intended VK");
        minifier.circuit_data.verify(compressed).expect("compressed proof must verify");

        // Foreign circuit: same public-input shape and recursion config (so
        // its proofs satisfy the in-circuit `verify_proof` equations) but a
        // different circuit, hence a different VK digest. Its proof verifies
        // against the foreign VK — only the missing fingerprint binding can
        // reject this witness.
        let (foreign_data, foreign_proof) = {
            let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let value = builder.add_virtual_target();
            builder.register_public_input(value);
            // One extra gate makes this a different circuit with (for this
            // config) the same common data.
            let zero = builder.zero();
            builder.connect(value, zero);
            let data = builder.build::<C>();
            let mut pw = PartialWitness::new();
            pw.set_target(value, F::ZERO);
            let proof = data.prove(pw).expect("foreign circuit must prove");
            (data, proof)
        };
        assert_ne!(
            foreign_data.verifier_only.circuit_digest, base_data.verifier_only.circuit_digest,
            "foreign circuit must have a different VK digest"
        );
        assert_eq!(
            foreign_data.common.degree_bits(),
            base_data.common.degree_bits(),
            "foreign circuit must share the base common data, else the test premise is vacuous"
        );

        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(
            minifier.verifier_data_target.as_ref().expect("dynamic VK mode must have a verifier target"),
            &foreign_data.verifier_only,
        )
        .unwrap();
        pw.set_proof_with_pis_target(&minifier.proof_target, &foreign_proof).unwrap();
        assert!(
            minifier.circuit_data.prove(pw).is_err(),
            "foreign verifier data must be rejected by the fingerprint binding"
        );
    }
}
