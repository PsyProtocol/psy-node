use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    gates::gate::GateRef,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData,
            VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_plonky2_basic_helpers::builder::verify::CircuitBuilderVerifyProofHelpers;

use super::type_layout::NormalizedTypeLayoutProofCircuit;
use crate::{
    gadgets::qdata::state_layout::LayoutAppendPublicInputsGadget,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

/// Verifier endpoint for a finite whitelist of pairwise
/// aggregation depths.
#[derive(Debug)]
pub struct CanonicalStateLayoutAppendWrapperCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub adapters: Vec<NormalizedTypeLayoutProofCircuit<C, D>>,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_target: VerifierCircuitTarget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize>
    CanonicalStateLayoutAppendWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        allowed: &[(
            &CommonCircuitData<C::F, D>,
            &VerifierOnlyCircuitData<C, D>,
        )],
    ) -> Self {
        assert!(
            !allowed.is_empty(),
            "layout aggregate whitelist is empty"
        );
        let preliminary = allowed
            .iter()
            .map(|(common, verifier)| {
                NormalizedTypeLayoutProofCircuit::<C, D>::build(
                    common,
                    verifier,
                    LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT,
                    &[],
                    None,
                )
            })
            .collect::<Vec<_>>();
        let target_degree = preliminary
            .iter()
            .map(|adapter| adapter.circuit_data.common.degree())
            .max()
            .unwrap();
        let mut common_gates = Vec::<GateRef<C::F, D>>::new();
        for adapter in &preliminary {
            for gate in &adapter.circuit_data.common.gates {
                if !common_gates.iter().any(|known| known == gate) {
                    common_gates.push(gate.clone());
                }
            }
        }
        let adapters = allowed
            .iter()
            .map(|(common, verifier)| {
                NormalizedTypeLayoutProofCircuit::<C, D>::build(
                    common,
                    verifier,
                    LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT,
                    &common_gates,
                    Some(target_degree),
                )
            })
            .collect::<Vec<_>>();
        let shared_common = &adapters[0].circuit_data.common;
        assert!(adapters
            .iter()
            .all(|adapter| adapter.circuit_data.common == *shared_common));

        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let proof_target =
            builder.add_virtual_proof_with_pis(shared_common);
        let cap_height = adapters[0]
            .circuit_data
            .verifier_only
            .constants_sigmas_cap
            .height();
        assert!(adapters.iter().all(|adapter| {
            adapter
                .circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height()
                == cap_height
        }));
        let verifier_target =
            builder.add_virtual_verifier_data(cap_height);
        builder.verify_proof::<C>(
            &proof_target,
            &verifier_target,
            shared_common,
        );

        let actual = builder
            .get_circuit_fingerprint::<C::Hasher>(&verifier_target);
        let zero = builder.zero();
        let one = builder.one();
        let mut allowed_count = zero;
        for adapter in &adapters {
            let expected = builder.constant_hash(
                get_circuit_fingerprint_generic::<D, C::F, C>(
                    &adapter.circuit_data.verifier_only,
                ),
            );
            let mut equal = one;
            for (actual, expected) in
                actual.elements.iter().zip(expected.elements)
            {
                let limb_equal =
                    builder.is_equal(*actual, expected);
                equal = builder.mul(equal, limb_equal.target);
            }
            allowed_count = builder.add(allowed_count, equal);
        }
        builder.connect(allowed_count, one);
        let output =
            LayoutAppendPublicInputsGadget::from_public_inputs(
                &proof_target.public_inputs,
            );
        output.register_public_inputs(&mut builder);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(
            get_circuit_fingerprint_generic(
                &circuit_data.verifier_only,
            ),
        );
        Self {
            adapters,
            proof_target,
            verifier_target,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove(
        &self,
        adapter_index: usize,
        inner_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let adapter = self.adapters.get(adapter_index).ok_or_else(|| {
            anyhow::anyhow!(
                "layout aggregation depth is not whitelisted"
            )
        })?;
        let normalized = adapter.prove(inner_proof)?;
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(
            &self.proof_target,
            &normalized,
        )?;
        witness.set_verifier_data_target(
            &self.verifier_target,
            &adapter.circuit_data.verifier_only,
        )?;
        self.circuit_data.prove(witness)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for CanonicalStateLayoutAppendWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(
        &self,
    ) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(
        &self,
    ) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}
