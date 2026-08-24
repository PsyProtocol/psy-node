use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};

use crate::{
    gadgets::qdata::state_layout::{
        LayoutAppendProofAggregationGadget,
        LayoutAppendPublicInputsGadget,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

/// Canonical deterministic pairwise aggregation level for layout transitions.
///
/// Both children use the same verifier. To build an arbitrary-size tree,
/// construct level 0 from the layout base verifier, then construct every
/// following level from the preceding level's verifier.
#[derive(Debug)]
pub struct StateLayoutAppendAggregateCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub aggregation: LayoutAppendProofAggregationGadget<D>,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize>
    StateLayoutAppendAggregateCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        child_common: &CommonCircuitData<C::F, D>,
        child_verifier: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        assert_eq!(
            child_common.num_public_inputs,
            LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT,
            "layout aggregation child must expose 19 public inputs",
        );
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let aggregation =
            LayoutAppendProofAggregationGadget::add_virtual_to::<C>(
                &mut builder,
                child_common,
                child_verifier,
            );
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(
            get_circuit_fingerprint_generic(
                &circuit_data.verifier_only,
            ),
        );
        Self {
            aggregation,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove(
        &self,
        left: &ProofWithPublicInputs<C::F, C, D>,
        right: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut witness = PartialWitness::new();
        self.aggregation
            .set_witness::<C>(&mut witness, left, right)?;
        self.circuit_data.prove(witness)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for StateLayoutAppendAggregateCircuit<C, D>
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

#[cfg(test)]
mod tests {
    use plonky2::plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
    };

    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    fn dummy_layout_circuit() -> CircuitData<
        <C as GenericConfig<D>>::F,
        C,
        D,
    > {
        let mut builder = CircuitBuilder::new(
            CircuitConfig::standard_recursion_config(),
        );
        for _ in 0..LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT {
            builder.add_virtual_public_input();
        }
        builder.build::<C>()
    }

    #[test]
    fn builds_pairwise_layout_aggregation_level() {
        let child = dummy_layout_circuit();
        let aggregate =
            StateLayoutAppendAggregateCircuit::<C, D>::new(
                &child.common,
                &child.verifier_only,
            );

        assert_eq!(
            aggregate.circuit_data.common.num_public_inputs,
            LayoutAppendPublicInputsGadget::PUBLIC_INPUT_COUNT
        );
    }
}
