use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_data::agg::{AggStateTransition, TPAltCircuitFingerprintConfig, TPCircuitFingerprintConfig};

use crate::gadgets::treeprover::{AggStateTransitionGadget, AggStateTransitionProofValidityGadget};
#[derive(Debug, Clone)]
pub struct VerifyStateTransitionProofGadget<const D: usize> {
    // start targets requiring witness
    pub state_transition: AggStateTransitionGadget,
    pub verifier_data: VerifierCircuitTarget,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    // end targets requiring witness
}

impl<const D: usize> VerifyStateTransitionProofGadget<D> {

    pub fn add_virtual_to_with_config<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        proof_common_data: &CommonCircuitData<F, D>,
        config: &TPAltCircuitFingerprintConfig<QHashOut<F>>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        Self::add_virtual_to::<C,F>(
            builder,
            proof_common_data,
            config.verifier_data_cap_height,
            config.leaf_fingerprint,
            config.aggregator_fingerprint,
            config.dummy_fingerprint
        )
    }
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        proof_common_data: &CommonCircuitData<F, D>,
        verifier_data_cap_height: usize,
        leaf_circuit_fingerprint: QHashOut<C::F>,
        agg_circuit_fingerprint: QHashOut<C::F>,
        dummy_circuit_fingerprint: QHashOut<C::F>,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let verifier_data = builder.add_virtual_verifier_data(verifier_data_cap_height);
        let proof_target = builder.add_virtual_proof_with_pis(proof_common_data);

        assert_eq!(
            proof_target.public_inputs.len(),
            19,
            "agg proofs should have 19 public inputs"
        );
        builder.verify_proof::<C>(&proof_target, &verifier_data, proof_common_data);

        let whitelist = QHashOut(C::Hasher::two_to_one(
            leaf_circuit_fingerprint.0,
            agg_circuit_fingerprint.0,
        ));
        let expected_state_transition_hash =
            AggStateTransitionProofValidityGadget::add_virtual_to::<C::Hasher, C::F, D>(
                builder,
                &proof_target,
                &verifier_data,
                &TPCircuitFingerprintConfig {
                    leaf_fingerprint: leaf_circuit_fingerprint,
                    aggregator_fingerprint: agg_circuit_fingerprint,
                    dummy_fingerprint: dummy_circuit_fingerprint,
                    allowed_circuit_hashes_root: whitelist,
                    leaf_circuit_type: 255,
                    aggregator_circuit_type: 255,
                },
            );

        let state_transition = AggStateTransitionGadget::add_virtual_to(builder);
        let computed_state_transition_hash =
            state_transition.get_combined_hash::<C::Hasher, F, D>(builder);

        tracing::debug!("expected_state_transition_hash={:#?}", expected_state_transition_hash);
        tracing::debug!("computed_state_transition_hash={:#?}", computed_state_transition_hash);
        builder.connect_hashes(
            expected_state_transition_hash,
            computed_state_transition_hash,
        );
        Self {
            verifier_data,
            proof_target,
            state_transition,
        }
    }

    pub fn set_witness<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        witness: &mut impl Witness<F>,
        state_transition: &AggStateTransition<QHashOut<F>>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        tracing::debug!("state_transition={}", serde_json::to_string_pretty(&state_transition).unwrap());
        self.state_transition
            .set_witness(witness, state_transition)?;

        witness.set_proof_with_pis_target(&self.proof_target, proof)?;
        witness.set_verifier_data_target(&self.verifier_data, &verifier_data)
    }
}
