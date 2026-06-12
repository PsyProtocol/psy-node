use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_plonky2_basic_helpers::builder::{hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers};

#[derive(Debug, Clone)]
pub struct VerifyBridgeCheckpointStateTransitionProofGadget<const D: usize> {
    pub verifier_data: VerifierCircuitTarget,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub public_inputs_hash: HashOutTarget,
}

impl<const D: usize> VerifyBridgeCheckpointStateTransitionProofGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        checkpoint_state_transition_common_data: &CommonCircuitData<F, D>,
        checkpoint_state_transition_cap_height: usize,
        known_checkpoint_state_transition_fingerprint: QHashOut<F>,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let verifier_data = builder.add_virtual_verifier_data(checkpoint_state_transition_cap_height);
        let proof_target = builder.add_virtual_proof_with_pis(checkpoint_state_transition_common_data);

        builder.verify_proof::<C>(&proof_target, &verifier_data, checkpoint_state_transition_common_data);

        let actual_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier_data);
        let expected_fingerprint = builder.constant_qhash(known_checkpoint_state_transition_fingerprint);
        builder.connect_hashes(actual_fingerprint, expected_fingerprint);

        assert_eq!(
            proof_target.public_inputs.len(),
            4,
            "checkpoint state transition proof must have 4 public inputs"
        );
        let public_inputs_hash = HashOutTarget {
            elements: [
                proof_target.public_inputs[0],
                proof_target.public_inputs[1],
                proof_target.public_inputs[2],
                proof_target.public_inputs[3],
            ],
        };

        Self {
            verifier_data,
            proof_target,
            public_inputs_hash,
        }
    }

    pub fn set_witness<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        &self,
        witness: &mut impl Witness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        witness.set_verifier_data_target::<C, D>(&self.verifier_data, verifier_data)?;
        witness.set_proof_with_pis_target::<C, D>(&self.proof_target, proof)?;
        Ok(())
    }
}
