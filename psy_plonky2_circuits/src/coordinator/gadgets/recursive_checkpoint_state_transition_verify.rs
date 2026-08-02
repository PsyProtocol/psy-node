use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, circuit_data::{CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}}};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore, verify::CircuitBuilderVerifyProofHelpers};

use crate::coordinator::gadgets::checkpoint_state_transition::CheckpointStateTransitionPublicInputsGadget;


// we keep this separate from DPNProvingSessionCompactMethodCallGadget incase it
// changes in the future
#[derive(Debug, Clone)]
pub struct VerifyRecursiveCheckpointStateTransitionProofGadget<const D: usize> {
    pub previous_checkpoint_state_transition_verifier_data: VerifierCircuitTarget,
    pub previous_checkpoint_state_transition_proof_target: ProofWithPublicInputsTarget<D>,
    pub last_old_checkpoint_tree_leaf_hash: HashOutTarget,
    pub last_old_checkpoint_tree_root_hash: HashOutTarget,
    pub previous_chain_hash: HashOutTarget,
}

impl<const D: usize> VerifyRecursiveCheckpointStateTransitionProofGadget<D> {
    pub fn add_virtual_to<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        builder: &mut CircuitBuilder<F, D>,
        checkpoint_transition_proof_common_data: &CommonCircuitData<F, D>,
        checkpoint_transition_proof_common_data_verifier_data_cap_height: usize,
        known_checkpoint_state_transition_genesis_fingerprint: QHashOut<C::F>,
        current_public_inputs_gadget: CheckpointStateTransitionPublicInputsGadget,
        checkpoint_id: Target,
    ) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
    {

        let previous_checkpoint_state_transition_verifier_data = builder.add_virtual_verifier_data(checkpoint_transition_proof_common_data_verifier_data_cap_height);
        let previous_checkpoint_state_transition_proof_target = builder.add_virtual_proof_with_pis(checkpoint_transition_proof_common_data);

        builder.verify_proof::<C>(&previous_checkpoint_state_transition_proof_target, &previous_checkpoint_state_transition_verifier_data, checkpoint_transition_proof_common_data);

        let last_old_checkpoint_tree_leaf_hash = builder.add_virtual_hash();
        let last_old_checkpoint_tree_root_hash = builder.add_virtual_hash();

        // NOTE:
        // In cumulative-chain mode, the previous proof public inputs are an opaque chain commitment.
        // We must not re-derive/constraint previous transition hash here using legacy transition semantics.
        // previous proof validity + fingerprint checks + PI linkage below are sufficient.

        let previous_proof_fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&previous_checkpoint_state_transition_verifier_data);

        // Genesis predecessors must use the known genesis verifier key. All later
        // predecessors must use the checkpoint transition verifier key declared
        // by the current witness.
        let is_previous_proof_genensis_block = builder.is_equal_to_u64(checkpoint_id, 1);
        let genesis_checkpoint_transition_proof_fingerprint = builder.constant_qhash(known_checkpoint_state_transition_genesis_fingerprint);
        builder.connect_hashes_if_true(
            is_previous_proof_genensis_block,
            previous_proof_fingerprint,
            genesis_checkpoint_transition_proof_fingerprint,
        );
        builder.connect_hashes_if_false(
            is_previous_proof_genensis_block,
            previous_proof_fingerprint,
            current_public_inputs_gadget.checkpoint_state_transition_circuit_fingerprint,
        );

        assert_eq!(previous_checkpoint_state_transition_proof_target.public_inputs.len(), 4, "state transition proofs must have 4 public inputs");

        let actual_previous_proof_public_inputs_hash = HashOutTarget {
            elements: [
                previous_checkpoint_state_transition_proof_target.public_inputs[0],
                previous_checkpoint_state_transition_proof_target.public_inputs[1],
                previous_checkpoint_state_transition_proof_target.public_inputs[2],
                previous_checkpoint_state_transition_proof_target.public_inputs[3]
            ]
        };

        // previous_chain_hash is sourced directly from previous proof public inputs.
        // Do not add a second witness-provided target for this value.
        let previous_chain_hash = actual_previous_proof_public_inputs_hash;

        Self {
            previous_checkpoint_state_transition_verifier_data,
            previous_checkpoint_state_transition_proof_target,
            last_old_checkpoint_tree_leaf_hash,
            last_old_checkpoint_tree_root_hash,
            previous_chain_hash,
        }
    }
    pub fn set_witness_params<C: GenericConfig<D, F = F>, F: RichField + Extendable<D>>(
        &self,
        witness: &mut impl Witness<F>,
        last_old_checkpoint_tree_leaf_hash: QHashOut<F>,
        last_old_checkpoint_tree_root_hash: QHashOut<F>,
        _previous_chain_hash: QHashOut<F>,
        previous_checkpoint_state_transition_proof: &ProofWithPublicInputs<F, C, D>,
        previous_checkpoint_state_transition_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        witness.set_hash_target(self.last_old_checkpoint_tree_leaf_hash, last_old_checkpoint_tree_leaf_hash.0)?;
        witness.set_hash_target(self.last_old_checkpoint_tree_root_hash, last_old_checkpoint_tree_root_hash.0)?;
        witness.set_verifier_data_target::<C, D>(&self.previous_checkpoint_state_transition_verifier_data, previous_checkpoint_state_transition_verifier_data)?;
        witness.set_proof_with_pis_target::<C, D>(&self.previous_checkpoint_state_transition_proof_target, previous_checkpoint_state_transition_proof)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::circuits::checkpoint_state_transition_genesis::QEDCheckpointStateTransitionGenesisCircuit;
    use crate::{
        coordinator::circuits::checkpoint_state_transition::QEDCheckpointStateTransitionCircuit,
        qstandard::QStandardCircuit,
    };
    use parth_core::utils::QPGenRandom;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::Field},
        hash::hash_types::HashOut,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use psy_plonky2_basic_helpers::builder::pad_circuit::CircuitBuilderQEDCommonGates;
    use psy_data::protocol::circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInput;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    fn qhash(seed: u64) -> QHashOut<F> {
        QHashOut(HashOut {
            elements: [
                F::from_canonical_u64(seed),
                F::from_canonical_u64(seed + 1),
                F::from_canonical_u64(seed + 2),
                F::from_canonical_u64(seed + 3),
            ],
        })
    }

    #[test]
    fn regression_checkpoint_id_two_rejects_genesis_proof_and_verifier_key_as_predecessor() {
        let genesis_circuit = QEDCheckpointStateTransitionGenesisCircuit::<C, D>::new();
        let genesis_proof = genesis_circuit
            .prove_base(qhash(10), qhash(20), qhash(30))
            .unwrap();
        genesis_circuit
            .circuit_data
            .verify(genesis_proof.clone())
            .unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let current_public_inputs_gadget =
            CheckpointStateTransitionPublicInputsGadget::add_virtual_to::<<C as GenericConfig<D>>::Hasher, F, D>(
                &mut builder,
            );
        let checkpoint_id = builder.constant(F::from_canonical_u64(2));
        let genesis_verifier_data_cap_height = genesis_circuit
            .circuit_data
            .verifier_only
            .constants_sigmas_cap
            .height();
        let recursive_verifier =
            VerifyRecursiveCheckpointStateTransitionProofGadget::<D>::add_virtual_to::<C, F>(
                &mut builder,
                &genesis_circuit.circuit_data.common,
                genesis_verifier_data_cap_height,
                genesis_circuit.fingerprint,
                current_public_inputs_gadget,
                checkpoint_id,
            );
        builder.register_public_inputs(&recursive_verifier.previous_chain_hash.elements);
        builder.add_qed_type_d_common_gates();
        let harness_circuit_data = builder.build::<C>();

        // Set the declared circuit fingerprint to a dummy non-genesis value.
        // The genesis VK fingerprint will not match this, so proving must fail.
        let mut witness = PartialWitness::<F>::new();
        witness.set_hash_target(
            current_public_inputs_gadget.checkpoint_state_transition_circuit_fingerprint,
            qhash(99).0,
        ).unwrap();
        recursive_verifier
            .set_witness_params::<C, F>(
                &mut witness,
                qhash(40),
                qhash(50),
                qhash(60),
                &genesis_proof,
                &genesis_circuit.circuit_data.verifier_only,
            )
            .unwrap();

        // Proving must fail: genesis VK fingerprint != declared non-genesis fingerprint.
        let result = harness_circuit_data.prove(witness);
        assert!(
            result.is_err(),
            "checkpoint_id=2 must reject genesis VK as predecessor (fingerprint mismatch)"
        );
    }

    #[test]
    #[should_panic(
        expected = "checkpoint state transition witness fingerprint must match the proving circuit fingerprint"
    )]
    fn regression_prove_base_rejects_genesis_fingerprint_as_declared_transition_fingerprint() {
        let genesis_circuit = QEDCheckpointStateTransitionGenesisCircuit::<C, D>::new();
        let genesis_proof = genesis_circuit
            .prove_base(qhash(10), qhash(20), qhash(30))
            .unwrap();
        let verifier_data_cap_height = genesis_circuit
            .circuit_data
            .verifier_only
            .constants_sigmas_cap
            .height();
        let checkpoint_circuit = QEDCheckpointStateTransitionCircuit::<C, D>::new_with_config(
            &genesis_circuit.circuit_data.common,
            verifier_data_cap_height,
            genesis_circuit.fingerprint,
            &genesis_circuit.circuit_data.common,
            verifier_data_cap_height,
            genesis_circuit.fingerprint,
            2,
            false,
        );
        assert_ne!(checkpoint_circuit.get_fingerprint(), genesis_circuit.fingerprint);

        let mut witness =
            QCQEDCheckpointStateTransitionInput::<F, QHashOut<F>>::qp_rand_gen();
        witness.checkpoint_state_transition_circuit_fingerprint = genesis_circuit.fingerprint;

        checkpoint_circuit
            .prove_base(
                qhash(40),
                &witness,
                qhash(50),
                &genesis_proof,
                &genesis_circuit.circuit_data.verifier_only,
                &genesis_proof,
                &genesis_circuit.circuit_data.verifier_only,
            )
            .unwrap();
    }

    #[test]
    fn genesis_checkpoint_id_one_accepts_genesis_proof_and_verifier_key() {
        let genesis_circuit = QEDCheckpointStateTransitionGenesisCircuit::<C, D>::new();
        let genesis_proof = genesis_circuit
            .prove_base(qhash(10), qhash(20), qhash(30))
            .unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let current_public_inputs_gadget =
            CheckpointStateTransitionPublicInputsGadget::add_virtual_to::<<C as GenericConfig<D>>::Hasher, F, D>(
                &mut builder,
            );
        let checkpoint_id = builder.constant(F::from_canonical_u64(1));
        let cap_height = genesis_circuit.circuit_data.verifier_only.constants_sigmas_cap.height();
        let recursive_verifier =
            VerifyRecursiveCheckpointStateTransitionProofGadget::<D>::add_virtual_to::<C, F>(
                &mut builder,
                &genesis_circuit.circuit_data.common,
                cap_height,
                genesis_circuit.fingerprint,
                current_public_inputs_gadget,
                checkpoint_id,
            );
        builder.register_public_inputs(&recursive_verifier.previous_chain_hash.elements);
        builder.add_qed_type_d_common_gates();
        let harness = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        // For genesis branch, declared_fp can be anything (connect_hashes_if_false is inactive).
        pw.set_hash_target(
            current_public_inputs_gadget.checkpoint_state_transition_circuit_fingerprint,
            qhash(99).0,
        ).unwrap();
        recursive_verifier
            .set_witness_params::<C, F>(
                &mut pw,
                qhash(40),
                qhash(50),
                qhash(60),
                &genesis_proof,
                &genesis_circuit.circuit_data.verifier_only,
            )
            .unwrap();
        harness.prove(pw).unwrap();
    }



    #[test]
    fn non_genesis_checkpoint_accepts_matching_verifier_key() {
        // Build a harness that verifies a predecessor proof under the *same* common data
        // as the genesis circuit, and set declared_fp == genesis fingerprint so that
        // connect_hashes_if_false passes (prev_fp == declared_fp == genesis_fp).
        let genesis_circuit = QEDCheckpointStateTransitionGenesisCircuit::<C, D>::new();
        let genesis_proof = genesis_circuit
            .prove_base(qhash(10), qhash(20), qhash(30))
            .unwrap();

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let current_public_inputs_gadget =
            CheckpointStateTransitionPublicInputsGadget::add_virtual_to::<<C as GenericConfig<D>>::Hasher, F, D>(
                &mut builder,
            );
        let checkpoint_id = builder.constant(F::from_canonical_u64(2));
        let cap_height = genesis_circuit.circuit_data.verifier_only.constants_sigmas_cap.height();
        let recursive_verifier =
            VerifyRecursiveCheckpointStateTransitionProofGadget::<D>::add_virtual_to::<C, F>(
                &mut builder,
                &genesis_circuit.circuit_data.common,
                cap_height,
                genesis_circuit.fingerprint,
                current_public_inputs_gadget,
                checkpoint_id,
            );
        builder.register_public_inputs(&recursive_verifier.previous_chain_hash.elements);
        builder.add_qed_type_d_common_gates();
        let harness = builder.build::<C>();

        let mut pw = PartialWitness::<F>::new();
        // Set declared_fp == genesis_fp so non-genesis branch passes.
        pw.set_hash_target(
            current_public_inputs_gadget.checkpoint_state_transition_circuit_fingerprint,
            genesis_circuit.fingerprint.0,
        ).unwrap();
        recursive_verifier
            .set_witness_params::<C, F>(
                &mut pw,
                qhash(40),
                qhash(50),
                qhash(60),
                &genesis_proof,
                &genesis_circuit.circuit_data.verifier_only,
            )
            .unwrap();
        harness.prove(pw).unwrap();
    }
}
