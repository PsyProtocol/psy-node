

use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{
        circuit_builder::CircuitBuilder, circuit_data::VerifierCircuitTarget,
        config::AlgebraicHasher, proof::ProofWithPublicInputsTarget,
    },
};
use psy_data::agg::{AggStateTransition, AggStateTransitionWithEvents, TPCircuitFingerprintConfig};
use psy_plonky2_basic_helpers::builder::{
    connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore,
    verify::CircuitBuilderVerifyProofHelpers,
};

use crate::agg::common::compute_agg_state_trackable_final_public_inputs;

pub fn check_agg_state_transition_proof_validity<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    proof_target: &ProofWithPublicInputsTarget<D>,
    verifier_data_target: &VerifierCircuitTarget,
    state_transition_hash: HashOutTarget,
    rewards_tree_value: HashOutTarget,
    total_proofs_generated: Target,
    fingerprint: &TPCircuitFingerprintConfig<QHashOut<F>>,
) {
    assert_eq!(
        proof_target.public_inputs.len(),
        4,
        "state aggregation proofs should have 4 public inputs"
    );
    let allowed_fingerprints = [
        builder.constant_qhash(fingerprint.aggregator_fingerprint),
        builder.constant_qhash(fingerprint.leaf_fingerprint),
        builder.constant_qhash(fingerprint.dummy_fingerprint),
    ];
    let actual_fingerprint = builder.get_circuit_fingerprint::<H>(verifier_data_target);
    builder.connect_hashes_enum(actual_fingerprint, &allowed_fingerprints);
    let allowed_circuit_hashes_root =
        builder.constant_qhash(fingerprint.allowed_circuit_hashes_root);
    let actual_proof_public_inputs_hash = HashOutTarget {
        elements: [
            proof_target.public_inputs[0],
            proof_target.public_inputs[1],
            proof_target.public_inputs[2],
            proof_target.public_inputs[3],
        ]
    };
    let expected_proof_public_inputs_hash = compute_agg_state_trackable_final_public_inputs::<H, F, D>(
        builder,
        allowed_circuit_hashes_root,
        state_transition_hash,
        rewards_tree_value,
        total_proofs_generated,
    );
    builder.connect_hashes(
        actual_proof_public_inputs_hash,
        expected_proof_public_inputs_hash,
    );
}

#[derive(Debug, Clone, Copy)]
pub struct AggStateTransitionGadget {
    pub state_transition_start: HashOutTarget,
    pub state_transition_end: HashOutTarget,
}

impl AggStateTransitionGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let state_transition_start = builder.add_virtual_hash();
        let state_transition_end = builder.add_virtual_hash();
        Self {
            state_transition_start,
            state_transition_end,
        }
    }

    pub fn get_combined_hash<
        H:AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        builder.hash_two_to_one::<H>(self.state_transition_start, self.state_transition_end)
    }

    pub fn combine_many<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        transitions: &[Self],
    ) -> Self {
        assert!(
            transitions.len() > 0,
            "you can only compute combined hash for 1 or more transition"
        );
        if transitions.len() == 1 {
            transitions[0]
        } else {
            let mut state_transition_start = transitions[0].state_transition_start;
            let mut state_transition_end = transitions[0].state_transition_end;
            for i in 1..transitions.len() {
                let transition = &transitions[i];
                state_transition_start = builder.hash_two_to_one::<H>(
                    state_transition_start,
                    transition.state_transition_start,
                );
                state_transition_end = builder
                    .hash_two_to_one::<H>(state_transition_end, transition.state_transition_end);
            }
            Self {
                state_transition_start,
                state_transition_end,
            }
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        transition: &AggStateTransition<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(
            self.state_transition_start,
            transition.state_transition_start.0,
        )?;
        witness.set_hash_target(self.state_transition_end, transition.state_transition_end.0)
    }
    pub fn set_witness_with_events<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        transition: &AggStateTransitionWithEvents<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(
            self.state_transition_start,
            transition.state_transition_start.0,
        )?;
        witness.set_hash_target(self.state_transition_end, transition.state_transition_end.0)
    }
    pub fn set_witness_values<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        state_transition_start: QHashOut<F>,
        state_transition_end: QHashOut<F>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.state_transition_start, state_transition_start.0)?;
        witness.set_hash_target(self.state_transition_end, state_transition_end.0)
    }
}