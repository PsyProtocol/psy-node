//! Fixed recursive aggregation for one user's normalized reward leaves.

use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::{
    builder::{
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
        verify::CircuitBuilderVerifyProofHelpers,
    },
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher};

use super::claim_rewards_l1_final::USER_REWARD_FINAL_PUBLIC_INPUTS;

/// Exactly two child circuit fingerprints are admitted: normalized leaf and
/// recursive aggregate. A height-1 tree is sufficient.
pub const USER_REWARD_CIRCUIT_WHITELIST_HEIGHT: usize = 1;

struct ChildTarget<const D: usize> {
    proof: ProofWithPublicInputsTarget<D>,
    verifier: VerifierCircuitTarget,
    inclusion: MerkleProofGadget,
}

pub struct UserRewardTreeCircuit<C: GenericConfig<D>, const D: usize>
where C::Hasher: AlgebraicHasher<C::F> {
    data: CircuitData<C::F, C, D>,
    left: ChildTarget<D>,
    right: ChildTarget<D>,
}

impl<C: GenericConfig<D>, const D: usize> UserRewardTreeCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(child_common: &plonky2::plonk::circuit_data::CommonCircuitData<C::F, D>, cap_height: usize) -> Self {
        assert_eq!(child_common.num_public_inputs, USER_REWARD_FINAL_PUBLIC_INPUTS);
        let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let left = Self::add_child(&mut builder, child_common, cap_height);
        let right = Self::add_child(&mut builder, child_common, cap_height);
        builder.connect_hashes(left.inclusion.root, right.inclusion.root);
        for i in 0..13 { builder.connect(left.proof.public_inputs[i], right.proof.public_inputs[i]); }
        builder.register_public_inputs(&left.proof.public_inputs[0..13]);
        let total = builder.add(left.proof.public_inputs[13], right.proof.public_inputs[13]);
        let count = builder.add(left.proof.public_inputs[14], right.proof.public_inputs[14]);
        builder.range_check(total, 62);
        builder.range_check(count, 32);
        builder.register_public_input(total);
        builder.register_public_input(count);
        let commitment = builder.hash_n_to_hash_no_pad::<C::Hasher>([
            &left.proof.public_inputs[15..19],
            &right.proof.public_inputs[15..19],
            &[left.proof.public_inputs[14], right.proof.public_inputs[14]],
        ].concat());
        builder.register_public_inputs(&commitment.elements);
        builder.add_psy_type_a_common_gates(None);
        pad_circuit_degree(&mut builder, 13);
        let data = builder.build::<C>();
        assert_eq!(&data.common, child_common, "reward leaf and aggregate common data must match");
        Self { data, left, right }
    }

    fn add_child(builder: &mut CircuitBuilder<C::F, D>, common: &plonky2::plonk::circuit_data::CommonCircuitData<C::F, D>, cap_height: usize) -> ChildTarget<D> {
        let proof = builder.add_virtual_proof_with_pis(common);
        let verifier = builder.add_virtual_verifier_data(cap_height);
        builder.verify_proof::<C>(&proof, &verifier, common);
        let fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier);
        let inclusion = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(builder, USER_REWARD_CIRCUIT_WHITELIST_HEIGHT);
        builder.connect_hashes(fingerprint, inclusion.value);
        ChildTarget { proof, verifier, inclusion }
    }

    pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> { &self.data }

    pub fn prove(
        &self,
        left: (&ProofWithPublicInputs<C::F, C, D>, &VerifierOnlyCircuitData<C, D>, &MerkleProofCore<QHashOut<C::F>>),
        right: (&ProofWithPublicInputs<C::F, C, D>, &VerifierOnlyCircuitData<C, D>, &MerkleProofCore<QHashOut<C::F>>),
    ) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(left.2.root == right.2.root, "child circuit whitelist roots differ");
        let mut witness = PartialWitness::new();
        Self::set_child(&mut witness, &self.left, left)?;
        Self::set_child(&mut witness, &self.right, right)?;
        Ok(self.data.prove(witness)?)
    }

    fn set_child(
        witness: &mut PartialWitness<C::F>, target: &ChildTarget<D>,
        value: (&ProofWithPublicInputs<C::F, C, D>, &VerifierOnlyCircuitData<C, D>, &MerkleProofCore<QHashOut<C::F>>),
    ) -> Result<()> {
        ensure!(value.0.public_inputs.len() == USER_REWARD_FINAL_PUBLIC_INPUTS, "child public-input shape mismatch");
        witness.set_proof_with_pis_target(&target.proof, value.0)?;
        witness.set_verifier_data_target(&target.verifier, value.1)?;
        target.inclusion.set_witness_core_proof_q(witness, value.2)?;
        Ok(())
    }
}
