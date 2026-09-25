//! Fixed recursion over one user's batch job-processing leaves.

use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
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
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
        verify::CircuitBuilderVerifyProofHelpers,
    },
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher};

use super::claim_rewards_l1_batch_job::{BATCH_JOB_PUBLIC_INPUTS, RewardBatchJobCircuit};
use psy_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic;

pub const BATCH_JOB_CIRCUIT_WHITELIST_HEIGHT: usize = 2;

/// Protocol-fixed batch job circuit set: one leaf plus the recursive pair
/// aggregator, plus the verifier-fingerprint whitelist that closes them.
pub struct RewardBatchJobCircuitSet<C: GenericConfig<D>, const D: usize>
where C::Hasher: AlgebraicHasher<C::F> {
    pub leaf: RewardBatchJobCircuit<C, D>,
    pub tree: RewardBatchJobTreeCircuit<C, D>,
    pub leaf_inclusion: MerkleProofCore<QHashOut<C::F>>,
    pub tree_inclusion: MerkleProofCore<QHashOut<C::F>>,
    pub whitelist_root: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> RewardBatchJobCircuitSet<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F>
        + psy_crypto::hash::traits::hasher::FieldQHasher<C::F>
        + MerkleZeroHasher<HashOut<C::F>>
        + psy_crypto::hash::traits::hasher::MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>>
        + psy_crypto::hash::traits::hasher::MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub fn new(user_final_data: &CircuitData<C::F, C, D>) -> Self {
        let leaf = RewardBatchJobCircuit::new(user_final_data);
        let tree = RewardBatchJobTreeCircuit::new(
            &leaf.circuit_data().common,
            leaf.circuit_data().verifier_only.constants_sigmas_cap.height(),
        );
        let mut whitelist = psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(
            BATCH_JOB_CIRCUIT_WHITELIST_HEIGHT as u8,
        );
        whitelist.set_leaf(0, QHashOut(get_circuit_fingerprint_generic(&leaf.circuit_data().verifier_only)));
        whitelist.set_leaf(1, QHashOut(get_circuit_fingerprint_generic(&tree.circuit_data().verifier_only)));
        let whitelist_root = whitelist.get_root();
        let leaf_inclusion = whitelist.get_leaf(0);
        let tree_inclusion = whitelist.get_leaf(1);
        Self { leaf, tree, leaf_inclusion, tree_inclusion, whitelist_root }
    }
}

struct ChildTarget<const D: usize> {
    proof: ProofWithPublicInputsTarget<D>,
    verifier: VerifierCircuitTarget,
    inclusion: MerkleProofGadget,
}

pub struct RewardBatchJobTreeCircuit<C: GenericConfig<D>, const D: usize>
where C::Hasher: AlgebraicHasher<C::F> {
    data: CircuitData<C::F, C, D>,
    left: ChildTarget<D>,
    right: ChildTarget<D>,
}

impl<C: GenericConfig<D>, const D: usize> RewardBatchJobTreeCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(child_common: &plonky2::plonk::circuit_data::CommonCircuitData<C::F, D>, cap_height: usize) -> Self {
        assert_eq!(child_common.num_public_inputs, BATCH_JOB_PUBLIC_INPUTS);
        let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let left = Self::add_child(&mut builder, child_common, cap_height);
        let right = Self::add_child(&mut builder, child_common, cap_height);
        builder.connect_hashes(left.inclusion.root, right.inclusion.root);
        builder.connect_hashes(left.inclusion.root, HashOutTarget { elements: left.proof.public_inputs[19..23].try_into().unwrap() });
        builder.connect_hashes(right.inclusion.root, HashOutTarget { elements: right.proof.public_inputs[19..23].try_into().unwrap() });
        // Common target anchor.
        for i in 0..4 { builder.connect(left.proof.public_inputs[i], right.proof.public_inputs[i]); }
        // Spent updates are a linear transition even though proofs form a tree.
        for i in 0..4 { builder.connect(left.proof.public_inputs[8+i], right.proof.public_inputs[4+i]); }
        // Every job in the subtree belongs to the same user.
        builder.connect(left.proof.public_inputs[12], right.proof.public_inputs[12]);
        builder.register_public_inputs(&left.proof.public_inputs[0..8]);
        builder.register_public_inputs(&right.proof.public_inputs[8..12]);
        builder.register_public_input(left.proof.public_inputs[12]);
        let total = builder.add(left.proof.public_inputs[13], right.proof.public_inputs[13]);
        let count = builder.add(left.proof.public_inputs[14], right.proof.public_inputs[14]);
        builder.range_check(total, 62);
        builder.range_check(count, 32);
        builder.register_public_input(total);
        builder.register_public_input(count);
        let left_commitment = plonky2::hash::hash_types::HashOutTarget {
            elements: left.proof.public_inputs[15..19].try_into().unwrap(),
        };
        let right_commitment = plonky2::hash::hash_types::HashOutTarget {
            elements: right.proof.public_inputs[15..19].try_into().unwrap(),
        };
        let pair = builder.hash_two_to_one::<C::Hasher>(left_commitment, right_commitment);
        let zero = builder.zero();
        let counts = plonky2::hash::hash_types::HashOutTarget {
            elements: [left.proof.public_inputs[14], right.proof.public_inputs[14], zero, zero],
        };
        let commitment = builder.hash_two_to_one::<C::Hasher>(pair, counts);
        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&left.inclusion.root.elements);
        builder.add_psy_type_a_common_gates(None);
        pad_circuit_degree(&mut builder, 12);
        let data = builder.build::<C>();
        assert_eq!(data.common.degree_bits(), 13, "batch job tree exceeds degree 13");
        assert_eq!(&data.common, child_common, "batch job leaf and aggregate common data must match");
        Self { data, left, right }
    }

    fn add_child(builder: &mut CircuitBuilder<C::F, D>, common: &plonky2::plonk::circuit_data::CommonCircuitData<C::F, D>, cap_height: usize) -> ChildTarget<D> {
        let proof = builder.add_virtual_proof_with_pis(common);
        let verifier = builder.add_virtual_verifier_data(cap_height);
        builder.verify_proof::<C>(&proof, &verifier, common);
        let fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier);
        let inclusion = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(builder, BATCH_JOB_CIRCUIT_WHITELIST_HEIGHT);
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
        ensure!(value.0.public_inputs.len() == BATCH_JOB_PUBLIC_INPUTS, "child public-input shape mismatch");
        witness.set_proof_with_pis_target(&target.proof, value.0)?;
        witness.set_verifier_data_target(&target.verifier, value.1)?;
        target.inclusion.set_witness_core_proof_q(witness, value.2)?;
        Ok(())
    }
}
