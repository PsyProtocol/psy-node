//! Fixed recursion over finalized per-user batch proofs.

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

use super::{claim_rewards_l1_batch_user::RewardBatchUserCircuit, claim_rewards_l1_final::REWARD_BATCH_FINAL_PUBLIC_INPUTS};

pub const REWARD_BATCH_CIRCUIT_WHITELIST_HEIGHT: usize = 2;

/// Protocol-fixed per-user batch circuit set: the user-closing circuit plus
/// the recursive pair aggregator, plus the verifier-fingerprint whitelist that
/// closes them in `RewardBatchFinalCircuit`.
pub struct RewardBatchCircuitSet<C: GenericConfig<D>, const D: usize>
where C::Hasher: AlgebraicHasher<C::F> {
    pub user: RewardBatchUserCircuit<C, D>,
    pub tree: RewardBatchTreeCircuit<C, D>,
    pub user_inclusion: MerkleProofCore<QHashOut<C::F>>,
    pub tree_inclusion: MerkleProofCore<QHashOut<C::F>>,
    pub whitelist_root: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> RewardBatchCircuitSet<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F>
        + psy_crypto::hash::traits::hasher::MerkleZeroHasher<HashOut<C::F>>
        + psy_crypto::hash::traits::hasher::MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>>
        + psy_crypto::hash::traits::hasher::MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub fn new(job_tree_data: &CircuitData<C::F, C, D>, user_final_data: &CircuitData<C::F, C, D>, job_whitelist_root: QHashOut<C::F>) -> Self {
        let user = RewardBatchUserCircuit::new(
            &job_tree_data.common,
            job_tree_data.verifier_only.constants_sigmas_cap.height(),
            user_final_data,
            job_whitelist_root,
        );
        let tree = RewardBatchTreeCircuit::new(
            &user.circuit_data().common,
            user.circuit_data().verifier_only.constants_sigmas_cap.height(),
        );
        let mut whitelist = psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(
            REWARD_BATCH_CIRCUIT_WHITELIST_HEIGHT as u8,
        );
        whitelist.set_leaf(0, QHashOut(psy_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic(&user.circuit_data().verifier_only)));
        whitelist.set_leaf(1, QHashOut(psy_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic(&tree.circuit_data().verifier_only)));
        let whitelist_root = whitelist.get_root();
        let user_inclusion = whitelist.get_leaf(0);
        let tree_inclusion = whitelist.get_leaf(1);
        Self { user, tree, user_inclusion, tree_inclusion, whitelist_root }
    }
}

struct ChildTarget<const D: usize> {
    proof: ProofWithPublicInputsTarget<D>,
    verifier: VerifierCircuitTarget,
    inclusion: MerkleProofGadget,
}

pub struct RewardBatchTreeCircuit<C: GenericConfig<D>, const D: usize>
where C::Hasher: AlgebraicHasher<C::F> {
    data: CircuitData<C::F, C, D>,
    left: ChildTarget<D>,
    right: ChildTarget<D>,
}

impl<C: GenericConfig<D>, const D: usize> RewardBatchTreeCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(child_common: &plonky2::plonk::circuit_data::CommonCircuitData<C::F, D>, cap_height: usize) -> Self {
        assert_eq!(child_common.num_public_inputs, REWARD_BATCH_FINAL_PUBLIC_INPUTS + 4);
        let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let left = Self::add_child(&mut builder, child_common, cap_height);
        let right = Self::add_child(&mut builder, child_common, cap_height);
        builder.connect_hashes(left.inclusion.root, right.inclusion.root);
        builder.connect_hashes(left.inclusion.root, HashOutTarget { elements: left.proof.public_inputs[21..25].try_into().unwrap() });
        builder.connect_hashes(right.inclusion.root, HashOutTarget { elements: right.proof.public_inputs[21..25].try_into().unwrap() });
        // Common target anchor.
        for i in 0..4 { builder.connect(left.proof.public_inputs[i], right.proof.public_inputs[i]); }
        // Spent updates are a linear transition even though proofs form a tree.
        for i in 0..4 { builder.connect(left.proof.public_inputs[8+i], right.proof.public_inputs[4+i]); }
        builder.register_public_inputs(&left.proof.public_inputs[0..8]);
        builder.register_public_inputs(&right.proof.public_inputs[8..12]);
        let rewards = builder.hash_two_to_one::<C::Hasher>(
            plonky2::hash::hash_types::HashOutTarget { elements: left.proof.public_inputs[12..16].try_into().unwrap() },
            plonky2::hash::hash_types::HashOutTarget { elements: right.proof.public_inputs[12..16].try_into().unwrap() },
        );
        builder.register_public_inputs(&rewards.elements);
        let jobs = builder.hash_two_to_one::<C::Hasher>(
            plonky2::hash::hash_types::HashOutTarget { elements: left.proof.public_inputs[16..20].try_into().unwrap() },
            plonky2::hash::hash_types::HashOutTarget { elements: right.proof.public_inputs[16..20].try_into().unwrap() },
        );
        builder.register_public_inputs(&jobs.elements);
        let total = builder.add(left.proof.public_inputs[20], right.proof.public_inputs[20]);
        builder.range_check(total, 62);
        builder.register_public_input(total);
        builder.register_public_inputs(&left.inclusion.root.elements);
        builder.add_psy_type_a_common_gates(None);
        pad_circuit_degree(&mut builder, 12);
        let data = builder.build::<C>();
        assert_eq!(data.common.degree_bits(), 13, "batch user tree exceeds degree 13");
        assert_eq!(&data.common, child_common, "batch user leaf and aggregate common data must match");
        Self { data, left, right }
    }

    fn add_child(builder: &mut CircuitBuilder<C::F, D>, common: &plonky2::plonk::circuit_data::CommonCircuitData<C::F, D>, cap_height: usize) -> ChildTarget<D> {
        let proof = builder.add_virtual_proof_with_pis(common);
        let verifier = builder.add_virtual_verifier_data(cap_height);
        builder.verify_proof::<C>(&proof, &verifier, common);
        let fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&verifier);
        let inclusion = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(builder, REWARD_BATCH_CIRCUIT_WHITELIST_HEIGHT);
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
        ensure!(value.0.public_inputs.len() == REWARD_BATCH_FINAL_PUBLIC_INPUTS + 4, "child public-input shape mismatch");
        witness.set_proof_with_pis_target(&target.proof, value.0)?;
        witness.set_verifier_data_target(&target.verifier, value.1)?;
        target.inclusion.set_witness_core_proof_q(witness, value.2)?;
        Ok(())
    }
}
