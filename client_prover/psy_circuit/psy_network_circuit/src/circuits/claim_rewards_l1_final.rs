//! Fixed final wrappers for the user and batch reward recursion trees.
//!
//! These circuits deliberately accept one fixed root verifier.  The variable
//! number of leaves is handled below them by the whitelisted recursion circuit
//! set; changing the root verifier creates a different protocol version.

use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::{
    builder::verify::CircuitBuilderVerifyProofHelpers,
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher};

use super::{
    claim_rewards_l1_user_header::{UserRewardHeader, UserRewardHeaderTarget},
    claim_rewards_l1_user_two_aggregate::USER_REWARD_AGG_WHITELIST_HEIGHT,
};

/// anchor[4], user_id, recipient[8], total_amount, job_count,
/// jobs_commitment[4].
pub const USER_REWARD_FINAL_PUBLIC_INPUTS: usize = 19;

/// anchor[4], old_spent_root[4], new_spent_root[4], rewards_root[4],
/// jobs_root[4], batch_total. Closing circuits additionally carry
/// batch_whitelist_root[4], so their public-input count is
/// REWARD_BATCH_FINAL_PUBLIC_INPUTS + 4.
pub const REWARD_BATCH_FINAL_PUBLIC_INPUTS: usize = 21;

pub struct UserRewardFinalCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    data: CircuitData<C::F, C, D>,
    root_proof: ProofWithPublicInputsTarget<D>,
    root_verifier: VerifierCircuitTarget,
    root_inclusion: MerkleProofGadget,
    header: UserRewardHeaderTarget,
}

impl<C: GenericConfig<D>, const D: usize> UserRewardFinalCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        root_common: &CommonCircuitData<C::F, D>,
        root_cap_height: usize,
        whitelist_root: QHashOut<C::F>,
    ) -> Self {
        assert_eq!(root_common.num_public_inputs, 8);
        let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let root_proof = builder.add_virtual_proof_with_pis(root_common);
        let root_verifier = builder.add_virtual_verifier_data(root_cap_height);
        builder.verify_proof::<C>(&root_proof, &root_verifier, root_common);

        let fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&root_verifier);
        let root_inclusion = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            USER_REWARD_AGG_WHITELIST_HEIGHT,
        );
        builder.connect_hashes(fingerprint, root_inclusion.value);
        let expected_root = builder.constant_hash(whitelist_root.0);
        builder.connect_hashes(root_inclusion.root, expected_root);
        builder.connect_hashes(
            HashOutTarget { elements: root_proof.public_inputs[4..8].try_into().unwrap() },
            expected_root,
        );

        let header = UserRewardHeaderTarget::add_virtual(&mut builder);
        let header_hash = header.hash::<C::Hasher, C::F, D>(&mut builder);
        builder.connect_hashes(
            header_hash,
            HashOutTarget { elements: root_proof.public_inputs[..4].try_into().unwrap() },
        );
        builder.register_public_inputs(&header.fields);
        let data = builder.build::<C>();
        assert_eq!(data.common.num_public_inputs, USER_REWARD_FINAL_PUBLIC_INPUTS);
        Self { data, root_proof, root_verifier, root_inclusion, header }
    }

    pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> { &self.data }

    pub fn prove(
        &self,
        root_proof: &ProofWithPublicInputs<C::F, C, D>,
        root_verifier: &VerifierOnlyCircuitData<C, D>,
        root_inclusion: &MerkleProofCore<QHashOut<C::F>>,
        header: &UserRewardHeader<C::F>,
    ) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(root_proof.public_inputs.len() == 8, "user aggregate root PI shape mismatch");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.root_proof, root_proof)?;
        witness.set_verifier_data_target(&self.root_verifier, root_verifier)?;
        self.root_inclusion.set_witness_core_proof_q(&mut witness, root_inclusion)?;
        self.header.set_witness(&mut witness, header)?;
        Ok(self.data.prove(witness)?)
    }
}

/// Fixed final wrapper over the batch reward recursion tree. The root
/// verifier's fingerprint must be present in the protocol-fixed batch circuit
/// whitelist; a different whitelist root creates a different protocol version.
pub struct RewardBatchFinalCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    data: CircuitData<C::F, C, D>,
    root_proof: ProofWithPublicInputsTarget<D>,
    root_verifier: VerifierCircuitTarget,
    root_inclusion: MerkleProofGadget,
    whitelist_root: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> RewardBatchFinalCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        root_common: &CommonCircuitData<C::F, D>,
        root_cap_height: usize,
        whitelist_root: QHashOut<C::F>,
    ) -> Self {
        assert_eq!(root_common.num_public_inputs, REWARD_BATCH_FINAL_PUBLIC_INPUTS + 4);
        let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let root_proof = builder.add_virtual_proof_with_pis(root_common);
        let root_verifier = builder.add_virtual_verifier_data(root_cap_height);
        builder.verify_proof::<C>(&root_proof, &root_verifier, root_common);

        let fingerprint = builder.get_circuit_fingerprint::<C::Hasher>(&root_verifier);
        let root_inclusion = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            super::claim_rewards_l1_batch_tree::REWARD_BATCH_CIRCUIT_WHITELIST_HEIGHT,
        );
        builder.connect_hashes(fingerprint, root_inclusion.value);
        let expected_root = builder.constant_hash(whitelist_root.0);
        builder.connect_hashes(root_inclusion.root, expected_root);
        builder.connect_hashes(HashOutTarget { elements: root_proof.public_inputs[21..25].try_into().unwrap() }, expected_root);

        builder.register_public_inputs(&root_proof.public_inputs[..REWARD_BATCH_FINAL_PUBLIC_INPUTS]);
        let data = builder.build::<C>();
        assert_eq!(data.common.num_public_inputs, REWARD_BATCH_FINAL_PUBLIC_INPUTS);
        Self { data, root_proof, root_verifier, root_inclusion, whitelist_root }
    }

    pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> { &self.data }

    pub fn prove(
        &self,
        root_proof: &ProofWithPublicInputs<C::F, C, D>,
        root_verifier: &VerifierOnlyCircuitData<C, D>,
        root_inclusion: &MerkleProofCore<QHashOut<C::F>>,
    ) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(root_proof.public_inputs.len() == REWARD_BATCH_FINAL_PUBLIC_INPUTS + 4, "batch root PI shape mismatch");
        ensure!(root_inclusion.root == self.whitelist_root, "batch root verifier not in the fixed whitelist");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.root_proof, root_proof)?;
        witness.set_verifier_data_target(&self.root_verifier, root_verifier)?;
        self.root_inclusion.set_witness_core_proof_q(&mut witness, root_inclusion)?;
        Ok(self.data.prove(witness)?)
    }
}
