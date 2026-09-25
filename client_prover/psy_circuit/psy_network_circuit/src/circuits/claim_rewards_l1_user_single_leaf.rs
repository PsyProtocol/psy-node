use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::builder::pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates};

use super::{
    claim_rewards_l1_final::USER_REWARD_FINAL_PUBLIC_INPUTS,
    claim_rewards_l1_user_header::UserRewardHeaderTarget,
};

/// Converts one direct user leaf to the common aggregate root shape.
pub struct UserRewardSingleLeafCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    data: CircuitData<C::F, C, D>,
    leaf: ProofWithPublicInputsTarget<D>,
    whitelist_root: HashOutTarget,
}

impl<C: GenericConfig<D>, const D: usize> UserRewardSingleLeafCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(leaf_data: &CircuitData<C::F, C, D>) -> Self {
        assert_eq!(leaf_data.common.num_public_inputs, USER_REWARD_FINAL_PUBLIC_INPUTS);
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let leaf = builder.add_virtual_proof_with_pis(&leaf_data.common);
        let verifier = builder.constant_verifier_data(&leaf_data.verifier_only);
        builder.verify_proof::<C>(&leaf, &verifier, &leaf_data.common);
        let header = UserRewardHeaderTarget { fields: leaf.public_inputs[..19].try_into().unwrap() };
        let hash = header.hash::<C::Hasher, C::F, D>(&mut builder);
        builder.register_public_inputs(&hash.elements);
        let whitelist_root = builder.add_virtual_hash();
        builder.register_public_inputs(&whitelist_root.elements);
        builder.add_psy_type_a_common_gates(None);
        pad_circuit_degree(&mut builder, 12);
        Self { data: builder.build::<C>(), leaf, whitelist_root }
    }

    pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> { &self.data }

    pub fn prove(
        &self,
        leaf: &ProofWithPublicInputs<C::F, C, D>,
        whitelist_root: QHashOut<C::F>,
    ) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(leaf.public_inputs.len() == USER_REWARD_FINAL_PUBLIC_INPUTS, "leaf PI shape mismatch");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.leaf, leaf)?;
        witness.set_hash_target(self.whitelist_root, whitelist_root.0)?;
        Ok(self.data.prove(witness)?)
    }
}
