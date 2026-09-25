//! Re-anchor one checkpoint leaf under a selected checkpoint-tree root.

use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::hasher::FieldQHasher};

/// Public inputs: target_anchor[4], checkpoint_id, checkpoint_leaf_hash[4].
pub const CHECKPOINT_UPGRADE_PUBLIC_INPUTS: usize = 9;

pub struct CheckpointUpgradeCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    data: CircuitData<C::F, C, D>,
    membership: MerkleProofGadget,
}

impl<C: GenericConfig<D>, const D: usize> CheckpointUpgradeCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + FieldQHasher<C::F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let membership = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder, CHECKPOINT_TREE_HEIGHT as usize);
        builder.register_public_inputs(&membership.root.elements);
        builder.register_public_input(membership.index);
        builder.register_public_inputs(&membership.value.elements);
        let data = builder.build::<C>();
        Self { data, membership }
    }

    pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> {
        &self.data
    }

    pub fn prove(&self, membership: &MerkleProofCore<QHashOut<C::F>>) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(membership.siblings.len() == CHECKPOINT_TREE_HEIGHT as usize, "checkpoint path height mismatch");
        ensure!(membership.index < (1u64 << CHECKPOINT_TREE_HEIGHT), "checkpoint ID out of range");
        ensure!(membership.verify::<C::Hasher>(), "invalid checkpoint membership proof");
        let mut witness = PartialWitness::new();
        self.membership.set_witness_core_proof_q(&mut witness, membership)?;
        Ok(self.data.prove(witness)?)
    }
}
