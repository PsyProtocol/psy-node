use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{
    common::witnesses::qrecursion::header::AttestTreeAwareProofInTreeInput,
    hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher},
};

use crate::{
    builder::hash::core::CircuitBuilderHashCore,
    hash::merkle::gadgets::{historical_root_merkle_proof::HistoricalRootMerkleProofGadget, merkle_proof::MerkleProofGadget},
};

pub fn compute_tree_aware_proof_public_inputs<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    proof_tree_root: HashOutTarget,
    inner_public_inputs_hash: HashOutTarget,
) -> HashOutTarget {
    builder.hash_two_to_one::<H>(proof_tree_root, inner_public_inputs_hash)
}

#[derive(Debug, Clone)]
pub struct AttestTreeAwareProofInTreeGadget {
    pub fingerprint: HashOutTarget,
    pub inner_public_inputs_hash: HashOutTarget,
    pub historical_root_proof: HistoricalRootMerkleProofGadget,
    pub inclusion_proof: MerkleProofGadget,

    // start computed targets
    pub public_inputs_hash: HashOutTarget,
    pub attested_proof_tree_root: HashOutTarget,
}

impl AttestTreeAwareProofInTreeGadget {
    pub fn add_virtual_to<H: MerkleZeroHasher<HashOut<F>> + AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        q_recursion_tree_height: usize,
    ) -> Self {
        let fingerprint = builder.add_virtual_hash();
        let inner_public_inputs_hash = builder.add_virtual_hash();

        let inclusion_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, q_recursion_tree_height);
        let historical_root_proof = HistoricalRootMerkleProofGadget::add_virtual_to_zero_gte::<H, F, D>(builder, q_recursion_tree_height);

        tracing::debug!(
            "🌳 AttestTreeAwareProof - roots created: inclusion_root={:?}, current_root={:?}, historical_root={:?}",
            inclusion_proof.root,
            historical_root_proof.current_root,
            historical_root_proof.historical_root
        );

        // ensure that the inclusion_proof and historical_root_merkle_proof are from the
        // same tree
        builder.connect_hashes(inclusion_proof.root, historical_root_proof.current_root);

        let public_inputs_hash =
            compute_tree_aware_proof_public_inputs::<H, F, D>(builder, historical_root_proof.historical_root, inner_public_inputs_hash);
        let expected_proof_leaf_value = builder.hash_two_to_one::<H>(fingerprint, public_inputs_hash);

        tracing::debug!(
            "🌳 AttestTreeAwareProof - computed values: public_inputs_hash={:?}, expected_leaf_value={:?}, inclusion_value={:?}",
            public_inputs_hash,
            expected_proof_leaf_value,
            inclusion_proof.value
        );
        tracing::debug!("🌳 AttestTreeAwareProof - inner_public_inputs={:?}", inner_public_inputs_hash);

        builder.connect_hashes(inclusion_proof.value, expected_proof_leaf_value);

        let attested_proof_tree_root = inclusion_proof.root;

        Self {
            fingerprint,
            inner_public_inputs_hash,
            historical_root_proof,
            inclusion_proof,

            public_inputs_hash,
            attested_proof_tree_root,
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(&self, witness: &mut W, input: &AttestTreeAwareProofInTreeInput<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.fingerprint, input.fingerprint.0)?;
        witness.set_hash_target(self.inner_public_inputs_hash, input.inner_public_inputs_hash.0)?;
        self.inclusion_proof.set_witness_generic(
            witness,
            F::from_noncanonical_u64(input.inclusion_proof.index),
            input.inclusion_proof.value,
            &input.inclusion_proof.siblings,
        )?;
        self.historical_root_proof.set_witness_proof_core(witness, &input.historical_root_proof)
    }
    pub fn set_witness_values<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        fingerprint: QHashOut<F>,
        public_inputs_hash: QHashOut<F>,
        inclusion_proof: MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.fingerprint, fingerprint.0)?;
        witness.set_hash_target(self.public_inputs_hash, public_inputs_hash.0)?;
        self.inclusion_proof.set_witness_generic(
            witness,
            F::from_noncanonical_u64(inclusion_proof.index),
            inclusion_proof.value,
            &inclusion_proof.siblings,
        )
    }
}
