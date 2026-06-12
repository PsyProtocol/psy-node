use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{common::witnesses::qrecursion::header::AttestProofInTreeInput, hash::merkle::core::MerkleProofCore};

use crate::{builder::hash::core::CircuitBuilderHashCore, hash::merkle::gadgets::merkle_proof::MerkleProofGadget};

#[derive(Debug, Clone)]
pub struct AttestProofInTreeGadget {
    pub fingerprint: HashOutTarget,
    pub public_inputs_hash: HashOutTarget,
    pub inclusion_proof: MerkleProofGadget,

    // start computed targets
    pub attested_proof_tree_root: HashOutTarget,
}

impl AttestProofInTreeGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        q_recursion_tree_height: usize,
    ) -> Self {
        let fingerprint = builder.add_virtual_hash();
        let public_inputs_hash = builder.add_virtual_hash();
        let inclusion_proof = MerkleProofGadget::add_virtual_to::<H, F, D>(builder, q_recursion_tree_height);

        let expected_proof_leaf_value = builder.hash_two_to_one::<H>(fingerprint, public_inputs_hash);
        builder.connect_hashes(inclusion_proof.value, expected_proof_leaf_value);

        let attested_proof_tree_root = inclusion_proof.root;

        Self {
            fingerprint,
            public_inputs_hash,
            inclusion_proof,
            attested_proof_tree_root,
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(&self, witness: &mut W, input: &AttestProofInTreeInput<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.fingerprint, input.fingerprint.0)?;
        witness.set_hash_target(self.public_inputs_hash, input.public_inputs_hash.0)?;
        self.inclusion_proof.set_witness_generic(
            witness,
            F::from_noncanonical_u64(input.inclusion_proof.index),
            input.inclusion_proof.value,
            &input.inclusion_proof.siblings,
        )
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
