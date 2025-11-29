use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::MerkleZeroHasher,
    },
    pgoldilocks::QHashOut,
};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_data::protocol::checkpoint_transition_hash::{CheckpointStateHashTransition, CheckpointStateTransitionPublicInputs};
use psy_plonky2_basic_helpers::builder::hash::core::CircuitBuilderHashCore;
use psy_plonky2_common_circuits::hash::merkle::gadgets::{delta_merkle_proof::DeltaMerkleProofGadget, merkle_proof::MerkleProofGadget};

#[derive(Debug, Clone, Copy)]
pub struct CheckpointStateTransitionPublicInputsGadget {
    pub checkpoint_transition: CheckpointStateHashTransitionGadget,
    pub genesis_checkpoint_state_transition_hash: HashOutTarget,
    pub checkpoint_state_transition_circuit_fingerprint: HashOutTarget,
}

impl CheckpointStateTransitionPublicInputsGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let checkpoint_transition = CheckpointStateHashTransitionGadget::add_virtual_to::<H, F, D>(builder);

        let genesis_checkpoint_state_transition_hash = builder.add_virtual_hash();
        let checkpoint_state_transition_circuit_fingerprint = builder.add_virtual_hash();
        Self {
            checkpoint_transition,
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        }
    }
    pub fn from_constant_config<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        config: &CheckpointStateTransitionPublicInputs<QHashOut<F>>,
    ) -> Self {
        let checkpoint_transition = CheckpointStateHashTransitionGadget {
            old_checkpoint_tree_root: builder.constant_qhash(config.checkpoint_transition.old_checkpoint_tree_root),
            new_checkpoint_tree_root: builder.constant_qhash(config.checkpoint_transition.new_checkpoint_tree_root),
            old_checkpoint_leaf_hash: builder.constant_qhash(config.checkpoint_transition.old_checkpoint_leaf_hash),
            new_checkpoint_leaf_hash: builder.constant_qhash(config.checkpoint_transition.new_checkpoint_leaf_hash),
        };
        let genesis_checkpoint_state_transition_hash = builder.constant_qhash(config.genesis_checkpoint_state_transition_hash);
        let checkpoint_state_transition_circuit_fingerprint = builder.constant_qhash(config.checkpoint_state_transition_circuit_fingerprint);
        Self {
            checkpoint_transition,
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        }
    }
    pub fn get_public_inputs_hash_no_rewards_tag<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.checkpoint_transition.get_public_inputs_hash_no_rewards_tag::<H, F, D>(
            builder,
            self.genesis_checkpoint_state_transition_hash,
            self.checkpoint_state_transition_circuit_fingerprint,
        )
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        old_checkpoint_tree_root: QHashOut<F>,
        old_checkpoint_leaf_hash: QHashOut<F>,
        new_checkpoint_tree_root: QHashOut<F>,
        new_checkpoint_leaf_hash: QHashOut<F>,
        genesis_checkpoint_state_transition_hash: QHashOut<F>,
    ) -> anyhow::Result<()> {
        self.checkpoint_transition.set_witness_params(
            witness,
            old_checkpoint_tree_root,
            new_checkpoint_tree_root,
            old_checkpoint_leaf_hash,
            new_checkpoint_leaf_hash,
        )?;
        witness.set_hash_target(self.genesis_checkpoint_state_transition_hash, genesis_checkpoint_state_transition_hash.0)?;
        Ok(())
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        input: &CheckpointStateTransitionPublicInputs<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.set_witness_params(
            witness,
            input.checkpoint_transition.old_checkpoint_tree_root,
            input.checkpoint_transition.old_checkpoint_leaf_hash,
            input.checkpoint_transition.new_checkpoint_tree_root,
            input.checkpoint_transition.new_checkpoint_leaf_hash,
            input.genesis_checkpoint_state_transition_hash,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CheckpointStateHashTransitionGadget {
    pub old_checkpoint_tree_root: HashOutTarget,
    pub new_checkpoint_tree_root: HashOutTarget,

    pub old_checkpoint_leaf_hash: HashOutTarget,
    pub new_checkpoint_leaf_hash: HashOutTarget,
}

impl CheckpointStateHashTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let old_checkpoint_tree_root = builder.add_virtual_hash();
        let new_checkpoint_tree_root = builder.add_virtual_hash();
        let old_checkpoint_leaf_hash = builder.add_virtual_hash();
        let new_checkpoint_leaf_hash = builder.add_virtual_hash();

        Self {
            old_checkpoint_tree_root,
            new_checkpoint_tree_root,
            old_checkpoint_leaf_hash,
            new_checkpoint_leaf_hash,
        }
    }
    pub fn get_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let checkpoint_tree_root_transition = builder.hash_two_to_one::<H>(self.old_checkpoint_tree_root, self.new_checkpoint_tree_root);
        let leaf_transition_hash = builder.hash_two_to_one::<H>(self.old_checkpoint_leaf_hash, self.new_checkpoint_leaf_hash);
        builder.hash_two_to_one::<H>(checkpoint_tree_root_transition, leaf_transition_hash)
    }
    pub fn get_public_inputs_hash_no_rewards_tag<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        genesis_checkpoint_state_transition_hash: HashOutTarget,
        checkpoint_state_transition_circuit_fingerprint: HashOutTarget,
    ) -> HashOutTarget {
        let checkpoint_transition_hash = self.get_hash::<H, F, D>(builder);
        let config_hash = builder.hash_two_to_one::<H>(genesis_checkpoint_state_transition_hash, checkpoint_state_transition_circuit_fingerprint);
        builder.hash_two_to_one::<H>(checkpoint_transition_hash, config_hash)
        
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        old_checkpoint_tree_root: QHashOut<F>,
        new_checkpoint_tree_root: QHashOut<F>,
        old_checkpoint_leaf_hash: QHashOut<F>,
        new_checkpoint_leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.old_checkpoint_tree_root, old_checkpoint_tree_root.0)?;
        witness.set_hash_target(self.new_checkpoint_tree_root, new_checkpoint_tree_root.0)?;
        witness.set_hash_target(self.old_checkpoint_leaf_hash, old_checkpoint_leaf_hash.0)?;
        witness.set_hash_target(self.new_checkpoint_leaf_hash, new_checkpoint_leaf_hash.0)?;
        Ok(())
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, input: &CheckpointStateHashTransition<QHashOut<F>>) -> anyhow::Result<()> {
        self.set_witness_params(
            witness,
            input.old_checkpoint_tree_root,
            input.new_checkpoint_tree_root,
            input.old_checkpoint_leaf_hash,
            input.new_checkpoint_leaf_hash,
        )
    }
}

#[derive(Debug, Clone)]
pub struct CheckpointStateTransitionCoreGadget {
    pub append_checkpoint_tree_proof: DeltaMerkleProofGadget,
    pub previous_checkpoint_proof: MerkleProofGadget,

    // computed
    pub checkpoint_hash_transition: CheckpointStateHashTransitionGadget,
}

impl CheckpointStateTransitionCoreGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        checkpoint_tree_height: usize,
    ) -> Self {
        let append_checkpoint_tree_proof = DeltaMerkleProofGadget::add_virtual_to_append_only::<H, F, D>(builder, checkpoint_tree_height);
        let previous_checkpoint_proof = MerkleProofGadget::add_virtual_to_append_only::<H, F, D>(builder, checkpoint_tree_height);

        // ensure we are appending to an empty leaf
        let zero_hash = builder.constant_qhash(QHashOut::ZERO);
        builder.connect_hashes(append_checkpoint_tree_proof.old_value, zero_hash);

        // ensure that old root == previous checkpoint root
        builder.connect_hashes(append_checkpoint_tree_proof.old_root, previous_checkpoint_proof.root);

        // sanity check: previous.index + 1 == current.index
        let one = builder.one();
        let previous_index_plus_one = builder.add(previous_checkpoint_proof.index, one);
        builder.connect(append_checkpoint_tree_proof.index, previous_index_plus_one);

        let old_checkpoint_tree_root = previous_checkpoint_proof.root;
        let new_checkpoint_tree_root = append_checkpoint_tree_proof.new_root;
        let old_checkpoint_leaf_hash = previous_checkpoint_proof.value;
        let new_checkpoint_leaf_hash = append_checkpoint_tree_proof.new_value;
        let checkpoint_hash_transition = CheckpointStateHashTransitionGadget {
            old_checkpoint_tree_root,
            new_checkpoint_tree_root,
            old_checkpoint_leaf_hash,
            new_checkpoint_leaf_hash,
        };

        Self {
            append_checkpoint_tree_proof,
            previous_checkpoint_proof,
            checkpoint_hash_transition,
        }
    }

    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        append_checkpoint_tree_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        previous_checkpoint_proof: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.append_checkpoint_tree_proof
            .set_witness_core_proof_q(witness, append_checkpoint_tree_proof)?;
        self.previous_checkpoint_proof
            .set_witness_core_proof_q_generic(witness, previous_checkpoint_proof)?;
        Ok(())
    }
}


