//! Direct user reward leaf. It verifies checkpoint and reward membership
//! against the user-selected target anchor and emits the canonical aggregation
//! header.

use anyhow::{ensure, Result};
use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField64},
    },
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, job::id::GUTA_REWARDS_TREE_V2_MAX_HEIGHT};
use psy_client_data::qdata::checkpoint::PsyCheckpointLeaf;
use psy_common_circuit::{
    builder::{comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers},
    hash::merkle::gadgets::merkle_proof::MerkleProofGadget,
    traits::CreatableTarget,
};
use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;
use psy_crypto::hash::{
    merkle::{core::MerkleProofCore, tag_tree::TagTreeMerkleProofWithRewardPreimage},
    traits::{hasher::FieldQHasher, qhashable::QFieldHashable},
};

use crate::gadgets::qdata::checkpoint::PsyCheckpointLeafGadget;

/// Amount/count are limited to 31 bits so the quotient product and remainder
/// cannot wrap in Goldilocks arithmetic. Fees are limited to 62 bits.
pub struct UserRewardLeafInput<F: RichField> {
    /// Target anchor advertised by the batcher.
    pub anchor_root: QHashOut<F>,
    pub checkpoint_id: u64,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub checkpoint_siblings: Vec<QHashOut<F>>,
    pub reward_proof: TagTreeMerkleProofWithRewardPreimage<QHashOut<F>>,
    pub user_id: u64,
    /// Little-endian 32-bit limbs of an EVM address; limbs 5..8 are zero.
    pub l1_recipient: [u32; 8],
    pub amount: u64,
    pub remainder: u64,
}

pub struct UserRewardLeafCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    data: CircuitData<C::F, C, D>,
    checkpoint_leaf: PsyCheckpointLeafGadget,
    checkpoint_proof: MerkleProofGadget,
    reward_index: Target,
    reward_preimage: HashOutTarget,
    reward_leaf_left: HashOutTarget,
    reward_leaf_right: HashOutTarget,
    reward_siblings: Vec<HashOutTarget>,
    reward_parent_tags: Vec<HashOutTarget>,
    reward_height: Target,
    user_id: Target,
    l1_recipient: [Target; 8],
    amount: Target,
    remainder: Target,
}

impl<C: GenericConfig<D>, const D: usize> UserRewardLeafCircuit<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<C::F> + FieldQHasher<C::F>,
{
    pub fn new() -> Self {
        let reward_tree_height = GUTA_REWARDS_TREE_V2_MAX_HEIGHT;
        let mut builder = CircuitBuilder::<C::F, D>::new(CircuitConfig::standard_recursion_config());
        let checkpoint_leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
        let checkpoint_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder, CHECKPOINT_TREE_HEIGHT as usize);
        let checkpoint_hash = checkpoint_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);
        builder.connect_hashes(checkpoint_hash, checkpoint_proof.value);

        let reward_index = builder.add_virtual_target();
        let reward_bits = builder.split_le(reward_index, reward_tree_height);
        let reward_height = builder.add_virtual_target();
        let max_height = builder.constant(C::F::from_canonical_usize(reward_tree_height));
        builder.ensure_is_less_than_or_equal(8, reward_height, max_height);
        let reward_preimage = builder.add_virtual_hash();
        let reward_tag = builder.hash_two_to_one::<C::Hasher>(reward_preimage, reward_preimage);
        let user_id = builder.add_virtual_target();
        builder.connect(user_id, reward_preimage.elements[0]);
        let l1_recipient = builder.add_virtual_target_arr::<8>();
        for limb in l1_recipient.iter().take(5) {
            builder.range_check(*limb, 32);
        }
        let zero = builder.zero();
        for limb in l1_recipient.iter().skip(5) {
            builder.connect(*limb, zero);
        }
        let mut recipient_sum = zero;
        for limb in l1_recipient.iter().take(5) {
            recipient_sum = builder.add(recipient_sum, *limb);
        }
        builder.assert_non_zero(recipient_sum);
        let reward_leaf_left = builder.add_virtual_hash();
        let reward_leaf_right = builder.add_virtual_hash();
        let mut reward_root = builder.hash_two_to_one::<C::Hasher>(reward_leaf_left, reward_leaf_right);
        reward_root = builder.hash_two_to_one::<C::Hasher>(reward_root, reward_tag);
        let mut reward_siblings = Vec::with_capacity(reward_tree_height);
        let mut reward_parent_tags = Vec::with_capacity(reward_tree_height);
        for (level, bit) in reward_bits.into_iter().enumerate() {
            let sibling = builder.add_virtual_hash();
            let parent_tag = builder.add_virtual_hash();
            let level_target = builder.constant(C::F::from_canonical_usize(level));
            let active = builder.is_less_than(8, level_target, reward_height);
            let inactive = builder.not(active);
            let inactive_bit = builder.and(bit, inactive);
            builder.connect(inactive_bit.target, zero);
            let candidate = builder.two_to_one_swapped::<C::Hasher>(reward_root, sibling, bit);
            let candidate = builder.hash_two_to_one::<C::Hasher>(candidate, parent_tag);
            reward_root = builder.select_hash(active, candidate, reward_root);
            reward_siblings.push(sibling);
            reward_parent_tags.push(parent_tag);
        }
        builder.connect_hashes(reward_root, checkpoint_leaf.stats.pm_rewards_commitment.gutas_root);

        let fees = checkpoint_leaf.stats.guta_fees_collected;
        let count = checkpoint_leaf.stats.pm_jobs_completed.gutas_completed;
        let amount = builder.add_virtual_target();
        let remainder = builder.add_virtual_target();
        builder.range_check(fees, 62);
        builder.range_check(count, 31);
        builder.range_check(amount, 31);
        builder.range_check(remainder, 31);
        builder.assert_non_zero(count);
        builder.assert_non_zero(amount);
        builder.ensure_is_less_than(31, remainder, count);
        let product = builder.mul(amount, count);
        let calculated_fees = builder.add(product, remainder);
        builder.connect(calculated_fees, fees);

        // Canonical user aggregation header:
        // target_anchor[4], user_id, recipient[8], amount, count=1, job_commitment[4].
        builder.register_public_inputs(&checkpoint_proof.root.elements);
        builder.register_public_input(user_id);
        builder.register_public_inputs(&l1_recipient);
        builder.register_public_input(amount);
        let one = builder.one();
        builder.register_public_input(one);
        let commitment = builder.hash_n_to_hash_no_pad::<C::Hasher>(
            [
                checkpoint_proof.index,
                reward_index,
                reward_height,
                amount,
                user_id,
                checkpoint_hash.elements[0],
                checkpoint_hash.elements[1],
                checkpoint_hash.elements[2],
                checkpoint_hash.elements[3],
            ]
            .to_vec(),
        );
        builder.register_public_inputs(&commitment.elements);
        let data = builder.build::<C>();
        Self {
            data,
            checkpoint_leaf,
            checkpoint_proof,
            reward_index,
            reward_preimage,
            reward_leaf_left,
            reward_leaf_right,
            reward_siblings,
            reward_parent_tags,
            reward_height,
            user_id,
            l1_recipient,
            amount,
            remainder,
        }
    }

    pub fn circuit_data(&self) -> &CircuitData<C::F, C, D> {
        &self.data
    }

    pub fn prove(&self, input: &UserRewardLeafInput<C::F>) -> Result<ProofWithPublicInputs<C::F, C, D>> {
        ensure!(
            input.checkpoint_siblings.len() == CHECKPOINT_TREE_HEIGHT as usize,
            "checkpoint path height mismatch"
        );
        let height = input.reward_proof.proof_height as usize;
        ensure!(height <= self.reward_siblings.len(), "reward path exceeds maximum height");
        ensure!(input.reward_proof.inner.siblings.len() >= height, "reward path shorter than proof_height");
        ensure!(input.reward_proof.inner.index < (1u64 << height), "reward index out of range");
        let fees = input.checkpoint_leaf.stats.guta_fees_collected.to_canonical_u64();
        let count = input.checkpoint_leaf.stats.pm_jobs_completed.gutas_completed.to_canonical_u64();
        ensure!(
            fees < (1u64 << 62) && count > 0 && count < (1u64 << 31),
            "reward stats out of circuit range"
        );
        ensure!(
            input.amount > 0 && input.amount < (1u64 << 31) && input.remainder < count,
            "reward quotient out of circuit range"
        );
        ensure!(input.amount * count + input.remainder == fees, "incorrect reward quotient");
        ensure!(
            input.reward_proof.reward_tree_tag_preimage.0.elements[0].to_canonical_u64() == input.user_id,
            "reward user mismatch"
        );
        ensure!(input.l1_recipient[5..] == [0; 3], "L1 recipient exceeds 160 bits");
        ensure!(input.l1_recipient[..5].iter().any(|limb| *limb != 0), "zero L1 recipient");
        let mut witness = PartialWitness::new();
        self.checkpoint_leaf.set_witness(&mut witness, &input.checkpoint_leaf)?;
        let checkpoint_hash = input.checkpoint_leaf.qfhash::<C::Hasher>();
        let source_membership =
            MerkleProofCore::new_from_params::<C::Hasher>(input.checkpoint_id, checkpoint_hash, input.checkpoint_siblings.clone());
        ensure!(
            source_membership.root == input.anchor_root,
            "checkpoint path does not match target anchor root"
        );
        self.checkpoint_proof.set_witness_generic(
            &mut witness,
            C::F::from_canonical_u64(input.checkpoint_id),
            checkpoint_hash,
            &input.checkpoint_siblings,
        )?;
        witness.set_target(self.reward_index, C::F::from_canonical_u64(input.reward_proof.inner.index))?;
        witness.set_target(self.reward_height, C::F::from_canonical_usize(height))?;
        witness.set_hash_target(self.reward_preimage, input.reward_proof.reward_tree_tag_preimage.0)?;
        witness.set_hash_target(self.reward_leaf_left, input.reward_proof.inner.leaf.left.0)?;
        witness.set_hash_target(self.reward_leaf_right, input.reward_proof.inner.leaf.right.0)?;
        for i in 0..self.reward_siblings.len() {
            let (sibling, parent_tag) = if i < height {
                (
                    input.reward_proof.inner.siblings[i].sibling.0,
                    input.reward_proof.inner.siblings[i].parent_tag.0,
                )
            } else {
                (plonky2::hash::hash_types::HashOut::ZERO, plonky2::hash::hash_types::HashOut::ZERO)
            };
            witness.set_hash_target(self.reward_siblings[i], sibling)?;
            witness.set_hash_target(self.reward_parent_tags[i], parent_tag)?;
        }
        witness.set_target(self.user_id, C::F::from_canonical_u64(input.user_id))?;
        for (target, limb) in self.l1_recipient.iter().zip(input.l1_recipient) {
            witness.set_target(*target, C::F::from_canonical_u64(limb as u64))?;
        }
        witness.set_target(self.amount, C::F::from_canonical_u64(input.amount))?;
        witness.set_target(self.remainder, C::F::from_canonical_u64(input.remainder))?;
        Ok(self.data.prove(witness)?)
    }
}
