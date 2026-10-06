use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, config::PoseidonGoldilocksConfig},
};
use psy_plonky2_basic_helpers::builder::{
    comparison::CircuitBuilderComparison, hash::core::CircuitBuilderHashCore,
    select::CircuitBuilderSelectHelpers,
};
use psy_plonky2_common_circuits::bridge::aggregate_commitment::RewardLeafTarget;
use psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget;
use crate::gadgets::tag_tree::hash_tag_tree_node_circuit;
use plonky2::plonk::{
    circuit_data::{CircuitConfig, CircuitData},
    proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
};
use psy_client_data::bridge_aggregate::{CircuitSetRegistration, NetworkConfig, RewardLeaf};
use psy_common_circuit::traits::CreatableTarget;
use psy_network_circuit::gadgets::qdata::{checkpoint::PsyCheckpointLeafGadget, user::PsyUserLeafGadget};
use psy_plonky2_common_circuits::bridge::{
    aggregate_commitment::AggregateLeafTarget, aggregate_config::NetworkConfigTarget,
};
use psy_ups_circuit::signature::reward_authorization::{
    build_reward_authorization_message_target, RewardAuthorizationCircuits, RewardAuthorizationContext, RewardAuthorizationInput,
};
use crate::proof_minifier::pm_core::get_circuit_fingerprint_generic;
use crate::bridge::aggregate_circuits::circuit_set_registration;

pub const REWARD_INCLUSION_PI_LEN: usize = 28;
const MAX_REWARD_HEIGHT: usize = 21;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

#[derive(Clone, Debug)]
pub struct RewardTagWitness {
    pub tag_preimage: QHashOut<F>,
    pub leaf_left: QHashOut<F>,
    pub leaf_right: QHashOut<F>,
    pub leaf_tag: QHashOut<F>,
    pub siblings: [QHashOut<F>; MAX_REWARD_HEIGHT],
    pub parent_tags: [QHashOut<F>; MAX_REWARD_HEIGHT],
}

pub struct RewardTagTarget {
    pub tag_preimage: HashOutTarget,
    pub leaf_left: HashOutTarget,
    pub leaf_right: HashOutTarget,
    pub leaf_tag: HashOutTarget,
    pub siblings: [HashOutTarget; MAX_REWARD_HEIGHT],
    pub parent_tags: [HashOutTarget; MAX_REWARD_HEIGHT],
    pub root: HashOutTarget,
}

impl RewardTagTarget {
    pub(super) fn new(builder: &mut CircuitBuilder<F, 2>, reward: &RewardLeafTarget) -> Self {
        let zero = builder.zero();
        let one = builder.one();
        builder.range_check(reward.height, 8);
        let heights: Vec<_> = (2..=MAX_REWARD_HEIGHT).map(|height| {
            let height = builder.constant(F::from_canonical_usize(height));
            builder.is_equal(reward.height, height)
        }).collect();
        let valid_height = builder.add_many(heights.iter().map(|bit| bit.target));
        builder.connect(valid_height, one);
        let path_bits = builder.split_le(reward.path_index, 32);
        let mut offset = zero;
        for (index, height) in (2..=MAX_REWARD_HEIGHT).enumerate() {
            offset = builder.mul_const_add(F::from_canonical_u32((1u32 << height) - 1), heights[index].target, offset);
        }
        let nullifier = builder.add(offset, reward.path_index);
        builder.connect(reward.nullifier_index, nullifier);
        builder.range_check(reward.nullifier_index, 32);
        for (bit_index, bit) in path_bits.iter().enumerate() {
            let allowed = builder.add_many(heights.iter().enumerate()
                .filter(|(index, _)| bit_index < *index)
                .map(|(_, height)| height.target));
            let forbidden = builder.sub(one, allowed);
            let high_bit = builder.mul(forbidden, bit.target);
            builder.assert_zero(high_bit);
        }
        let tag_preimage = builder.add_virtual_hash();
        let leaf_left = builder.add_virtual_hash();
        let leaf_right = builder.add_virtual_hash();
        let leaf_tag = builder.add_virtual_hash();
        builder.connect(tag_preimage.elements[0], reward.user_id);
        builder.range_check(reward.user_id, 32);
        builder.assert_non_zero_hash(tag_preimage);
        builder.assert_non_zero_hash(leaf_tag);
        let owner_tag = builder.hash_two_to_one::<PoseidonHash>(tag_preimage, tag_preimage);
        builder.connect_hashes(owner_tag, leaf_tag);
        let siblings = std::array::from_fn(|_| builder.add_virtual_hash());
        let parent_tags = std::array::from_fn(|_| builder.add_virtual_hash());
        let mut root = hash_tag_tree_node_circuit::<PoseidonHash, F, 2>(builder, leaf_left, leaf_right, leaf_tag);
        for level in 0..MAX_REWARD_HEIGHT {
            let level_target = builder.constant(F::from_canonical_usize(level));
            let active = builder.is_less_than(8, level_target, reward.height);
            let inactive = builder.not(active);
            for target in siblings[level].elements.into_iter().chain(parent_tags[level].elements) {
                let unused = builder.mul(inactive.target, target);
                builder.assert_zero(unused);
            }
            let left = builder.select_hash(path_bits[level], siblings[level], root);
            let right = builder.select_hash(path_bits[level], root, siblings[level]);
            let parent = hash_tag_tree_node_circuit::<PoseidonHash, F, 2>(builder, left, right, parent_tags[level]);
            root = builder.select_hash(active, parent, root);
        }
        Self { tag_preimage, leaf_left, leaf_right, leaf_tag, siblings, parent_tags, root }
    }

    pub(super) fn set_witness(&self, witness: &mut PartialWitness<F>, input: &RewardTagWitness) -> anyhow::Result<()> {
        for (target, value) in [self.tag_preimage, self.leaf_left, self.leaf_right, self.leaf_tag]
            .into_iter().zip([input.tag_preimage, input.leaf_left, input.leaf_right, input.leaf_tag]) {
            witness.set_hash_target(target, value.0)?;
        }
        for (target, value) in self.siblings.iter().chain(&self.parent_tags)
            .zip(input.siblings.iter().chain(&input.parent_tags)) {
            witness.set_hash_target(*target, value.0)?;
        }
        Ok(())
    }
}

fn less_u64(builder: &mut CircuitBuilder<F, 2>, left: [Target; 2], right: [Target; 2]) -> plonky2::iop::target::BoolTarget {
    for word in left.into_iter().chain(right) { builder.range_check(word, 32); }
    let high_less = builder.is_less_than(32, left[1], right[1]);
    let high_equal = builder.is_equal(left[1], right[1]);
    let low_less = builder.is_less_than(32, left[0], right[0]);
    let equal_high_low_less = builder.and(high_equal, low_less);
    builder.or(high_less, equal_high_low_less)
}

pub struct RewardWitness {
    pub config: NetworkConfig,
    pub authorization: RewardAuthorizationInput,
    pub tag: RewardTagWitness,
}

use psy_config::network_constants::CHECKPOINT_TREE_HEIGHT;

fn historical_merkle_proof(builder: &mut CircuitBuilder<F, 2>, claim_id: [Target; 2],
    claim_leaf: &PsyCheckpointLeafGadget, end_id: [Target; 2], end_root: HashOutTarget) -> MerkleProofGadget {
    super::historical_merkle_proof::historical_merkle_proof(
        builder, claim_id, claim_leaf, end_id, end_root,
    ).path
}

pub struct RewardInclusionCircuit {
    pub config: NetworkConfigTarget,
    pub reward: RewardLeafTarget,
    pub claim_leaf: PsyCheckpointLeafGadget,
    pub claim_path: MerkleProofGadget,
    pub end_leaf: PsyCheckpointLeafGadget,
    pub authorization_user_leaf: PsyUserLeafGadget,
    pub tag: RewardTagTarget,
    pub authorization_proof: ProofWithPublicInputsTarget<2>,
    pub circuit_data: CircuitData<F, C, 2>,
    pub fingerprint: QHashOut<F>,
    authorization_circuits: RewardAuthorizationCircuits,
}

impl RewardInclusionCircuit {
    pub fn authorization_circuits(&self) -> &RewardAuthorizationCircuits {
        &self.authorization_circuits
    }

    pub fn circuit_set_registrations(&self) -> anyhow::Result<Vec<CircuitSetRegistration>> {
        let auth = &self.authorization_circuits;
        let mut registrations = Vec::with_capacity(5);
        registrations.push(circuit_set_registration(3, 0, 0, REWARD_INCLUSION_PI_LEN, &self.circuit_data, [0; 4])?);
        for (variant, (data, identity)) in [(&auth.zk.circuit_data, auth.zk.identity_fingerprint),
            (&auth.secp.circuit_data, auth.secp.identity_fingerprint),
            (&auth.personal_sign.circuit_data, auth.personal_sign.identity_fingerprint),
            (&auth.multisig.circuit_data, auth.multisig.identity_fingerprint)].into_iter().enumerate() {
            let registration = circuit_set_registration(4, 0, variant as u8, 30, data, identity.0.elements.map(|value| value.to_canonical_u64()))?;
            anyhow::ensure!(data.common == auth.zk.circuit_data.common, "reward authorization common data mismatch");
            if variant > 0 {
                anyhow::ensure!(registration.common_digest == registrations[1].common_digest, "reward authorization common serialization mismatch");
            }
            registrations.push(registration);
        }
        Ok(registrations)
    }

    pub fn new(source_chain_count: usize) -> anyhow::Result<Self> {
        let authorization_circuits = RewardAuthorizationCircuits::new()?;
        let circuits = [
            &authorization_circuits.zk.circuit_data,
            &authorization_circuits.secp.circuit_data,
            &authorization_circuits.personal_sign.circuit_data,
            &authorization_circuits.multisig.circuit_data,
        ];
        let common = &circuits[0].common;
        anyhow::ensure!(common.num_public_inputs == 30, "reward authorization PI layout mismatch");
        for circuit in &circuits[1..] {
            anyhow::ensure!(&circuit.common == common, "reward authorization common data mismatch");
        }
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let config = NetworkConfigTarget::new(&mut builder, source_chain_count);
        let config_hash = config.hash(&mut builder);
        let reward = RewardLeafTarget {
            claim_checkpoint_id: std::array::from_fn(|_| builder.add_virtual_target()),
            user_id: builder.add_virtual_target(), height: builder.add_virtual_target(),
            path_index: builder.add_virtual_target(), nullifier_index: builder.add_virtual_target(),
            recipient: std::array::from_fn(|_| builder.add_virtual_target()),
        };
        let before_cutover = less_u64(&mut builder, reward.claim_checkpoint_id, config.reward_cutover);
        builder.assert_zero(before_cutover.target);
        let before_end = less_u64(&mut builder, reward.claim_checkpoint_id, config.reward_end_exclusive);
        builder.assert_one(before_end.target);
        let leaf_commit = AggregateLeafTarget::Reward(reward).leaf_commit(&mut builder);
        let mut recipient_is_zero = builder._true();
        let zero = builder.zero();
        for word in reward.recipient {
            let is_zero = builder.is_equal(word, zero);
            recipient_is_zero = builder.and(recipient_is_zero, is_zero);
        }
        builder.assert_zero(recipient_is_zero.target);
        let claim_leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
        let end_leaf = PsyCheckpointLeafGadget::create_virtual(&mut builder);
        let authorization_user_leaf = PsyUserLeafGadget::create_virtual(&mut builder);
        builder.connect(authorization_user_leaf.user_id, reward.user_id);
        let claim_hash = claim_leaf.to_hash::<PoseidonHash, F, 2>(&mut builder);
        let end_hash = end_leaf.to_hash::<PoseidonHash, F, 2>(&mut builder);
        let user_hash = authorization_user_leaf.to_hash::<PoseidonHash, F, 2>(&mut builder);
        let tag = RewardTagTarget::new(&mut builder, &reward);
        builder.connect_hashes(tag.root, claim_leaf.stats.pm_rewards_commitment.gutas_root);

        let authorization_proof = builder.add_virtual_proof_with_pis(common);
        let pi = &authorization_proof.public_inputs;
        let variant_bits = builder.split_le(pi[2], 2);
        let pinned: Vec<_> = circuits.iter().map(|circuit| builder.constant_verifier_data(&circuit.verifier_only)).collect();
        let mut verifier = pinned[0].clone();
        for index in 0..verifier.constants_sigmas_cap.0.len() {
            let low = builder.select_hash(variant_bits[0], pinned[1].constants_sigmas_cap.0[index], pinned[0].constants_sigmas_cap.0[index]);
            let high = builder.select_hash(variant_bits[0], pinned[3].constants_sigmas_cap.0[index], pinned[2].constants_sigmas_cap.0[index]);
            verifier.constants_sigmas_cap.0[index] = builder.select_hash(variant_bits[1], high, low);
        }
        let low = builder.select_hash(variant_bits[0], pinned[1].circuit_digest, pinned[0].circuit_digest);
        let high = builder.select_hash(variant_bits[0], pinned[3].circuit_digest, pinned[2].circuit_digest);
        verifier.circuit_digest = builder.select_hash(variant_bits[1], high, low);
        builder.verify_proof::<C>(&authorization_proof, &verifier, common);
        for (index, value) in [(0, 1), (1, 4), (3, 0)] {
            let constant = builder.constant(F::from_canonical_u32(value));
            builder.connect(pi[index], constant);
        }
        for (&target, &value) in pi[4..12].iter().zip(&config_hash) { builder.connect(target, value); }
        let end_id = [pi[12], pi[13]];
        let end_root = [pi[14], pi[15], pi[16], pi[17]];
        let claim_path = historical_merkle_proof(&mut builder, reward.claim_checkpoint_id,
            &claim_leaf, end_id, HashOutTarget { elements: end_root });
        let message = build_reward_authorization_message_target(
            &mut builder, config_hash, end_id, end_root, end_hash.elements,
            user_hash.elements, claim_hash.elements, &reward,
        );
        for (&target, &value) in pi[18..26].iter().zip(&message) { builder.connect(target, value); }
        for (&target, &value) in pi[26..30].iter().zip(&user_hash.elements) { builder.connect(target, value); }
        for value in [1, 3, 0, 0] {
            let constant = builder.constant(F::from_canonical_u32(value));
            builder.register_public_input(constant);
        }
        builder.register_public_inputs(&config_hash);
        builder.register_public_inputs(&end_id);
        builder.register_public_inputs(&end_root);
        builder.register_public_inputs(&leaf_commit);
        builder.register_public_inputs(&reward.claim_checkpoint_id);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Ok(Self { config, reward, claim_leaf, claim_path, end_leaf, authorization_user_leaf, tag,
            authorization_proof, circuit_data, fingerprint, authorization_circuits })
    }

    pub fn build_witness(&self, input: &RewardWitness) -> anyhow::Result<PartialWitness<F>> {
        let proof = self.authorization_circuits.prove(&input.authorization)?;
        self.build_witness_with_authorization_proof(&input.config, &input.authorization.context, &input.tag, &proof)
    }

    fn build_witness_with_authorization_proof(&self, config: &NetworkConfig,
        context: &RewardAuthorizationContext, tag: &RewardTagWitness,
        proof: &ProofWithPublicInputs<F, C, 2>) -> anyhow::Result<PartialWitness<F>>
    {
        anyhow::ensure!(config.config_hash()? == context.config_hash, "reward authorization configuration mismatch");
        anyhow::ensure!(context.claim_checkpoint_path.len() == usize::from(CHECKPOINT_TREE_HEIGHT), "claim checkpoint path height mismatch");
        let pi = &proof.public_inputs;
        anyhow::ensure!(pi.len() == 30, "reward authorization PI layout mismatch");
        anyhow::ensure!(pi[0] == F::ONE && pi[1] == F::from_canonical_u32(4)
            && pi[2].to_canonical_u64() < 4 && pi[3] == F::ZERO, "reward authorization proof header mismatch");
        anyhow::ensure!(pi[12].to_canonical_u64() == context.end_checkpoint_id as u32 as u64
            && pi[13].to_canonical_u64() == context.end_checkpoint_id >> 32,
            "reward authorization checkpoint mismatch");
        anyhow::ensure!(pi[14..18].iter().map(|value| value.to_canonical_u64()).eq(context.end_checkpoint_root),
            "reward authorization checkpoint root mismatch");
        let message = context.message()?;
        for (target, bytes) in pi[18..26].iter().zip(message.chunks_exact(4)) {
            anyhow::ensure!(target.to_canonical_u64() == u32::from_be_bytes(bytes.try_into()?) as u64,
                "reward authorization message mismatch");
        }
        let mut witness = PartialWitness::new();
        self.config.set_witness(&mut witness, config)?;
        self.set_reward_witness(&mut witness, &context.reward)?;
        self.claim_leaf.set_witness(&mut witness, &context.claim_checkpoint_leaf)?;
        witness.set_target(self.claim_path.index, F::from_canonical_u64(context.reward.claim_checkpoint_id))?;
        for (target, sibling) in self.claim_path.siblings.iter().zip(&context.claim_checkpoint_path) {
            witness.set_hash_target(*target, sibling.0)?;
        }
        self.end_leaf.set_witness(&mut witness, &context.end_checkpoint_leaf)?;
        self.authorization_user_leaf.set_witness(&mut witness, &context.authorization_user_leaf)?;
        self.tag.set_witness(&mut witness, tag)?;
        witness.set_proof_with_pis_target(&self.authorization_proof, proof)?;
        Ok(witness)
    }

    fn set_reward_witness(&self, witness: &mut PartialWitness<F>, reward: &RewardLeaf) -> anyhow::Result<()> {
        reward.validate()?;
        witness.set_target(self.reward.claim_checkpoint_id[0], F::from_canonical_u32(reward.claim_checkpoint_id as u32))?;
        witness.set_target(self.reward.claim_checkpoint_id[1], F::from_canonical_u32((reward.claim_checkpoint_id >> 32) as u32))?;
        for (target, value) in [self.reward.user_id, self.reward.height, self.reward.path_index, self.reward.nullifier_index]
            .into_iter().zip([reward.user_id, reward.height as u32, reward.path_index, reward.nullifier_index]) {
            witness.set_target(target, F::from_canonical_u32(value))?;
        }
        for (target, bytes) in self.reward.recipient.iter().zip(reward.recipient.chunks_exact(4)) {
            witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap())))?;
        }
        Ok(())
    }

    pub fn prove(&self, input: &RewardWitness) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>> {
        self.circuit_data.prove(self.build_witness(input)?)
    }

    pub fn prove_with_authorization_proof(&self, config: &NetworkConfig,
        context: &RewardAuthorizationContext, tag: &RewardTagWitness,
        proof: &ProofWithPublicInputs<F, C, 2>) -> anyhow::Result<ProofWithPublicInputs<F, C, 2>>
    {
        self.circuit_data.prove(self.build_witness_with_authorization_proof(config, context, tag, proof)?)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, 2>) -> anyhow::Result<()> {
        self.circuit_data.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher};

    fn hash(value: u64) -> QHashOut<F> {
        QHashOut(HashOut { elements: [F::from_canonical_u64(value); 4] })
    }

    fn fixture(height: u8, path_index: u32) -> (RewardLeaf, RewardTagWitness, HashOut<F>) {
        let reward = RewardLeaf { claim_checkpoint_id: 7, user_id: 1000, height, path_index,
            nullifier_index: (1u32 << height) - 1 + path_index, recipient: [1; 20] };
        let mut tag_preimage = hash(11);
        tag_preimage.0.elements[0] = F::from_canonical_u32(reward.user_id);
        let leaf_tag = QHashOut(PoseidonHash::two_to_one(tag_preimage.0, tag_preimage.0));
        let mut input = RewardTagWitness { tag_preimage, leaf_left: hash(12), leaf_right: hash(13), leaf_tag,
            siblings: [hash(0); MAX_REWARD_HEIGHT], parent_tags: [hash(0); MAX_REWARD_HEIGHT] };
        let mut root = PoseidonHash::two_to_one(PoseidonHash::two_to_one(input.leaf_left.0, input.leaf_right.0), leaf_tag.0);
        for level in 0..height as usize {
            input.siblings[level] = hash(20 + level as u64);
            input.parent_tags[level] = hash(50 + level as u64);
            let children = if path_index & (1 << level) == 0 {
                PoseidonHash::two_to_one(root, input.siblings[level].0)
            } else { PoseidonHash::two_to_one(input.siblings[level].0, root) };
            root = PoseidonHash::two_to_one(children, input.parent_tags[level].0);
        }
        (reward, input, root)
    }

    fn prove_tag(reward: RewardLeaf, input: RewardTagWitness, expected_root: HashOut<F>) -> anyhow::Result<()> {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let target = RewardLeafTarget {
            claim_checkpoint_id: [builder.zero(); 2], user_id: builder.add_virtual_target(),
            height: builder.add_virtual_target(), path_index: builder.add_virtual_target(),
            nullifier_index: builder.add_virtual_target(), recipient: [builder.zero(); 5],
        };
        let tag = RewardTagTarget::new(&mut builder, &target);
        let root = builder.constant_hash(expected_root);
        builder.connect_hashes(tag.root, root);
        let circuit = builder.build::<C>();
        let mut witness = PartialWitness::new();
        for (target, value) in [target.user_id, target.height, target.path_index, target.nullifier_index]
            .into_iter().zip([reward.user_id, reward.height as u32, reward.path_index, reward.nullifier_index]) {
            witness.set_target(target, F::from_canonical_u32(value))?;
        }
        tag.set_witness(&mut witness, &input)?;
        let proof = circuit.prove(witness)?;
        circuit.verify(proof)
    }

    #[test]
    fn accepts_full_root_guta_positions_at_both_height_boundaries() {
        for (height, index) in [(2, 0), (21, (1 << 19) - 1)] {
            let (reward, input, root) = fixture(height, index);
            prove_tag(reward, input, root).unwrap();
        }
    }

    #[test]
    fn rejects_non_guta_rootward_bits_and_high_index_bits() {
        for (height, index) in [(3, 2), (4, 6), (4, 7), (2, 1), (21, 1 << 31)] {
            let (reward, input, root) = fixture(height, index);
            assert!(prove_tag(reward, input, root).is_err());
        }
    }

    #[test]
    fn rejects_height_relabeling_and_noncanonical_nullifier() {
        let (reward, input, root) = fixture(3, 1);
        let mut bad = reward.clone();
        bad.height = 2;
        bad.nullifier_index = 4;
        assert!(prove_tag(bad, input.clone(), root).is_err());
        let mut bad = reward.clone();
        bad.nullifier_index += 1;
        assert!(prove_tag(bad, input.clone(), root).is_err());
        for height in [0, 1, 22, 255] {
            let mut bad = reward.clone();
            bad.height = height;
            assert!(prove_tag(bad, input.clone(), root).is_err());
        }
    }

    #[test]
    fn rejects_tag_owner_and_path_mutations() {
        let (reward, input, root) = fixture(3, 1);
        let mut bad = reward.clone();
        bad.user_id += 1;
        assert!(prove_tag(bad, input.clone(), root).is_err());
        for mutation in 0..7 {
            let mut bad = input.clone();
            match mutation {
                0 => bad.tag_preimage.0.elements[1] += F::ONE,
                1 => bad.leaf_tag = hash(0),
                2 => bad.siblings[0] = hash(99),
                3 => bad.parent_tags[0] = hash(99),
                4 => bad.siblings[3] = hash(99),
                5 => bad.parent_tags[3] = hash(99),
                _ => { bad.tag_preimage = hash(0); bad.leaf_tag = QHashOut(PoseidonHash::two_to_one(hash(0).0, hash(0).0)); }
            }
            assert!(prove_tag(reward.clone(), bad, root).is_err());
        }
    }

    #[test]
    fn direct_claim_membership_rejects_path_anchor_and_bound_mutations() {
        use psy_client_data::qdata::checkpoint::PsyCheckpointLeaf;
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let claim_id = builder.add_virtual_target_arr();
        let end_id = builder.add_virtual_target_arr();
        let claim_leaf_target = PsyCheckpointLeafGadget::create_virtual(&mut builder);
        let end_root = builder.add_virtual_hash();
        let proof = historical_merkle_proof(&mut builder, claim_id, &claim_leaf_target, end_id, end_root);
        let circuit = builder.build::<C>();
        let mut leaf = PsyCheckpointLeaf::default();
        leaf.global_chain_root = psy_client_common::data::qhashout::QHashOut(hash(3).0);
        let value = leaf.qfhash::<PoseidonHash>().0;
        let siblings: Vec<_> = (0..CHECKPOINT_TREE_HEIGHT).map(|i| hash(20 + u64::from(i)).0).collect();
        let mut root = value;
        for (level, sibling) in siblings.iter().enumerate() {
            root = if 7u32 & (1 << level) == 0 { PoseidonHash::two_to_one(root, *sibling) }
                else { PoseidonHash::two_to_one(*sibling, root) };
        }
        for mutation in 0..9 {
            let mut witness = PartialWitness::new();
            let claim = if mutation == 3 { 6 } else { 7 };
            let end = if mutation == 6 { 6 } else if mutation == 8 { 7 } else { 9 };
            witness.set_target(claim_id[0], F::from_canonical_u32(claim)).unwrap();
            witness.set_target(claim_id[1], if mutation == 4 { F::ONE } else { F::ZERO }).unwrap();
            witness.set_target(end_id[0], F::from_canonical_u32(end)).unwrap();
            witness.set_target(end_id[1], if mutation == 5 { F::ONE } else { F::ZERO }).unwrap();
            let mut opened = leaf;
            if mutation == 1 { opened.global_chain_root = psy_client_common::data::qhashout::QHashOut(hash(99).0); }
            claim_leaf_target.set_witness(&mut witness, &opened).unwrap();
            witness.set_hash_target(end_root, if mutation == 7 { hash(99).0 } else { root }).unwrap();
            for (level, target) in proof.siblings.iter().enumerate() {
                witness.set_hash_target(*target, if mutation == 2 && level == 0 { hash(99).0 } else { siblings[level] }).unwrap();
            }
            let result = circuit.prove(witness);
            if mutation == 0 || mutation == 8 { circuit.verify(result.unwrap()).unwrap(); }
            else { assert!(result.is_err(), "accepted direct claim mutation {mutation}"); }
        }
    }
}

#[cfg(test)]
mod authorization_binding_tests {
    use super::*;
    use tiny_keccak::{Hasher, Keccak};

    fn message(domain_label: &[u8], words: &[[u8; 32]]) -> [u8; 32] {
        let mut domain = [0; 32];
        let mut hash = Keccak::v256();
        hash.update(domain_label);
        hash.finalize(&mut domain);
        let mut hash = Keccak::v256();
        hash.update(&domain);
        for word in words { hash.update(word); }
        let mut result = [0; 32];
        hash.finalize(&mut result);
        result
    }

    #[test]
    fn reward_message_rejects_checkpoint_current_user_recipient_and_domain_mutations() {
        let word = |value: u64| { let mut bytes = [0; 32]; bytes[24..].copy_from_slice(&value.to_be_bytes()); bytes };
        let mut words = vec![[0x11; 32], word(7)];
        for values in [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]] {
            words.extend(values.map(word));
        }
        let reward = RewardLeaf { claim_checkpoint_id: 6, user_id: 1000, height: 2,
            path_index: 0, nullifier_index: 3, recipient: [1; 20] };
        words.extend(reward.encode().unwrap().chunks_exact(32).map(|bytes| <[u8; 32]>::try_from(bytes).unwrap()));
        let expected = message(b"PsyBridge/TwoArtifact/1/RewardAuthorization", &words);
        for mutation in 0..6 {
            let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
            let config = std::array::from_fn(|_| builder.constant(F::from_canonical_u32(0x11111111)));
            let end_id = [builder.constant(F::from_canonical_u32(7)), builder.zero()];
            let end_root = [1, 2, 3, 4].map(|value| builder.constant(F::from_canonical_u32(value)));
            let end_hash = [5, 6, 7, 8].map(|value| builder.constant(F::from_canonical_u32(value)));
            let mut user_hash = [9, 10, 11, 12].map(|value| builder.constant(F::from_canonical_u32(value)));
            let mut claim_hash = [13, 14, 15, 16].map(|value| builder.constant(F::from_canonical_u32(value)));
            let mut leaf = RewardLeafTarget {
                claim_checkpoint_id: [builder.constant(F::from_canonical_u32(6)), builder.zero()],
                user_id: builder.constant(F::from_canonical_u32(1000)),
                height: builder.constant(F::from_canonical_u32(2)), path_index: builder.zero(),
                nullifier_index: builder.constant(F::from_canonical_u32(3)),
                recipient: std::array::from_fn(|_| builder.constant(F::from_canonical_u32(0x01010101))),
            };
            match mutation {
                1 => claim_hash[0] = builder.constant(F::from_canonical_u32(99)),
                2 => user_hash[0] = builder.constant(F::from_canonical_u32(99)),
                3 => leaf.recipient[0] = builder.constant(F::from_canonical_u32(99)),
                4 => leaf.claim_checkpoint_id[0] = builder.constant(F::from_canonical_u32(5)),
                _ => {},
            }
            let actual = build_reward_authorization_message_target(&mut builder, config, end_id,
                end_root, end_hash, user_hash, claim_hash, &leaf);
            let mut expected = expected;
            if mutation == 5 { expected = message(b"PsyBridge/TwoArtifact/1/Reward", &words); }
            let mut witness = PartialWitness::new();
            for (target, bytes) in actual.into_iter().zip(expected.chunks_exact(4)) {
                let expected_target = builder.add_virtual_target();
                witness.set_target(expected_target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))).unwrap();
                builder.connect(target, expected_target);
            }
            let circuit = builder.build::<C>();
            let result = circuit.prove(witness);
            if mutation == 0 { circuit.verify(result.unwrap()).unwrap(); }
            else { assert!(result.is_err()); }
        }
    }
}

#[cfg(test)]
mod eligibility_tests {
    use super::*;

    #[test]
    fn compares_checkpoint_bounds_as_integers_without_field_wrap() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let left = std::array::from_fn(|_| builder.add_virtual_target());
        let right = std::array::from_fn(|_| builder.add_virtual_target());
        let less = less_u64(&mut builder, left, right);
        builder.register_public_input(less.target);
        let circuit = builder.build::<C>();
        for (a, b, expected) in [(7u64, 7u64, false), (7, 8, true), (8, 7, false),
            (u32::MAX as u64, 1u64 << 32, true), (u64::MAX, 0, false), (0, u64::MAX, true)] {
            let mut witness = PartialWitness::new();
            for (targets, value) in [(left, a), (right, b)] {
                witness.set_target(targets[0], F::from_canonical_u32(value as u32)).unwrap();
                witness.set_target(targets[1], F::from_canonical_u32((value >> 32) as u32)).unwrap();
            }
            let proof = circuit.prove(witness).unwrap();
            assert_eq!(proof.public_inputs, vec![if expected { F::ONE } else { F::ZERO }]);
            circuit.verify(proof).unwrap();
        }
    }
}
