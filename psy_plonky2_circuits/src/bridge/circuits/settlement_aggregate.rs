use anyhow::Context;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOutTarget,
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_data::bridge_aggregate::{DepositAggregateOpening, Hash4, NetworkConfig, SettlementOpening, SourceCheckpointRewardOpening, WithdrawalAggregateOpening, MAX_LEAVES};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use psy_plonky2_common_circuits::{
    bridge::aggregate_commitment::{self as hash, keccak_prefix_words, Bytes32Target},
    hash::keccak::{keccak256_bytes_targets, keccak256_u32_words_be_abi},
};
use tiny_keccak::Hasher as _;

use super::inclusion_aggregate::set_bytes;

type F = GoldilocksField;
pub const SETTLEMENT_AGGREGATE_PI_LEN: usize = 12;
const MAX_SOURCE_CHAINS: usize = 8;
const MAX_PAYOUTS: usize = MAX_LEAVES;

pub struct SettlementAggregateCircuit<C: GenericConfig<D, F = F>, const D: usize>
where
    F: Extendable<D>,
{
    pub circuit_data: CircuitData<F, C, D>,
    finalizations: Vec<ProofWithPublicInputsTarget<D>>,
    withdrawal: ProofWithPublicInputsTarget<D>,
    reward: ProofWithPublicInputsTarget<D>,
    opening_digest: [Target; 8],
    withdrawal_digest: Bytes32Target,
    reward_digest: Bytes32Target,
    config_hash: Bytes32Target,
    window_id: Bytes32Target,
    end_id: Target,
    end_root: [Target; 4],
    global_deposit_root: [Target; 8],
    global_withdrawal_root: [Target; 8],
    start_roots: Vec<[Target; 4]>,
    checkpoint_counts: Vec<Target>,
    deposit_roots: Vec<[Target; 4]>,
    deposit_counts: Vec<Target>,
    withdrawal_roots: Vec<[Target; 4]>,
    old_reward_ledger_root: [Target; 4],
    new_reward_ledger_root: [Target; 4],
    economic_domain: Bytes32Target,
    withdrawal_count: Target,
    reward_count: Target,
    withdrawal_leaf_words: Vec<Vec<Target>>,
    reward_leaf_words: Vec<Vec<Target>>,
    deposit_digest: Bytes32Target,
}

impl<C: GenericConfig<D, F = F>, const D: usize> SettlementAggregateCircuit<C, D>
where
    F: Extendable<D>,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        chain_count: usize,
        final_common: &CommonCircuitData<F, D>,
        final_verifier: &VerifierOnlyCircuitData<C, D>,
        withdrawal_common: &CommonCircuitData<F, D>,
        withdrawal_verifier: &VerifierOnlyCircuitData<C, D>,
        reward_common: &CommonCircuitData<F, D>,
        reward_verifier: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=MAX_SOURCE_CHAINS).contains(&chain_count), "source chain count must be 1..8");
        anyhow::ensure!(final_common.num_public_inputs == 26 + 9 * chain_count, "final public width mismatch");
        anyhow::ensure!(withdrawal_common.num_public_inputs >= 12, "withdrawal publication width mismatch");
        anyhow::ensure!(reward_common.num_public_inputs >= 12, "reward publication width mismatch");
        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());
        let pinned_final = builder.constant_verifier_data(final_verifier);
        let finalizations = (0..chain_count).map(|_| {
            let proof = builder.add_virtual_proof_with_pis(final_common);
            builder.verify_proof::<C>(&proof, &pinned_final, final_common);
            proof
        }).collect::<Vec<_>>();
        let withdrawal = verified_child(&mut builder, withdrawal_common, withdrawal_verifier);
        let reward = verified_child(&mut builder, reward_common, reward_verifier);
        let config_hash = builder.add_virtual_target_arr();
        let window_id = builder.add_virtual_target_arr();
        for word in config_hash.into_iter().chain(window_id) { builder.range_check(word, 32); }
        let end_id = builder.add_virtual_target();
        builder.range_check(end_id, 32);
        let end_root = builder.add_virtual_target_arr();
        hash::encode_hash4(&mut builder, end_root);
        let global_deposit_root = builder.add_virtual_target_arr();
        let global_withdrawal_root = builder.add_virtual_target_arr();
        for word in global_deposit_root.into_iter().chain(global_withdrawal_root) { builder.range_check(word, 32); }
        let mut start_roots = Vec::with_capacity(chain_count);
        let mut checkpoint_counts = Vec::with_capacity(chain_count);
        let mut deposit_roots = Vec::with_capacity(chain_count);
        let mut deposit_counts = Vec::with_capacity(chain_count);
        let mut withdrawal_roots = Vec::with_capacity(chain_count);
        for index in 0..chain_count {
            let start_root = builder.add_virtual_target_arr();
            hash::encode_hash4(&mut builder, start_root);
            let checkpoint_count = builder.add_virtual_target();
            builder.range_check(checkpoint_count, 32);
            builder.assert_non_zero(checkpoint_count);
            let deposit_root = builder.add_virtual_target_arr();
            hash::encode_hash4(&mut builder, deposit_root);
            let deposit_count = builder.add_virtual_target();
            builder.range_check(deposit_count, 32);
            let withdrawal_root = builder.add_virtual_target_arr();
            hash::encode_hash4(&mut builder, withdrawal_root);
            let proof = &finalizations[index];
            for (target, public) in start_root.iter().zip(&proof.public_inputs[0..4]) { builder.connect(*target, *public); }
            for (target, public) in global_deposit_root.iter().zip(&proof.public_inputs[4..12]) { builder.connect(*target, *public); }
            for (target, public) in global_withdrawal_root.iter().zip(&proof.public_inputs[12..20]) { builder.connect(*target, *public); }
            for (target, public) in end_root.iter().zip(&proof.public_inputs[20..24]) { builder.connect(*target, *public); }
            builder.connect(end_id, proof.public_inputs[24]);
            builder.connect(checkpoint_count, proof.public_inputs[25]);
            let base = 26 + 9 * index;
            for (target, public) in deposit_root.iter().zip(&proof.public_inputs[base..base + 4]) { builder.connect(*target, *public); }
            builder.connect(deposit_count, proof.public_inputs[base + 4]);
            for (target, public) in withdrawal_root.iter().zip(&proof.public_inputs[base + 5..base + 9]) { builder.connect(*target, *public); }
            start_roots.push(start_root);
            checkpoint_counts.push(checkpoint_count);
            deposit_roots.push(deposit_root);
            deposit_counts.push(deposit_count);
            withdrawal_roots.push(withdrawal_root);
        }
        connect_common_finalization(&mut builder, &finalizations, chain_count);
        let deposit_digest = builder.add_virtual_target_arr();
        for word in deposit_digest { builder.range_check(word, 32); }
        let (withdrawal_digest, withdrawal_count, withdrawal_leaf_words) = family_opening(
            &mut builder, b"PsyBridge/TwoArtifact/1/WithdrawalBatch", config_hash, window_id, end_id, end_root,
            Some(&withdrawal_roots),
        );
        let (reward_digest, reward_count, reward_leaf_words) = family_opening(
            &mut builder, b"PsyBridge/SourceCheckpointReward/1/Opening", config_hash, window_id, end_id, end_root, None,
        );
        connect_child_digest(&mut builder, &withdrawal, &withdrawal_digest);
        connect_child_digest(&mut builder, &reward, &reward_digest);
        let old_reward_ledger_root = builder.add_virtual_target_arr();
        let new_reward_ledger_root = builder.add_virtual_target_arr();
        hash::encode_hash4(&mut builder, old_reward_ledger_root);
        hash::encode_hash4(&mut builder, new_reward_ledger_root);
        let economic_domain = builder.add_virtual_target_arr();
        for word in economic_domain { builder.range_check(word, 32); }
        let zero = builder.zero();
        let reward_empty = builder.is_equal(reward_count, zero);
        for (old, new) in old_reward_ledger_root.iter().zip(new_reward_ledger_root) {
            builder.connect_if_true(reward_empty, *old, new);
        }
        let opening_digest = settlement_digest(&mut builder, chain_count, config_hash, window_id, end_id, end_root,
            deposit_digest, global_deposit_root, global_withdrawal_root, &start_roots, &checkpoint_counts,
            &deposit_roots, &deposit_counts, &withdrawal_roots, withdrawal_count, reward_count,
            old_reward_ledger_root, new_reward_ledger_root, economic_domain, &withdrawal_leaf_words, &reward_leaf_words);
        let prefix = [2, 12, 2, 0].map(|value| builder.constant(F::from_canonical_u32(value)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&opening_digest);
        let circuit_data = builder.build::<C>();
        anyhow::ensure!(circuit_data.common.num_public_inputs == SETTLEMENT_AGGREGATE_PI_LEN, "settlement public width mismatch");
        Ok(Self { circuit_data, finalizations, withdrawal, reward, opening_digest, withdrawal_digest, reward_digest,
            config_hash, window_id, end_id, end_root, global_deposit_root, global_withdrawal_root, start_roots,
            checkpoint_counts, deposit_roots, deposit_counts, withdrawal_roots, old_reward_ledger_root,
            new_reward_ledger_root, economic_domain, withdrawal_count, reward_count, withdrawal_leaf_words,
            reward_leaf_words, deposit_digest })
    }

    pub fn prove(
        &self, config: &NetworkConfig, deposit: &DepositAggregateOpening, settlement: &SettlementOpening,
        finalizations: &[ProofWithPublicInputs<F, C, D>],
        withdrawal: &ProofWithPublicInputs<F, C, D>, reward: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(finalizations.len() == self.finalizations.len(), "configured finalization count mismatch");
        let digest = settlement.opening_digest(config, deposit)?;
        let mut witness = PartialWitness::new();
        set_bytes(&mut witness, &self.config_hash, &settlement.config_hash)?;
        set_bytes(&mut witness, &self.window_id, &settlement.window_id)?;
        witness.set_target(self.end_id, F::from_canonical_u64(settlement.end_checkpoint_id)).context("end id")?;
        set_hash4(&mut witness, self.end_root, settlement.end_checkpoint_root)?;
        set_u32x8(&mut witness, self.global_deposit_root, settlement.global_deposit_root)?;
        set_u32x8(&mut witness, self.global_withdrawal_root, settlement.global_withdrawal_root)?;
        for (index, slot) in settlement.finalizations.iter().enumerate() {
            set_hash4(&mut witness, self.start_roots[index], slot.start_checkpoint_root)?;
            witness.set_target(self.checkpoint_counts[index], F::from_canonical_u32(slot.checkpoint_count))?;
        }
        for (index, endpoint) in settlement.endpoints.iter().enumerate() {
            set_hash4(&mut witness, self.deposit_roots[index], endpoint.deposit_root)?;
            witness.set_target(self.deposit_counts[index], F::from_canonical_u32(endpoint.deposit_count))?;
            set_hash4(&mut witness, self.withdrawal_roots[index], endpoint.withdrawal_root)?;
        }
        set_hash4(&mut witness, self.old_reward_ledger_root, settlement.old_reward_ledger_root)?;
        set_hash4(&mut witness, self.new_reward_ledger_root, settlement.new_reward_ledger_root)?;
        set_bytes(&mut witness, &self.economic_domain, &settlement.economic_domain)?;
        witness.set_target(self.withdrawal_count, F::from_canonical_usize(settlement.withdrawals.len()))?;
        witness.set_target(self.reward_count, F::from_canonical_usize(settlement.rewards.len()))?;
        assign_leaves(&mut witness, &self.withdrawal_leaf_words, &word_leaves(&settlement.withdrawals.iter().map(|leaf| leaf.encode()).collect::<Result<Vec<_>, _>>()?)?)?;
        assign_leaves(&mut witness, &self.reward_leaf_words, &word_leaves(&settlement.rewards.iter().map(|leaf| leaf.encode()).collect::<Result<Vec<_>, _>>()?)?)?;
        set_bytes(&mut witness, &self.deposit_digest, &deposit.opening_digest(config)?)?;
        let withdrawal_opening = WithdrawalAggregateOpening {
            config_hash: settlement.config_hash, window_id: settlement.window_id,
            end_checkpoint_id: settlement.end_checkpoint_id, end_checkpoint_root: settlement.end_checkpoint_root,
            withdrawal_roots: settlement.endpoints.iter().map(|endpoint| endpoint.withdrawal_root).collect(),
            withdrawals: settlement.withdrawals.clone(),
        };
        set_bytes(&mut witness, &self.withdrawal_digest, &withdrawal_opening.opening_digest(config)?)?;
        let reward_opening = SourceCheckpointRewardOpening {
            config_hash: settlement.config_hash, window_id: settlement.window_id,
            end_checkpoint_id: settlement.end_checkpoint_id, end_checkpoint_root: settlement.end_checkpoint_root,
            leaves: settlement.rewards.clone(),
        };
        set_bytes(&mut witness, &self.reward_digest, &reward_opening.opening_digest()?)?;
        for (target, proof) in self.finalizations.iter().zip(finalizations) {
            witness.set_proof_with_pis_target(target, proof).context("finalization witness")?;
        }
        witness.set_proof_with_pis_target(&self.withdrawal, withdrawal).context("withdrawal witness")?;
        witness.set_proof_with_pis_target(&self.reward, reward).context("reward witness")?;
        let proof = self.circuit_data.prove(witness)?;
        let words = digest.chunks_exact(4).map(|bytes| F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap())));
        anyhow::ensure!(proof.public_inputs[4..].iter().copied().eq(words), "settlement public digest differs from opening");
        Ok(proof)
    }

}

fn verified_child<C: GenericConfig<D, F = F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, common: &CommonCircuitData<F, D>, verifier: &VerifierOnlyCircuitData<C, D>,
) -> ProofWithPublicInputsTarget<D>
where
    F: Extendable<D>,
    C::Hasher: AlgebraicHasher<F>,
{
    let proof = builder.add_virtual_proof_with_pis(common);
    let pinned = builder.constant_verifier_data(verifier);
    builder.verify_proof::<C>(&proof, &pinned, common);
    proof
}

fn connect_common_finalization<const D: usize>(builder: &mut CircuitBuilder<F, D>, proofs: &[ProofWithPublicInputsTarget<D>], chain_count: usize)
where
    F: Extendable<D>,
{
    let Some(first) = proofs.first() else { return };
    let endpoint_start = 26;
    for proof in &proofs[1..] {
        for index in 4..26 { builder.connect(first.public_inputs[index], proof.public_inputs[index]); }
        for index in endpoint_start..endpoint_start + 9 * chain_count {
            builder.connect(first.public_inputs[index], proof.public_inputs[index]);
        }
    }
    let _digest: HashOutTarget = HashOutTarget::from_vec(first.public_inputs[16..20].to_vec());
}

fn connect_child_digest<const D: usize>(builder: &mut CircuitBuilder<F, D>, proof: &ProofWithPublicInputsTarget<D>, digest: &Bytes32Target)
where
    F: Extendable<D>,
{
    for (child, family) in proof.public_inputs[4..12].iter().zip(digest) { builder.connect(*child, *family); }
}

fn family_opening<const D: usize>(
    builder: &mut CircuitBuilder<F, D>, domain_label: &[u8], config_hash: Bytes32Target, window_id: Bytes32Target,
    end_id: Target, end_root: [Target; 4], roots: Option<&[[Target; 4]]>,
) -> (Bytes32Target, Target, Vec<Vec<Target>>)
where
    F: Extendable<D>,
{
    let count = builder.add_virtual_target();
    builder.range_check(count, 32);
    let maximum = builder.constant(F::from_canonical_usize(MAX_PAYOUTS));
    builder.ensure_is_less_than_or_equal(32, count, maximum);
    let mut header = config_hash.to_vec();
    header.extend(window_id);
    header.extend(hash::word(builder, end_id, 32));
    header.extend(hash::encode_hash4(builder, end_root));
    if let Some(roots) = roots {
        let chain_count = builder.constant(F::from_canonical_usize(roots.len()));
        header.extend(hash::word(builder, chain_count, 32));
        for root in roots { header.extend(hash::encode_hash4(builder, *root)); }
    }
    header.extend(hash::word(builder, count, 32));
    let leaves = (0..MAX_PAYOUTS).map(|_| {
        let words = builder.add_virtual_targets(48);
        for &word in &words { builder.range_check(word, 32); }
        words
    }).collect::<Vec<_>>();
    let zero = builder.zero();
    for (index, words) in leaves.iter().enumerate() {
        let position = builder.constant(F::from_canonical_usize(index));
        let active = builder.is_less_than(32, position, count);
        let inactive = builder.not(active);
        for &word in words { builder.connect_if_true(inactive, word, zero); }
    }
    let digest = if roots.is_some() {
        hash::prefix_commitment(builder, hash::Domain::WithdrawalAggregate, &header, &leaves, count, 0)
    } else {
        let mut words = domain_bytes(builder, domain_label).to_vec();
        words.extend_from_slice(&header);
        for leaf in &leaves { words.extend_from_slice(leaf); }
        let header_bytes = builder.constant(F::from_canonical_usize(32 + header.len() * 4));
        let length = builder.mul_const_add(F::from_canonical_usize(192), count, header_bytes);
        keccak_prefix_words(builder, &words, length)
    };
    (digest, count, leaves)
}

fn domain_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, label: &[u8]) -> Bytes32Target
where
    F: Extendable<D>,
{
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(label);
    let mut digest = [0u8; 32];
    keccak.finalize(&mut digest);
    hash::constant_bytes32(builder, digest)
}

fn settlement_digest<const D: usize>(
    builder: &mut CircuitBuilder<F, D>, chain_count: usize, config_hash: Bytes32Target, window_id: Bytes32Target,
    end_id: Target, end_root: [Target; 4], deposit_digest: Bytes32Target, global_deposit_root: [Target; 8],
    global_withdrawal_root: [Target; 8], start_roots: &[[Target; 4]], checkpoint_counts: &[Target],
    deposit_roots: &[[Target; 4]], deposit_counts: &[Target], withdrawal_roots: &[[Target; 4]],
    withdrawal_count: Target, reward_count: Target, old_root: [Target; 4], new_root: [Target; 4],
    economic_domain: Bytes32Target, withdrawal_leaves: &[Vec<Target>], reward_leaves: &[Vec<Target>],
) -> Bytes32Target
where
    F: Extendable<D>,
{
    let settlement_domain = domain_bytes(builder, b"PsyBridge/TwoArtifact/2/B");
    let mut bytes = bytes32_bytes(builder, settlement_domain).to_vec();
    bytes.extend(bytes32_bytes(builder, config_hash));
    bytes.extend(bytes32_bytes(builder, window_id));
    bytes.extend(word_bytes(builder, end_id));
    bytes.extend(hash4_bytes(builder, end_root));
    bytes.extend(bytes32_bytes(builder, deposit_digest));
    for limb in global_deposit_root.into_iter().chain(global_withdrawal_root) { bytes.extend(word_bytes(builder, limb)); }
    let chain_count_word = builder.constant(F::from_canonical_usize(chain_count));
    bytes.extend(word_bytes(builder, chain_count_word));
    for (root, count) in start_roots.iter().zip(checkpoint_counts) {
        bytes.extend(hash4_bytes(builder, *root));
        bytes.extend(word_bytes(builder, *count));
    }
    for index in 0..chain_count {
        bytes.extend(hash4_bytes(builder, deposit_roots[index]));
        bytes.extend(word_bytes(builder, deposit_counts[index]));
        bytes.extend(hash4_bytes(builder, withdrawal_roots[index]));
    }
    bytes.extend(word_bytes(builder, withdrawal_count));
    bytes.extend(word_bytes(builder, reward_count));
    bytes.extend(hash4_bytes(builder, old_root));
    bytes.extend(hash4_bytes(builder, new_root));
    bytes.extend(bytes32_bytes(builder, economic_domain));
    let batch_count = chunk_count(builder, withdrawal_count, reward_count);
    bytes.extend(word_bytes(builder, batch_count));
    let root = batch_root(builder, config_hash, window_id, end_id, end_root,
        withdrawal_count, reward_count, batch_count, withdrawal_leaves, reward_leaves);
    bytes.extend(bytes32_bytes(builder, root));
    digest_words(builder, &bytes)
}

fn chunk_count<const D: usize>(builder: &mut CircuitBuilder<F, D>, withdrawal_count: Target, reward_count: Target) -> Target
where
    F: Extendable<D>,
{
    let mut total = builder.zero();
    for count in [withdrawal_count, reward_count] {
        let mut chunks = builder.zero();
        let mut covered = builder._false();
        for candidate in 0..=MAX_PAYOUTS / 32 {
            let value = builder.constant(F::from_canonical_usize(candidate));
            let product = builder.mul_const(F::from_canonical_usize(32), value);
            let reaches = builder.is_less_than_or_equal(32, count, product);
            let uncovered = builder.not(covered);
            let first = builder.and(reaches, uncovered);
            chunks = builder.select(first, value, chunks);
            covered = builder.or(covered, reaches);
        }
        total = builder.add(total, chunks);
    }
    total
}

fn batch_root<const D: usize>(
    builder: &mut CircuitBuilder<F, D>, config_hash: Bytes32Target, window_id: Bytes32Target, end_id: Target,
    end_root: [Target; 4], withdrawal_count: Target, reward_count: Target, batch_count: Target,
    withdrawal_leaves: &[Vec<Target>], reward_leaves: &[Vec<Target>],
) -> Bytes32Target
where
    F: Extendable<D>,
{
    let width = (2 * MAX_PAYOUTS / 32).next_power_of_two();
    let mut nodes = Vec::with_capacity(width);
    for ordinal in 0..width {
        let position = builder.constant(F::from_canonical_usize(ordinal));
        let active = builder.is_less_than(32, position, batch_count);
        let family = family_at(builder, position, withdrawal_count);
        let first = first_ordinal(builder, position, withdrawal_count);
        let commit = batch_commit(builder, config_hash, window_id, end_id, end_root, family, position, first,
            withdrawal_count, reward_count, withdrawal_leaves, reward_leaves);
        let leaf = batch_leaf(builder, batch_count, position, family, commit);
        let empty = batch_empty(builder, batch_count, position);
        nodes.push(std::array::from_fn(|index| builder.select(active, leaf[index], empty[index])));
    }
    let mut levels = vec![nodes];
    let mut height = 1u32;
    while levels.last().expect("batch level").len() > 1 {
        let parents = levels.last().expect("batch level").chunks_exact(2)
            .map(|pair| batch_parent(builder, height, pair[0], pair[1])).collect();
        levels.push(parents);
        height += 1;
    }
    let depth = batch_depth(builder, batch_count);
    let mut root = levels[0][0];
    for (level, nodes) in levels.iter().enumerate().skip(1) {
        let level = builder.constant(F::from_canonical_usize(level));
        let selected = builder.is_equal(depth, level);
        root = std::array::from_fn(|index| builder.select(selected, nodes[0][index], root[index]));
    }
    root
}
fn batch_depth<const D: usize>(builder: &mut CircuitBuilder<F, D>, batch_count: Target) -> Target
where
    F: Extendable<D>,
{
    let zero = builder.zero();
    let one = builder.one();
    let empty = builder.is_equal(batch_count, zero);
    let normalized = builder.select(empty, one, batch_count);
    let mut depth = builder.zero();
    let mut covered = builder._false();
    for level in 0..=6 {
        let width = builder.constant(F::from_canonical_u32(1 << level));
        let reaches = builder.is_less_than_or_equal(32, normalized, width);
        let uncovered = builder.not(covered);
        let first = builder.and(reaches, uncovered);
        let level = builder.constant(F::from_canonical_u32(level));
        depth = builder.select(first, level, depth);
        covered = builder.or(covered, reaches);
    }
    depth
}

fn family_at<const D: usize>(builder: &mut CircuitBuilder<F, D>, ordinal: Target, withdrawal_count: Target) -> Target
where
    F: Extendable<D>,
{
    let zero = builder.zero();
    let withdrawal_chunks = chunk_count(builder, withdrawal_count, zero);
    let one = builder.one();
    let next = builder.add(ordinal, one);
    let reward = builder.is_less_than(32, withdrawal_chunks, next);
    let reward_family = builder.constant(F::from_canonical_u32(3));
    let withdrawal_family = builder.constant(F::from_canonical_u32(2));
    builder.select(reward, reward_family, withdrawal_family)
}

fn first_ordinal<const D: usize>(builder: &mut CircuitBuilder<F, D>, ordinal: Target, withdrawal_count: Target) -> Target
where
    F: Extendable<D>,
{
    let zero = builder.zero();
    let withdrawal_chunks = chunk_count(builder, withdrawal_count, zero);
    let one = builder.one();
    let next = builder.add(ordinal, one);
    let in_reward = builder.is_less_than(32, withdrawal_chunks, next);
    let preceding_chunks = builder.select(in_reward, withdrawal_chunks, zero);
    let family_ordinal = builder.sub(ordinal, preceding_chunks);
    builder.mul_const(F::from_canonical_u32(32), family_ordinal)
}

fn batch_commit<const D: usize>(
    builder: &mut CircuitBuilder<F, D>, config_hash: Bytes32Target, window_id: Bytes32Target, end_id: Target,
    end_root: [Target; 4], family: Target, ordinal: Target, first: Target, withdrawal_count: Target,
    reward_count: Target, withdrawal_leaves: &[Vec<Target>], reward_leaves: &[Vec<Target>],
) -> Bytes32Target
where
    F: Extendable<D>,
{
    let mut words = domain_bytes(builder, b"PsyBridge/TwoArtifact/2/Batch").to_vec();
    words.extend(config_hash);
    words.extend(window_id);
    words.extend(hash::word(builder, end_id, 32));
    words.extend(hash::encode_hash4(builder, end_root));
    words.extend(hash::word(builder, family, 8));
    words.extend(hash::word(builder, ordinal, 32));
    words.extend(hash::word(builder, first, 32));
    let count = chunk_leaf_count(builder, first, family, withdrawal_count, reward_count);
    words.extend(hash::word(builder, count, 32));
    let header_words = words.len();
    assert_eq!(header_words, 96);
    for offset in 0..32 {
        let source = leaf_word(builder, first, offset, family, withdrawal_leaves, reward_leaves);
        words.extend(source);
    }
    let header_bytes = builder.constant(F::from_canonical_usize(header_words * 4));
    let length = builder.mul_const_add(F::from_canonical_usize(192), count, header_bytes);
    keccak_prefix_words(builder, &words, length)
}

fn chunk_leaf_count<const D: usize>(
    builder: &mut CircuitBuilder<F, D>, first: Target, family: Target, withdrawal_count: Target, reward_count: Target,
) -> Target
where
    F: Extendable<D>,
{
    let reward_family_word = builder.constant(F::from_canonical_u32(3));
    let reward_family = builder.is_equal(family, reward_family_word);
    let total = builder.select(reward_family, reward_count, withdrawal_count);
    let in_range = builder.is_less_than_or_equal(32, first, total);
    let bounded_total = builder.select(in_range, total, first);
    let remaining = builder.sub(bounded_total, first);
    let capacity = builder.constant(F::from_canonical_u32(32));
    let fits = builder.is_less_than_or_equal(32, remaining, capacity);
    builder.select(fits, remaining, capacity)
}

fn leaf_word<const D: usize>(
    builder: &mut CircuitBuilder<F, D>, first: Target, offset: usize, family: Target,
    withdrawal_leaves: &[Vec<Target>], reward_leaves: &[Vec<Target>],
) -> Vec<Target>
where
    F: Extendable<D>,
{
    let reward_family_word = builder.constant(F::from_canonical_u32(3));
    let reward_family = builder.is_equal(family, reward_family_word);
    let zero = builder.zero();
    let mut selected = vec![zero; 48];
    for index in 0..MAX_PAYOUTS {
        let position = builder.constant(F::from_canonical_usize(index));
        let offset_word = builder.constant(F::from_canonical_usize(offset));
        let selected_index = builder.add(first, offset_word);
        let chosen = builder.is_equal(position, selected_index);
        let withdrawal_family = builder.not(reward_family);
        let withdrawal_selected = builder.and(chosen, withdrawal_family);
        for (word, withdrawal) in selected.iter_mut().zip(&withdrawal_leaves[index]) {
            *word = builder.select(withdrawal_selected, *withdrawal, *word);
        }
        let reward_selected = builder.and(chosen, reward_family);
        for (word, reward) in selected.iter_mut().zip(&reward_leaves[index]) {
            *word = builder.select(reward_selected, *reward, *word);
        }
    }
    selected
}

fn batch_leaf<const D: usize>(builder: &mut CircuitBuilder<F, D>, batch_count: Target, ordinal: Target, family: Target, commit: Bytes32Target) -> Bytes32Target
where
    F: Extendable<D>,
{
    let mut words = domain_bytes(builder, b"PsyBridge/TwoArtifact/2/Leaf").to_vec();
    words.extend(hash::word(builder, batch_count, 32));
    words.extend(hash::word(builder, ordinal, 32));
    words.extend(hash::word(builder, family, 8));
    words.extend(commit);
    keccak256_u32_words_be_abi(builder, &words).map(|word| word.0)
}

fn batch_empty<const D: usize>(builder: &mut CircuitBuilder<F, D>, batch_count: Target, ordinal: Target) -> Bytes32Target
where
    F: Extendable<D>,
{
    let mut words = domain_bytes(builder, b"PsyBridge/TwoArtifact/2/Empty").to_vec();
    words.extend(hash::word(builder, batch_count, 32));
    words.extend(hash::word(builder, ordinal, 32));
    keccak256_u32_words_be_abi(builder, &words).map(|word| word.0)
}

fn batch_parent<const D: usize>(builder: &mut CircuitBuilder<F, D>, level: u32, left: Bytes32Target, right: Bytes32Target) -> Bytes32Target
where
    F: Extendable<D>,
{
    let mut words = domain_bytes(builder, b"PsyBridge/TwoArtifact/2/Node").to_vec();
    let level_word = builder.constant(F::from_canonical_u32(level));
    words.extend(hash::word(builder, level_word, 32));
    words.extend(left);
    words.extend(right);
    keccak256_u32_words_be_abi(builder, &words).map(|word| word.0)
}

fn bytes32_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, words: Bytes32Target) -> [Target; 32]
where
    F: Extendable<D>,
{
    let mut bytes = [builder.zero(); 32];
    for (index, word) in words.into_iter().enumerate() {
        let raw = raw_u32_bytes(builder, word);
        bytes[index * 4] = raw[3];
        bytes[index * 4 + 1] = raw[2];
        bytes[index * 4 + 2] = raw[1];
        bytes[index * 4 + 3] = raw[0];
    }
    bytes
}

fn word_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, value: Target) -> [Target; 32]
where
    F: Extendable<D>,
{
    let mut bytes = [builder.zero(); 32];
    let raw = raw_u32_bytes(builder, value);
    bytes[28] = raw[3];
    bytes[29] = raw[2];
    bytes[30] = raw[1];
    bytes[31] = raw[0];
    bytes
}

fn hash4_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, hash: [Target; 4]) -> Vec<Target>
where
    F: Extendable<D>,
{
    let mut bytes = Vec::with_capacity(128);
    for words in hash::encode_hash4(builder, hash).chunks_exact(8) {
        let mut word = word_bytes(builder, words[7]);
        let high = raw_u32_bytes(builder, words[6]);
        word[24..28].copy_from_slice(&[high[3], high[2], high[1], high[0]]);
        bytes.extend(word);
    }
    bytes
}

fn raw_u32_bytes<const D: usize>(builder: &mut CircuitBuilder<F, D>, value: Target) -> [Target; 4]
where
    F: Extendable<D>,
{
    let bits = builder.split_le(value, 32);
    std::array::from_fn(|index| {
        let mut byte = builder.zero();
        let mut place = builder.one();
        for bit in &bits[index * 8..(index + 1) * 8] {
            byte = builder.mul_add(bit.target, place, byte);
            place = builder.add(place, place);
        }
        byte
    })
}

fn digest_words<const D: usize>(builder: &mut CircuitBuilder<F, D>, bytes: &[Target]) -> Bytes32Target
where
    F: Extendable<D>,
{
    let digest = keccak256_bytes_targets(builder, bytes);
    std::array::from_fn(|index| {
        let raw = raw_u32_bytes(builder, digest[index].0);
        let mut word = builder.zero();
        for byte in raw { word = builder.mul_const_add(F::from_canonical_u32(256), word, byte); }
        word
    })
}

fn set_hash4(witness: &mut PartialWitness<F>, targets: [Target; 4], value: Hash4) -> anyhow::Result<()> {
    for (target, limb) in targets.iter().zip(value) { witness.set_target(*target, F::from_canonical_u64(limb))?; }
    Ok(())
}

fn set_u32x8(witness: &mut PartialWitness<F>, targets: [Target; 8], value: [u32; 8]) -> anyhow::Result<()> {
    for (target, limb) in targets.iter().zip(value) { witness.set_target(*target, F::from_canonical_u32(limb))?; }
    Ok(())
}

fn word_leaves(leaves: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
    leaves.iter().map(|bytes| {
        anyhow::ensure!(bytes.len() == 192, "settlement leaf width mismatch");
        Ok(bytes.clone())
    }).collect()
}

fn assign_leaves(witness: &mut PartialWitness<F>, targets: &[Vec<Target>], leaves: &[Vec<u8>]) -> anyhow::Result<()> {
    for (index, words) in targets.iter().enumerate() {
        if let Some(bytes) = leaves.get(index) { set_bytes(witness, words, bytes)?; }
        else { for &word in words { witness.set_target(word, F::ZERO)?; } }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    fn native_hash4(hash: Hash4) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        for (index, limb) in hash.into_iter().enumerate() {
            bytes[index * 32 + 24..index * 32 + 32].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn hash4_bytes_match_native_word_and_reject_two_word_encoding() {
        let hash = [0, u32::MAX as u64 + 7, F::ORDER - 1, 0x0102030405060708];
        let native = native_hash4(hash);
        assert_eq!(native.len(), 128);
        let mut doubled = [0u8; 256];
        for (index, limb) in hash.into_iter().enumerate() {
            doubled[index * 64 + 24..index * 64 + 32].copy_from_slice(&(limb >> 32).to_be_bytes());
            doubled[index * 64 + 56..index * 64 + 64].copy_from_slice(&(limb as u32).to_be_bytes());
        }
        assert_ne!(native.as_slice(), &doubled[..128]);
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let targets = hash.map(|limb| builder.constant(F::from_canonical_u64(limb)));
        let bytes = hash4_bytes(&mut builder, targets);
        assert_eq!(bytes.len(), 128);
        builder.register_public_inputs(&bytes);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        let proof = data.prove(PartialWitness::new()).unwrap();
        let produced = proof.public_inputs.iter().map(|limb| limb.to_canonical_u64() as u8).collect::<Vec<_>>();
        assert_eq!(produced, native);
        data.verify(proof).unwrap();
    }

    #[test]
    fn batch_depth_follows_native_power_of_two() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let count = builder.add_virtual_target();
        let depth = batch_depth(&mut builder, count);
        builder.register_public_input(depth);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        for (batch_count, expected) in [(0, 0), (1, 0), (2, 1), (3, 2), (32, 5), (33, 6), (64, 6)] {
            let mut witness = PartialWitness::new();
            witness.set_target(count, F::from_canonical_u32(batch_count)).unwrap();
            let proof = data.prove(witness).unwrap();
            assert_eq!(proof.public_inputs, [F::from_canonical_u32(expected)]);
            data.verify(proof).unwrap();
        }
    }
}

