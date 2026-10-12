//! Top bridge aggregate: pinned children and the version-4 raw opening.
//!
//! One D5-S proof, one withdrawal-claim proof, one reward-claim proof, and
//! one finalization proof per configured chain feed this circuit. The two
//! finalizer kinds share one `CommonCircuitData`; the Boolean selects only
//! their verifier data. Every opening word is copied from a verified child
//! public input. Keccak stays outside Plonky2.

use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOutTarget,
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_client_data::bridge_aggregate::deposit_aggregate_pi_len;
use psy_common_circuit::builder::comparison::CircuitBuilderComparison;
use psy_plonky2_basic_helpers::u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

use super::bridge_claim::{
    BRIDGE_CLAIM_CAPACITY, BRIDGE_REWARD_CLAIM_STATEMENT_LEN, BRIDGE_REWARD_CLAIM_WORDS,
    BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN, BRIDGE_WITHDRAWAL_CLAIM_WORDS,
};

type F = GoldilocksField;
const D: usize = 2;
const DEPOSIT_CAPACITY: usize = 32;
const OPENING_PREFIX: [u32; 4] = [4, 12, 0, 0];
const FINAL_PREFIX_LEN: usize = 18;
const FINAL_CHAIN_LEN: usize = 5;
const HEADER_WORDS: usize = 15;
const CHAIN_WORDS: usize = 16;

pub const fn bridge_aggregate_pi_len(chain_count: usize) -> usize {
    4 + 8 * (HEADER_WORDS + CHAIN_WORDS * chain_count + 7 * DEPOSIT_CAPACITY
        + BRIDGE_WITHDRAWAL_CLAIM_WORDS * BRIDGE_CLAIM_CAPACITY
        + BRIDGE_REWARD_CLAIM_WORDS * BRIDGE_CLAIM_CAPACITY)
}

pub struct BridgeChainOpeningTargets {
    pub chain_index: [U32Target; 8],
    pub start_id: [U32Target; 8],
    pub start_root: [[U32Target; 8]; 4],
    pub old_deposit_root: [[U32Target; 8]; 4],
    pub new_deposit_root: [[U32Target; 8]; 4],
    pub old_count: [U32Target; 8],
    pub new_count: [U32Target; 8],
}

pub struct BridgeOpeningTargets {
    pub prefix: [Target; 4],
    pub version: [U32Target; 8],
    pub config_hash: [U32Target; 8],
    pub end_id: [U32Target; 8],
    pub end_root: [[U32Target; 8]; 4],
    pub end_gusr: [[U32Target; 8]; 4],
    pub chain_count: [U32Target; 8],
    pub deposit_count: [U32Target; 8],
    pub withdrawal_count: [U32Target; 8],
    pub reward_count: [U32Target; 8],
    pub rows: Vec<BridgeChainOpeningTargets>,
    pub deposits: [[[U32Target; 8]; 7]; DEPOSIT_CAPACITY],
    pub withdrawals: [[[U32Target; 8]; BRIDGE_WITHDRAWAL_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY],
    pub rewards: [[[U32Target; 8]; BRIDGE_REWARD_CLAIM_WORDS]; BRIDGE_CLAIM_CAPACITY],
    pub zero_span: Vec<BoolTarget>,
}


pub struct BridgeAggregateCircuit<C: GenericConfig<D, F = F>>
where
    F: Extendable<D>,
{
    pub circuit_data: CircuitData<F, C, D>,
    pub targets: BridgeOpeningTargets,
    deposit: ProofWithPublicInputsTarget<D>,
    withdrawal: ProofWithPublicInputsTarget<D>,
    reward: ProofWithPublicInputsTarget<D>,
    finalizations: Vec<ProofWithPublicInputsTarget<D>>,
    chain_indices: Vec<u8>,
}

impl<C: GenericConfig<D, F = F>> BridgeAggregateCircuit<C>
where
    F: Extendable<D>,
    C::Hasher: AlgebraicHasher<F>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_indices: &[u8],
        deposit: &CommonCircuitData<F, D>,
        deposit_verifier: &VerifierOnlyCircuitData<C, D>,
        withdrawal: &CommonCircuitData<F, D>,
        withdrawal_verifier: &VerifierOnlyCircuitData<C, D>,
        reward: &CommonCircuitData<F, D>,
        reward_verifier: &VerifierOnlyCircuitData<C, D>,
        positive_common: &CommonCircuitData<F, D>,
        positive_verifier: &VerifierOnlyCircuitData<C, D>,
        membership_common: &CommonCircuitData<F, D>,
        membership_verifier: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<Self> {
        let chain_count = chain_indices.len();
        anyhow::ensure!((1..=8).contains(&chain_count), "configured chain count must be 1..=8");
        anyhow::ensure!(chain_indices.windows(2).all(|pair| pair[0] < pair[1]), "configured chain indices must be strictly increasing");
        anyhow::ensure!(deposit.num_public_inputs == deposit_aggregate_pi_len(chain_count), "deposit aggregate width differs from configured chain count");
        anyhow::ensure!(withdrawal.num_public_inputs == BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN, "withdrawal claim width mismatch");
        anyhow::ensure!(reward.num_public_inputs == BRIDGE_REWARD_CLAIM_STATEMENT_LEN, "reward claim width mismatch");
        let final_width = FINAL_PREFIX_LEN + FINAL_CHAIN_LEN * chain_count;
        anyhow::ensure!(positive_common.num_public_inputs == final_width && membership_common.num_public_inputs == final_width, "finalization width differs from 18+5*C");
        anyhow::ensure!(positive_common == membership_common, "positive and membership finalizers must share one common circuit");
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let deposit_proof = verified(&mut builder, deposit, deposit_verifier);
        let withdrawal_proof = verified(&mut builder, withdrawal, withdrawal_verifier);
        let reward_proof = verified(&mut builder, reward, reward_verifier);
        let positive_verifier = builder.constant_verifier_data(positive_verifier);
        let membership_verifier = builder.constant_verifier_data(membership_verifier);
        let mut finalizations = Vec::with_capacity(chain_count);
        let mut zero_span = Vec::with_capacity(chain_count);
        for _ in 0..chain_count {
            let proof = builder.add_virtual_proof_with_pis(positive_common);
            let branch = builder.add_virtual_bool_target_safe();
            let verifier = select_verifier(&mut builder, branch, &membership_verifier, &positive_verifier);
            builder.verify_proof::<C>(&proof, &verifier, positive_common);
            finalizations.push(proof);
            zero_span.push(branch);
        }
        let targets = bind_opening(&mut builder, chain_indices, &deposit_proof, &withdrawal_proof, &reward_proof, &finalizations, &zero_span);
        register_opening(&mut builder, &targets);
        let circuit_data = builder.build::<C>();
        anyhow::ensure!(circuit_data.common.num_public_inputs == bridge_aggregate_pi_len(chain_count), "bridge aggregate width mismatch");
        Ok(Self {
            circuit_data, targets, deposit: deposit_proof, withdrawal: withdrawal_proof, reward: reward_proof,
            finalizations, chain_indices: chain_indices.to_vec(),
        })
    }

    pub fn prove(
        &self,
        deposit: &ProofWithPublicInputs<F, C, D>,
        withdrawal: &ProofWithPublicInputs<F, C, D>,
        reward: &ProofWithPublicInputs<F, C, D>,
        finalizations: &[ProofWithPublicInputs<F, C, D>],
        zero_span: &[bool],
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(finalizations.len() == self.chain_indices.len() && zero_span.len() == self.chain_indices.len(), "finalization count differs from configured chains");
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.deposit, deposit)?;
        witness.set_proof_with_pis_target(&self.withdrawal, withdrawal)?;
        witness.set_proof_with_pis_target(&self.reward, reward)?;
        for (index, proof) in finalizations.iter().enumerate() {
            witness.set_bool_target(self.targets.zero_span[index], zero_span[index])?;
            witness.set_proof_with_pis_target(&self.finalizations[index], proof)?;
        }
        self.circuit_data.prove(witness)
    }
}

fn verified<C: GenericConfig<D, F = F>>(
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

fn select_verifier<const D2: usize>(
    builder: &mut CircuitBuilder<F, D2>, condition: BoolTarget, selected: &VerifierCircuitTarget, other: &VerifierCircuitTarget,
) -> VerifierCircuitTarget
where
    F: Extendable<D2>,
{
    let mut verifier = selected.clone();
    verifier.circuit_digest = HashOutTarget { elements: std::array::from_fn(|index| builder.select(condition, selected.circuit_digest.elements[index], other.circuit_digest.elements[index])) };
    for (selected_cap, other_cap) in verifier.constants_sigmas_cap.0.iter_mut().zip(&other.constants_sigmas_cap.0) {
        *selected_cap = HashOutTarget { elements: std::array::from_fn(|index| builder.select(condition, selected_cap.elements[index], other_cap.elements[index])) };
    }
    verifier
}

fn bind_opening<const D2: usize>(
    builder: &mut CircuitBuilder<F, D2>, chains: &[u8], deposit: &ProofWithPublicInputsTarget<D2>,
    withdrawal: &ProofWithPublicInputsTarget<D2>, reward: &ProofWithPublicInputsTarget<D2>,
    finalizations: &[ProofWithPublicInputsTarget<D2>], zero_span: &[BoolTarget],
) -> BridgeOpeningTargets
where
    F: Extendable<D2>,
{
    let deposit_pi = &deposit.public_inputs;
    for (target, value) in deposit_pi[..4].iter().zip([2u32, 11, 1, 0]) {
        let expected = builder.constant(F::from_canonical_u32(value));
        builder.connect(*target, expected);
    }
    let config_hash = copy_u32s(builder, &deposit_pi[4..12]);
    let zero = builder.zero();
    builder.connect(deposit_pi[21], zero);
    let end_id = project_u64(builder, [deposit_pi[20], deposit_pi[21]]);
    let end_root = [22, 23, 24, 25].map(|offset| project_field(builder, deposit_pi[offset]));
    let deposit_count = project_u32(builder, deposit_pi[26]);
    let mut rows = Vec::with_capacity(chains.len());
    let mut published_gusr: Option<[[U32Target; 8]; 4]> = None;
    for (index, &chain) in chains.iter().enumerate() {
        let base = 27 + 17 * index;
        let row = &deposit_pi[base..base + 17];
        let expected_chain = builder.constant(F::from_canonical_u8(chain));
        builder.connect(row[0], expected_chain);
        builder.connect(row[2], zero);
        let selected = &finalizations[index].public_inputs;
        builder.connect(selected[16], end_id[7].0);
        for (offset, word) in end_root.iter().enumerate() { connect_field(builder, selected[12 + offset], word); }
        let gusr = [4, 5, 6, 7].map(|offset| project_field(builder, selected[offset]));
        if let Some(first) = &published_gusr {
            for (left, right) in first.iter().zip(&gusr) { connect_word(builder, left, right); }
        } else {
            published_gusr = Some(gusr);
        }
        for (offset, word) in (8..12).enumerate() {
            let projected = project_field(builder, withdrawal.public_inputs[10 + offset]);
            connect_field(builder, selected[word], &projected);
        }
        let endpoint = 18 + FINAL_CHAIN_LEN * index;
        let endpoint_root = [0, 1, 2, 3].map(|limb| project_field(builder, selected[endpoint + limb]));
        let endpoint_count = project_u32(builder, selected[endpoint + 4]);
        let start_id = project_u64(builder, [row[1], row[2]]);
        let start_root = [3, 4, 5, 6].map(|offset| project_field(builder, row[offset]));
        let old_root = [7, 8, 9, 10].map(|offset| project_field(builder, row[offset]));
        let new_root = [11, 12, 13, 14].map(|offset| project_field(builder, row[offset]));
        let old_count = project_u32(builder, row[15]);
        let new_count = project_u32(builder, row[16]);
        for (endpoint_word, published) in endpoint_root.iter().zip(&new_root) { connect_word(builder, endpoint_word, published); }
        connect_word(builder, &endpoint_count, &new_count);
        for (old, new) in old_root.iter().zip(&new_root) { connect_word_if(builder, zero_span[index], old, new); }
        connect_word_if(builder, zero_span[index], &old_count, &new_count);
        let span_zero = builder.is_equal(selected[17], zero);
        let span_positive = builder.not(span_zero);
        let selected_span = builder.select(zero_span[index], span_zero.target, span_positive.target);
        let one = builder.one();
        builder.connect(selected_span, one);
        connect_if(builder, zero_span[index], start_id[7].0, end_id[7].0);
        for (start, end) in start_root.iter().zip(&end_root) { connect_word_if(builder, zero_span[index], start, end); }
        rows.push(BridgeChainOpeningTargets {
            chain_index: project_u32(builder, row[0]), start_id, start_root,
            old_deposit_root: old_root, new_deposit_root: new_root, old_count, new_count,
        });
    }
    let leaf_base = 27 + 17 * chains.len();
    let mut deposits = [[[builder.zero_u32(); 8]; 7]; DEPOSIT_CAPACITY];
    for slot in 0..DEPOSIT_CAPACITY {
        let leaf = &deposit_pi[leaf_base + 39 * slot..leaf_base + 39 * (slot + 1)];
        deposits[slot] = [
            project_u32(builder, leaf[0]), project_u32(builder, leaf[1]), copy_u32s(builder, &leaf[2..10]),
            padded_address(builder, &leaf[10..15]), copy_u32s(builder, &leaf[15..23]),
            copy_u32s(builder, &leaf[23..31]), copy_u32s(builder, &leaf[31..39]),
        ];
    }
    let withdrawals = claim_words::<D2, BRIDGE_WITHDRAWAL_CLAIM_WORDS>(builder, &withdrawal.public_inputs[14..]);
    let rewards = claim_words::<D2, BRIDGE_REWARD_CLAIM_WORDS>(builder, &reward.public_inputs[6..]);
    for proof in [withdrawal, reward] {
        builder.connect(proof.public_inputs[1], end_id[7].0);
        for (offset, word) in end_root.iter().enumerate() { connect_field(builder, proof.public_inputs[2 + offset], word); }
    }
    let end_gusr = published_gusr.expect("at least one configured chain");
    for (offset, word) in end_gusr.iter().enumerate() { connect_field(builder, withdrawal.public_inputs[6 + offset], word); }
    BridgeOpeningTargets {
        prefix: OPENING_PREFIX.map(|value| builder.constant(F::from_canonical_u32(value))),
        version: constant_word(builder, 4), config_hash, end_id, end_root, end_gusr,
        chain_count: constant_word(builder, chains.len() as u32), deposit_count,
        withdrawal_count: project_u32(builder, withdrawal.public_inputs[0]),
        reward_count: project_u32(builder, reward.public_inputs[0]),
        rows, deposits, withdrawals, rewards, zero_span: zero_span.to_vec(),
    }
}


fn register_opening<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, targets: &BridgeOpeningTargets)
where
    F: Extendable<D2>,
{
    builder.register_public_inputs(&targets.prefix);
    for word in header_words(targets).into_iter()
        .chain(targets.rows.iter().flat_map(row_words))
        .chain(targets.deposits.iter().flatten().copied())
        .chain(targets.withdrawals.iter().flatten().copied())
        .chain(targets.rewards.iter().flatten().copied())
    {
        builder.register_public_inputs(&word.map(|limb| limb.0));
    }
}

fn header_words(targets: &BridgeOpeningTargets) -> [[U32Target; 8]; HEADER_WORDS] {
    let mut words = [targets.version; HEADER_WORDS];
    words[0] = targets.version;
    words[1] = targets.config_hash;
    words[2] = targets.end_id;
    words[3..7].copy_from_slice(&targets.end_root);
    words[7..11].copy_from_slice(&targets.end_gusr);
    words[11] = targets.chain_count;
    words[12] = targets.deposit_count;
    words[13] = targets.withdrawal_count;
    words[14] = targets.reward_count;
    words
}

fn row_words(row: &BridgeChainOpeningTargets) -> [[U32Target; 8]; CHAIN_WORDS] {
    let mut words = [row.chain_index; CHAIN_WORDS];
    words[0] = row.chain_index;
    words[1] = row.start_id;
    words[2..6].copy_from_slice(&row.start_root);
    words[6..10].copy_from_slice(&row.old_deposit_root);
    words[10..14].copy_from_slice(&row.new_deposit_root);
    words[14] = row.old_count;
    words[15] = row.new_count;
    words
}

fn claim_words<const D2: usize, const WORDS: usize>(builder: &mut CircuitBuilder<F, D2>, inputs: &[Target]) -> [[[U32Target; 8]; WORDS]; BRIDGE_CLAIM_CAPACITY]
where
    F: Extendable<D2>,
{
    let mut claims = [[[builder.zero_u32(); 8]; WORDS]; BRIDGE_CLAIM_CAPACITY];
    for slot in 0..BRIDGE_CLAIM_CAPACITY {
        for word in 0..WORDS {
            let start = (slot * WORDS + word) * 8;
            claims[slot][word] = copy_u32s(builder, &inputs[start..start + 8]);
        }
    }
    claims
}

fn copy_u32s<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, inputs: &[Target]) -> [U32Target; 8]
where
    F: Extendable<D2>,
{
    let mut word = [builder.zero_u32(); 8];
    for (limb, input) in inputs.iter().enumerate() {
        builder.range_check(*input, 32);
        word[limb] = U32Target(*input);
    }
    word
}

fn padded_address<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, inputs: &[Target]) -> [U32Target; 8]
where
    F: Extendable<D2>,
{
    let mut word = [builder.zero_u32(); 8];
    for (index, input) in inputs.iter().enumerate() {
        builder.range_check(*input, 32);
        word[3 + index] = U32Target(*input);
    }
    word
}

fn project_u32<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, value: Target) -> [U32Target; 8]
where
    F: Extendable<D2>,
{
    builder.range_check(value, 32);
    let mut word = [builder.zero_u32(); 8];
    word[7] = U32Target(value);
    word
}

fn project_u64<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, value: [Target; 2]) -> [U32Target; 8]
where
    F: Extendable<D2>,
{
    for limb in value { builder.range_check(limb, 32); }
    let mut word = [builder.zero_u32(); 8];
    word[6] = U32Target(value[1]);
    word[7] = U32Target(value[0]);
    word
}

fn project_field<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, value: Target) -> [U32Target; 8]
where
    F: Extendable<D2>,
{
    let (low, high) = builder.split_low_high(value, 32, 64);
    let max_u32 = builder.constant(F::from_canonical_u32(u32::MAX));
    let saturated = builder.is_equal(high, max_u32);
    let saturated_low = builder.mul(saturated.target, low);
    let zero = builder.zero();
    builder.connect(saturated_low, zero);
    let mut word = [builder.zero_u32(); 8];
    word[6] = U32Target(high);
    word[7] = U32Target(low);
    word
}

fn connect_field<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, value: Target, word: &[U32Target; 8])
where
    F: Extendable<D2>,
{
    let limb_base = builder.constant(F::from_canonical_u64(1u64 << 32));
    let shifted = builder.mul(word[6].0, limb_base);
    let combined = builder.add(shifted, word[7].0);
    builder.connect(value, combined);
}

fn connect_word<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, left: &[U32Target; 8], right: &[U32Target; 8])
where
    F: Extendable<D2>,
{
    for index in 0..8 { builder.connect(left[index].0, right[index].0); }
}

fn connect_word_if<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, active: BoolTarget, left: &[U32Target; 8], right: &[U32Target; 8])
where
    F: Extendable<D2>,
{
    for index in 0..8 { connect_if(builder, active, left[index].0, right[index].0); }
}

fn connect_if<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, active: BoolTarget, left: Target, right: Target)
where
    F: Extendable<D2>,
{
    let selected = builder.select(active, right, left);
    builder.connect(left, selected);
}

fn constant_word<const D2: usize>(builder: &mut CircuitBuilder<F, D2>, value: u32) -> [U32Target; 8]
where
    F: Extendable<D2>,
{
    let mut word = [builder.zero_u32(); 8];
    word[7] = builder.constant_u32(value);
    word
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_width_matches_frozen_opening() {
        assert_eq!(bridge_aggregate_pi_len(0), 8316);
        assert_eq!(bridge_aggregate_pi_len(1), 8444);
        assert_eq!(bridge_aggregate_pi_len(8), 9340);
        assert_eq!(8316 + 128 * 8, 9340);
    }


    #[test]
    fn aggregate_authenticates_both_finalizer_branches() {
        use plonky2::{field::types::PrimeField64, hash::{hash_types::HashOut, poseidon::PoseidonHash}, plonk::config::{Hasher, PoseidonGoldilocksConfig}};
        use psy_client_data::qdata::{checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf}, contract::PsyContractLeaf, user::PsyUserLeaf};
        use psy_data::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeafCompact};
        use psy_client_common::data::qhashout::QHashOut as ClientHash;
        use psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit;
        use psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT;
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        use parth_core::crypto::hash::merkle_proof::MerkleProofCore;
        use psy_plonky2_basic_helpers::builder::pad_circuit::CircuitBuilderQEDCommonGates;
        use super::super::{
            bridge_agg_chain::{BridgeAggChainBoundary, BridgeAggChainCircuit},
            bridge_agg_final::{build_shared_finalizers, tests as final_tests, BridgeAggFinalEndpointWitness, BridgeAggFinalSlotWitness},
            bridge_claim::{BridgeRewardClaimCircuit, BridgeRewardClaimInput, BridgeRewardClaimWitness, BridgeTokenPolicy, BridgeWithdrawalClaimCircuit, BridgeWithdrawalClaimInput},
            deposit_aggregate::DepositAggregateCircuit,
            reward_chain::{tests as reward_tests, RewardMergeCircuit, RewardMergeWitness, RewardRootCircuit, RewardRootWitness, RewardSegmentCircuit, REWARD_ROOT_STATEMENT_LEN},
            reward_claim_batch::{RewardClaimBatchCircuit, RewardClaimBatchMode, RewardClaimBatchWitness},
        };
        use crate::proof_minifier::pm_core::get_circuit_fingerprint_generic;
        use crate::qstandard::QStandardCircuit;
        use psy_client_data::bridge_aggregate::{ChainConfig, ChainStart, DepositAggregateOpening, DepositTransition, NetworkConfig};
        use parth_core::pgoldilocks::QHashOut;
        type TestConfig = PoseidonGoldilocksConfig;
        const CHECKPOINT_HEIGHT: usize = 32;
        const BRIDGE_USER: u64 = 524_288;
        const USER_HEIGHT: usize = GLOBAL_USER_TREE_HEIGHT as usize;
        const CONTRACT_HEIGHT: usize = 2;
        const STATE_HEIGHT: usize = final_tests::TEST_CONTRACT_STATE_TREE_HEIGHT;

        fn hash_two(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F> { QHashOut(<plonky2::plonk::config::PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(left.0, right.0)) }
        fn words(value: HashOut<F>) -> [u64; 4] { value.elements.map(|limb| limb.to_canonical_u64()) }
        fn word(value: u64) -> [u8; 32] { let mut bytes = [0; 32]; bytes[24..].copy_from_slice(&value.to_be_bytes()); bytes }

        let chain_index = 0u8;
        // All consumers open the same state: the reward identity and bridge owner
        // coexist in GUSR, and both legacy and endpoint slots open one empty CSTATE.
        let (mut deposit_root, mut deposit_count) = final_tests::endpoint_fixture(2, chain_index, 0, [0; 8]);
        let private_key = QHashOut::from_values(17, 23, 31, 47);
        let param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&ClientHash(private_key.0));
        let identity = PsyBasicZKSignatureCircuit::<TestConfig, D>::new().fingerprint.0;
        let mut user = PsyUserLeaf::default();
        user.user_id = F::from_canonical_u32(7);
        user.public_key = ClientHash(PoseidonHash::two_to_one(identity, param.0));
        let users = [(7, user.qfhash::<PoseidonHash>().0), (BRIDGE_USER, final_tests::user_leaf_hash(&deposit_root.user_leaf).0)].into_iter().collect::<reward_tests::Leaves>();
        let (user_siblings, user_root) = reward_tests::path::<USER_HEIGHT>(&users, 7, HashOut::ZERO);
        let (bridge_siblings, bridge_root) = reward_tests::path::<USER_HEIGHT>(&users, BRIDGE_USER, HashOut::ZERO);
        assert_eq!(user_root, bridge_root);
        deposit_root.user_tree_proof = MerkleProofCore {
            root: QHashOut(user_root), value: final_tests::user_leaf_hash(&deposit_root.user_leaf),
            index: BRIDGE_USER, siblings: bridge_siblings.into_iter().map(QHashOut).collect(),
        };
        deposit_count.user_tree_proof = deposit_root.user_tree_proof.clone();
        let mut legacy_deposit_root = deposit_root.clone();
        let state_leaves = [(0, QHashOut::ZERO), (1, QHashOut::ZERO), (16_386, QHashOut::ZERO), (16_451, QHashOut::ZERO), (16_452, QHashOut::ZERO)].into_iter().collect();
        legacy_deposit_root.slot0_proof = final_tests::sparse_merkle_proof(&state_leaves, 0, STATE_HEIGHT);
        legacy_deposit_root.slot1_proof = final_tests::sparse_merkle_proof(&state_leaves, 1, STATE_HEIGHT);
        assert_eq!(legacy_deposit_root.slot0_proof.root, deposit_root.slot0_proof.root);
        assert_eq!(legacy_deposit_root.slot1_proof.root, deposit_root.slot1_proof.root);
        let endpoint_witness = BridgeAggFinalEndpointWitness { chain_index, deposit_root, deposit_count };
        let gusr = QHashOut(user_root);
        let gcon = final_tests::zero_hash(psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        let roots = PQEDCheckpointGlobalStateRoots { contract_tree_root: gcon, deposit_tree_root: final_tests::empty_deposit_root(), user_tree_root: gusr, withdrawal_tree_root: final_tests::zero_hash(32), user_registration_tree_root: final_tests::zero_hash(32), validator_tree_root: final_tests::zero_hash(20) };
        let global_roots = PsyCheckpointGlobalStateRoots {
            contract_tree_root: ClientHash(roots.contract_tree_root.0), deposit_tree_root: ClientHash(roots.deposit_tree_root.0),
            user_tree_root: ClientHash(roots.user_tree_root.0), withdrawal_tree_root: ClientHash(roots.withdrawal_tree_root.0),
            user_registration_tree_root: ClientHash(roots.user_registration_tree_root.0), validator_tree_root: ClientHash(roots.validator_tree_root.0),
        };
        let mut anchor_leaf = PsyCheckpointLeaf::default();
        anchor_leaf.global_chain_root = global_roots.qfhash::<PoseidonHash>();
        let leaf = PQEDCheckpointLeafCompact { global_chain_root: QHashOut(anchor_leaf.global_chain_root.0), stats_hash: QHashOut(anchor_leaf.stats.qfhash::<PoseidonHash>().0) };
        let leaf_hash = QHashOut(anchor_leaf.qfhash::<PoseidonHash>().0);
        assert_eq!(leaf_hash, final_tests::compact_leaf_hash(&leaf));
        assert_eq!(leaf.global_chain_root, final_tests::global_roots_hash(&roots));

        let segment_circuit = RewardSegmentCircuit::new();
        let merge_circuit = RewardMergeCircuit::new(&segment_circuit);
        let root_circuit = RewardRootCircuit::new(&merge_circuit);
        let mut fixture = reward_tests::Fixture::for_user(7, 12);
        fixture.checkpoints.remove(&1024);
        fixture.checkpoints.remove(&2048);
        // Append-only delta12 requires nonempty left subtrees at levels 2 and 3.
        // Populate the earlier prefix with full empty checkpoint leaves, not zero leaves.
        let empty_checkpoint = PsyCheckpointLeaf::<F>::default().qfhash::<PoseidonHash>().0;
        for checkpoint_id in 0..10 { fixture.checkpoints.insert(checkpoint_id, empty_checkpoint); }
        fixture.checkpoints.insert(12, leaf_hash.0);
        let anchor_siblings = reward_tests::path::<32>(&fixture.checkpoints, 12, HashOut::ZERO).0;
        let segment_proof = segment_circuit.prove(&fixture.node(10, 0..1)).unwrap();
        let merge_proof = merge_circuit.prove(&RewardMergeWitness::Leaf { segment: segment_proof }).unwrap();
        let root_proof = root_circuit.prove(&RewardRootWitness {
            recipient: [1, 2, 3, 4, 5, 0, 0, 0], anchor_checkpoint_id: 12, anchor_leaf,
            anchor_siblings, global_roots, user_leaf: user, user_siblings, private_key: private_key.0, merge_proof,
        }).unwrap();
        let endpoint_root = HashOut { elements: root_proof.public_inputs[26..30].try_into().unwrap() };
        let batch = RewardClaimBatchCircuit::new(root_circuit.get_common_circuit_data_ref(), root_circuit.get_verifier_config_ref());
        let batch_proof = batch.prove(&RewardClaimBatchWitness { mode: RewardClaimBatchMode::Leaf, statements: vec![root_proof.public_inputs[..REWARD_ROOT_STATEMENT_LEN].try_into().unwrap()], tip: Some(root_proof), children: None }).unwrap();
        let reward = BridgeRewardClaimCircuit::new(batch.get_common_circuit_data_ref(), batch.get_verifier_config_ref(), chain_index);
        let reward_proof = reward.prove(&BridgeRewardClaimInput { end_checkpoint_id: 12, end_checkpoint_root: endpoint_root, claims: vec![BridgeRewardClaimWitness { statement_index: 0, anchor_checkpoint_id: 12, anchor_leaf: leaf_hash.0, anchor_siblings }], batch_proof }).unwrap();

        let prior = std::array::from_fn(|index| QHashOut(fixture.checkpoints[&(index as u64)]));
        let delta = final_tests::height32_delta_ending_at_12(&prior, leaf_hash);
        let before = delta.old_root;
        assert_eq!(delta.new_root.0, endpoint_root);

        let chain = BridgeAggChainCircuit::<TestConfig, D>::new(QHashOut::ZERO, CHECKPOINT_HEIGHT);
        let boundary = BridgeAggChainBoundary { chain_hash: QHashOut::ZERO, checkpoint_tree_root: before, checkpoint_leaf_hash: QHashOut::ZERO, checkpoint_index: 11 };
        let base = chain.prove_base(boundary, &delta).unwrap();
        // Test-only four-PI dependency: genuinely proved under its pinned VK,
        // not a production checkpoint transition or E2E claim.
        let mut checkpoint = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let checkpoint_inputs = checkpoint.add_virtual_targets(4);
        checkpoint.register_public_inputs(&checkpoint_inputs);
        checkpoint.add_qed_type_d_common_gates();
        let checkpoint = checkpoint.build::<TestConfig>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&checkpoint.verifier_only));
        let commitment = hash_two(QHashOut::ZERO, hash_two(hash_two(delta.new_root, leaf_hash), QHashOut::ZERO));
        let mut checkpoint_witness = PartialWitness::new();
        for (target, value) in checkpoint.prover_only.public_inputs.iter().zip(commitment.0.elements) { checkpoint_witness.set_target(*target, value).unwrap(); }
        let checkpoint_proof = checkpoint.prove(checkpoint_witness).unwrap();
        let (positive, membership) = build_shared_finalizers::<TestConfig, D>(
            chain.get_common_circuit_data_ref(), chain.get_verifier_config_ref().constants_sigmas_cap.height(), chain.get_fingerprint(),
            &checkpoint.common, checkpoint.verifier_only.constants_sigmas_cap.height(), fingerprint, QHashOut::ZERO,
            CHECKPOINT_HEIGHT, USER_HEIGHT, CONTRACT_HEIGHT, STATE_HEIGHT, &[chain_index]);
        let positive_proof = positive.prove_base(&base, chain.get_verifier_config_ref(), &[BridgeAggFinalSlotWitness { checkpoint_delta_merkle_proof: &delta }], &checkpoint_proof, &checkpoint.verifier_only, &leaf, &roots, &legacy_deposit_root, &[endpoint_witness.clone()]).unwrap();
        let member_path = MerkleProofCore { root: delta.new_root, value: leaf_hash, index: 12, siblings: delta.siblings.clone() };
        let membership_proof = membership.prove(&leaf, &member_path, &roots, &[endpoint_witness], delta.new_root.0).unwrap();

        let empty_deposit = words(final_tests::empty_deposit_root().0);
        let endpoint_words = words(endpoint_root);
        let network = NetworkConfig { version: 1, network_magic: 0, bridge_user_id: BRIDGE_USER as u32, circuit_set_hash: [7; 32], chains: vec![ChainConfig { chain_index, chain_id: word(1), bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: empty_deposit }], ethereum_index: chain_index, reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: [1; 32], reward_token_decimals: 0, max_withdrawals: 1, max_rewards: 1 };
        let hash = network.config_hash().unwrap();
        let deposit = DepositAggregateCircuit::<TestConfig, D>::new(1);
        let mut proofs = Vec::new();
        for start in [11u32, 12] {
            let mut opening = DepositAggregateOpening { config_hash: hash, window_id: [0; 32], end_checkpoint_id: 12, end_checkpoint_root: endpoint_words, starts: vec![ChainStart { chain_index, start_checkpoint_id: start, start_checkpoint_root: if start == 11 { words(before.0) } else { endpoint_words } }], deposits: vec![DepositTransition { chain_index, old_root: empty_deposit, new_root: empty_deposit, old_count: 0, new_count: 0 }], deposit_leaves: Vec::new() };
            opening.window_id = opening.window_id().unwrap();
            proofs.push(deposit.prove(&network, &opening, &[]).unwrap());
        }
        let policy = BridgeTokenPolicy { chain_index, token_contract_id: 7, token_address: [0; 8], approved_leaf: PsyContractLeaf { state_tree_height: F::from_canonical_usize(32), ..PsyContractLeaf::default() }, map_base: 0, capacity: 1 };
        let withdrawal = BridgeWithdrawalClaimCircuit::new(vec![policy]).unwrap();
        let withdrawal_proof = withdrawal.prove(&BridgeWithdrawalClaimInput { end_checkpoint_id: 12, end_checkpoint_root: endpoint_root, end_gusr: gusr.0, end_gcon: gcon.0, claims: Vec::new() }).unwrap();
        let aggregate = BridgeAggregateCircuit::<TestConfig>::new(&[chain_index], &deposit.circuit_data.common, &deposit.circuit_data.verifier_only, &withdrawal.circuit_data.common, &withdrawal.circuit_data.verifier_only, &reward.circuit_data.common, &reward.circuit_data.verifier_only, &positive.circuit_data.common, &positive.circuit_data.verifier_only, &membership.circuit_data.common, &membership.circuit_data.verifier_only).unwrap();
        for (branch, proof, deposit_proof) in [(false, positive_proof, proofs.remove(0)), (true, membership_proof, proofs.remove(0))] {
            let output = aggregate.prove(&deposit_proof, &withdrawal_proof, &reward_proof, std::slice::from_ref(&proof), &[branch]).unwrap();
            aggregate.circuit_data.verify(output).unwrap();
            let mut corrupt = proof.clone();
            corrupt.proof.openings.quotient_polys[0].0[0] += F::ONE;
            assert_eq!(corrupt.public_inputs, proof.public_inputs);
            assert!(aggregate.prove(&deposit_proof, &withdrawal_proof, &reward_proof, std::slice::from_ref(&corrupt), &[branch]).is_err());
        }
    }
}
