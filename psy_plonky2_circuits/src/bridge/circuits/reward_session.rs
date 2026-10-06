use anyhow::Context;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::HashOutTarget, hashing::PlonkyPermutation, poseidon::{PoseidonHash, PoseidonPermutation}},
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget},
        config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputsTarget},
};
use psy_client_data::bridge_aggregate::{origin_state_root, REWARD_SESSION_PROOF_FIELD_COUNT};
use psy_plonky2_basic_helpers::builder::{connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore, select::CircuitBuilderSelectHelpers};
use psy_common_circuit::traits::CreatableTarget;
use psy_network_circuit::gadgets::qdata::{checkpoint::PsyCheckpointLeafGadget,
    checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget, user::PsyUserLeafGadget};
use super::historical_merkle_proof::{historical_merkle_proof, HistoricalMerkleProofTarget};
use psy_plonky2_common_circuits::{
    bridge::aggregate_commitment::RewardLeafTarget,
    hash::merkle::gadgets::delta_merkle_proof::DeltaMerkleProofGadget,
};
use super::reward_inclusion::RewardTagTarget;
use psy_plonky2_common_circuits::hash::keccak::keccak256_bytes_targets;
use psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget};
use psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT;
use psy_common_circuit::crypto::secp256k1::gadget::Secp256K1Gadget;
use psy_ups_circuit::signature::reward_authorization::constrain_signature;

type F = GoldilocksField;

pub const REWARD_SESSION_STEP_CAPACITY: usize = 1;

struct RewardSessionStatement {
    fields: [Target; REWARD_SESSION_PROOF_FIELD_COUNT],
}

impl RewardSessionStatement {
    fn new(builder: &mut CircuitBuilder<F, 2>) -> Self {
        let fields = builder.add_virtual_target_arr();
        for index in 4..22 {
            builder.range_check(fields[index], 32);
        }
        for index in 10..13 {
            builder.assert_zero(fields[index]);
        }
        Self { fields }
    }

    fn hash(&self, offset: usize) -> HashOutTarget {
        HashOutTarget { elements: std::array::from_fn(|i| self.fields[offset + i]) }
    }

    fn amount(&self) -> [Target; 8] {
        std::array::from_fn(|i| self.fields[13 + i])
    }
}

fn add_u32_limbs(
    builder: &mut CircuitBuilder<F, 2>, left: [Target; 8], right: [Target; 8],
) -> [Target; 8] {
    let mut carry = builder.zero();
    let sum = std::array::from_fn(|index| {
        builder.range_check(left[index], 32);
        builder.range_check(right[index], 32);
        let total = builder.add_many([left[index], right[index], carry]);
        let bits = builder.split_le(total, 33);
        carry = bits[32].target;
        builder.le_sum(bits[..32].iter())
    });
    builder.assert_zero(carry);
    sum
}

fn append_u32_bytes(builder: &mut CircuitBuilder<F, 2>, bytes: &mut Vec<Target>, value: Target) {
    let bits = builder.split_le(value, 32);
    for byte in bits.chunks_exact(8) {
        bytes.push(builder.le_sum(byte.iter()));
    }
}

fn append_hash_bytes(builder: &mut CircuitBuilder<F, 2>, bytes: &mut Vec<Target>, value: HashOutTarget) {
    for limb in value.elements {
        let (low, high) = builder.split_low_high(limb, 32, 64);
        let maximum = builder.constant(F::from_canonical_u32(u32::MAX));
        let high_is_maximum = builder.is_equal(high, maximum);
        let excess = builder.mul(high_is_maximum.target, low);
        builder.assert_zero(excess);
        append_u32_bytes(builder, bytes, low);
        append_u32_bytes(builder, bytes, high);
    }
}

fn domain_bytes(builder: &mut CircuitBuilder<F, 2>, domain: &[u8]) -> Vec<Target> {
    domain.iter().map(|byte| builder.constant(F::from_canonical_u8(*byte))).collect()
}

pub(super) fn summary_path_root(
    builder: &mut CircuitBuilder<F, 2>, user_id: Target, value: HashOutTarget,
    siblings: &[HashOutTarget; 32],
) -> HashOutTarget {
    let bits = builder.split_le(user_id, 32);
    let mut root = value;
    for (height, sibling) in siblings.iter().enumerate() {
        let left = builder.select_hash(bits[height], *sibling, root);
        let right = builder.select_hash(bits[height], root, *sibling);
        let mut bytes = domain_bytes(builder, b"PsyRewardLedger/Node/1");
        bytes.push(builder.constant(F::from_canonical_usize(height + 1)));
        append_hash_bytes(builder, &mut bytes, left);
        append_hash_bytes(builder, &mut bytes, right);
        root = builder.hash_n_to_hash_no_pad::<PoseidonHash>(bytes);
    }
    root
}

struct RewardSessionTargets {
    source_checkpoint_id: Target,
    end_checkpoint_id: Target,
    source: HistoricalMerkleProofTarget,
    seed: HashOutTarget,
}

impl RewardSessionTargets {
    fn new(
        builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
        economic_domain: &[Target; 32],
    ) -> Self {
        let zero = builder.zero();
        let source_checkpoint_id = builder.add_virtual_target();
        let end_checkpoint_id = builder.add_virtual_target();
        let source_leaf = PsyCheckpointLeafGadget::create_virtual(builder);
        let source = historical_merkle_proof(builder, [source_checkpoint_id, zero],
            &source_leaf, [end_checkpoint_id, zero], statement.hash(0));
        let seed = reward_session_seed(builder, economic_domain, source_checkpoint_id,
            statement.fields[4], &std::array::from_fn(|i| statement.fields[5 + i]),
            statement.hash(0), source.checkpoint_leaf_hash);
        Self { source_checkpoint_id, end_checkpoint_id, source, seed }
    }
}

pub(super) fn reward_session_seed(
    builder: &mut CircuitBuilder<F, 2>, economic_domain: &[Target; 32],
    source_checkpoint_id: Target, user_id: Target, recipient: &[Target; 5],
    checkpoint_tree_root: HashOutTarget, source_leaf_hash: HashOutTarget,
) -> HashOutTarget {
    let mut bytes = domain_bytes(builder, b"PsyRewardJobs/Session/1");
    for byte in economic_domain {
        builder.range_check(*byte, 8);
        bytes.push(*byte);
    }
    append_u32_bytes(builder, &mut bytes, source_checkpoint_id);
    append_u32_bytes(builder, &mut bytes, user_id);
    for word in recipient { append_u32_bytes(builder, &mut bytes, *word); }
    append_hash_bytes(builder, &mut bytes, checkpoint_tree_root);
    append_hash_bytes(builder, &mut bytes, source_leaf_hash);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(bytes)
}

pub(super) struct RewardLedgerStateTargets {
    pub(super) ledger_window_hash: HashOutTarget,
    pub(super) ledger_root: HashOutTarget,
    pub(super) user_root: HashOutTarget,
    pub(super) session_count: Target,
    pub(super) unfinished_session_count: Target,
    pub(super) root: HashOutTarget,
}

impl RewardLedgerStateTargets {
    pub(super) fn new(builder: &mut CircuitBuilder<F, 2>) -> Self {
        let ledger_window_hash = builder.add_virtual_hash();
        let ledger_root = builder.add_virtual_hash();
        let user_root = builder.add_virtual_hash();
        let session_count = builder.add_virtual_target();
        let unfinished_session_count = builder.add_virtual_target();
        let mut bytes = domain_bytes(builder, b"PsyRewardLedger/State/1");
        for hash in [ledger_window_hash, ledger_root, user_root] {
            append_hash_bytes(builder, &mut bytes, hash);
        }
        append_u32_bytes(builder, &mut bytes, session_count);
        append_u32_bytes(builder, &mut bytes, unfinished_session_count);
        let root = builder.hash_n_to_hash_no_pad::<PoseidonHash>(bytes);
        Self { ledger_window_hash, ledger_root, user_root, session_count, unfinished_session_count, root }
    }
}

pub(super) struct RewardLedgerWindowTargets {
    pub(super) config_hash: [Target; 32],
    pub(super) economic_domain: [Target; 32],
    pub(super) window_id: [Target; 32],
    pub(super) end_checkpoint_id: Target,
    pub(super) end_checkpoint_root: HashOutTarget,
    pub(super) start_root: HashOutTarget,
    pub(super) verifier_hash: HashOutTarget,
    pub(super) hash: HashOutTarget,
}

impl RewardLedgerWindowTargets {
    pub(super) fn new(
        builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
        end_checkpoint_id: Target, verifier: &VerifierCircuitTarget,
    ) -> Self {
        let config_hash = builder.add_virtual_target_arr();
        let economic_domain = builder.add_virtual_target_arr();
        let window_id = builder.add_virtual_target_arr();
        let start_root = builder.add_virtual_hash();
        let end_checkpoint_root = statement.hash(0);
        let (verifier_hash, hash) = reward_ledger_window_hash(builder, &config_hash, &economic_domain,
            &window_id, end_checkpoint_id, end_checkpoint_root, start_root, verifier);
        Self { config_hash, economic_domain, window_id, end_checkpoint_id, end_checkpoint_root, start_root, verifier_hash, hash }
    }
}

pub(super) fn reward_ledger_window_hash(
    builder: &mut CircuitBuilder<F, 2>, config_hash: &[Target; 32],
    economic_domain: &[Target; 32], window_id: &[Target; 32],
    end_checkpoint_id: Target, checkpoint_root: HashOutTarget,
    start_root: HashOutTarget, verifier: &VerifierCircuitTarget,
) -> (HashOutTarget, HashOutTarget) {
    let mut verifier_bytes = domain_bytes(builder, b"PsyRewardLedger/Verifier/1");
    append_hash_bytes(builder, &mut verifier_bytes, verifier.circuit_digest);
    let cap_length = builder.constant(F::from_canonical_usize(verifier.constants_sigmas_cap.0.len()));
    append_u32_bytes(builder, &mut verifier_bytes, cap_length);
    for hash in &verifier.constants_sigmas_cap.0 {
        append_hash_bytes(builder, &mut verifier_bytes, *hash);
    }
    let verifier_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(verifier_bytes);
    let mut bytes = domain_bytes(builder, b"PsyRewardLedger/Window/1");
    for byte in config_hash.iter().chain(economic_domain).chain(window_id) {
        builder.range_check(*byte, 8);
        bytes.push(*byte);
    }
    append_u32_bytes(builder, &mut bytes, end_checkpoint_id);
    for hash in [checkpoint_root, start_root, verifier_hash] {
        append_hash_bytes(builder, &mut bytes, hash);
    }
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(bytes);
    (verifier_hash, hash)
}

struct RewardPredecessorTargets {
    has_own: BoolTarget,
    has_global: BoolTarget,
    own: ProofWithPublicInputsTarget<2>,
    global: ProofWithPublicInputsTarget<2>,
    dummy: ProofWithPublicInputsTarget<2>,
    verifier: VerifierCircuitTarget,
}

impl RewardPredecessorTargets {
    fn new(
        builder: &mut CircuitBuilder<F, 2>, common: &CommonCircuitData<F, 2>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(common.num_public_inputs == REWARD_SESSION_PROOF_FIELD_COUNT,
            "user reward predecessor must expose exactly 34 fields");
        let has_own = builder.add_virtual_bool_target_safe();
        let has_global = builder.add_virtual_bool_target_safe();
        let own = builder.add_virtual_proof_with_pis(common);
        let global = builder.add_virtual_proof_with_pis(common);
        let verifier = builder.add_virtual_verifier_data(common.config.fri_config.cap_height);
        let (dummy, dummy_verifier) = builder
            .dummy_proof_and_constant_vk_no_generator::<PoseidonGoldilocksConfig>(common)?;
        for (active, predecessor) in [(has_own, &own), (has_global, &global)] {
            builder.conditionally_verify_proof::<PoseidonGoldilocksConfig>(
                active, predecessor, &verifier, &dummy, &dummy_verifier, common,
            );
        }
        Ok(Self { has_own, has_global, own, global, dummy, verifier })
    }

    fn connect(
        &self, builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
        ledger_window: &RewardLedgerWindowTargets, old: &RewardLedgerStateTargets,
        own_state: &RewardLedgerStateTargets, origin_root: [u64; 4],
    ) -> BoolTarget {
        let first_global = builder.not(self.has_global);
        builder.connect_hashes_if_true(first_global, statement.hash(26), ledger_window.start_root);
        let zero = builder.zero();
        let empty = builder.is_equal(statement.fields[21], zero);
        let nonempty = builder.not(empty);
        let same_window = builder.and(self.has_global, nonempty);
        builder.connect_hashes_if_true(same_window, ledger_window.hash, old.ledger_window_hash);
        let global_new = HashOutTarget {
            elements: std::array::from_fn(|i| self.global.public_inputs[30 + i]),
        };
        builder.connect_hashes_if_true(self.has_global, statement.hash(26), global_new);
        builder.connect_hashes(old.root, statement.hash(26));
        let origin_state = builder.constant_hash(plonky2::hash::hash_types::HashOut { elements: origin_root.map(F::from_canonical_u64) });
        let mut origin = first_global;
        for (limb, origin_limb) in ledger_window.start_root.elements.into_iter().zip(origin_state.elements) {
            let equal = builder.is_equal(limb, origin_limb);
            origin = builder.and(origin, equal);
        }
        for index in 0..13 {
            builder.connect_if_true(self.has_own, statement.fields[index], self.own.public_inputs[index]);
        }
        let own_new = HashOutTarget {
            elements: std::array::from_fn(|i| self.own.public_inputs[30 + i]),
        };
        builder.connect_hashes_if_true(self.has_own, own_state.root, own_new);
        builder.connect_hashes_if_true(self.has_own, ledger_window.hash, own_state.ledger_window_hash);
        origin
}
    }

struct RewardSessionJobTargets {
    is_active: BoolTarget,
    reward: RewardLeafTarget,
    tag: RewardTagTarget,
    nullifier: DeltaMerkleProofGadget,
    next_root: HashOutTarget,
    job_amount: [Target; 8],
}

impl RewardSessionJobTargets {
    fn new(
        builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
        session: &RewardSessionTargets, old_root: HashOutTarget,
        reward_amount: [Target; 8],
    ) -> Self {
        let zero = builder.zero();
        let is_active = builder.add_virtual_bool_target_safe();
        let one = builder.one();
        let tag_user_id = builder.select(is_active, statement.fields[4], one);
        let reward = RewardLeafTarget {
            claim_checkpoint_id: [session.source_checkpoint_id, zero],
            user_id: tag_user_id, height: builder.add_virtual_target(),
            path_index: builder.add_virtual_target(), nullifier_index: builder.add_virtual_target(),
            recipient: std::array::from_fn(|i| statement.fields[5 + i]),
        };
        let tag = RewardTagTarget::new(builder, &reward);
        builder.connect_hashes_if_true(is_active, session.source.checkpoint_leaf.stats.pm_rewards_commitment.gutas_root,
            tag.root);
        let nullifier = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, 2>(builder, 63);
        let source_part = builder.mul_const(F::from_canonical_u64(1u64 << 31), session.source_checkpoint_id);
        let level_part = builder.mul_const(F::from_canonical_u64(1u64 << 26), reward.height);
        let key = builder.add_many([source_part, level_part, reward.path_index]);
        builder.connect(nullifier.index, key);
        let empty = HashOutTarget { elements: [zero; 4] };
        let one = builder.one();
        let occupied = HashOutTarget { elements: [one, zero, zero, zero] };
        builder.connect_hashes(nullifier.old_value, empty);
        builder.connect_hashes(nullifier.new_value, occupied);
        builder.connect_hashes_if_true(is_active, old_root, nullifier.old_root);
        let next_root = builder.select_hash(is_active, nullifier.new_root, old_root);
        let job_amount = reward_amount.map(|word| {
            builder.range_check(word, 32);
            builder.select(is_active, word, zero)
        });
        Self { is_active, reward, tag, nullifier, next_root, job_amount }
    }
}

impl RewardSessionJobTargets {
    fn record_bytes(&self, builder: &mut CircuitBuilder<F, 2>) -> Vec<Target> {
        let mut bytes = Vec::with_capacity(83);
        append_u32_bytes(builder, &mut bytes, self.reward.claim_checkpoint_id[0]);
        builder.range_check(self.reward.height, 8);
        bytes.push(self.reward.height);
        append_u32_bytes(builder, &mut bytes, self.reward.path_index);
        append_u32_bytes(builder, &mut bytes, self.reward.nullifier_index);
        append_u32_bytes(builder, &mut bytes, self.reward.user_id);
        for word in self.job_amount {
            append_u32_bytes(builder, &mut bytes, word);
        }
        append_hash_bytes(builder, &mut bytes, self.tag.leaf_tag);
        bytes.push(builder.zero());
        bytes.push(builder.one());
        bytes
    }
}

fn rolling_jobs_commitment(
    builder: &mut CircuitBuilder<F, 2>, previous: HashOutTarget,
    previous_count: Target, step_count: Target, new_count: Target,
    jobs: &[RewardSessionJobTargets],
) -> HashOutTarget {
    let mut bytes = domain_bytes(builder, b"PsyRewardJobs/Step/1");
    append_hash_bytes(builder, &mut bytes, previous);
    for count in [previous_count, step_count, new_count] {
        append_u32_bytes(builder, &mut bytes, count);
    }
    let fixed_length = bytes.len();
    let one = builder._true();
    let mut active_bytes = vec![one; fixed_length];
    for job in jobs {
        let record = job.record_bytes(builder);
        active_bytes.extend(std::iter::repeat(job.is_active).take(record.len()));
        bytes.extend(record);
    }
    let zero = builder.zero();
    let mut state = PoseidonPermutation::<Target>::new(std::iter::repeat(zero));
    for (values, active) in bytes.chunks(8).zip(active_bytes.chunks(8)) {
        let previous_state = state;
        let mut absorb = state;
        for (index, (value, enabled)) in values.iter().zip(active).enumerate() {
            let selected = builder.select(*enabled, *value, previous_state.as_ref()[index]);
            absorb.set_elt(selected, index);
        }
        let permuted = builder.permute::<PoseidonHash>(absorb);
        for index in 0..12 {
            state.set_elt(builder.select(active[0], permuted.as_ref()[index], previous_state.as_ref()[index]), index);
        }
    }
    HashOutTarget { elements: std::array::from_fn(|i| state.as_ref()[i]) }
}

fn constrain_reward_session_step(
    builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
    predecessors: &RewardPredecessorTargets, session: &RewardSessionTargets,
    jobs: &[RewardSessionJobTargets], ledger_window: &RewardLedgerWindowTargets,
) -> BoolTarget {
    let zero = builder.zero();
    let mut amount = std::array::from_fn(|i| builder.select(predecessors.has_own, predecessors.own.public_inputs[13 + i], zero));
    let previous_count = builder.select(predecessors.has_own, predecessors.own.public_inputs[21], zero);
    builder.range_check(previous_count, 32);
    let mut step_count = zero;
    let mut previous_active = builder._true();
    for job in jobs {
        let previous_inactive = builder.not(previous_active);
        let invalid_prefix = builder.and(previous_inactive, job.is_active);
        builder.assert_zero(invalid_prefix.target);
        previous_active = job.is_active;
        step_count = builder.add(step_count, job.is_active.target);
        amount = add_u32_limbs(builder, amount, job.job_amount);
    }
    let is_empty = builder.is_equal(step_count, zero);
    let count_zero = builder.is_equal(statement.fields[21], zero);
    let no_own = builder.not(predecessors.has_own);
    let empty_count = builder.and(is_empty, count_zero);
    let identity = builder.and(empty_count, no_own);
    let credit = builder.not(identity);
    builder.connect_if_true(credit, is_empty.target, zero);
    let count = builder.add(previous_count, step_count);
    builder.range_check(count, 32);
    builder.connect(count, statement.fields[21]);
    for (computed, public) in amount.into_iter().zip(statement.amount()) { builder.connect(computed, public); }
    let mut recipient_zero = builder._true();
    for word in &statement.fields[5..10] {
        let is_zero = builder.is_equal(*word, zero);
        recipient_zero = builder.and(recipient_zero, is_zero);
        builder.connect_if_true(identity, *word, zero);
    }
    let recipient_nonzero = builder.not(recipient_zero);
    let one = builder.one();
    builder.connect_if_true(credit, recipient_nonzero.target, one);
    for word in statement.amount() { builder.connect_if_true(identity, word, zero); }
    let previous_jobs = HashOutTarget { elements: std::array::from_fn(|i| predecessors.own.public_inputs[22 + i]) };
    let previous_jobs = builder.select_hash(predecessors.has_own, previous_jobs, session.seed);
    let jobs_commitment = rolling_jobs_commitment(builder, previous_jobs, previous_count, step_count, count, jobs);
    let committed = builder.select_hash(identity, ledger_window.hash, jobs_commitment);
    builder.connect_hashes(committed, statement.hash(22));
    identity
}

struct RewardLedgerLeafTargets {
    siblings: [HashOutTarget; 64],
    old_root: HashOutTarget,
    new_root: HashOutTarget,
    value: HashOutTarget,
}

impl RewardLedgerLeafTargets {
    fn new(
        builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
        session: &RewardSessionTargets, ledger_window: &RewardLedgerWindowTargets,
        is_final_step: BoolTarget, current_root: HashOutTarget,
    ) -> Self {
        let zero = builder.zero();
        let mut key_bits = builder.split_le(statement.fields[4], 32);
        key_bits.extend(builder.split_le(session.source_checkpoint_id, 32));
        let siblings = std::array::from_fn(|_| builder.add_virtual_hash());
        let mut bytes = domain_bytes(builder, b"PsyRewardLedger/Issued/1");
        bytes.extend_from_slice(&ledger_window.economic_domain);
        append_u32_bytes(builder, &mut bytes, session.source_checkpoint_id);
        append_u32_bytes(builder, &mut bytes, statement.fields[4]);
        for word in statement.amount().into_iter().chain(statement.fields[5..10].iter().copied()) {
            append_u32_bytes(builder, &mut bytes, word);
        }
        append_hash_bytes(builder, &mut bytes, statement.hash(22));
        append_hash_bytes(builder, &mut bytes, ledger_window.hash);
        let value = builder.hash_n_to_hash_no_pad::<PoseidonHash>(bytes);
        let mut is_empty_value = builder._true();
        for limb in value.elements {
            let is_zero = builder.is_equal(limb, zero);
            is_empty_value = builder.and(is_empty_value, is_zero);
        }
        builder.assert_zero(is_empty_value.target);
        let empty = HashOutTarget { elements: [zero; 4] };
        let old_root = psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget
            ::compute_root_bits::<PoseidonHash, F, 2>(builder, &key_bits, empty, &siblings);
        let inserted_root = psy_plonky2_common_circuits::hash::merkle::gadgets::merkle_proof::MerkleProofGadget
            ::compute_root_bits::<PoseidonHash, F, 2>(builder, &key_bits, value, &siblings);
        builder.connect_hashes_if_true(is_final_step, current_root, old_root);
        let new_root = builder.select_hash(is_final_step, inserted_root, current_root);
        Self { siblings, old_root, new_root, value }
    }
}

pub(super) fn reward_session_summary(
    builder: &mut CircuitBuilder<F, 2>, fields: &[Target],
    seed: HashOutTarget, session_root: HashOutTarget, is_final_step: BoolTarget,
) -> HashOutTarget {
    assert_eq!(fields.len(), REWARD_SESSION_PROOF_FIELD_COUNT);
    let mut bytes = domain_bytes(builder, b"PsyRewardSession/Summary/1");
    for index in 0..30 {
        let (low, high) = builder.split_low_high(fields[index], 32, 64);
        let maximum = builder.constant(F::from_canonical_u32(u32::MAX));
        let high_is_maximum = builder.is_equal(high, maximum);
        let excess = builder.mul(high_is_maximum.target, low);
        builder.assert_zero(excess);
        append_u32_bytes(builder, &mut bytes, low);
        append_u32_bytes(builder, &mut bytes, high);
    }
    append_hash_bytes(builder, &mut bytes, seed);
    append_hash_bytes(builder, &mut bytes, session_root);
    bytes.push(is_final_step.target);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(bytes)
}

fn connect_session_predecessor(
    builder: &mut CircuitBuilder<F, 2>, predecessors: &RewardPredecessorTargets,
    session: &RewardSessionTargets, own_state: &RewardLedgerStateTargets,
    old_summary: HashOutTarget, old_session_root: HashOutTarget,
    own_siblings: &[HashOutTarget; 32], empty_session_root: HashOutTarget,
) {
    let first_own = builder.not(predecessors.has_own);
    builder.connect_hashes_if_true(first_own, empty_session_root, old_session_root);
    let is_final_step = builder._false();
    let previous_summary = reward_session_summary(builder, &predecessors.own.public_inputs,
        session.seed, old_session_root, is_final_step);
    builder.connect_hashes_if_true(predecessors.has_own, old_summary, previous_summary);
    let previous_user_root = summary_path_root(builder, predecessors.own.public_inputs[4],
        previous_summary, own_siblings);
    builder.connect_hashes_if_true(predecessors.has_own, own_state.user_root, previous_user_root);
}

fn constrain_session_update(
    builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
    predecessors: &RewardPredecessorTargets, session: &RewardSessionTargets,
    old_state: &RewardLedgerStateTargets, new_state: &RewardLedgerStateTargets,
    ledger_window: &RewardLedgerWindowTargets, old_summary: HashOutTarget,
    new_session_root: HashOutTarget, siblings: &[HashOutTarget; 32],
    empty_user_root: HashOutTarget, is_final_step: BoolTarget,
    ledger_leaf: &RewardLedgerLeafTargets, identity: BoolTarget,
) {
    let zero = builder.zero();
    let empty_bytes = domain_bytes(builder, b"PsyRewardLedger/Empty/1");
    let empty_summary = builder.hash_n_to_hash_no_pad::<PoseidonHash>(empty_bytes);
    let first_own = builder.not(predecessors.has_own);
    builder.connect_hashes_if_true(first_own, empty_summary, old_summary);
    let old_user_root = summary_path_root(builder, statement.fields[4], old_summary, siblings);
    let working_user_root = builder.select_hash(predecessors.has_global, old_state.user_root, empty_user_root);
    let credit = builder.not(identity);
    builder.connect_hashes_if_true(credit, old_user_root, working_user_root);
    let summary = reward_session_summary(builder, &statement.fields,
        session.seed, new_session_root, is_final_step);
    let mut summary_is_empty = builder._true();
    for (value, empty) in summary.elements.into_iter().zip(empty_summary.elements) {
        let equal = builder.is_equal(value, empty);
        summary_is_empty = builder.and(summary_is_empty, equal);
    }
    builder.connect_if_true(credit, summary_is_empty.target, zero);
    let user_root = summary_path_root(builder, statement.fields[4], summary, siblings);
    let next_user_root = builder.select_hash(identity, old_state.user_root, user_root);
    let next_window_hash = builder.select_hash(identity, old_state.ledger_window_hash, ledger_window.hash);
    let next_ledger_root = builder.select_hash(identity, old_state.ledger_root, ledger_leaf.new_root);
    builder.connect_hashes(new_state.user_root, next_user_root);
    builder.connect_hashes(new_state.ledger_window_hash, next_window_hash);
    builder.connect_hashes(new_state.ledger_root, next_ledger_root);
    let session_count = builder.select(predecessors.has_global, old_state.session_count, zero);
    let unfinished_session_count = builder.select(predecessors.has_global, old_state.unfinished_session_count, zero);
    let incremented = builder.add(session_count, first_own.target);
    let next_session_count = builder.select(identity, session_count, incremented);
    builder.range_check(next_session_count, 32);
    builder.connect(new_state.session_count, next_session_count);
    let not_final_step = builder.not(is_final_step);
    let opened = builder.and(first_own, not_final_step);
    let closed = builder.and(predecessors.has_own, is_final_step);
    let after_open = builder.add(unfinished_session_count, opened.target);
    let decremented = builder.sub(after_open, closed.target);
    let next_unfinished_session_count = builder.select(identity, unfinished_session_count, decremented);
    builder.range_check(next_unfinished_session_count, 32);
    builder.connect(new_state.unfinished_session_count, next_unfinished_session_count);
    let completed = builder.sub(next_session_count, next_unfinished_session_count);
    builder.range_check(completed, 32);
    builder.connect_hashes(new_state.root, statement.hash(30));
}

fn auth_message(
    builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
    session: &RewardSessionTargets, ledger_window: &RewardLedgerWindowTargets,
    end_leaf: &PsyCheckpointLeafGadget, user: &PsyUserLeafGadget,
    identity: HashOutTarget, public_key_param: HashOutTarget,
) -> [Target; 32] {
    let mut bytes = domain_bytes(builder, psy_vm::reward_authorization::REWARD_SESSION_AUTHORIZATION_DOMAIN);
    for value in ledger_window.config_hash.into_iter().chain(ledger_window.economic_domain).chain(ledger_window.window_id) {
        builder.range_check(value, 8);
        bytes.push(value);
    }
    let action = builder.one();
    for value in [action, session.source_checkpoint_id, session.end_checkpoint_id, statement.fields[4]] {
        append_u32_bytes(builder, &mut bytes, value);
    }
    let end_hash = end_leaf.to_hash::<PoseidonHash, F, 2>(builder);
    let user_hash = user.to_hash::<PoseidonHash, F, 2>(builder);
    for hash in [statement.hash(0), session.source.checkpoint_leaf_hash,
        end_hash, user_hash, identity, public_key_param] {
        append_hash_bytes(builder, &mut bytes, hash);
    }
    let (nonce_low, nonce_high) = builder.split_low_high(user.nonce, 32, 64);
    let maximum = builder.constant(F::from_canonical_u32(u32::MAX));
    let high_is_maximum = builder.is_equal(nonce_high, maximum);
    let excess = builder.mul(high_is_maximum.target, nonce_low);
    builder.assert_zero(excess);
    append_u32_bytes(builder, &mut bytes, nonce_low);
    append_u32_bytes(builder, &mut bytes, nonce_high);
    append_hash_bytes(builder, &mut bytes, statement.hash(22));
    append_u32_bytes(builder, &mut bytes, statement.fields[21]);
    for word in statement.amount().into_iter().chain(statement.fields[5..10].iter().copied()) {
        append_u32_bytes(builder, &mut bytes, word);
    }
    let digest = keccak256_bytes_targets(builder, &bytes);
    let mut message = Vec::with_capacity(32);
    for word in digest {
        append_u32_bytes(builder, &mut message, word.0);
    }
    std::array::from_fn(|index| message[index])
}

struct EndCheckpointTargets {
    end_leaf: PsyCheckpointLeafGadget,
    end_path: HistoricalMerkleProofTarget,
    roots: PsyCheckpointGlobalStateRootsGadget,
}

impl EndCheckpointTargets {
    fn new(
        builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
        session: &RewardSessionTargets,
    ) -> Self {
        let zero = builder.zero();
        let end_leaf = PsyCheckpointLeafGadget::create_virtual(builder);
        let end_path = historical_merkle_proof(builder,
            [session.end_checkpoint_id, zero], &end_leaf,
            [session.end_checkpoint_id, zero], statement.hash(0));
        let roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(builder);
        let global_root = roots.to_hash::<PoseidonHash, F, 2>(builder);
        builder.connect_hashes(global_root, end_leaf.global_chain_root);
        Self { end_leaf, end_path, roots }
    }
}

struct AuthUserLeafTargets {
    user: PsyUserLeafGadget,
    user_path: MerkleProofGadget,
}

impl AuthUserLeafTargets {
    fn new(
        builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
        end: &EndCheckpointTargets, is_final_step: BoolTarget,
        identity: HashOutTarget, public_key_param: HashOutTarget,
    ) -> Self {
        let user = PsyUserLeafGadget::create_virtual(builder);
        builder.range_check(user.user_id, 32);
        builder.connect_if_true(is_final_step, statement.fields[4], user.user_id);
        let user_hash = user.to_hash::<PoseidonHash, F, 2>(builder);
        let user_path = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, 2>(
            builder, GLOBAL_USER_TREE_HEIGHT as usize, OptionalMerkleProofGadget {
                root: None, value: Some(user_hash), index: Some(user.user_id), siblings: None,
            },
        );
        builder.connect_hashes_if_true(is_final_step, end.roots.user_tree_root, user_path.root);
        let public_key = builder.hash_two_to_one::<PoseidonHash>(identity, public_key_param);
        builder.connect_hashes_if_true(is_final_step, user.public_key, public_key);
        Self { user, user_path }
    }
}

fn auth_secp_signature(
    builder: &mut CircuitBuilder<F, 2>, is_active_scheme: BoolTarget,
    message: &[Target; 32], is_personal_sign: bool,
) -> Secp256K1Gadget {
    let signature = if is_personal_sign {
        Secp256K1Gadget::add_virtual_to_eth_personal_sign::<PoseidonHash, F, 2>(builder)
    } else {
        Secp256K1Gadget::add_virtual_to::<PoseidonHash, F, 2>(builder, b"")
    };
    constrain_signature(builder, &signature);
    for (target, byte) in signature.msg_bytes_target.iter().zip(message) {
        builder.range_check(*target, 8);
        builder.connect_if_true(is_active_scheme, *byte, *target);
    }
    signature
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::PrimeField64;
    use parth_core::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::{MerkleHasher, MerkleZeroHasher}}, pgoldilocks::QHashOut};
    use plonky2::{hash::hash_types::HashOut, iop::witness::{PartialWitness, WitnessWrite}, plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};
    use std::collections::BTreeMap;

    #[test]
    fn reward_amount_propagates_carries_and_rejects_overflow() {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let left = builder.add_virtual_target_arr();
        let right = builder.add_virtual_target_arr();
        let sum = add_u32_limbs(&mut builder, left, right);
        builder.register_public_inputs(&sum);
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let input = |left_words: [u32; 8], right_words: [u32; 8]| {
            let mut witness = PartialWitness::new();
            for (targets, words) in [(left, left_words), (right, right_words)] {
                for (target, word) in targets.into_iter().zip(words) {
                    witness.set_target(target, F::from_canonical_u32(word)).unwrap();
                }
            }
            witness
        };
        let mut left_words = [u32::MAX; 8];
        left_words[7] = 6;
        let right_words = [1, 0, 0, 0, 0, 0, 0, 0];
        let proof = circuit.prove(input(left_words, right_words)).unwrap();
        assert_eq!(proof.public_inputs, [0, 0, 0, 0, 0, 0, 0, 7].map(F::from_canonical_u32));
        circuit.verify(proof).unwrap();
        assert!(circuit.prove(input([u32::MAX; 8], right_words)).is_err());
    }

    #[test]
    fn auth_message_matches_host_encoding() {
        use plonky2::field::types::PrimeField64;
        use psy_common_circuit::traits::ToTargets;
        use psy_vm::reward_authorization::{RewardSessionAuthorization, build_reward_session_authorization_message};
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let statement = RewardSessionStatement::new(&mut builder);
        let config = [0x12u8; 32];
        let economic = [0x34u8; 32];
        let window = [0x56u8; 32];
        let economic_targets = economic.map(|byte| builder.constant(F::from_canonical_u8(byte)));
        let session = RewardSessionTargets::new(&mut builder, &statement, &economic_targets);
        let zero_hash = HashOutTarget { elements: [builder.zero(); 4] };
        let ledger_window = RewardLedgerWindowTargets {
            config_hash: config.map(|byte| builder.constant(F::from_canonical_u8(byte))),
            economic_domain: economic_targets,
            window_id: window.map(|byte| builder.constant(F::from_canonical_u8(byte))),
            end_checkpoint_id: builder.zero(), end_checkpoint_root: zero_hash,
            start_root: zero_hash, verifier_hash: zero_hash, hash: zero_hash,
        };
        let end = PsyCheckpointLeafGadget::create_virtual(&mut builder);
        let user = PsyUserLeafGadget::create_virtual(&mut builder);
        let identity_words = [1u64, 0x0102030405060708, 0xffffffff00000000, 19];
        let param_words = [23u64, 29, 31, 37];
        let identity = builder.constant_hash(plonky2::hash::hash_types::HashOut {
            elements: identity_words.map(F::from_canonical_u64),
        });
        let param = builder.constant_hash(plonky2::hash::hash_types::HashOut {
            elements: param_words.map(F::from_canonical_u64),
        });
        let message = auth_message(&mut builder, &statement, &session,
            &ledger_window, &end, &user, identity, param);
        let end_hash = end.to_hash::<PoseidonHash, F, 2>(&mut builder);
        let user_hash = user.to_hash::<PoseidonHash, F, 2>(&mut builder);
        builder.register_public_inputs(&message);
        for hash in [statement.hash(0), session.source.checkpoint_leaf_hash, end_hash, user_hash] {
            builder.register_public_inputs(&hash.elements);
        }
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let mut witness = PartialWitness::new();
        let amount = [7u32, 1, 0, 0x89abcdef, 0, 0, 3, 0x10203040];
        let recipient = [0x01020304u32, 0x55667788, 9, 10, 11];
        let jobs = [41u64, 43, 47, 53];
        for index in 4..REWARD_SESSION_PROOF_FIELD_COUNT {
            let value = match index {
                4 => 7,
                5..=9 => u64::from(recipient[index - 5]),
                13..=20 => u64::from(amount[index - 13]),
                21 => 3,
                22..=25 => jobs[index - 22],
                _ => 0,
            };
            witness.set_target(statement.fields[index], F::from_canonical_u64(value)).unwrap();
        }
        witness.set_target(session.source_checkpoint_id, F::ONE).unwrap();
        witness.set_target(session.end_checkpoint_id, F::from_canonical_u32(2)).unwrap();
        for leaf in [&session.source.checkpoint_leaf, &end] {
            for target in leaf.to_targets() { witness.set_target(target, F::ZERO).unwrap(); }
        }
        for target in user.to_targets() {
            let value = if target == user.nonce { F::from_canonical_u64(0xffffffff00000000) }
                else if target == user.user_id { F::from_canonical_u32(7) } else { F::ZERO };
            witness.set_target(target, value).unwrap();
        }
        for sibling in &session.source.path.siblings {
            witness.set_hash_target(*sibling, plonky2::hash::hash_types::HashOut { elements: [F::ZERO; 4] }).unwrap();
        }
        let proof = circuit.prove(witness).unwrap();
        let read_hash = |offset: usize| std::array::from_fn(|i| proof.public_inputs[offset + i].to_canonical_u64());
        let expected = build_reward_session_authorization_message(&RewardSessionAuthorization {
            config_hash: config, economic_domain: economic, window_id: window,
            source_checkpoint_id: 1, end_checkpoint_id: 2, user_id: 7,
            checkpoint_tree_root: read_hash(32), source_checkpoint_leaf_hash: read_hash(36),
            end_checkpoint_leaf_hash: read_hash(40), user_leaf_hash: read_hash(44),
            identity_fingerprint: identity_words, public_key_param: param_words,
            nonce: 0xffffffff00000000, jobs_commitment: jobs, count: 3, amount, recipient,
        }).unwrap();
        assert_eq!(proof.public_inputs[..32], expected.map(F::from_canonical_u8));
        circuit.verify(proof).unwrap();
    }

    const NULLIFIER_TREE_HEIGHT: usize = 63;
    const SOURCE: u64 = 1;
    const EMPTY_AUTHENTICATED: [u64; 4] = [0; 4];

    fn occupied() -> QHashOut<F> {
        QHashOut(HashOut { elements: [F::ONE, F::ZERO, F::ZERO, F::ZERO] })
    }

    fn nullifier_key(source: u64, height: u64, path_index: u64) -> u64 {
        (source << 31) | (height << 26) | path_index
    }

    fn canonical_zero_siblings() -> [QHashOut<F>; NULLIFIER_TREE_HEIGHT] {
        std::array::from_fn(|level| <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(level))
    }

    fn siblings_from_known_leaves(leaves: &BTreeMap<u64, QHashOut<F>>, index: u64) -> [QHashOut<F>; NULLIFIER_TREE_HEIGHT] {
        let mut nodes = leaves.clone();
        let mut position = index;
        std::array::from_fn(|level| {
            let zero = <PoseidonHash as MerkleZeroHasher<QHashOut<F>>>::get_zero_hash(level);
            let sibling = nodes.get(&(position ^ 1)).copied().unwrap_or(zero);
            let mut parents = BTreeMap::new();
            for &child in nodes.keys() {
                let left = nodes.get(&(child & !1)).copied().unwrap_or(zero);
                let right = nodes.get(&(child | 1)).copied().unwrap_or(zero);
                parents.insert(child >> 1, <PoseidonHash as MerkleHasher<QHashOut<F>>>::two_to_one(&left, &right));
            }
            nodes = parents;
            position >>= 1;
            sibling
        })
    }

    fn nullifier_delta(index: u64, siblings: [QHashOut<F>; NULLIFIER_TREE_HEIGHT]) -> DeltaMerkleProofCore<QHashOut<F>> {
        DeltaMerkleProofCore::from_params::<PoseidonHash>(index, QHashOut::ZERO, occupied(), siblings.to_vec())
    }

    struct NullifierStep {
        source: Target,
        height: Target,
        path_index: Target,
        active: BoolTarget,
        next_root: HashOutTarget,
        nullifier: DeltaMerkleProofGadget,
    }

    fn add_nullifier_step(builder: &mut CircuitBuilder<F, 2>, source: Target, old_root: HashOutTarget) -> NullifierStep {
        let active = builder.add_virtual_bool_target_safe();
        let height = builder.add_virtual_target();
        let path_index = builder.add_virtual_target();
        let nullifier = DeltaMerkleProofGadget::add_virtual_to::<PoseidonHash, F, 2>(builder, NULLIFIER_TREE_HEIGHT);
        let source_part = builder.mul_const(F::from_canonical_u64(1u64 << 31), source);
        let level_part = builder.mul_const(F::from_canonical_u64(1u64 << 26), height);
        let key = builder.add_many([source_part, level_part, path_index]);
        builder.connect(nullifier.index, key);
        let empty = HashOutTarget { elements: [builder.zero(); 4] };
        let occupied_value = builder.constant_hash(occupied().0);
        builder.connect_hashes(nullifier.old_value, empty);
        builder.connect_hashes(nullifier.new_value, occupied_value);
        builder.connect_hashes_if_true(active, old_root, nullifier.old_root);
        let next_root = builder.select_hash(active, nullifier.new_root, old_root);
        NullifierStep { source, height, path_index, active, next_root, nullifier }
    }

    struct NullifierTransition {
        circuit: CircuitData<F, PoseidonGoldilocksConfig, 2>,
        first_step: BoolTarget,
        authenticated: HashOutTarget,
        steps: [NullifierStep; 2],
    }

    fn nullifier_transition() -> NullifierTransition {
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let source = builder.add_virtual_target();
        builder.range_check(source, 32);
        let mut root = HashOutTarget { elements: [builder.zero(); 4] };
        for _ in 0..NULLIFIER_TREE_HEIGHT {
            root = builder.hash_two_to_one::<PoseidonHash>(root, root);
        }
        let first_step = builder.add_virtual_bool_target_safe();
        let authenticated = builder.add_virtual_hash();
        let old_root = builder.select_hash(first_step, root, authenticated);
        let first = add_nullifier_step(&mut builder, source, old_root);
        let second = add_nullifier_step(&mut builder, source, first.next_root);
        builder.register_public_input(first_step.target);
        builder.register_public_inputs(&authenticated.elements);
        for step in [&first, &second] {
            builder.register_public_input(step.active.target);
            builder.register_public_input(step.height);
            builder.register_public_input(step.path_index);
            builder.register_public_inputs(&step.next_root.elements);
        }
        NullifierTransition {
            circuit: builder.build::<PoseidonGoldilocksConfig>(),
            first_step, authenticated, steps: [first, second],
        }
    }

    struct NullifierCase {
        first_step: bool,
        authenticated: [u64; 4],
        known: &'static [(u64, u64)],
        positions: [(bool, u64, u64); 2],
    }

    fn prove_nullifier_case(transition: &NullifierTransition, case: NullifierCase) -> anyhow::Result<ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>> {
        let mut witness = PartialWitness::new();
        witness.set_target(transition.steps[0].source, F::from_canonical_u64(SOURCE))?;
        witness.set_bool_target(transition.first_step, case.first_step)?;
        witness.set_hash_target(transition.authenticated, HashOut { elements: case.authenticated.map(F::from_canonical_u64) })?;
        let mut leaves = case.known.iter().map(|(height, path_index)| {
            (nullifier_key(SOURCE, *height, *path_index), occupied())
        }).collect::<BTreeMap<_, _>>();
        for (step, (active, height, path_index)) in transition.steps.iter().zip(case.positions) {
            witness.set_bool_target(step.active, active)?;
            witness.set_target(step.height, F::from_canonical_u64(height))?;
            witness.set_target(step.path_index, F::from_canonical_u64(path_index))?;
            let key = nullifier_key(SOURCE, height, path_index);
            let siblings = if active {
                siblings_from_known_leaves(&leaves, key)
            } else {
                canonical_zero_siblings()
            };
            let delta = nullifier_delta(key, siblings);
            for (target, sibling) in step.nullifier.siblings.iter().zip(delta.siblings) {
                witness.set_hash_target(*target, sibling.0)?;
            }
            if active { leaves.insert(key, occupied()); }
        }
        transition.circuit.prove(witness)
    }

    #[test]
    fn session_nullifier_updates_distinct_positions_and_rejects_replay() {
        use plonky2::field::types::PrimeField64;
        let transition = nullifier_transition();
        let first = nullifier_delta(nullifier_key(SOURCE, 2, 0), canonical_zero_siblings());
        let carried = BTreeMap::from([(nullifier_key(SOURCE, 2, 0), occupied())]);
        let second = nullifier_delta(nullifier_key(SOURCE, 2, 1), siblings_from_known_leaves(&carried, nullifier_key(SOURCE, 2, 1)));
        let carried_root = second.new_root.0.elements.map(|limb| limb.to_canonical_u64());
        let proof = prove_nullifier_case(&transition, NullifierCase {
            first_step: true, authenticated: EMPTY_AUTHENTICATED, known: &[],
            positions: [(true, 2, 0), (true, 2, 1)],
        }).unwrap();
        let read = |offset: usize| std::array::from_fn(|index| proof.public_inputs[offset + index].to_canonical_u64());
        assert_eq!(read(8), first.new_root.0.elements.map(|limb| limb.to_canonical_u64()));
        assert_eq!(read(15), carried_root);
        transition.circuit.verify(proof).unwrap();
        assert!(prove_nullifier_case(&transition, NullifierCase {
            first_step: false, authenticated: carried_root, known: &[(2, 0), (2, 1)],
            positions: [(true, 2, 1), (false, 2, 0)],
        }).is_err());
        assert!(prove_nullifier_case(&transition, NullifierCase {
            first_step: false, authenticated: carried_root, known: &[],
            positions: [(true, 2, 0), (false, 2, 1)],
        }).is_err());
    }

    fn empty_user_root() -> [u64; 4] {
        use plonky2::{field::types::Field, hash::hash_types::HashOut, plonk::config::Hasher};
        let mut root = PoseidonHash::hash_no_pad(&b"PsyRewardLedger/Empty/1".map(F::from_canonical_u8));
        for height in 1..=32 {
            let mut bytes = b"PsyRewardLedger/Node/1".map(F::from_canonical_u8).to_vec();
            bytes.push(F::from_canonical_u8(height));
            for hash in [root, root] {
                for limb in hash.elements {
                    let value = limb.to_canonical_u64();
                    bytes.extend([value as u32, (value >> 32) as u32].map(F::from_canonical_u32));
                }
            }
            root = PoseidonHash::hash_no_pad(&bytes);
        }
        root.elements.map(|limb| limb.to_canonical_u64())
    }

    fn empty_issued_root() -> [u64; 4] {
        use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher};
        let mut root = HashOut { elements: [F::ZERO; 4] };
        for _ in 0..64 { root = <PoseidonHash as Hasher<F>>::two_to_one(root, root); }
        root.elements.map(|limb| limb.to_canonical_u64())
    }

    #[derive(Clone, Copy)]
    struct OriginCase {
        start_root: [u64; 4],
        old_window: [u64; 4],
        old_issued: [u64; 4],
        old_user: [u64; 4],
        old_counts: [u32; 2],
        statement_old: [u64; 4],
    }

    fn prove_origin_case(case: OriginCase) -> anyhow::Result<ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>> {
        use plonky2::recursion::dummy_circuit::{dummy_circuit, dummy_proof};
        let config = CircuitConfig::standard_recursion_config();
        let mut common_builder = CircuitBuilder::<F, 2>::new(config.clone());
        for _ in 0..REWARD_SESSION_PROOF_FIELD_COUNT { common_builder.add_virtual_public_input(); }
        let common = common_builder.build::<PoseidonGoldilocksConfig>().common;
        let mut builder = CircuitBuilder::<F, 2>::new(config);
        let statement = RewardSessionStatement::new(&mut builder);
        let predecessors = RewardPredecessorTargets::new(&mut builder, &common)?;
        let end_id = builder.add_virtual_target();
        let window = RewardLedgerWindowTargets::new(&mut builder, &statement, end_id, &predecessors.verifier);
        let old = RewardLedgerStateTargets::new(&mut builder);
        let own = RewardLedgerStateTargets::new(&mut builder);
        let origin = predecessors.connect(&mut builder, &statement, &window, &old, &own, origin_state_root());
        let empty_bytes = domain_bytes(&mut builder, b"PsyRewardLedger/Empty/1");
        let mut empty_user_root = builder.hash_n_to_hash_no_pad::<PoseidonHash>(empty_bytes);
        for height in 1..=32 {
            let mut bytes = domain_bytes(&mut builder, b"PsyRewardLedger/Node/1");
            bytes.push(builder.constant(F::from_canonical_usize(height)));
            append_hash_bytes(&mut builder, &mut bytes, empty_user_root);
            append_hash_bytes(&mut builder, &mut bytes, empty_user_root);
            empty_user_root = builder.hash_n_to_hash_no_pad::<PoseidonHash>(bytes);
        }
        let zero_hash = builder.constant_hash(plonky2::hash::hash_types::HashOut { elements: [F::ZERO; 4] });
        let mut empty_issued_root = zero_hash;
        for _ in 0..64 { empty_issued_root = builder.hash_two_to_one::<PoseidonHash>(empty_issued_root, empty_issued_root); }
        builder.connect_hashes_if_true(origin, old.ledger_window_hash, zero_hash);
        builder.connect_hashes_if_true(origin, old.ledger_root, empty_issued_root);
        builder.connect_hashes_if_true(origin, old.user_root, empty_user_root);
        let zero = builder.zero();
        builder.connect_if_true(origin, old.session_count, zero);
        builder.connect_if_true(origin, old.unfinished_session_count, zero);
        builder.register_public_inputs(&statement.fields);
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let mut witness = PartialWitness::new();
        let mut fields = [0u64; REWARD_SESSION_PROOF_FIELD_COUNT];
        fields[26..30].copy_from_slice(&case.statement_old);
        for (target, value) in statement.fields.into_iter().zip(fields) {
            witness.set_target(target, F::from_canonical_u64(value))?;
        }
        witness.set_bool_target(predecessors.has_own, false)?;
        witness.set_bool_target(predecessors.has_global, false)?;
        witness.set_verifier_data_target(&predecessors.verifier, &circuit.verifier_only)?;
        let dummy_data = dummy_circuit::<F, PoseidonGoldilocksConfig, 2>(&common);
        let dummy = dummy_proof(&dummy_data, Default::default())?;
        for proof in [&predecessors.own, &predecessors.global, &predecessors.dummy] {
            witness.set_proof_with_pis_target(proof, &dummy)?;
        }
        set_hash(&mut witness, window.start_root, case.start_root)?;
        for target in window.config_hash.into_iter().chain(window.economic_domain).chain(window.window_id) {
            witness.set_target(target, F::ZERO)?;
        }
        witness.set_target(window.end_checkpoint_id, F::ZERO)?;
        set_hash(&mut witness, old.ledger_window_hash, case.old_window)?;
        set_hash(&mut witness, old.ledger_root, case.old_issued)?;
        set_hash(&mut witness, old.user_root, case.old_user)?;
        witness.set_target(old.session_count, F::from_canonical_u32(case.old_counts[0]))?;
        witness.set_target(old.unfinished_session_count, F::from_canonical_u32(case.old_counts[1]))?;
        for hash in [own.ledger_window_hash, own.ledger_root, own.user_root, own.root] {
            set_hash(&mut witness, hash, [0; 4])?;
        }
        witness.set_target(own.session_count, F::ZERO)?;
        witness.set_target(own.unfinished_session_count, F::ZERO)?;
        circuit.prove(witness)
    }

    #[test]
    fn zero_origin_requires_empty_old_state() {
        use plonky2::field::types::PrimeField64;
        let origin = origin_state_root();
        let issued = empty_issued_root();
        let user = empty_user_root();
        let proof = prove_origin_case(OriginCase {
            start_root: origin, old_window: [0; 4], old_issued: issued, old_user: user,
            old_counts: [0, 0], statement_old: origin,
        }).unwrap();
        assert_eq!(proof.public_inputs[26..30].iter().map(|limb| limb.to_canonical_u64()).collect::<Vec<_>>(), origin);
        let mut nonzero_opening = OriginCase {
            start_root: origin, old_window: [1, 0, 0, 0], old_issued: issued, old_user: user,
            old_counts: [0, 0], statement_old: origin,
        };
        assert!(prove_origin_case(nonzero_opening).is_err());
        nonzero_opening.old_window = [0; 4];
        nonzero_opening.old_counts = [1, 0];
        assert!(prove_origin_case(nonzero_opening).is_err());
    }
}

pub(super) struct MultisigPolicyTargets {
    pub(super) initial_slots: [HashOutTarget; 4],
    pub(super) current_slots: [HashOutTarget; 4],
    pub(super) selected: [Target; 2],
    pub(super) slot_paths: Vec<MerkleProofGadget>,
    pub(super) contract_paths: Vec<MerkleProofGadget>,
    pub(super) public_key_param: HashOutTarget,
}

impl MultisigPolicyTargets {
    fn new(
        builder: &mut CircuitBuilder<F, 2>, is_active_scheme: BoolTarget,
        user: &PsyUserLeafGadget, signatures: [&Secp256K1Gadget; 2],
    ) -> Self {
        use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
        use psy_ups_circuit::signature::reward_authorization::PolicyTarget;
        let initial_slots = std::array::from_fn(|_| builder.add_virtual_hash());
        let current_slots = std::array::from_fn(|_| builder.add_virtual_hash());
        let initial = PolicyTarget::new(builder, initial_slots);
        let current = PolicyTarget::new(builder, current_slots);
        let one = builder.one();
        builder.connect(initial.version, one);
        let contract_id = builder.constant(F::from_canonical_u32(6));
        let mut slot_paths = Vec::with_capacity(4);
        let mut contract_paths = Vec::with_capacity(4);
        let mut state_root = None;
        for (index, value) in current_slots.iter().enumerate() {
            let slot = builder.constant(F::from_canonical_usize(index));
            let slot_path = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, 2>(
                builder, 4, OptionalMerkleProofGadget {
                    root: None, value: Some(*value), index: Some(slot), siblings: None,
                },
            );
            if let Some(root) = state_root {
                builder.connect_hashes(slot_path.root, root);
            } else {
                state_root = Some(slot_path.root);
            }
            let contract_path = MerkleProofGadget::add_virtual_to_with_options::<PoseidonHash, F, 2>(
                builder, psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
                OptionalMerkleProofGadget {
                    root: None, value: Some(slot_path.root), index: Some(contract_id), siblings: None,
                },
            );
            builder.connect_hashes_if_true(is_active_scheme, user.user_state_tree_root, contract_path.root);
            slot_paths.push(slot_path);
            contract_paths.push(contract_path);
        }
        let selected = builder.add_virtual_target_arr();
        let three = builder.constant(F::from_canonical_u32(3));
        for index in 0..2 {
            builder.range_check(selected[index], 2);
            let valid = builder.is_less_than(2, selected[index], three);
            builder.assert_one(valid.target);
            for member_index in 0..3 {
                let member = builder.constant(F::from_canonical_usize(member_index));
                let matches = builder.is_equal(selected[index], member);
                let active = builder.and(is_active_scheme, matches);
                builder.connect_hashes_if_true(active, current.members[member_index], signatures[index].public_key_hash);
            }
        }
        let ordered = builder.is_less_than(2, selected[0], selected[1]);
        builder.assert_one(ordered.target);
        let domain = builder.constant(F::from_canonical_u32(0x4d534741));
        let zero = builder.zero();
        let height = builder.constant(F::from_canonical_u32(4));
        let mut fields = vec![domain, contract_id, zero, height];
        fields.extend(initial.commitment.elements);
        let public_key_param = builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields);
        Self { initial_slots, current_slots, selected, slot_paths, contract_paths, public_key_param }
    }
}

struct UserAuthTargets {
    scheme: Target,
    end_checkpoint: EndCheckpointTargets,
    user_leaf: AuthUserLeafTargets,
    private_key: HashOutTarget,
    public_key_param: HashOutTarget,
    signatures: [Secp256K1Gadget; 3],
    policy: MultisigPolicyTargets,
    message: [Target; 32],
}

impl UserAuthTargets {
    fn new(
        builder: &mut CircuitBuilder<F, 2>, statement: &RewardSessionStatement,
        session: &RewardSessionTargets, ledger_window: &RewardLedgerWindowTargets,
        is_final_step: BoolTarget, fingerprints: [[F; 4]; 4],
    ) -> Self {
        let scheme = builder.add_virtual_target();
        let scheme_bits = builder.split_le(scheme, 2);
        let selected: [BoolTarget; 4] = std::array::from_fn(|index| {
            let value = builder.constant(F::from_canonical_usize(index));
            builder.is_equal(scheme, value)
        });
        let active = selected.map(|selected| builder.and(is_final_step, selected));
        let pinned = fingerprints.map(|elements| {
            builder.constant_hash(plonky2::hash::hash_types::HashOut { elements })
        });
        let low = builder.select_hash(scheme_bits[0], pinned[1], pinned[0]);
        let high = builder.select_hash(scheme_bits[0], pinned[3], pinned[2]);
        let identity = builder.select_hash(scheme_bits[1], high, low);
        let public_key_param = builder.add_virtual_hash();
        let end_checkpoint = EndCheckpointTargets::new(builder, statement, session);
        let user_leaf = AuthUserLeafTargets::new(builder, statement, &end_checkpoint, is_final_step, identity, public_key_param);
        let message = auth_message(builder, statement, session, ledger_window,
            &end_checkpoint.end_leaf, &user_leaf.user, identity, public_key_param);
        let private_key = builder.add_virtual_hash();
        let zk_param = psy_ups_circuit::signature::software_defined
            ::get_zk_public_key_param::<PoseidonGoldilocksConfig, 2>(builder, &private_key);
        let first_raw_active = builder.or(active[1], active[3]);
        let raw = auth_secp_signature(builder, first_raw_active, &message, false);
        let second_raw = auth_secp_signature(builder, active[3], &message, false);
        let personal = auth_secp_signature(builder, active[2], &message, true);
        let policy = MultisigPolicyTargets::new(builder, active[3], &user_leaf.user, [&raw, &second_raw]);
        for (active, param) in active.into_iter().zip([
            zk_param, raw.public_key_hash, personal.public_key_hash, policy.public_key_param,
        ]) {
            builder.connect_hashes_if_true(active, param, public_key_param);
        }
        Self { scheme, end_checkpoint, user_leaf, private_key, public_key_param, signatures: [raw, second_raw, personal], policy, message }
    }
}

struct RewardSessionCircuitTargets {
    statement: RewardSessionStatement,
    session: RewardSessionTargets,
    ledger_window: RewardLedgerWindowTargets,
    predecessors: RewardPredecessorTargets,
    old_state: RewardLedgerStateTargets,
    new_state: RewardLedgerStateTargets,
    own_state: RewardLedgerStateTargets,
    old_summary: HashOutTarget,
    old_session_root: HashOutTarget,
    session_siblings: [HashOutTarget; 32],
    own_siblings: [HashOutTarget; 32],
    is_final_step: BoolTarget,
    jobs: Vec<RewardSessionJobTargets>,
    ledger_leaf: RewardLedgerLeafTargets,
    identity: UserAuthTargets,
    config: psy_plonky2_common_circuits::bridge::aggregate_config::NetworkConfigTarget,
}

fn build_reward_session_circuit(
    common: &CommonCircuitData<F, 2>, capacity: usize, source_chain_count: usize,
    fingerprints: [[F; 4]; 4], origin_root: [u64; 4],
) -> anyhow::Result<(CircuitData<F, PoseidonGoldilocksConfig, 2>, RewardSessionCircuitTargets)> {
    use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;
    anyhow::ensure!(capacity > 0 && capacity <= u32::MAX as usize, "invalid reward session step capacity");
    let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_ecc_config());
    for gate in &common.gates { builder.add_gate_to_gate_set(gate.clone()); }
    let statement = RewardSessionStatement::new(&mut builder);
    let predecessors = RewardPredecessorTargets::new(&mut builder, common)?;
    let end_id = builder.add_virtual_target();
    let ledger_window = RewardLedgerWindowTargets::new(&mut builder, &statement, end_id, &predecessors.verifier);
    let session = RewardSessionTargets::new(&mut builder, &statement, &ledger_window.economic_domain);
    builder.connect(end_id, session.end_checkpoint_id);
    let config = psy_plonky2_common_circuits::bridge::aggregate_config::NetworkConfigTarget::new(
        &mut builder, source_chain_count,
    );
    let config_hash = config.hash(&mut builder);
    for (index, word) in config_hash.into_iter().enumerate() {
        let bits = builder.split_le(word, 32);
        for byte in 0..4 {
            let value = builder.le_sum(bits[(3 - byte) * 8..(4 - byte) * 8].iter());
            builder.connect(value, ledger_window.config_hash[index * 4 + byte]);
        }
    }
    let source_low = builder.is_less_than(32, session.source_checkpoint_id, config.reward_cutover[0]);
    let zero = builder.zero();
    builder.assert_zero(config.reward_cutover[1]);
    builder.assert_zero(source_low.target);
    let end_high_zero = builder.is_equal(config.reward_end_exclusive[1], zero);
    let source_before_end = builder.is_less_than(32, session.source_checkpoint_id, config.reward_end_exclusive[0]);
    let not_before = builder.not(source_before_end);
    let invalid_source = builder.and(end_high_zero, not_before);
    builder.assert_zero(invalid_source.target);
    let mut is_payer = builder._true();
    for index in 0..5 {
        let equal = builder.is_equal(statement.fields[5 + index], config.reward_payer[4 - index]);
        is_payer = builder.and(is_payer, equal);
    }
    builder.assert_zero(is_payer.target);
    let old_state = RewardLedgerStateTargets::new(&mut builder);
    let new_state = RewardLedgerStateTargets::new(&mut builder);
    let own_state = RewardLedgerStateTargets::new(&mut builder);
    let origin = predecessors.connect(&mut builder, &statement, &ledger_window, &old_state, &own_state, origin_root);
    let old_summary = builder.add_virtual_hash();
    let old_session_root = builder.add_virtual_hash();
    let session_siblings = std::array::from_fn(|_| builder.add_virtual_hash());
    let own_siblings = std::array::from_fn(|_| builder.add_virtual_hash());
    let mut empty_session_root = HashOutTarget { elements: [zero; 4] };
    for _ in 0..63 {
        empty_session_root = builder.hash_two_to_one::<PoseidonHash>(empty_session_root, empty_session_root);
    }
    connect_session_predecessor(&mut builder, &predecessors, &session, &own_state,
        old_summary, old_session_root, &own_siblings, empty_session_root);
    let reward_amount = std::array::from_fn(|index| config.reward_per_claim[7 - index]);
    let mut jobs = Vec::with_capacity(capacity);
    let mut session_root = old_session_root;
    for _ in 0..capacity {
        let job = RewardSessionJobTargets::new(&mut builder, &statement, &session, session_root, reward_amount);
        session_root = job.next_root;
        jobs.push(job);
    }
    let identity_step = constrain_reward_session_step(&mut builder, &statement, &predecessors, &session, &jobs, &ledger_window);
    let is_final_step = builder.add_virtual_bool_target_safe();
    builder.connect_if_true(identity_step, is_final_step.target, zero);
    let no_global = builder.not(predecessors.has_global);
    let first_identity = builder.and(identity_step, no_global);
    let one = builder.one();
    builder.connect_if_true(first_identity, origin.target, one);
    builder.connect_hashes_if_true(identity_step, statement.hash(26), ledger_window.start_root);
    builder.connect_hashes_if_true(identity_step, old_state.root, new_state.root);
    let ledger_leaf = RewardLedgerLeafTargets::new(&mut builder, &statement, &session, &ledger_window,
        is_final_step, old_state.ledger_root);
    let empty_bytes = domain_bytes(&mut builder, b"PsyRewardLedger/Empty/1");
    let mut empty_user_root = builder.hash_n_to_hash_no_pad::<PoseidonHash>(empty_bytes);
    for height in 1..=32 {
        let mut bytes = domain_bytes(&mut builder, b"PsyRewardLedger/Node/1");
        bytes.push(builder.constant(F::from_canonical_usize(height)));
        append_hash_bytes(&mut builder, &mut bytes, empty_user_root);
        append_hash_bytes(&mut builder, &mut bytes, empty_user_root);
        empty_user_root = builder.hash_n_to_hash_no_pad::<PoseidonHash>(bytes);
    }
    let zero_hash = builder.constant_hash(plonky2::hash::hash_types::HashOut { elements: [F::ZERO; 4] });
    let mut empty_issued_root = zero_hash;
    for _ in 0..64 {
        empty_issued_root = builder.hash_two_to_one::<PoseidonHash>(empty_issued_root, empty_issued_root);
    }
    builder.connect_hashes_if_true(origin, old_state.ledger_window_hash, zero_hash);
    builder.connect_hashes_if_true(origin, old_state.ledger_root, empty_issued_root);
    builder.connect_hashes_if_true(origin, old_state.user_root, empty_user_root);
    builder.connect_if_true(origin, old_state.session_count, zero);
    builder.connect_if_true(origin, old_state.unfinished_session_count, zero);
    constrain_session_update(&mut builder, &statement, &predecessors, &session,
        &old_state, &new_state, &ledger_window, old_summary, session_root, &session_siblings,
        empty_user_root, is_final_step, &ledger_leaf, identity_step);
    let identity = UserAuthTargets::new(&mut builder, &statement, &session, &ledger_window,
        is_final_step, fingerprints);
    builder.register_public_inputs(&statement.fields);
    while builder.num_gates() < common.degree() / 2 + 1 {
        builder.add_gate(plonky2::gates::noop::NoopGate, vec![]);
    }
    let circuit = builder.build::<PoseidonGoldilocksConfig>();
    let targets = RewardSessionCircuitTargets { statement, session, ledger_window, predecessors,
        old_state, new_state, own_state, old_summary, old_session_root, session_siblings,
        own_siblings, is_final_step, jobs, ledger_leaf, identity, config };
    Ok((circuit, targets))
}

pub struct RewardSessionCircuit {
    pub circuit_data: CircuitData<F, PoseidonGoldilocksConfig, 2>,
    targets: RewardSessionCircuitTargets,
    capacity: usize,

    identity_fingerprints: [[F; 4]; 4],
}

impl RewardSessionCircuit {
    pub fn new(capacity: usize, source_chain_count: usize) -> anyhow::Result<Self> {
        use psy_common_circuit::circuits::{
            traits::qstandard::QStandardCircuit,
            zk_signature3::core::PsyBasicZKSignatureCircuit,
            secp256k1_signature::{Secp256K1SignatureCircuit, EthPersonalSignSecp256K1SignatureCircuit},
        };
        use psy_ups_circuit::signature::multisig::MultisigSignatureCircuit;
        anyhow::ensure!(capacity > 0 && capacity <= u32::MAX as usize, "invalid reward session step capacity");
        let fingerprints = [
            PsyBasicZKSignatureCircuit::<PoseidonGoldilocksConfig, 2>::new().get_fingerprint().0.elements,
            Secp256K1SignatureCircuit::<PoseidonGoldilocksConfig, 2>::new().get_fingerprint().0.elements,
            EthPersonalSignSecp256K1SignatureCircuit::<PoseidonGoldilocksConfig, 2>::new().get_fingerprint().0.elements,
            MultisigSignatureCircuit::new()?.get_fingerprint().0.elements,
        ];
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_ecc_config());
        let origin_state = origin_state_root();
        for _ in 0..REWARD_SESSION_PROOF_FIELD_COUNT { builder.add_virtual_public_input(); }
        while builder.num_gates() < 32 { builder.add_gate(plonky2::gates::noop::NoopGate, vec![]); }
        let mut common = builder.build::<PoseidonGoldilocksConfig>().common;
        for _ in 0..8 {
            let (circuit_data, targets) = build_reward_session_circuit(&common, capacity, source_chain_count, fingerprints, origin_state)?;
            anyhow::ensure!(circuit_data.common.num_public_inputs == REWARD_SESSION_PROOF_FIELD_COUNT,
                "reward session circuit changed its 34-field statement");
            if circuit_data.common == common {
                return Ok(Self { circuit_data, targets, capacity, identity_fingerprints: fingerprints });
            }
            common = circuit_data.common;
        }
        anyhow::bail!("reward session recursion common data did not stabilize for capacity {capacity}")
    }

    pub fn identity_fingerprint(&self, authorization: &psy_vm::reward_authorization::RewardAuthorizationWitness) -> anyhow::Result<[u64; 4]> {
        use psy_vm::reward_authorization::RewardAuthorizationWitness;
        let scheme = match authorization {
            RewardAuthorizationWitness::Zk { .. } => 0,
            RewardAuthorizationWitness::Secp { .. } => 1,
            RewardAuthorizationWitness::PersonalSign { .. } => 2,
            RewardAuthorizationWitness::Multisig { .. } => 3,
        };
        self.identity_fingerprint_for_scheme(scheme)
    }

    pub fn identity_fingerprint_for_scheme(&self, scheme: u8) -> anyhow::Result<[u64; 4]> {
        use plonky2::field::types::PrimeField64;
        let fingerprint = self.identity_fingerprints.get(usize::from(scheme))
            .context("reward session identity scheme must be 0..3")?;
        Ok(fingerprint.map(|value| value.to_canonical_u64()))
    }
}


impl RewardSessionCircuit {
    pub fn prove_identity(
        &self, config: &psy_client_data::bridge_aggregate::NetworkConfig,
        window: &super::reward_ledger::RewardLedgerWindowValues,
        leaf: &psy_client_data::qdata::checkpoint::PsyCheckpointLeaf<F>,
        path: &[[u64; 4]; 32],
        roots: &psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots<F>,
        prior: Option<(&plonky2::plonk::proof::ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>, &RewardLedgerStateValues)>,
    ) -> anyhow::Result<(plonky2::plonk::proof::ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>, RewardLedgerStateValues)> {
        use plonky2::{field::types::PrimeField64, hash::hash_types::HashOut, plonk::config::Hasher};
        anyhow::ensure!(window.config_hash == config.config_hash()? && window.economic_domain == config.clone().load()?.economic_domain(), "reward identity configuration mismatch");
        let mut empty_session = HashOut { elements: [F::ZERO; 4] };
        for _ in 0..63 { empty_session = PoseidonHash::two_to_one(empty_session, empty_session); }
        let state = if let Some((proof, state)) = prior {
            self.circuit_data.verify(proof.clone())?;
            anyhow::ensure!(proof.public_inputs[30..34].iter().zip(window.start_root).all(|(value, limb)| value.to_canonical_u64() == limb), "reward identity predecessor root mismatch");
            *state
        } else {
            anyhow::ensure!(window.start_root == origin_state_root(), "reward identity predecessor missing");
            let issued = PoseidonHash::two_to_one(empty_session, empty_session);
            RewardLedgerStateValues { ledger_window_hash: [0; 4], ledger_root: issued.elements.map(|value| value.to_canonical_u64()),
                user_root: super::reward_ledger::empty_user_root()?, session_count: 0, unfinished_session_count: 0 }
        };
        anyhow::ensure!(super::reward_ledger::state_root(&state)? == window.start_root, "reward identity state mismatch");
        let (_, commitment) = super::reward_ledger::window_hash(window, &self.circuit_data.verifier_only)?;
        let input = RewardSessionWitness {
            statement: psy_client_data::bridge_aggregate::RewardSessionProofFields {
                checkpoint_tree_root: window.end_checkpoint_root, user_id: 0, recipient: [0; 8], total_amount: [0; 8], count: 0,
                jobs_commitment: commitment, old_ledger_state_root: window.start_root, new_ledger_state_root: window.start_root,
            },
            config: config.clone(), economic_domain: window.economic_domain, window_id: window.window_id, start_root: window.start_root,
            source_checkpoint_id: window.end_checkpoint_id, end_checkpoint_id: window.end_checkpoint_id,
            source_leaf: leaf.clone(), source_path: *path, old_state: state, new_state: state, own_state: state,
            old_summary: super::reward_ledger::empty_summary()?, old_session_root: empty_session.elements.map(|value| value.to_canonical_u64()),
            session_siblings: [[0; 4]; 32], own_siblings: [[0; 4]; 32], ledger_siblings: [[0; 4]; 64],
            own_previous: None, global_previous: prior.map(|(proof, _)| proof), jobs: &[], is_final_step: false,
            end_leaf: leaf.clone(), end_path: *path, end_roots: roots.clone(), user_leaf: Default::default(),
            user_path: vec![[0; 4]; GLOBAL_USER_TREE_HEIGHT as usize], public_key_param: [0; 4], authorization: None,
        };
        let proof = self.prove(&input)?;
        self.circuit_data.verify(proof.clone())?;
        Ok((proof, state))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardLedgerStateValues {
    pub ledger_window_hash: [u64; 4],
    pub ledger_root: [u64; 4],
    pub user_root: [u64; 4],
    pub session_count: u32,
    pub unfinished_session_count: u32,
}

pub struct RewardSessionJobWitness {
    pub height: u8,
    pub path_index: u32,
    pub tag: super::reward_inclusion::RewardTagWitness,
    pub nullifier_siblings: [[u64; 4]; 63],
}

pub struct RewardSessionWitness<'a> {
    pub statement: psy_client_data::bridge_aggregate::RewardSessionProofFields,
    pub config: psy_client_data::bridge_aggregate::NetworkConfig,
    pub economic_domain: [u8; 32],
    pub window_id: [u8; 32],
    pub start_root: [u64; 4],
    pub source_checkpoint_id: u32,
    pub end_checkpoint_id: u32,
    pub source_leaf: psy_client_data::qdata::checkpoint::PsyCheckpointLeaf<F>,
    pub source_path: [[u64; 4]; 32],
    pub old_state: RewardLedgerStateValues,
    pub new_state: RewardLedgerStateValues,
    pub own_state: RewardLedgerStateValues,
    pub old_summary: [u64; 4],
    pub old_session_root: [u64; 4],
    pub session_siblings: [[u64; 4]; 32],
    pub own_siblings: [[u64; 4]; 32],
    pub ledger_siblings: [[u64; 4]; 64],
    pub own_previous: Option<&'a plonky2::plonk::proof::ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>>,
    pub global_previous: Option<&'a plonky2::plonk::proof::ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>>,
    pub jobs: &'a [RewardSessionJobWitness],
    pub is_final_step: bool,
    pub end_leaf: psy_client_data::qdata::checkpoint::PsyCheckpointLeaf<F>,
    pub end_path: [[u64; 4]; 32],
    pub end_roots: psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots<F>,
    pub user_leaf: psy_client_data::qdata::user::PsyUserLeaf<F>,
    pub user_path: Vec<[u64; 4]>,
    pub public_key_param: [u64; 4],
    pub authorization: Option<&'a psy_vm::reward_authorization::RewardAuthorizationWitness>,
}

fn set_hash(
    witness: &mut plonky2::iop::witness::PartialWitness<F>, target: HashOutTarget, value: [u64; 4],
) -> anyhow::Result<()> {
    use plonky2::iop::witness::WitnessWrite;
    anyhow::ensure!(value.iter().all(|limb| *limb < 0xffff_ffff_0000_0001), "noncanonical reward session hash");
    witness.set_hash_target(target, plonky2::hash::hash_types::HashOut {
        elements: value.map(F::from_canonical_u64),
    })
}

impl RewardLedgerStateTargets {
    pub(super) fn set_witness(
        &self, witness: &mut plonky2::iop::witness::PartialWitness<F>, state: &RewardLedgerStateValues,
    ) -> anyhow::Result<()> {
        use plonky2::iop::witness::WitnessWrite;
        set_hash(witness, self.ledger_window_hash, state.ledger_window_hash)?;
        set_hash(witness, self.ledger_root, state.ledger_root)?;
        set_hash(witness, self.user_root, state.user_root)?;
        witness.set_target(self.session_count, F::from_canonical_u32(state.session_count))?;
        witness.set_target(self.unfinished_session_count, F::from_canonical_u32(state.unfinished_session_count))
    }
}

impl RewardSessionCircuit {
    fn set_reward_session_witness(
        &self, input: &RewardSessionWitness<'_>,
    ) -> anyhow::Result<plonky2::iop::witness::PartialWitness<F>> {
        use plonky2::iop::witness::{PartialWitness, WitnessWrite};
        use plonky2::recursion::dummy_circuit::{dummy_circuit, dummy_proof};
        anyhow::ensure!(input.jobs.len() <= self.capacity, "reward session job count is outside circuit capacity");
        if input.jobs.is_empty() {
            anyhow::ensure!(input.own_previous.is_none() && !input.is_final_step && input.statement.count == 0
                && input.statement.total_amount == [0; 8] && input.statement.recipient == [0; 8]
                && input.old_state == input.new_state && input.statement.old_ledger_state_root == input.statement.new_ledger_state_root,
                "invalid reward identity transition");
            anyhow::ensure!(input.global_previous.is_some() || input.start_root == origin_state_root(), "reward identity predecessor missing");
        }
        anyhow::ensure!(!input.is_final_step || input.authorization.is_some(), "final-step authorization missing");
        let mut witness = PartialWitness::new();
        let targets = &self.targets;
        for (target, value) in targets.statement.fields.into_iter().zip(input.statement.to_public_inputs()?) {
            witness.set_target(target, F::from_canonical_u64(value))?;
        }
        targets.config.set_witness(&mut witness, &input.config)?;
        for (targets, bytes) in [(&targets.ledger_window.economic_domain, &input.economic_domain),
            (&targets.ledger_window.window_id, &input.window_id)] {
            for (target, byte) in targets.iter().zip(bytes) {
                witness.set_target(*target, F::from_canonical_u8(*byte))?;
            }
        }
        set_hash(&mut witness, targets.ledger_window.start_root, input.start_root)?;
        witness.set_target(targets.session.source_checkpoint_id, F::from_canonical_u32(input.source_checkpoint_id))?;
        witness.set_target(targets.session.end_checkpoint_id, F::from_canonical_u32(input.end_checkpoint_id))?;
        targets.session.source.checkpoint_leaf.set_witness(&mut witness, &input.source_leaf)?;
        for (target, value) in targets.session.source.path.siblings.iter().zip(input.source_path) {
            set_hash(&mut witness, *target, value)?;
        }
        targets.old_state.set_witness(&mut witness, &input.old_state)?;
        targets.new_state.set_witness(&mut witness, &input.new_state)?;
        targets.own_state.set_witness(&mut witness, &input.own_state)?;
        set_hash(&mut witness, targets.old_summary, input.old_summary)?;
        set_hash(&mut witness, targets.old_session_root, input.old_session_root)?;
        for (target, value) in targets.session_siblings.iter().zip(input.session_siblings)
            .chain(targets.own_siblings.iter().zip(input.own_siblings))
            .chain(targets.ledger_leaf.siblings.iter().zip(input.ledger_siblings)) {
            set_hash(&mut witness, *target, value)?;
        }
        witness.set_bool_target(targets.is_final_step, input.is_final_step)?;
        let predecessors = &targets.predecessors;
        witness.set_bool_target(predecessors.has_own, input.own_previous.is_some())?;
        witness.set_bool_target(predecessors.has_global, input.global_previous.is_some())?;
        witness.set_verifier_data_target(&predecessors.verifier, &self.circuit_data.verifier_only)?;
        let dummy_data = dummy_circuit::<F, PoseidonGoldilocksConfig, 2>(&self.circuit_data.common);
        let dummy = dummy_proof(&dummy_data, Default::default())?;
        witness.set_proof_with_pis_target(&predecessors.dummy, &dummy)?;
        for (target, proof) in [(&predecessors.own, input.own_previous), (&predecessors.global, input.global_previous)] {
            if let Some(proof) = proof {
                anyhow::ensure!(proof.public_inputs.len() == REWARD_SESSION_PROOF_FIELD_COUNT, "reward session predecessor width mismatch");
                witness.set_proof_with_pis_target(target, proof)?;
            } else {
                witness.set_proof_with_pis_target(target, &dummy)?;
            }
        }
        use plonky2::plonk::config::Hasher;
        use parth_core::pgoldilocks::QHashOut;
        let preimage = plonky2::hash::hash_types::HashOut { elements: [F::ONE; 4] };
        let tag = PoseidonHash::two_to_one(preimage, preimage);
        let padding = RewardSessionJobWitness {
            height: 2, path_index: 0,
            tag: super::reward_inclusion::RewardTagWitness {
                tag_preimage: QHashOut(preimage), leaf_left: QHashOut::default(), leaf_right: QHashOut::default(), leaf_tag: QHashOut(tag),
                siblings: [QHashOut::default(); 21], parent_tags: [QHashOut::default(); 21],
            },
            nullifier_siblings: [[0; 4]; 63],
        };
        for (index, target) in targets.jobs.iter().enumerate() {
            let job = input.jobs.get(index).unwrap_or(&padding);
            anyhow::ensure!((2..=21).contains(&job.height), "reward session job height out of range");
            anyhow::ensure!(job.path_index < 1u32 << (job.height - 2), "reward session job index out of range");
            witness.set_bool_target(target.is_active, index < input.jobs.len())?;
            witness.set_target(target.reward.height, F::from_canonical_u8(job.height))?;
            witness.set_target(target.reward.path_index, F::from_canonical_u32(job.path_index))?;
            target.tag.set_witness(&mut witness, &job.tag)?;
            for (sibling, hash) in target.nullifier.siblings.iter().zip(job.nullifier_siblings) {
                set_hash(&mut witness, *sibling, hash)?;
            }
        }
        targets.identity.end_checkpoint.end_leaf.set_witness(&mut witness, &input.end_leaf)?;
        targets.identity.end_checkpoint.roots.set_witness(&mut witness, &input.end_roots)?;
        targets.identity.user_leaf.user.set_witness(&mut witness, &input.user_leaf)?;
        for (target, value) in targets.identity.end_checkpoint.end_path.path.siblings.iter().zip(input.end_path) {
            set_hash(&mut witness, *target, value)?;
        }
        anyhow::ensure!(input.user_path.len() == targets.identity.user_leaf.user_path.siblings.len(), "reward session user path length mismatch");
        for (target, value) in targets.identity.user_leaf.user_path.siblings.iter().zip(&input.user_path) {
            set_hash(&mut witness, *target, *value)?;
        }
        Ok(witness)
    }
}

impl RewardSessionCircuit {
    pub fn capacity(&self) -> usize { self.capacity }

}


impl RewardSessionCircuit {
    pub fn authorization_message(&self, input: &RewardSessionWitness<'_>) -> anyhow::Result<[u8; 32]> {
        use plonky2::field::types::PrimeField64;
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        use psy_vm::reward_authorization::{RewardSessionAuthorization,
            build_reward_session_authorization_message};
        let authorization = input.authorization.context("final-step authorization scheme missing")?;
        build_reward_session_authorization_message(&RewardSessionAuthorization {
            config_hash: input.config.config_hash()?, economic_domain: input.economic_domain,
            window_id: input.window_id, source_checkpoint_id: input.source_checkpoint_id,
            end_checkpoint_id: input.end_checkpoint_id, user_id: input.statement.user_id,
            checkpoint_tree_root: input.statement.checkpoint_tree_root,
            source_checkpoint_leaf_hash: input.source_leaf.qfhash::<PoseidonHash>().0.elements.map(|v| v.to_canonical_u64()),
            end_checkpoint_leaf_hash: input.end_leaf.qfhash::<PoseidonHash>().0.elements.map(|v| v.to_canonical_u64()),
            user_leaf_hash: input.user_leaf.qfhash::<PoseidonHash>().0.elements.map(|v| v.to_canonical_u64()),
            identity_fingerprint: self.identity_fingerprint(authorization)?,
            public_key_param: input.public_key_param, nonce: input.user_leaf.nonce.to_canonical_u64(),
            jobs_commitment: input.statement.jobs_commitment, count: input.statement.count,
            amount: input.statement.total_amount,
            recipient: std::array::from_fn(|i| input.statement.recipient[i]),
        })
    }
}

impl RewardSessionCircuit {
    fn set_identity_witness(
        &self, witness: &mut plonky2::iop::witness::PartialWitness<F>, input: &RewardSessionWitness<'_>,
    ) -> anyhow::Result<()> {
        use plonky2::iop::witness::WitnessWrite;
        use psy_vm::reward_authorization::RewardAuthorizationWitness;
        use super::reward_session_witness::{AuthSignatureValues, MultisigPolicyValues,
            auth_signature_padding, multisig_policy_padding, set_auth_signature, set_multisig_policy};
        let target = &self.targets.identity;
        let message = if input.is_final_step { self.authorization_message(input)? } else { [0; 32] };
        let mut signatures = [auth_signature_padding(false)?, auth_signature_padding(false)?,
            auth_signature_padding(true)?];
        let mut policy = multisig_policy_padding()?;
        let mut private_key = [0; 4];
        let scheme = if input.is_final_step {
            match input.authorization.context("final-step authorization missing")? {
                RewardAuthorizationWitness::Zk { private_key: key } => {
                    use plonky2::field::types::PrimeField64;
                    private_key = key.0.elements.map(|value| value.to_canonical_u64());
                    0
                },
                RewardAuthorizationWitness::Secp { compressed_public_key, signature_rs } => {
                    signatures[0] = AuthSignatureValues::from_bytes(compressed_public_key, signature_rs, message)?;
                    1
                },
                RewardAuthorizationWitness::PersonalSign { compressed_public_key, signature_rs } => {
                    signatures[2] = AuthSignatureValues::from_bytes(compressed_public_key, signature_rs, message)?;
                    2
                },
                RewardAuthorizationWitness::Multisig { contract_id, initial_policy, policy_slots,
                    contract_state_paths, policy_slot_paths, member_indices, compressed_public_keys, signatures_rs } => {
                    initial_policy.validate()?;
                    let account = psy_vm::ups::multisig::MultisigAccount {
                        contract_id: *contract_id, initial_policy: initial_policy.clone(),
                    };
                    let initial_slots = [psy_client_common::data::qhashout::QHashOut::from_values(
                        initial_policy.version as u64, 2, 3, 0), initial_policy.member_hashes[0],
                        initial_policy.member_hashes[1], initial_policy.member_hashes[2]];
                    policy = MultisigPolicyValues { initial_slots, current_slots: *policy_slots,
                        selected: *member_indices, slot_paths: *policy_slot_paths,
                        contract_paths: contract_state_paths.clone(), public_key_param: account.public_key_param()? };
                    for index in 0..2 {
                        signatures[index] = AuthSignatureValues::from_bytes(
                            &compressed_public_keys[index], &signatures_rs[index], message)?;
                    }
                    3
                },
            }
        } else { 0 };
        witness.set_target(target.scheme, F::from_canonical_u32(scheme))?;
        set_hash(witness, target.private_key, private_key)?;
        set_hash(witness, target.public_key_param, input.public_key_param)?;
        for (gadget, signature) in target.signatures.iter().zip(&signatures) {
            set_auth_signature(witness, gadget, signature)?;
        }
        set_multisig_policy(witness, &target.policy, &policy)
    }

    pub fn prove(
        &self, input: &RewardSessionWitness<'_>,
    ) -> anyhow::Result<plonky2::plonk::proof::ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>> {
        let mut witness = self.set_reward_session_witness(input)?;
        self.set_identity_witness(&mut witness, input)?;
        self.circuit_data.prove(witness)
    }
}
