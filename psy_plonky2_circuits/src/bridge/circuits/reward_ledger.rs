use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, Field64, PrimeField64}},
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::PoseidonHash,
    },
    plonk::{
        circuit_data::{CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData},
        config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_data::{
    bridge_aggregate::{RewardSessionProofFields, SourceCheckpointRewardLeaf, REWARD_SESSION_PROOF_FIELD_COUNT},
    qdata::checkpoint::PsyCheckpointLeaf,
};
use psy_crypto::hash::{core::sha256::CoreSha256Hasher, traits::qhashable::QFieldHashable};
use super::reward_session::RewardLedgerStateValues;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
pub type Hash4 = [u64; 4];

const SESSION_DOMAIN: &[u8] = b"PsyRewardJobs/Session/1";
const SUMMARY_DOMAIN: &[u8] = b"PsyRewardSession/Summary/1";
const STATE_DOMAIN: &[u8] = b"PsyRewardLedger/State/1";
const WINDOW_DOMAIN: &[u8] = b"PsyRewardLedger/Window/1";
const VERIFIER_DOMAIN: &[u8] = b"PsyRewardLedger/Verifier/1";
const NODE_DOMAIN: &[u8] = b"PsyRewardLedger/Node/1";
const EMPTY_DOMAIN: &[u8] = b"PsyRewardLedger/Empty/1";
const PROOF_ID_DOMAIN: &[u8] = b"PsyRewardLedger/Proof/1";
const ORDER: u64 = F::ORDER;
const PROOF_BYTES_LIMIT: usize = 16_777_216;

/// Server-trusted window. Its hash is computed from these values and `verifier`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardLedgerWindowValues {
    pub config_hash: [u8; 32],
    pub economic_domain: [u8; 32],
    pub window_id: [u8; 32],
    pub end_checkpoint_id: u32,
    pub end_checkpoint_root: Hash4,
    pub start_root: Hash4,
}

/// One host-visible sparse write. Height 0 is the user-tree leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardLedgerNodeUpdate {
    pub height: u8,
    pub index: u64,
    pub hash: [u8; 32],
}

/// Owned public step. Verification borrows its fields; there is no second step type.
#[derive(Clone, Debug)]
pub struct RewardLedgerStep {
    pub proof: Vec<u8>,
    pub old_state: RewardLedgerStateValues,
    pub new_state: RewardLedgerStateValues,
    pub source_checkpoint_id: u32,
    pub source_leaf: PsyCheckpointLeaf<F>,
    pub source_path: [Hash4; 32],
    pub old_summary: Hash4,
    pub session_root: Hash4,
    pub summary_siblings: [Hash4; 32],
    pub is_final_step: bool,
}

/// Verified public transition.
/// `proof_id` is `SHA-256(PsyRewardLedger/Proof/1 || full verifier hash || canonical proof bytes)`.
/// The verifier hash is `PsyRewardLedger/Verifier/1` over the digest and cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardLedgerTransition {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub proof_id: [u8; 32],
    pub transition_bytes: Vec<u8>,
    pub nodes: Vec<RewardLedgerNodeUpdate>,
    pub source_payout: Option<SourceCheckpointRewardLeaf>,
}

pub fn reward_ledger_proof_id(verifier: &VerifierOnlyCircuitData<C, 2>, proof: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(PROOF_ID_DOMAIN.len() + 32 + proof.len());
    preimage.extend_from_slice(PROOF_ID_DOMAIN);
    preimage.extend_from_slice(&canonical_bytes(verifier_hash(verifier)?)?);
    preimage.extend_from_slice(proof);
    Ok(CoreSha256Hasher::hash_bytes(&preimage).0)
}

pub fn reward_session_root(
    source: u32, old_root: Hash4, jobs: &[super::reward_session::RewardSessionJobWitness],
) -> anyhow::Result<Hash4> {
    anyhow::ensure!(!jobs.is_empty(), "reward session step includes no job");
    let mut root = old_root;
    for job in jobs {
        anyhow::ensure!((2..=21).contains(&job.height), "reward session job height is outside 2..=21");
        let width = u32::from(job.height) - 2;
        let bound = 1u32.checked_shl(width).ok_or_else(|| anyhow::anyhow!("reward session job index bound overflow"))?;
        anyhow::ensure!(job.path_index < bound, "reward session job index exceeds its height");
        anyhow::ensure!(job.nullifier_siblings.len() == 63, "reward session job path is not 63 siblings");
        let key = (u64::from(source) << 31) | (u64::from(job.height) << 26) | u64::from(job.path_index);
        anyhow::ensure!(poseidon_path(key, [0; 4], &job.nullifier_siblings)? == root, "reward session job is not in the current root");
        root = poseidon_path(key, [1, 0, 0, 0], &job.nullifier_siblings)?;
    }
    anyhow::ensure!(root != old_root, "reward session root did not change");
    Ok(root)
}

pub fn verify_reward_ledger_step(
    common: &CommonCircuitData<F, 2>,
    verifier: &VerifierOnlyCircuitData<C, 2>,
    window: &RewardLedgerWindowValues,
    expected_old_root: Hash4,
    step: &RewardLedgerStep,
) -> anyhow::Result<RewardLedgerTransition> {
    anyhow::ensure!((1..=PROOF_BYTES_LIMIT).contains(&step.proof.len()), "reward ledger proof bytes out of range");
    let proof = ProofWithPublicInputs::<F, C, 2>::from_bytes(step.proof.to_vec(), common)
        .map_err(|error| anyhow::anyhow!("reward ledger proof bytes are not canonical: {error}"))?;
    let canonical = proof.to_bytes();
    anyhow::ensure!(canonical.as_slice() == step.proof, "reward ledger proof serialization is not canonical");
    let inputs = public_inputs(&proof)?;
    let circuit = VerifierCircuitData { verifier_only: verifier.clone(), common: common.clone() };
    circuit.verify(proof).map_err(|error| anyhow::anyhow!("reward ledger verifier rejected the proof: {error}"))?;
    let fields = RewardSessionProofFields::from_public_inputs(&inputs)
        .map_err(|error| anyhow::anyhow!("reward ledger statement rejected: {error}"))?;
    let old_root = state_root(&step.old_state)?;
    let new_root = state_root(&step.new_state)?;
    anyhow::ensure!(old_root == expected_old_root, "reward ledger old root is not the locked state");
    anyhow::ensure!(fields.old_ledger_state_root == old_root, "reward ledger proof old root mismatch");
    anyhow::ensure!(fields.new_ledger_state_root == new_root, "reward ledger proof new root mismatch");
    let (_, expected_window) = window_hash(window, verifier)?;
    anyhow::ensure!(step.new_state.ledger_window_hash == expected_window, "reward ledger window hash mismatch");
    let first_global = old_root == window.start_root;
    let working_user_root = if first_global { empty_user_root()? } else { step.old_state.user_root };
    if !first_global {
        anyhow::ensure!(step.old_state.ledger_window_hash == expected_window, "reward ledger predecessor left its window");
    }
    let source_id = step.source_checkpoint_id;
    anyhow::ensure!(u64::from(source_id) <= u64::from(window.end_checkpoint_id), "source checkpoint follows the window end");
    let source_hash = hash4(step.source_leaf.qfhash::<PoseidonHash>().0.elements.map(|limb| limb.to_canonical_u64()))?;
    let source_root = poseidon_path(u64::from(source_id), source_hash, &step.source_path)?;
    anyhow::ensure!(source_root == fields.checkpoint_tree_root, "source checkpoint is not under the statement end root");
    anyhow::ensure!(fields.checkpoint_tree_root == window.end_checkpoint_root, "statement end root is not the trusted window end");
    let seed = session_seed(window, source_id, &fields, source_hash)?;
    let old_user_root = summary_root(fields.user_id, step.old_summary, &step.summary_siblings)?;
    anyhow::ensure!(old_user_root == working_user_root, "reward ledger old summary is not in the working user root");
    let new_summary = summary(&fields, seed, step.session_root, step.is_final_step)?;
    anyhow::ensure!(new_summary != empty_summary()?, "reward ledger summary collided with the empty summary");
    let new_user_root = summary_root(fields.user_id, new_summary, &step.summary_siblings)?;
    anyhow::ensure!(new_user_root == step.new_state.user_root, "reward ledger new user root mismatch");
    anyhow::ensure!(step.new_state.ledger_root == step.old_state.ledger_root || step.is_final_step, "nonfinal reward ledger root changed");
    let first_own = step.old_summary == empty_summary()?;
    check_counts(step, first_global, first_own)?;
    let source_payout = if step.is_final_step { Some(payout(&fields, window, source_id)?) } else { None };
    let nodes = user_nodes(fields.user_id, new_summary, &step.summary_siblings)?;
    Ok(RewardLedgerTransition {
        old_root: canonical_bytes(old_root)?,
        new_root: canonical_bytes(new_root)?,
        proof_id: reward_ledger_proof_id(verifier, &canonical)?,
        transition_bytes: transition_bytes(window, step, &fields, &nodes)?,
        nodes,
        source_payout,
    })
}
fn public_inputs(proof: &ProofWithPublicInputs<F, C, 2>) -> anyhow::Result<[u64; REWARD_SESSION_PROOF_FIELD_COUNT]> {
    anyhow::ensure!(proof.public_inputs.len() == REWARD_SESSION_PROOF_FIELD_COUNT, "reward ledger proof does not expose 34 fields");
    Ok(std::array::from_fn(|index| proof.public_inputs[index].to_canonical_u64()))
}

fn transition_bytes(
    window: &RewardLedgerWindowValues, step: &RewardLedgerStep, fields: &RewardSessionProofFields,
    nodes: &[RewardLedgerNodeUpdate],
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&window.config_hash);
    bytes.extend_from_slice(&window.economic_domain);
    bytes.extend_from_slice(&window.window_id);
    append_u32(&mut bytes, window.end_checkpoint_id);
    append_raw_hash(&mut bytes, window.end_checkpoint_root)?;
    append_raw_hash(&mut bytes, window.start_root)?;
    append_state(&mut bytes, &step.old_state)?;
    append_state(&mut bytes, &step.new_state)?;
    append_u32(&mut bytes, step.source_checkpoint_id);
    append_u32(&mut bytes, fields.user_id);
    append_raw_hash(&mut bytes, fields.checkpoint_tree_root)?;
    let leaf = bincode::serialize(&step.source_leaf).map_err(|error| anyhow::anyhow!("source checkpoint leaf encoding rejected: {error}"))?;
    anyhow::ensure!(leaf.len() <= PROOF_BYTES_LIMIT, "source checkpoint leaf exceeds transition bound");
    bytes.extend_from_slice(&(leaf.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&leaf);
    for sibling in &step.source_path { append_raw_hash(&mut bytes, *sibling)?; }
    append_raw_hash(&mut bytes, step.old_summary)?;
    append_raw_hash(&mut bytes, step.session_root)?;
    for sibling in &step.summary_siblings { append_raw_hash(&mut bytes, *sibling)?; }
    bytes.push(u8::from(step.is_final_step));
    bytes.extend_from_slice(&33u32.to_le_bytes());
    for node in nodes {
        bytes.push(node.height);
        bytes.extend_from_slice(&node.index.to_le_bytes());
        bytes.extend_from_slice(&node.hash);
    }
    bytes.extend_from_slice(&(step.proof.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&step.proof);
    anyhow::ensure!((1..=PROOF_BYTES_LIMIT).contains(&bytes.len()), "reward ledger transition bytes out of range");
    Ok(bytes)
}

pub fn deserialize_reward_ledger_transition(bytes: &[u8]) -> anyhow::Result<(RewardLedgerWindowValues, RewardLedgerStep, Vec<RewardLedgerNodeUpdate>)> {
    anyhow::ensure!((1..=PROOF_BYTES_LIMIT).contains(&bytes.len()), "reward ledger transition bytes out of range");
    let mut cursor = bytes;
    anyhow::ensure!(read_u32(&mut cursor)? == 1, "reward ledger transition version is not 1");
    let window = RewardLedgerWindowValues {
        config_hash: read_array(&mut cursor)?, economic_domain: read_array(&mut cursor)?, window_id: read_array(&mut cursor)?,
        end_checkpoint_id: read_u32(&mut cursor)?, end_checkpoint_root: read_hash(&mut cursor)?, start_root: read_hash(&mut cursor)?,
    };
    let old_state = read_state(&mut cursor)?;
    let new_state = read_state(&mut cursor)?;
    let source_checkpoint_id = read_u32(&mut cursor)?;
    let _user_id = read_u32(&mut cursor)?;
    let _checkpoint_tree_root = read_hash(&mut cursor)?;
    let leaf_len = read_u32(&mut cursor)? as usize;
    anyhow::ensure!(leaf_len <= cursor.len() && leaf_len <= PROOF_BYTES_LIMIT, "source checkpoint leaf length exceeds transition");
    let (leaf_bytes, rest) = cursor.split_at(leaf_len);
    cursor = rest;
    let source_leaf = bincode::deserialize(leaf_bytes).map_err(|error| anyhow::anyhow!("source checkpoint leaf decoding rejected: {error}"))?;
    let mut source_path = [[0; 4]; 32];
    for sibling in &mut source_path { *sibling = read_hash(&mut cursor)?; }
    let old_summary = read_hash(&mut cursor)?;
    let session_root = read_hash(&mut cursor)?;
    let mut summary_siblings = [[0; 4]; 32];
    for sibling in &mut summary_siblings { *sibling = read_hash(&mut cursor)?; }
    let is_final_step = match read_byte(&mut cursor)? { 0 => false, 1 => true, _ => anyhow::bail!("reward ledger final flag is not canonical") };
    anyhow::ensure!(read_u32(&mut cursor)? == 33, "reward ledger node count is not 33");
    let mut nodes = Vec::with_capacity(33);
    for _ in 0..33 {
        nodes.push(RewardLedgerNodeUpdate { height: read_byte(&mut cursor)?, index: read_u64(&mut cursor)?, hash: read_array(&mut cursor)? });
    }
    let proof_len = read_u32(&mut cursor)? as usize;
    anyhow::ensure!((1..=PROOF_BYTES_LIMIT).contains(&proof_len) && proof_len == cursor.len() && bytes.len() <= PROOF_BYTES_LIMIT, "reward ledger proof or transition exceeds 16MiB");
    let step = RewardLedgerStep { proof: cursor.to_vec(), old_state, new_state, source_checkpoint_id, source_leaf, source_path, old_summary, session_root, summary_siblings, is_final_step };
    Ok((window, step, nodes))
}
fn read_exact<'a>(bytes: &mut &'a [u8], width: usize) -> anyhow::Result<&'a [u8]> {
    anyhow::ensure!(bytes.len() >= width, "reward ledger transition is truncated");
    let (head, rest) = bytes.split_at(width);
    *bytes = rest;
    Ok(head)
}
fn read_byte(bytes: &mut &[u8]) -> anyhow::Result<u8> { Ok(read_exact(bytes, 1)?[0]) }
fn read_u32(bytes: &mut &[u8]) -> anyhow::Result<u32> { Ok(u32::from_le_bytes(read_exact(bytes, 4)?.try_into().unwrap())) }
fn read_u64(bytes: &mut &[u8]) -> anyhow::Result<u64> { Ok(u64::from_le_bytes(read_exact(bytes, 8)?.try_into().unwrap())) }
fn read_array<const N: usize>(bytes: &mut &[u8]) -> anyhow::Result<[u8; N]> { Ok(read_exact(bytes, N)?.try_into().unwrap()) }
fn read_hash(bytes: &mut &[u8]) -> anyhow::Result<Hash4> {
    let mut value = [0; 4];
    for limb in &mut value { *limb = read_u64(bytes)?; }
    hash4(value)
}
fn read_state(bytes: &mut &[u8]) -> anyhow::Result<RewardLedgerStateValues> {
    Ok(RewardLedgerStateValues { ledger_window_hash: read_hash(bytes)?, ledger_root: read_hash(bytes)?, user_root: read_hash(bytes)?, session_count: read_u32(bytes)?, unfinished_session_count: read_u32(bytes)? })
}
fn payout(fields: &RewardSessionProofFields, window: &RewardLedgerWindowValues, source_id: u32) -> anyhow::Result<SourceCheckpointRewardLeaf> {
    anyhow::ensure!(fields.count > 0 && fields.total_amount != [0; 8], "terminal reward session is empty");
    let mut recipient = [0u8; 20];
    for index in 0..5 {
        recipient[index * 4..index * 4 + 4].copy_from_slice(&fields.recipient[4 - index].to_be_bytes());
    }
    anyhow::ensure!(recipient != [0; 20], "terminal reward recipient is zero");
    let leaf = SourceCheckpointRewardLeaf {
        economic_domain: window.economic_domain, source_checkpoint_id: u64::from(source_id),
        user_id: fields.user_id, amount: fields.total_amount, recipient, initialized: true,
    };
    leaf.leaf_commit().map_err(|error| anyhow::anyhow!("source payout leaf rejected: {error}"))?;
    Ok(leaf)
}
fn check_counts(step: &RewardLedgerStep, first_global: bool, first_own: bool) -> anyhow::Result<()> {
    let sessions = if first_global { 0 } else { step.old_state.session_count };
    let open = if first_global { 0 } else { step.old_state.unfinished_session_count };
    let session_count = if first_own { sessions.checked_add(1).ok_or_else(|| anyhow::anyhow!("reward ledger session count overflow"))? } else { sessions };
    let unfinished = match (first_own, step.is_final_step) {
        (true, false) => open.checked_add(1).ok_or_else(|| anyhow::anyhow!("reward ledger unfinished count overflow"))?,
        (false, true) => open.checked_sub(1).ok_or_else(|| anyhow::anyhow!("reward ledger close without an open session"))?,
        _ => open,
    };
    anyhow::ensure!(step.new_state.session_count == session_count, "reward ledger session count mismatch");
    anyhow::ensure!(step.new_state.unfinished_session_count == unfinished, "reward ledger unfinished count mismatch");
    anyhow::ensure!(session_count >= unfinished, "reward ledger closed more sessions than it opened");
    Ok(())
}

fn user_nodes(user_id: u32, new_summary: Hash4, siblings: &[Hash4; 32]) -> anyhow::Result<Vec<RewardLedgerNodeUpdate>> {
    let mut nodes = Vec::with_capacity(33);
    let mut index = u64::from(user_id);
    let mut value = new_summary;
    nodes.push(node_update(0, index, value)?);
    for (height, sibling) in siblings.iter().enumerate() {
        let bit = ((user_id >> height) & 1) == 1;
        let (left, right) = if bit { (*sibling, value) } else { (value, *sibling) };
        value = node_hash(height + 1, left, right)?;
        index >>= 1;
        nodes.push(node_update((height + 1) as u8, index, value)?);
    }
    anyhow::ensure!(nodes.len() == 33, "reward ledger user update is not one leaf plus 32 ancestors");
    let mut coordinates = nodes.iter().map(|node| (node.height, node.index)).collect::<Vec<_>>();
    coordinates.sort_unstable();
    coordinates.dedup();
    anyhow::ensure!(coordinates.len() == 33, "reward ledger node coordinates are not unique");
    Ok(nodes)
}

fn node_update(height: u8, index: u64, value: Hash4) -> anyhow::Result<RewardLedgerNodeUpdate> {
    let width = 32u32.checked_sub(u32::from(height)).ok_or_else(|| anyhow::anyhow!("reward ledger node height exceeds 32"))?;
    let limit = 1u64.checked_shl(width).ok_or_else(|| anyhow::anyhow!("reward ledger node index bound overflow"))?;
    anyhow::ensure!(index < limit, "reward ledger node index exceeds its height");
    Ok(RewardLedgerNodeUpdate { height, index, hash: canonical_bytes(value)? })
}

fn session_seed(
    window: &RewardLedgerWindowValues, source_id: u32, fields: &RewardSessionProofFields, source_hash: Hash4,
) -> anyhow::Result<Hash4> {
    let mut bytes = domain(SESSION_DOMAIN);
    bytes.extend_from_slice(&window.economic_domain);
    append_u32(&mut bytes, source_id);
    append_u32(&mut bytes, fields.user_id);
    for limb in &fields.recipient[..5] { append_u32(&mut bytes, *limb); }
    append_hash(&mut bytes, fields.checkpoint_tree_root)?;
    append_hash(&mut bytes, source_hash)?;
    Ok(hash_bytes(&bytes))
}

fn summary(fields: &RewardSessionProofFields, seed: Hash4, session_root: Hash4, is_final_step: bool) -> anyhow::Result<Hash4> {
    let inputs = fields.to_public_inputs().map_err(|error| anyhow::anyhow!("reward ledger statement encoding rejected: {error}"))?;
    let mut bytes = domain(SUMMARY_DOMAIN);
    for limb in &inputs[..30] { append_canonical_u64(&mut bytes, *limb)?; }
    append_hash(&mut bytes, seed)?;
    append_hash(&mut bytes, session_root)?;
    bytes.push(u8::from(is_final_step));
    Ok(hash_bytes(&bytes))
}

pub(super) fn state_root(state: &RewardLedgerStateValues) -> anyhow::Result<Hash4> {
    let mut bytes = domain(STATE_DOMAIN);
    for hash in [state.ledger_window_hash, state.ledger_root, state.user_root] { append_hash(&mut bytes, hash)?; }
    append_u32(&mut bytes, state.session_count);
    append_u32(&mut bytes, state.unfinished_session_count);
    Ok(hash_bytes(&bytes))
}

pub fn window_hash(window: &RewardLedgerWindowValues, verifier: &VerifierOnlyCircuitData<C, 2>) -> anyhow::Result<(Hash4, Hash4)> {
    let verifier_hash = verifier_hash(verifier)?;
    let mut bytes = domain(WINDOW_DOMAIN);
    bytes.extend_from_slice(&window.config_hash);
    bytes.extend_from_slice(&window.economic_domain);
    bytes.extend_from_slice(&window.window_id);
    append_u32(&mut bytes, window.end_checkpoint_id);
    for hash in [window.end_checkpoint_root, window.start_root, verifier_hash] { append_hash(&mut bytes, hash)?; }
    Ok((verifier_hash, hash_bytes(&bytes)))
}

fn verifier_hash(verifier: &VerifierOnlyCircuitData<C, 2>) -> anyhow::Result<Hash4> {
    let mut bytes = domain(VERIFIER_DOMAIN);
    append_hash(&mut bytes, hash_out(verifier.circuit_digest))?;
    append_u32(&mut bytes, u32::try_from(verifier.constants_sigmas_cap.0.len()).map_err(|_| anyhow::anyhow!("verifier cap is too long"))?);
    for hash in &verifier.constants_sigmas_cap.0 { append_hash(&mut bytes, hash_out(*hash))?; }
    Ok(hash_bytes(&bytes))
}


pub(super) fn empty_summary() -> anyhow::Result<Hash4> { Ok(hash_bytes(&domain(EMPTY_DOMAIN))) }

pub(super) fn empty_user_root() -> anyhow::Result<Hash4> {
    let mut root = empty_summary()?;
    for height in 1..=32 { root = node_hash(height, root, root)?; }
    Ok(root)
}

fn summary_root(user_id: u32, mut value: Hash4, siblings: &[Hash4; 32]) -> anyhow::Result<Hash4> {
    for (height, sibling) in siblings.iter().enumerate() {
        let bit = ((user_id >> height) & 1) == 1;
        let (left, right) = if bit { (*sibling, value) } else { (value, *sibling) };
        value = node_hash(height + 1, left, right)?;
    }
    Ok(value)
}

fn node_hash(height: usize, left: Hash4, right: Hash4) -> anyhow::Result<Hash4> {
    let mut bytes = domain(NODE_DOMAIN);
    bytes.push(u8::try_from(height).map_err(|_| anyhow::anyhow!("reward ledger node height exceeds one byte"))?);
    append_hash(&mut bytes, left)?;
    append_hash(&mut bytes, right)?;
    Ok(hash_bytes(&bytes))
}

fn poseidon_path(index: u64, mut value: Hash4, siblings: &[Hash4]) -> anyhow::Result<Hash4> {
    for (height, sibling) in siblings.iter().enumerate() {
        let bit = ((index >> height) & 1) == 1;
        value = if bit { two_to_one(*sibling, value)? } else { two_to_one(value, *sibling)? };
    }
    Ok(value)
}

fn two_to_one(left: Hash4, right: Hash4) -> anyhow::Result<Hash4> {
    let mut elements = Vec::with_capacity(8);
    elements.extend(left.map(F::from_canonical_u64));
    elements.extend(right.map(F::from_canonical_u64));
    Ok(hash_out(PoseidonHash::hash_no_pad(&elements)))
}

fn hash_bytes(bytes: &[u8]) -> Hash4 {
    hash_out(PoseidonHash::hash_no_pad(&bytes.iter().copied().map(F::from_canonical_u8).collect::<Vec<_>>()))
}

fn domain(label: &[u8]) -> Vec<u8> { label.to_vec() }

fn append_u32(bytes: &mut Vec<u8>, value: u32) { bytes.extend_from_slice(&value.to_le_bytes()); }
fn append_raw_hash(bytes: &mut Vec<u8>, value: Hash4) -> anyhow::Result<()> {
    let canonical = hash4(value)?;
    for limb in canonical {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    Ok(())
}

fn append_state(bytes: &mut Vec<u8>, state: &RewardLedgerStateValues) -> anyhow::Result<()> {
    append_raw_hash(bytes, state.ledger_window_hash)?;
    append_raw_hash(bytes, state.ledger_root)?;
    append_raw_hash(bytes, state.user_root)?;
    append_u32(bytes, state.session_count);
    append_u32(bytes, state.unfinished_session_count);
    Ok(())
}

fn append_hash(bytes: &mut Vec<u8>, value: Hash4) -> anyhow::Result<()> {
    for limb in value { append_canonical_u64(bytes, limb)?; }
    Ok(())
}

fn append_canonical_u64(bytes: &mut Vec<u8>, value: u64) -> anyhow::Result<()> {
    anyhow::ensure!(value < ORDER, "reward ledger hash limb is not canonical");
    let (low, high) = (value as u32, (value >> 32) as u32);
    anyhow::ensure!(high != u32::MAX || low == 0, "reward ledger hash limb is not canonical");
    append_u32(bytes, low);
    append_u32(bytes, high);
    Ok(())
}

fn hash4(value: Hash4) -> anyhow::Result<Hash4> {
    for limb in value { anyhow::ensure!(limb < ORDER, "reward ledger hash limb is not canonical"); }
    Ok(value)
}

pub fn reward_hash(value: Hash4) -> anyhow::Result<Hash4> { hash4(value) }

pub fn reward_hash_bytes(value: Hash4) -> anyhow::Result<[u8; 32]> { canonical_bytes(value) }

pub fn reward_ledger_state_root(state: &RewardLedgerStateValues) -> anyhow::Result<Hash4> { state_root(state) }

pub fn encode_reward_ledger_state(state: &RewardLedgerStateValues) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(104);
    append_state(&mut bytes, state)?;
    Ok(bytes)
}

pub fn decode_reward_ledger_state(bytes: &[u8]) -> anyhow::Result<RewardLedgerStateValues> {
    let mut cursor = bytes;
    let state = read_state(&mut cursor)?;
    anyhow::ensure!(cursor.is_empty(), "reward ledger state has trailing bytes");
    Ok(state)
}

pub fn encode_reward_ledger_window(window: &RewardLedgerWindowValues) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(164);
    bytes.extend_from_slice(&window.config_hash);
    bytes.extend_from_slice(&window.economic_domain);
    bytes.extend_from_slice(&window.window_id);
    append_u32(&mut bytes, window.end_checkpoint_id);
    append_raw_hash(&mut bytes, window.end_checkpoint_root)?;
    append_raw_hash(&mut bytes, window.start_root)?;
    Ok(bytes)
}

pub fn decode_reward_ledger_window(bytes: &[u8]) -> anyhow::Result<RewardLedgerWindowValues> {
    let mut cursor = bytes;
    let window = RewardLedgerWindowValues {
        config_hash: read_array(&mut cursor)?, economic_domain: read_array(&mut cursor)?, window_id: read_array(&mut cursor)?,
        end_checkpoint_id: read_u32(&mut cursor)?, end_checkpoint_root: read_hash(&mut cursor)?, start_root: read_hash(&mut cursor)?,
    };
    anyhow::ensure!(cursor.is_empty(), "reward ledger window has trailing bytes");
    Ok(window)
}

pub fn reward_user_empty_hash(height: u8) -> anyhow::Result<Hash4> {
    anyhow::ensure!(height <= 32, "reward user empty height exceeds 32");
    let mut hash = empty_summary()?;
    for level in 1..=height { hash = node_hash(usize::from(level), hash, hash)?; }
    Ok(hash)
}

pub fn reward_issued_empty_hash(height: u8) -> anyhow::Result<Hash4> {
    anyhow::ensure!(height <= 64, "reward issued empty height exceeds 64");
    let mut hash = [0u64; 4];
    for _ in 0..height { hash = two_to_one(hash, hash)?; }
    Ok(hash)
}

pub fn reward_user_parent_hash(height: u8, left: Hash4, right: Hash4) -> anyhow::Result<Hash4> {
    anyhow::ensure!((1..=32).contains(&height), "reward user parent height is outside 1..=32");
    node_hash(usize::from(height), left, right)
}

pub fn reward_issued_parent_hash(left: Hash4, right: Hash4) -> anyhow::Result<Hash4> { two_to_one(left, right) }

fn hash_out(value: HashOut<F>) -> Hash4 { value.elements.map(|limb| limb.to_canonical_u64()) }

fn canonical_bytes(value: Hash4) -> anyhow::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    for (index, limb) in hash4(value)?.into_iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u64) -> Hash4 { [seed, seed + 1, seed + 2, seed + 3] }

    #[test]
    fn canonical_hash_rejects_noncanonical_limb() {
        assert!(append_canonical_u64(&mut Vec::new(), ORDER).is_err());
        assert!(append_canonical_u64(&mut Vec::new(), (u64::from(u32::MAX) << 32) | 1).is_err());
        assert!(append_canonical_u64(&mut Vec::new(), u64::from(u32::MAX) << 32).is_ok());
    }

    #[test]
    fn node_updates_cover_leaf_and_thirty_two_ancestors() {
        let siblings = std::array::from_fn(|index| hash(index as u64 + 10));
        let nodes = user_nodes(0b101, hash(2), &siblings).unwrap();
        assert_eq!(nodes.len(), 33);
        assert_eq!(nodes.iter().map(|node| node.height).collect::<Vec<_>>(), (0..=32).collect::<Vec<_>>());
        assert_eq!(nodes[0].index, 0b101);
        assert_eq!(nodes[1].index, 0b10);
        assert_eq!(nodes[32].index, 0);
        assert!(nodes.iter().all(|node| node.index < 1u64 << (32 - node.height)));
    }

    #[test]
    fn first_own_updates_counts_and_keeps_credit_root() {
        let credit = [4, 3, 2, 1];
        let previous = RewardLedgerStateValues {
            ledger_window_hash: [9, 8, 7, 6], ledger_root: credit, user_root: [11, 12, 13, 14],
            session_count: 7, unfinished_session_count: 0,
        };
        let leaf = PsyCheckpointLeaf::default();
        let path = [[0; 4]; 32];
        let siblings = [[0; 4]; 32];
        let step = RewardLedgerStep {
            proof: Vec::new(), old_state: previous, new_state: previous, source_checkpoint_id: 1,
            source_leaf: leaf, source_path: path, old_summary: [0; 4], session_root: [0; 4],
            summary_siblings: siblings, is_final_step: false,
        };
        assert!(check_counts(&step, false, false).is_err());
        let opened_state = RewardLedgerStateValues { session_count: 8, unfinished_session_count: 1, ..previous };
        let opened = RewardLedgerStep { new_state: opened_state, ..step };
        assert!(check_counts(&opened, false, true).is_ok());
        let continued = RewardLedgerStep { old_state: opened_state, new_state: opened_state, ..opened };
        assert!(check_counts(&continued, false, false).is_ok());
        assert_eq!(continued.old_state.ledger_root, credit);
    }

    #[test]
    fn host_summary_matches_reward_session_circuit_hash() {
        use plonky2::{iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}}, plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig}};
        use super::super::reward_session::{reward_session_seed, reward_session_summary};
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let fields: [Target; REWARD_SESSION_PROOF_FIELD_COUNT] = builder.add_virtual_target_arr();
        let economic = [0x34u8; 32].map(|byte| builder.constant(F::from_canonical_u8(byte)));
        let source = builder.constant(F::from_canonical_u32(9));
        let root = builder.constant_hash(plonky2::hash::hash_types::HashOut { elements: [3, 5, 7, 11].map(F::from_canonical_u64) });
        let source_hash = builder.constant_hash(plonky2::hash::hash_types::HashOut { elements: [13, 17, 19, 23].map(F::from_canonical_u64) });
        let seed = reward_session_seed(&mut builder, &economic, source, fields[4], &std::array::from_fn(|index| fields[5 + index]), root, source_hash);
        let session_root = builder.constant_hash(plonky2::hash::hash_types::HashOut { elements: [29, 31, 37, 41].map(F::from_canonical_u64) });
        let is_final = BoolTarget::new_unsafe(builder.constant(F::ONE));
        let summary = reward_session_summary(&mut builder, &fields, seed, session_root, is_final);
        builder.register_public_inputs(&summary.elements);
        let circuit = builder.build::<PoseidonGoldilocksConfig>();
        let mut witness = PartialWitness::new();
        let values = [1u64, 2, 3, 4, 7, 11, 13, 17, 19, 23, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 41, 43, 47, 53, 59, 61, 67, 71, 0, 0, 0, 0];
        for (target, value) in fields.into_iter().zip(values) { witness.set_target(target, F::from_canonical_u64(value)).unwrap(); }
        let proof = circuit.prove(witness).unwrap();
        circuit.verify(proof.clone()).unwrap();
        let fields = RewardSessionProofFields::from_public_inputs(&values).unwrap();
        let window = RewardLedgerWindowValues { config_hash: [0; 32], economic_domain: [0x34; 32], window_id: [0; 32], end_checkpoint_id: 0, end_checkpoint_root: [3, 5, 7, 11], start_root: [0; 4] };
        let expected = super::summary(&fields, session_seed(&window, 9, &fields, [13, 17, 19, 23]).unwrap(), [29, 31, 37, 41], true).unwrap();
        assert_eq!(proof.public_inputs.iter().map(|limb| limb.to_canonical_u64()).collect::<Vec<_>>(), expected.to_vec());
    }

    #[test]
    fn host_session_root_matches_poseidon_delta_path() {
        use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut};
        let source = 9u32;
        for (height, path_index) in [(2u8, 0u32), (3, 1)] {
            let key = (u64::from(source) << 31) | (u64::from(height) << 26) | u64::from(path_index);
            let siblings: [QHashOut<F>; 63] = std::array::from_fn(|index| QHashOut::from_values(index as u64 + 1, 2, 3, 4));
            let delta = DeltaMerkleProofCore::from_params::<PoseidonHash>(key, QHashOut::ZERO, QHashOut::from_values(1, 0, 0, 0), siblings.to_vec());
            assert!(delta.verify::<PoseidonHash>());
            let hash_words = |hash: QHashOut<F>| hash.0.elements.map(|limb| limb.to_canonical_u64());
            let witness = super::super::reward_session::RewardSessionJobWitness {
                height, path_index,
                tag: super::super::reward_inclusion::RewardTagWitness { tag_preimage: QHashOut::ZERO, leaf_left: QHashOut::ZERO,
                    leaf_right: QHashOut::ZERO, leaf_tag: QHashOut::ZERO, siblings: [QHashOut::ZERO; 21], parent_tags: [QHashOut::ZERO; 21] },
                nullifier_siblings: siblings.map(hash_words),
            };
            assert_eq!(reward_session_root(source, hash_words(delta.old_root), &[witness]).unwrap(), hash_words(delta.new_root));
        }
    }

    #[test]
    fn empty_reward_paths_fold_to_the_empty_roots() {
        let user_siblings = std::array::from_fn(|height| reward_user_empty_hash(height as u8).unwrap());
        let user_leaf = reward_user_empty_hash(0).unwrap();
        assert_eq!(summary_root(0, user_leaf, &user_siblings).unwrap(), reward_user_empty_hash(32).unwrap());
        let issued_siblings: [[u64; 4]; 64] = std::array::from_fn(|height| reward_issued_empty_hash(height as u8).unwrap());
        assert_eq!(poseidon_path(0, [0; 4], &issued_siblings).unwrap(), reward_issued_empty_hash(64).unwrap());
    }

    #[test]
    fn host_state_root_matches_origin_state_root() {
        use psy_client_data::bridge_aggregate::origin_state_root;
        let mut issued = [0u64; 4];
        for _ in 0..64 { issued = two_to_one(issued, issued).unwrap(); }
        let origin = RewardLedgerStateValues { ledger_window_hash: [0; 4], ledger_root: issued, user_root: empty_user_root().unwrap(), session_count: 0, unfinished_session_count: 0 };
        assert_eq!(state_root(&origin).unwrap(), origin_state_root());
    }

    #[test]
    fn zero_state_root_matches_circuit_and_rejects_zero_output() {
        use plonky2::{iop::witness::PartialWitness, plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig}};
        use super::super::reward_session::RewardLedgerStateTargets;
        let state = RewardLedgerStateValues { ledger_window_hash: [0; 4], ledger_root: [0; 4], user_root: [0; 4], session_count: 0, unfinished_session_count: 0 };
        let expected = state_root(&state).unwrap();
        assert_ne!(expected, [0; 4]);
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let targets = RewardLedgerStateTargets::new(&mut builder);
        builder.register_public_inputs(&targets.root.elements);
        let circuit = builder.build::<C>();
        let mut witness = PartialWitness::new();
        targets.set_witness(&mut witness, &state).unwrap();
        let proof = circuit.prove(witness).unwrap();
        assert_eq!(proof.public_inputs.iter().map(|limb| limb.to_canonical_u64()).collect::<Vec<_>>(), expected);
        circuit.verify(proof.clone()).unwrap();
        let mut changed = proof;
        changed.public_inputs.fill(F::ZERO);
        assert!(circuit.verify(changed).is_err());
    }
}
