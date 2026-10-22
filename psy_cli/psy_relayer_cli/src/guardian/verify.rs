use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use anyhow::anyhow;
use plonky2::{field::{goldilocks_field::GoldilocksField as F, types::{Field, PrimeField64}}, hash::poseidon::PoseidonHash};
use psy_client_common::{args::{ContractCallArgs, ContractCallData}, data::{base_types::hash256::Hash256, qhashout::QHashOut}};
use psy_client_data::{config::store_config::PsyHasher, qdata::{checkpoint::{PsyCheckpointLeaf, PsyCheckpointGlobalStateRoots}, contract::PsyContractLeaf}, traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync}};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, TOKEN_BURN_METHOD_ID};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::{hasher::{FieldQHasher, MerkleZeroHasher}, qhashable::QFieldHashable}};
use psy_provider::{provider::RpcProvider, request::QIMTMembershipProofRPCRequest};
use psy_prover::{session::session::WalletSession, trace::{TxTrace, TraceStep}};
use psy_vm::ups::multisig::{MultisigPolicy, MultisigSignatureWitness, StoredMultisigPolicy, MULTISIG_POLICY_CONTRACT_ID};

use guardian_common::protocol::*;

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

pub struct GuardianVerificationContext<'a> {
    pub wallet: &'a WalletSession,
    pub provider: &'a RpcProvider,
    pub network: &'a psy_config::NetworkConfigGoldilocks,
    pub verified_checkpoint_id: u64,
    pub verified_checkpoint_tree_root: Hash4,
    pub l1_chains: &'a [ChainEndpoint],
    /// Bounded durable snapshot restored from the journal; verified material only,
    /// never mutated by verification staging.
    pub history: &'a GuardianHistory,
    /// Request-scoped reservation material (re-verification of the same exact request).
    pub reserved_deposit_tree_states: &'a [DepositTreeState],
    /// Conflicts for the current request only, computed by the caller with journal
    /// point queries; the verifier adds within-batch duplicate detection on top.
    pub conflicting_withdrawal_burns: &'a BTreeSet<(u32, u32, [u32; 8])>,
    pub conflicting_nonces: &'a BTreeSet<(u8, [u32; 8])>,
}

pub struct VerifiedGuardianSession {
    pub trace: TxTrace,
    pub current_policy: MultisigPolicy,
    pub ending_policy: MultisigPolicy,
    pub starting_leaf_hash: Hash4,
    pub ending_leaf_hash: Hash4,
    pub message: [u8; 32],
    pub withdrawal_appends: Vec<WithdrawalAppendRecord>,
}

/// Bounded durable snapshot restored from the journal, never replayed from zero:
/// the included account nonce and leaf, one withdrawal head per destination chain,
/// and at most three included deposit anchors. Unbounded identity/nonce sets are
/// gone; cross-request conflicts are caller-side point queries on the current batch.
#[derive(Default, Clone)]
pub struct GuardianHistory {
    pub(crate) nonce: u64,
    pub(crate) ending_leaf: Option<Hash4>,
    pub(crate) chains: BTreeMap<u8, (u32, [Hash4; 32], Hash4)>,
    pub(crate) deposits: BTreeMap<u8, (u32, Hash4)>,
    pub(crate) deposit_tree_states: BTreeMap<u8, DepositTreeState>,
}
impl GuardianHistory {
    pub fn new() -> Self { Self::default() }
    pub fn nonce(&self) -> u64 { self.nonce }
}

/// Request-scoped reservation material first, then the included durable anchor.
fn reserved_deposit_tree_state<'a>(reserved: &'a [DepositTreeState], history: &'a GuardianHistory, chain_index: u8) -> Option<&'a DepositTreeState> {
    reserved.iter().find(|deposit_tree_state| deposit_tree_state.anchor.chain_index == chain_index)
        .or_else(|| history.deposit_tree_states.get(&chain_index))
}

/// The restored frontier is the L2 opening only when it folds to the stored root.
/// A zero count may still carry the empty on-chain encoding `Hash4::ZERO`.
fn withdrawal_opening(history: &GuardianHistory, chain_index: u8) -> std::result::Result<(u32, Hash4), GuardianAccountError> {
    match history.chains.get(&chain_index).copied() {
        None => Ok((0, <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32))),
        Some((count, frontier, root)) if guardian_common::protocol::frontier_root(count, &frontier) == root || (count == 0 && root == Hash4::ZERO) => Ok((count, root)),
        Some(_) => Err(GuardianAccountError::Conflict(HaltReason::CheckpointConflict)),
    }
}


pub fn verify_path(path: &MerkleProofCore<Hash4>, root: Hash4, index: u64, value: Hash4, height: usize) -> Result<()> {
    if height > 63 || index >= (1u64 << height) || path.siblings.len() != height || path.index != index || path.root != root || path.value != value || !path.verify::<PsyHasher>() {
        return Err(GuardianSignError::ProofMismatch);
    }
    Ok(())
}

pub fn verify_checkpoint(checkpoint_id: u64, leaf: &PsyCheckpointLeaf<F>, roots: &PsyCheckpointGlobalStateRoots<F>, path: &MerkleProofCore<Hash4>, verified_root: Hash4) -> Result<()> {
    if roots.qfhash::<PsyHasher>() != leaf.global_chain_root { return Err(GuardianSignError::ProofMismatch); }
    verify_path(path, verified_root, checkpoint_id, leaf.qfhash::<PsyHasher>(), CHECKPOINT_TREE_HEIGHT as usize)
}

pub fn withdrawal_key(record: &WithdrawalBurnRecord) -> Hash4 {
    let nonce = record.nonce.map(F::from_canonical_u32);
    let key = PsyHasher::q_hash_many(&nonce);
    let mut namespaced = [F::ZERO; 5];
    namespaced[0] = F::from_canonical_u64(6);
    namespaced[1..].copy_from_slice(&key.0.elements);
    PsyHasher::q_hash_many(&namespaced)
}

pub fn withdrawal_leaf(record: &WithdrawalBurnRecord) -> Hash4 {
    let mut fields = [F::ZERO; 34];
    fields[0] = F::from_canonical_u32(record.sender_user_id);
    for (target, words) in fields[1..33].chunks_exact_mut(8).zip([&record.recipient, &record.token, &record.amount, &record.nonce]) {
        for (target, word) in target.iter_mut().zip(words) { *target = F::from_canonical_u32(*word); }
    }
    fields[33] = F::from_canonical_u8(record.destination_chain_index);
    PsyHasher::q_hash_many(&fields)
}

/// Compiled method binding from `psy-genesis/genesis_abi`. The id is
/// `sha256(name(arg[size],...))` truncated to four little-endian bytes, and the
/// count is the ABI `input_felt_count`.
struct MethodBinding { name: &'static str, method_id: u32, input_felt_count: u32 }
const SET_POLICY: MethodBinding = MethodBinding { name: "set_policy", method_id: 930_568_152, input_felt_count: 28 };
const SET_CHAIN_ROOT: MethodBinding = MethodBinding { name: "set_chain_root", method_id: 4_192_350_829, input_felt_count: 10 };
const APPEND_WITHDRAWAL: MethodBinding = MethodBinding { name: "append_withdrawal", method_id: 2_140_131_902, input_felt_count: 35 };
const BATCH_APPEND_WITHDRAWALS_2: MethodBinding = MethodBinding { name: "batch_append_withdrawals_2", method_id: 4_283_677_324, input_felt_count: 71 };
const BATCH_APPEND_WITHDRAWALS_5: MethodBinding = MethodBinding { name: "batch_append_withdrawals_5", method_id: 961_124_698, input_felt_count: 176 };
const BURN: MethodBinding = MethodBinding { name: "burn", method_id: TOKEN_BURN_METHOD_ID, input_felt_count: 1 };
fn contract_method(contract_id: u32, name: &str) -> Result<MethodBinding> {
    let binding = match (contract_id, name) {
        (id, "set_policy") if id == u32::from(MULTISIG_POLICY_CONTRACT_ID) => SET_POLICY,
        (crate::bridge::constants::DEPOSIT_TREE_CONTRACT_ID, "set_chain_root") => SET_CHAIN_ROOT,
        (crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID, "append_withdrawal") => APPEND_WITHDRAWAL,
        (crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID, "batch_append_withdrawals_2") => BATCH_APPEND_WITHDRAWALS_2,
        (crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID, "batch_append_withdrawals_5") => BATCH_APPEND_WITHDRAWALS_5,
        (psy_config::TOKEN_CONTRACT_ID, "burn") => BURN,
        _ => return Err(GuardianSignError::UnsupportedCall),
    };
    Ok(binding)
}
fn contract_height(contract_id: u32) -> Result<u16> {
    match contract_id {
        crate::bridge::constants::DEPOSIT_TREE_CONTRACT_ID => Ok(u16::from(psy_config::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT)),
        crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID => Ok(u16::from(psy_config::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT)),
        psy_config::TOKEN_CONTRACT_ID => Ok(u16::from(psy_config::TOKEN_CONTRACT_STATE_TREE_HEIGHT)),
        4 => Ok(u16::from(psy_config::network_constants::USDT_TOKEN_CONTRACT_STATE_TREE_HEIGHT)),
        id if id == u32::from(MULTISIG_POLICY_CONTRACT_ID) => Ok(4),
        _ => Err(GuardianSignError::UnsupportedCall),
    }
}
/// Token `state_map` from the compiled ABI: offset 8589934680, capacity 1048576.
/// The IMT sentinel is the map base; records occupy the following felts.
const WITHDRAWAL_MAP_BASE: u64 = 8_589_934_680;
const WITHDRAWAL_MAP_CAPACITY: u64 = 1_048_576;
fn token_contract(id: u32) -> Result<()> {
    if matches!(id, psy_config::TOKEN_CONTRACT_ID | 4) { Ok(()) } else { Err(GuardianSignError::ProofMismatch) }
}

pub fn verify_withdrawal_burn(config: &GuardianConfig, record: &WithdrawalBurnRecord, proof: &psy_provider::lps::WithdrawalBurnProof, verified_checkpoint_root: Hash4) -> Result<()> {
    record.amount_u64()?;
    record.recipient_address()?;
    record.token_address()?;
    token_contract(record.token_contract_id)?;
    config.chain(record.destination_chain_index)?;
    verify_checkpoint(proof.checkpoint_id, &proof.checkpoint_leaf, &proof.global_roots, &proof.checkpoint_path, verified_checkpoint_root)?;
    if proof.contract_leaf.state_tree_height.to_canonical_u64() != u64::from(contract_height(record.token_contract_id)?) { return Err(GuardianSignError::ProofMismatch); }
    let (base, capacity) = (WITHDRAWAL_MAP_BASE / 4, WITHDRAWAL_MAP_CAPACITY);
    verify_path(&proof.global_contract_path, proof.global_roots.contract_tree_root, u64::from(record.token_contract_id), proof.contract_leaf.qfhash::<PsyHasher>(), GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
    if proof.user_leaf.user_id.to_canonical_u64() != u64::from(record.sender_user_id) { return Err(GuardianSignError::ProofMismatch); }
    verify_path(&proof.user_path, proof.global_roots.user_tree_root, u64::from(record.sender_user_id), proof.user_leaf.qfhash::<PsyHasher>(), GLOBAL_USER_TREE_HEIGHT as usize)?;
    verify_path(&proof.contract_path, proof.user_leaf.user_state_tree_root, u64::from(record.token_contract_id), proof.record_membership.merkle_proof.root, GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
    let membership = &proof.record_membership;
    let request = QIMTMembershipProofRPCRequest { checkpoint_id: proof.checkpoint_id, user_id: u64::from(record.sender_user_id), contract_id: record.token_contract_id, key: withdrawal_key(record), state_slot_base: base, capacity };
    request.validate_indices(membership.merkle_proof.index, membership.leaf.next_index.to_canonical_u64()).map_err(|_| GuardianSignError::ProofMismatch)?;
    if membership.leaf.key != request.key || membership.leaf.value != withdrawal_leaf(record) { return Err(GuardianSignError::ProofMismatch); }
    verify_path(&membership.merkle_proof, proof.contract_path.value, membership.merkle_proof.index, membership.leaf.qfhash::<PsyHasher>(), proof.contract_leaf.state_tree_height.to_canonical_u64() as usize)
}

pub async fn get_withdrawal_burn_proof(context: &GuardianVerificationContext<'_>, config: &GuardianConfig, checkpoint_id: u64, record: &WithdrawalBurnRecord) -> Result<psy_provider::lps::WithdrawalBurnProof> {
    if checkpoint_id > context.verified_checkpoint_id { return Err(GuardianSignError::CheckpointProofUnavailable); }
    token_contract(record.token_contract_id)?;
    let (base, capacity) = (WITHDRAWAL_MAP_BASE / 4, WITHDRAWAL_MAP_CAPACITY);
    let mut proof = context.provider.get_withdrawal_burn_proof(QIMTMembershipProofRPCRequest { checkpoint_id, user_id: u64::from(record.sender_user_id), contract_id: record.token_contract_id, key: withdrawal_key(record), state_slot_base: base, capacity }).await.map_err(|_| GuardianSignError::CheckpointProofUnavailable)?;
    proof.checkpoint_path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id, checkpoint_id).await.map_err(|_| GuardianSignError::CheckpointProofUnavailable)?;
    verify_withdrawal_burn(config, record, &proof, context.verified_checkpoint_tree_root)?;
    Ok(proof)
}

fn hash_words(hash: Hash4) -> [u64; 8] {
    let mut words = [0; 8];
    for (pair, field) in words.chunks_exact_mut(2).zip(hash.0.elements) { let value = field.to_canonical_u64(); pair[0] = value & 0xffff_ffff; pair[1] = value >> 32; }
    words
}

async fn read_subslots(context: &GuardianVerificationContext<'_>, trace: &TxTrace, contract_id: u32, start: u64, count: usize, height: u8) -> Result<Vec<u64>> {
    let checkpoint = trace.anchor.start_checkpoint_id;
    let user = &trace.ups_start_witness.ups_header.session_start_context.start_session_user_leaf;
    let contract = context.provider.get_user_contract_tree_merkle_proof(checkpoint,trace.meta.user_id,contract_id).await.map_err(|error| { tracing::warn!(checkpoint, contract_id, error = %error, "contract inclusion proof unavailable"); GuardianSignError::CheckpointProofUnavailable })?;
    verify_path(&contract,user.user_state_tree_root,u64::from(contract_id),contract.value,GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
    let root = if contract.value == Hash4::ZERO { <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(height as usize) } else { contract.value };
    read_subslots_at(context,checkpoint,trace.meta.user_id,root,contract_id,start,count,height).await
}

async fn read_subslots_at(context: &GuardianVerificationContext<'_>, checkpoint_id: u64, user_id: u64, state_root: Hash4, contract_id: u32, start: u64, count: usize, height: u8) -> Result<Vec<u64>> {
    let end = start.checked_add(count as u64).ok_or(GuardianSignError::ProofMismatch)?;
    let mut values = Vec::with_capacity(count);
    let mut slot = start / 4;
    while slot * 4 < end {
        let proof = context.provider.get_user_contract_state_tree_merkle_proof(checkpoint_id,user_id,contract_id,height,slot).await.map_err(|error| { tracing::warn!(checkpoint_id, contract_id, slot, height, error = %error, "contract state proof unavailable"); GuardianSignError::CheckpointProofUnavailable })?;
        verify_path(&proof,state_root,slot,proof.value,height as usize)?;
        for (index,field) in proof.value.0.elements.iter().enumerate() { let subslot = slot * 4 + index as u64; if subslot >= start && subslot < end { values.push(field.to_canonical_u64()); } }
        slot += 1;
    }
    Ok(values)
}

async fn verify_chain_state(context: &GuardianVerificationContext<'_>, trace: &TxTrace, contract: u32, chain: u8, count: u32, root: Hash4) -> Result<()> {
    let height = u8::try_from(contract_height(contract)?).map_err(|_| GuardianSignError::ProofMismatch)?;
    let stored_count = read_subslots(context, trace, contract, 65544 + u64::from(chain), 1, height).await?;
    let stored_root = read_subslots(context, trace, contract, 65804 + u64::from(chain) * 8, 8, height).await?;
    if stored_count != [u64::from(count)] || (stored_root != hash_words(root) && !(count == 0 && stored_root == [0; 8])) { return Err(if contract == 2 { GuardianSignError::DepositMismatch } else { GuardianSignError::WithdrawalMismatch }); }
    Ok(())
}

pub fn trace_policy(trace: &TxTrace, config: &GuardianConfig) -> Result<MultisigSignatureWitness> {
    let mut signatures = trace.steps.iter().filter_map(|step| if let TraceStep::ZkSign(sign) = step { Some(sign) } else { None });
    let sign = signatures.next().ok_or(GuardianSignError::PolicyMismatch)?;
    let account = config.initial_account()?;
    let account_public_key = config.account_public_key()?;
    if signatures.next().is_some() || !matches!(sign.sign_circuit_source, psy_prover::trace::TraceSignCircuitSource::Multisig) || sign.fingerprint != multisig_fingerprint()? { return Err(GuardianSignError::PolicyMismatch); }
    let witness: MultisigSignatureWitness = parse_canonical_json(&sign.sign_witness)?;
    if witness.account.contract_id != account.contract_id || witness.account.initial_policy != account.initial_policy || witness.nonce != trace.finalization.nonce || witness.start_session_user_leaf.public_key != account_public_key || witness.sign_context.user_leaf.public_key != account_public_key { return Err(GuardianSignError::PolicyMismatch); }
    witness.policies().map_err(|_|GuardianSignError::PolicyMismatch)?;
    Ok(witness)
}

fn policy_call(operation: GuardianOperation, witness: &MultisigSignatureWitness) -> Result<ContractCallArgs> {
    let start = StoredMultisigPolicy::load(&witness.start_state).map_err(|_|GuardianSignError::PolicyMismatch)?;
    let ending = StoredMultisigPolicy::load(&witness.end_state).map_err(|_|GuardianSignError::PolicyMismatch)?;
    let bootstrap = start.header == Hash4::ZERO && start.members == [Hash4::ZERO;3];
    if (operation == GuardianOperation::Bootstrap) != bootstrap || start == ending { return Err(GuardianSignError::PolicyMismatch); }
    let mut inputs = Vec::with_capacity(28);
    for hash in std::iter::once(start.header).chain(start.members).chain(ending.members) { inputs.extend(hash.0.elements.map(|field|field.to_canonical_u64())); }
    Ok(ContractCallArgs { contract_id:u64::from(MULTISIG_POLICY_CONTRACT_ID),method_name:"set_policy".into(),inputs })
}

async fn verify_sign_request_trace(context: &GuardianVerificationContext<'_>, config: &GuardianConfig, request: &GuardianSignRequest, pending: &GuardianHistory, historical: bool) -> Result<(VerifiedGuardianSession, ContractCallData, Hash4, Vec<DepositTreeState>),GuardianAccountError> {
    let network_magic = psy_config::parse_magic_hex(&context.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
    if request.network_magic != network_magic { return Err(GuardianSignError::AuthorizationMismatch.into()); }
    request.validate_authorization(config)?;
    let supplied = request.decode_trace()?;
    let checkpoint = supplied.anchor.start_checkpoint_id;
    if checkpoint > context.verified_checkpoint_id { return Err(GuardianSignError::CheckpointProofUnavailable.into()); }
    let checkpoint_path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id, checkpoint).await.map_err(|_| GuardianSignError::CheckpointProofUnavailable)?;
    verify_checkpoint(checkpoint, &supplied.anchor.checkpoint_leaf, &supplied.anchor.global_state_roots, &checkpoint_path, context.verified_checkpoint_tree_root)?;
    let witness = trace_policy(&supplied, config)?;
    let (current_policy, ending_policy) = witness.policies().map_err(|_| GuardianSignError::PolicyMismatch)?;
    let mut calls = Vec::new();
    let mut appends = Vec::new();
    let mut withdrawal_burns = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut counts = BTreeMap::new();
    let mut staged_deposit_tree_states = Vec::with_capacity(request.deposit_anchors.len());
    let start_hash = supplied.finalization.submit_end_cap_input.core.state_transition.start_user_leaf_hash;
    if pending.nonce.checked_add(1) != Some(request.session_nonce) || pending.ending_leaf.is_some_and(|leaf| leaf != start_hash) { return Err(GuardianSignError::TraceMismatch.into()); }
    for chain in &config.l1_chains {
        let (count, root) = withdrawal_opening(pending, chain.chain_index)?;
        verify_chain_state(context, &supplied, 3, chain.chain_index, count, root).await?;
        let (count, root) = pending.deposits.get(&chain.chain_index).copied().unwrap_or((0, <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32)));
        verify_chain_state(context, &supplied, 2, chain.chain_index, count, root).await?;
    }
    if request.operation == GuardianOperation::Bridge {
        if current_policy != ending_policy { return Err(GuardianSignError::PolicyMismatch.into()); }
        for anchor in &request.deposit_anchors {
            let chain = config.chain(anchor.chain_index)?;
            let reserved = reserved_deposit_tree_state(context.reserved_deposit_tree_states, context.history, anchor.chain_index);
            let (old_root, new_root, state) = super::verify_l1::verify_deposit_anchor(reserved, chain, anchor).await?;
            verify_chain_state(context, &supplied, 2, anchor.chain_index, anchor.old_count, old_root).await?;
            let mut inputs = vec![u64::from(anchor.chain_index), u64::from(anchor.new_count)];
            inputs.extend(hash_words(new_root));
            calls.push(ContractCallArgs { contract_id: 2, method_name: "set_chain_root".into(), inputs });
            staged_deposit_tree_states.push(state);
        }
        let mut withdrawals = Vec::with_capacity(request.withdrawal_records.len());
        for burn in &request.withdrawal_records {
            let burn_key = (burn.sender_user_id, burn.token_contract_id, burn.nonce);
            let nonce = (burn.destination_chain_index, burn.nonce);
            if context.conflicting_withdrawal_burns.contains(&burn_key) || context.conflicting_nonces.contains(&nonce) || !withdrawal_burns.insert(burn_key) || !nonces.insert(nonce) { return Err(GuardianSignError::WithdrawalNonceConflict.into()); }
            let chain = config.chain(burn.destination_chain_index)?;
            get_withdrawal_burn_proof(context, config, checkpoint, burn).await?;
            // Current Router mapping applies only to a fresh or pending sign.
            // An already-included session authenticates the burn proof and checkpoint.
            if !historical { super::verify_l1::verify_withdrawal_token(chain, burn).await?; }
            let count = counts.entry(burn.destination_chain_index).or_insert_with(|| pending.chains.get(&burn.destination_chain_index).map_or(0, |state| state.0));
            appends.push(WithdrawalAppendRecord { chain_index: burn.destination_chain_index, append_index: *count, burn: burn.clone() });
            *count = count.checked_add(1).ok_or(GuardianSignError::WithdrawalMismatch)?;
            withdrawals.push(crate::bridge::propose_withdrawals::PendingWithdrawal { event_id: 0, checkpoint_id: checkpoint, user_id: u64::from(burn.sender_user_id), sender_user_id: u64::from(burn.sender_user_id), contract_id: u64::from(burn.token_contract_id), destination_chain_index: u64::from(burn.destination_chain_index), token_address: burn.token, amount: burn.amount, recipient: burn.recipient, nonce: burn.nonce, leaf_hash: withdrawal_leaf(burn).to_string() });
        }
        calls.extend(crate::bridge::daemon::build_withdrawal_batch_calls(&withdrawals));
    } else { calls.push(policy_call(request.operation, &witness)?); }
    let expected = ContractCallData::new(calls);
    if serde_json::to_value(&expected).map_err(|_| GuardianSignError::MalformedRequest)? != request.trace_json.decode()?.call_data { return Err(GuardianSignError::UnsupportedCall.into()); }
    verify_trace_contracts(&supplied)?;
    let fees: Vec<_> = supplied.steps.iter().filter_map(|step| if let TraceStep::BurnFee(step) = step { Some(step) } else { None }).collect();
    if fees.len() != 1 || fees[0].contract_id != 0 || fees[0].method_id != TOKEN_BURN_METHOD_ID || fees[0].method_name != "burn" { return Err(GuardianSignError::UnsupportedCall.into()); }
    let message = Hash256::from(supplied.finalization.sig_hash).0;
    let ending_leaf_hash = supplied.finalization.submit_end_cap_input.core.new_user_leaf.qfhash::<PsyHasher>();
    Ok((VerifiedGuardianSession { trace: supplied, current_policy, ending_policy, starting_leaf_hash: start_hash, ending_leaf_hash, message, withdrawal_appends: appends }, expected, historical_checkpoint_root(&checkpoint_path), staged_deposit_tree_states))
}

pub async fn verify_guardian_session(context: &GuardianVerificationContext<'_>, config: &GuardianConfig, request: &GuardianSignRequest) -> Result<(VerifiedGuardianSession, Vec<DepositTreeState>),GuardianAccountError> {
    let (verified, expected, historical_root, deposit_tree_states) = verify_sign_request_trace(context, config, request, &context.history, false).await?;
    let checkpoint = verified.trace.anchor.start_checkpoint_id;
    let account_public_key = config.account_public_key()?;
    let mut builder = context.wallet.begin_trace_build_at_checkpoint(account_public_key, BRIDGE_USER_ID, checkpoint, request.session_nonce, historical_root).await.map_err(|_| GuardianSignError::TraceMismatch)?;
    for call in &expected.contract_calls { builder.trace_call(call.clone()).await.map_err(|_| GuardianSignError::TraceMismatch)?; }
    let fee = builder.required_fee().map_err(|_| GuardianSignError::TraceMismatch)?;
    if fee >= GOLDILOCKS_MODULUS { return Err(GuardianSignError::UnsupportedCall.into()); }
    let replayed = builder.finalize_tx_trace(expected.software_defined_call.clone()).await.map_err(|_| GuardianSignError::TraceMismatch)?;
    if !traces_equal(&verified.trace, &replayed)? { return Err(GuardianSignError::TraceMismatch.into()); }
    Ok((VerifiedGuardianSession { trace: replayed, ..verified }, deposit_tree_states))
}

fn verify_trace_contracts(trace: &TxTrace) -> Result<()> {
    let mut codes = BTreeMap::new();
    for code in &trace.contract_codes {
        if codes.contains_key(&code.contract_id) { return Err(GuardianSignError::ProofMismatch); }
        let id = u32::try_from(code.contract_id).map_err(|_| GuardianSignError::ProofMismatch)?;
        let definition: psy_client_data::qdata::contract::ContractCodeDefinition = bincode::deserialize(&code.code).map_err(|_| GuardianSignError::ProofMismatch)?;
        if definition.state_tree_height != contract_height(id)? { return Err(GuardianSignError::ProofMismatch); }
        let mut hashes = Vec::with_capacity(definition.functions.len());
        for function in &definition.functions {
            let method = psy_vm::dpn::contract::cfc_code_definition_to_dapen_fc(function).map_err(|_| GuardianSignError::ProofMismatch)?;
            hashes.push(psy_vm::dpn::contract::hash_dpn_function::<F>(&method));
        }
        let root = psy_client_data::qblock::cmds::deploy_contract::get_code_root_by_code_hashes::<F, PsyHasher>(&hashes, psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT - 1);
        codes.insert(code.contract_id, root);
    }
    for step in &trace.steps {
        let Some(step) = step.as_cfc() else { continue; };
        let root = codes.get(&step.contract_id).ok_or(GuardianSignError::ProofMismatch)?;
        let id = u32::try_from(step.contract_id).map_err(|_| GuardianSignError::UnsupportedCall)?;
        let binding = contract_method(id, &step.method_name)?;
        if binding.method_id != step.method_id { return Err(GuardianSignError::UnsupportedCall); }
        let inclusion = &step.cfc_inclusion_proof;
        let contract = &inclusion.contract_inclusion_proof;
        if contract.contract_leaf.code_root != *root || contract.contract_leaf.state_tree_height.to_canonical_u64() != u64::from(contract_height(id)?) { return Err(GuardianSignError::ProofMismatch); }
        verify_path(&contract.contract_tree_merkle_proof, trace.anchor.global_state_roots.contract_tree_root, step.contract_id, contract.contract_leaf.qfhash::<PsyHasher>(), GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
        let fingerprint_index = step.fn_id.checked_mul(2).ok_or(GuardianSignError::ProofMismatch)?;
        verify_path(&inclusion.contract_function_merkle_proof, contract.contract_leaf.function_tree_root, u64::from(fingerprint_index), step.cfc_fingerprint, psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT as usize)?;
        if inclusion.get_method_id() != step.method_id { return Err(GuardianSignError::ProofMismatch); }
    }
    Ok(())
}

fn historical_checkpoint_root(path: &MerkleProofCore<Hash4>) -> Hash4 {
    let mut current = path.value;
    let mut zero = Hash4::ZERO;
    for (level,sibling) in path.siblings.iter().enumerate() {
        current = if (path.index >> level) & 1 == 0 { PsyHasher::q_two_to_one(current,zero) } else { PsyHasher::q_two_to_one(*sibling,current) };
        zero = PsyHasher::q_two_to_one(zero,zero);
    }
    current
}



async fn verify_session_leaf(context: &GuardianVerificationContext<'_>, config: &GuardianConfig, record: &GuardianSessionRecord, ending_leaf: &psy_client_data::qdata::user::PsyUserLeaf<F>) -> Result<()> {
    let id = record.included_checkpoint_id;
    if id > context.verified_checkpoint_id { return Err(GuardianSignError::CheckpointProofUnavailable); }
    let leaf = context.provider.get_checkpoint_leaf_data(id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    let roots = context.provider.get_checkpoint_global_state_roots(id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    let path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id,id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    verify_checkpoint(id,&leaf,&roots,&path,context.verified_checkpoint_tree_root)?;
    if leaf.qfhash::<PsyHasher>() != record.included_checkpoint_hash { return Err(GuardianSignError::TraceMismatch); }
    let account_public_key = config.account_public_key()?;
    if ending_leaf.public_key != account_public_key || ending_leaf.user_id.to_canonical_u64()!=BRIDGE_USER_ID { return Err(GuardianSignError::AccountIdentityConflict); }
    let user = context.provider.get_user_tree_merkle_proof(id,BRIDGE_USER_ID).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    verify_path(&user,roots.user_tree_root,BRIDGE_USER_ID,ending_leaf.qfhash::<PsyHasher>(),GLOBAL_USER_TREE_HEIGHT as usize)
}

// Recovery authenticates the operation commitment, not arbitrary execution-witness JSON.
// It must not execute the calls again against the live IMT allocator.
fn verify_guardian_session_commitment(config: &GuardianConfig, request: &GuardianSignRequest, trace: &TxTrace, expected: &ContractCallData, historical_root: Hash4) -> Result<()> {
    use psy_client_data::{dpn::proving_session::DPNProvingSessionSimpleMethodCall, qdata::{ups_signature::PsyUserProvingSessionSignatureDataCompact, user_contract_state::SignContext}, qstore::controllers::register_helpers::get_new_empty_user_leaf};
    let start = &trace.ups_start_witness.ups_header.session_start_context;
    let leaf = &start.start_session_user_leaf;
    let core = &trace.finalization.submit_end_cap_input.core;
    let checkpoint = trace.anchor.start_checkpoint_id;
    let user_id = F::from_canonical_u64(BRIDGE_USER_ID);
    let nonce = F::from_canonical_u64(request.session_nonce);
    let account_public_key = config.account_public_key()?;
    if start.checkpoint_id.to_canonical_u64()!=checkpoint || start.checkpoint_tree_root!=historical_root || start.checkpoint_leaf_hash!=trace.anchor.checkpoint_leaf.qfhash::<PsyHasher>() || leaf.user_id!=user_id || leaf.public_key!=account_public_key {
        return Err(GuardianSignError::TraceMismatch);
    }
    let path = &trace.ups_start_witness.user_tree_proof;
    verify_path(path,trace.anchor.global_state_roots.user_tree_root,BRIDGE_USER_ID,path.value,GLOBAL_USER_TREE_HEIGHT as usize)?;
    if path.value==Hash4::ZERO {
        if *leaf!=get_new_empty_user_leaf(user_id,account_public_key) || request.session_nonce!=1 { return Err(GuardianSignError::TraceMismatch); }
        let registration = trace.ups_start_witness.user_registration_tree_proof.as_ref().ok_or(GuardianSignError::ProofMismatch)?;
        verify_path(registration,trace.anchor.global_state_roots.user_registration_tree_root,psy_crypto::common::user_id::get_registration_id_from_user_id(BRIDGE_USER_ID),account_public_key,GLOBAL_USER_TREE_HEIGHT as usize)?;
    } else if trace.ups_start_witness.user_registration_tree_proof.is_some() || path.value!=leaf.qfhash::<PsyHasher>() {
        return Err(GuardianSignError::TraceMismatch);
    }
    if leaf.nonce.to_canonical_u64().checked_add(1)!=Some(request.session_nonce) || core.state_transition.start_user_leaf_hash!=path.value || core.state_transition.start_user_leaf_hash!=guardian_proved_start_hash(leaf) || core.state_transition.checkpoint_tree_root_hash!=historical_root || core.state_transition.user_id!=user_id {
        return Err(GuardianSignError::TraceMismatch);
    }
    if core.new_user_leaf.user_id!=user_id || core.new_user_leaf.public_key!=account_public_key || core.new_user_leaf.nonce!=nonce || core.new_user_leaf.last_checkpoint_id.to_canonical_u64()!=checkpoint || core.checkpoint_id.to_canonical_u64()!=checkpoint || core.new_user_leaf.qfhash::<PsyHasher>()!=core.state_transition.end_user_leaf_hash {
        return Err(GuardianSignError::TraceMismatch);
    }
    let witness = trace_policy(trace, config)?;
    let mut end = core.new_user_leaf;
    end.nonce = leaf.nonce;
    let sign_context = SignContext { checkpoint_tree_root:historical_root,user_leaf:end };
    if witness.start_session_user_leaf!=*leaf || witness.sign_context!=sign_context || witness.start_state.state.checkpoint_id!=start.checkpoint_id || witness.end_state.state.checkpoint_id!=start.checkpoint_id || witness.nonce!=nonce {
        return Err(GuardianSignError::PolicyMismatch);
    }
    // The verified EndCap commits these fee fields and enforces the fee schedule.
    let fee = core.stats.guta_fees_collected.to_canonical_u64().checked_add(core.stats.da_fees_collected.to_canonical_u64()).ok_or(GuardianSignError::UnsupportedCall)?;
    if fee >= GOLDILOCKS_MODULUS { return Err(GuardianSignError::UnsupportedCall); }
    // Code roots authenticate method IDs and inputs, but not method names.
    let mut methods = BTreeMap::new();
    for code in &trace.contract_codes {
        let definition: psy_client_data::qdata::contract::ContractCodeDefinition = bincode::deserialize(&code.code).map_err(|_|GuardianSignError::ProofMismatch)?;
        let contract_methods = methods.entry(code.contract_id).or_insert_with(BTreeMap::new);
        for function in &definition.functions {
            let method = psy_vm::dpn::contract::cfc_code_definition_to_dapen_fc(function).map_err(|_|GuardianSignError::ProofMismatch)?;
            if contract_methods.insert(method.method_id,method.circuit_inputs.len()).is_some() { return Err(GuardianSignError::ProofMismatch); }
        }
    }
    let mut stack = Hash4::ZERO;
    for call in &expected.contract_calls {
        let id = u32::try_from(call.contract_id).map_err(|_| GuardianSignError::UnsupportedCall)?;
        let binding = contract_method(id, &call.method_name)?;
        let input_count = methods.get(&call.contract_id).and_then(|methods| methods.get(&binding.method_id)).ok_or(GuardianSignError::UnsupportedCall)?;
        if *input_count != binding.input_felt_count as usize || call.inputs.len() != *input_count || call.inputs.iter().any(|input| *input >= GOLDILOCKS_MODULUS) { return Err(GuardianSignError::UnsupportedCall); }
        let call = DPNProvingSessionSimpleMethodCall::new(F::from_canonical_u32(id), F::from_canonical_u32(binding.method_id), call.inputs.iter().copied().map(F::from_canonical_u64).collect());
        stack = PsyHasher::q_two_to_one(stack, call.qfhash::<PsyHasher>());
    }
    let fee_call = DPNProvingSessionSimpleMethodCall::new(F::ZERO,F::from_canonical_u32(TOKEN_BURN_METHOD_ID),vec![F::from_canonical_u64(fee)]);
    stack = PsyHasher::q_two_to_one(stack,fee_call.qfhash::<PsyHasher>());
    let count = u64::try_from(expected.contract_calls.len()).ok().and_then(|count|count.checked_add(1)).filter(|count|*count<GOLDILOCKS_MODULUS).ok_or(GuardianSignError::UnsupportedCall)?;
    let sig_data = PsyUserProvingSessionSignatureDataCompact { start_user_leaf_hash:leaf.qfhash::<PsyHasher>(),end_user_leaf_hash:core.state_transition.end_user_leaf_hash,checkpoint_leaf_hash:start.checkpoint_leaf_hash,tx_stack_hash:stack,tx_count:F::from_canonical_u64(count) };
    if core.stats.total_transactions!=sig_data.tx_count || witness.sig_data!=sig_data { return Err(GuardianSignError::TraceMismatch); }
    let message = sig_data.get_sig_action_for_user::<PsyHasher>(request.network_magic,user_id,nonce,sign_context).get_qhash::<PsyHasher>();
    if message!=trace.finalization.sig_hash { return Err(GuardianSignError::TraceMismatch); }
    Ok(())
}

fn guardian_proved_start_hash(leaf: &psy_client_data::qdata::user::PsyUserLeaf<F>) -> Hash4 {
    // Match the EndCap circuit's default-state-root selector, not a trace flag.
    if leaf.user_state_tree_root==psy_config::get_default_user_state_tree_root::<F>() { Hash4::ZERO } else { leaf.qfhash::<PsyHasher>() }
}


/// Expected EndCap fingerprint for the stage this binary was measured on.
/// The limbs stay in `PsyNetworkLocalDevnetConstants`; this only reads them.
/// Every other network magic fails closed.
pub fn canonical_endcap_fingerprint() -> Result<Hash4> {
    use parth_core::protocol::core_types::QNetworkTreeCircuitSpecificConstants;
    use plonky2::field::types::Field;
    const STAGE_MAGIC: u64 = 0x1337CF514544CF69;
    if psy_config::PSY_NETWORK_MAGIC != STAGE_MAGIC { return Err(GuardianSignError::AuthorizationMismatch); }
    let limbs = psy_core::network_config::PsyNetworkLocalDevnetConstants::END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4;
    if limbs.iter().any(|limb| *limb >= GOLDILOCKS_MODULUS) { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok(Hash4::from_values(limbs[0], limbs[1], limbs[2], limbs[3]))
}

pub async fn verify_cached_endcap_proof(wallet: &WalletSession, proof: &[u8], input: &psy_client_data::guta::end_cap_input::SubmitUserEndCapNonProofInput<F>) -> Result<()> {
    use plonky2::plonk::{circuit_data::VerifierCircuitData, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs};
    let decoded: ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2> = decode_endcap_proof(proof)?;
    if bincode::serialize(&decoded).map_err(|_| GuardianSignError::ProofMismatch)? != proof { return Err(GuardianSignError::ProofMismatch); }
    let expected = input.core.get_proof_public_inputs_hash::<PsyHasher>();
    if decoded.public_inputs.as_slice() != expected.0.elements { return Err(GuardianSignError::ProofMismatch); }
    let canonical = canonical_endcap_fingerprint()?;
    let mut verifier_only = None;
    let managers = wallet.wallet.circuit_managers();
    if managers.is_empty() { return Err(GuardianSignError::KeyUnavailable); }
    for manager in managers {
        let verifier = manager.ups_end_cap_circuit_verifier_config().await.map_err(|_| GuardianSignError::KeyUnavailable)?;
        let current = QHashOut(psy_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic::<2, F, PoseidonGoldilocksConfig>(&verifier));
        if current != canonical { return Err(GuardianSignError::ProofMismatch); }
        verifier_only = Some(verifier);
    }
    let verifier_only = verifier_only.ok_or(GuardianSignError::KeyUnavailable)?;
    let common = psy_plonky2_basic_helpers::lookalike::standard::get_end_cap_type_e_common_data::<PoseidonGoldilocksConfig, 2>();
    VerifierCircuitData { verifier_only, common }.verify(decoded).map_err(|_| GuardianSignError::ProofMismatch)
}

pub async fn verify_session(context: &GuardianVerificationContext<'_>, config: &GuardianConfig, record: GuardianSessionRecord, pending: &GuardianHistory) -> Result<(GuardianSession, Vec<DepositTreeState>), GuardianAccountError> {
    let request = record.validate(config)?;
    let (verified, expected_calls, historical_root, deposit_tree_states) = verify_sign_request_trace(context, config, &request, pending, true).await?;
    verify_guardian_session_commitment(config, &request, &verified.trace, &expected_calls, historical_root)?;
    let signatures = record.signatures_json.decode()?;
    psy_prover::signature::users::multisig_user::validate_policy_signatures(&signatures, &verified.current_policy, verified.trace.finalization.sig_hash).map_err(|_| GuardianSignError::PolicyMismatch)?;
    let input = record.endcap_input_json.decode()?;
    if serde_json::to_value(&input).map_err(|_| GuardianSignError::MalformedRequest)? != serde_json::to_value(&verified.trace.finalization.submit_end_cap_input).map_err(|_| GuardianSignError::MalformedRequest)? || record.included_checkpoint_id < verified.trace.anchor.start_checkpoint_id { return Err(GuardianSignError::TraceMismatch.into()); }
    verify_cached_endcap_proof(context.wallet, &record.proof_bytes()?, &input).await?;
    verify_session_leaf(context, config, &record, &input.core.new_user_leaf).await?;
    if input.core.new_user_leaf.nonce.to_canonical_u64() != request.session_nonce { return Err(GuardianSignError::TraceMismatch.into()); }
    Ok((GuardianSession { network_magic: request.network_magic, user_id: request.user_id, nonce: request.session_nonce, record, starting_leaf_hash: verified.starting_leaf_hash, ending_leaf_hash: verified.ending_leaf_hash, withdrawal_appends: verified.withdrawal_appends }, deposit_tree_states))
}


/// Bounded pending-signature recheck: the signed-but-unincluded reservations are
/// re-bound to the current L1 headers only — chain identity, genesis and finalized
/// ancestry per stored anchor — with the typed `FinalityConflict` halt on a
/// contradicting canonical hash. No historical evidence is replayed here; inclusion
/// re-verifies every anchor with full evidence at import time.
pub async fn verify_pending_signed_anchors(config: &GuardianConfig, pending: &[GuardianSigned]) -> std::result::Result<(), GuardianAccountError> {
    for signed in pending {
        signed.validate()?;
        let request = GuardianSignRequest::from_canonical_bytes(&signed.request_bytes)?;
        request.validate_authorization(config)?;
        for state in &signed.deposit_tree_states {
            state.validate()?;
            let anchor = &state.anchor;
            let chain = config.chain(anchor.chain_index)?;
            let canonical = super::verify_l1::verify_saved_deposit_anchor_headers(chain, anchor).await?;
            super::verify_l1::verify_cached_anchor_hash(canonical,anchor.block_hash)?;
        }
    }
    Ok(())
}

/// Startup gate: the durable snapshot must equal the account state authenticated at
/// the saved checkpoint. The checkpoint is proven against the current committed head,
/// and every contract-state proof chains into its authenticated global roots. The
/// restored withdrawal frontier must fold to the `(count, root)` opening authenticated
/// on-chain; a contradictory frontier halts here instead of waiting for a later import.
pub async fn verify_restored_history(context: &GuardianVerificationContext<'_>, config: &GuardianConfig, saved_checkpoint_id: u64) -> std::result::Result<(), GuardianAccountError> {
    if saved_checkpoint_id > context.verified_checkpoint_id { return Err(GuardianSignError::CheckpointProofUnavailable.into()); }
    let leaf = context.provider.get_checkpoint_leaf_data(saved_checkpoint_id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    let roots = context.provider.get_checkpoint_global_state_roots(saved_checkpoint_id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    let path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id,saved_checkpoint_id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    verify_checkpoint(saved_checkpoint_id,&leaf,&roots,&path,context.verified_checkpoint_tree_root)?;
    // Contract state proofs anchor at the bridge account's own state tree: the user
    // leaf is proven via the checkpoint's user tree root first (mirrors
    // verified_account_nonce), never via the global contract tree root.
    let user_path = context.provider.get_user_tree_merkle_proof(saved_checkpoint_id,BRIDGE_USER_ID).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    verify_path(&user_path,roots.user_tree_root,BRIDGE_USER_ID,user_path.value,GLOBAL_USER_TREE_HEIGHT as usize)?;
    let state_root = if user_path.value == Hash4::ZERO {
        <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32)
    } else {
        let user_leaf = context.provider.get_user_leaf_data(saved_checkpoint_id,BRIDGE_USER_ID).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
        if user_path.value != user_leaf.qfhash::<PsyHasher>() { return Err(GuardianAccountError::Conflict(HaltReason::CheckpointConflict)); }
        user_leaf.user_state_tree_root
    };
    for chain in &config.l1_chains {
        let openings = [
            (3u32, withdrawal_opening(context.history, chain.chain_index)?),
            (2u32, context.history.deposits.get(&chain.chain_index).copied().unwrap_or((0, <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32)))),
        ];
        for (contract, expected) in openings {
            let contract_proof = context.provider.get_user_contract_tree_merkle_proof(saved_checkpoint_id, BRIDGE_USER_ID, contract).await.map_err(|_| GuardianSignError::CheckpointProofUnavailable)?;
            verify_path(&contract_proof, state_root, u64::from(contract), contract_proof.value, GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
            let height = u8::try_from(contract_height(contract)?).map_err(|_| GuardianSignError::ProofMismatch)?;
            let root = if contract_proof.value == Hash4::ZERO { <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(height as usize) } else { contract_proof.value };
            let stored_count = read_subslots_at(context, saved_checkpoint_id, BRIDGE_USER_ID, root, contract, 65544 + u64::from(chain.chain_index), 1, height).await?;
            let stored_root = read_subslots_at(context, saved_checkpoint_id, BRIDGE_USER_ID, root, contract, 65804 + u64::from(chain.chain_index) * 8, 8, height).await?;
            if stored_count != [u64::from(expected.0)] || (stored_root != hash_words(expected.1) && !(expected.0 == 0 && stored_root == [0;8])) { return Err(GuardianAccountError::Conflict(HaltReason::CheckpointConflict)); }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum GuardianAccountError { Unavailable(GuardianSignError), Conflict(HaltReason) }
impl From<GuardianSignError> for GuardianAccountError { fn from(error: GuardianSignError) -> Self { Self::Unavailable(error) } }
impl std::fmt::Display for GuardianAccountError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(formatter,"{self:?}") }
}
impl std::error::Error for GuardianAccountError {}

/// Reads the nonce authenticated at the context's fixed checkpoint. Missing user
/// indexes wait only until the caller's observer/sign deadline, then return
/// `IndexCheckpointTimeout`; other user-proof RPC failures return `CheckpointProofUnavailable`.
pub async fn verified_account_nonce(context: &GuardianVerificationContext<'_>, config: &GuardianConfig, deadline: tokio::time::Instant) -> Result<u64> {
    let id = context.verified_checkpoint_id;
    let checkpoint = context.provider.get_checkpoint_leaf_data(id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    let roots = context.provider.get_checkpoint_global_state_roots(id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    let path = context.provider.get_checkpoint_tree_merkle_proof(id,id).await.map_err(|_|GuardianSignError::CheckpointProofUnavailable)?;
    verify_checkpoint(id,&checkpoint,&roots,&path,context.verified_checkpoint_tree_root)?;
    let account_public_key = config.account_public_key()?;
    let user = context.provider.get_user_leaf_data(id, config.user_id()).await.map_err(|_| GuardianSignError::CheckpointProofUnavailable)?;
    let user_path = user_tree_proof(context.provider, id, config.user_id(), deadline).await?;
    verify_path(&user_path, roots.user_tree_root, config.user_id(), user_path.value, GLOBAL_USER_TREE_HEIGHT as usize)?;
    if user_path.value == Hash4::ZERO { return Ok(0); }
    if user_path.value != user.qfhash::<PsyHasher>() || user.public_key != account_public_key || user.user_id.to_canonical_u64() != config.user_id() { return Err(GuardianSignError::AccountIdentityConflict); }
    Ok(user.nonce.to_canonical_u64())
}
async fn user_tree_proof(provider: &RpcProvider, checkpoint_id: u64, user_id: u64, deadline: tokio::time::Instant) -> Result<MerkleProofCore<Hash4>> {
    wait_user_tree_proof(checkpoint_id, user_id, deadline, |checkpoint, user| provider.get_user_tree_merkle_proof(checkpoint, user)).await
}

enum UserTreeProofFailure {
    MissingCheckpointProof,
    Other,
}

fn classify_user_tree_proof(error: &anyhow::Error, checkpoint_id: u64) -> UserTreeProofFailure {
    match error.downcast_ref::<psy_provider::lps::MissingCheckpointProof>() {
        Some(missing) if missing.checkpoint_id == checkpoint_id => UserTreeProofFailure::MissingCheckpointProof,
        _ => UserTreeProofFailure::Other,
    }
}

// Retry only the provider's typed missing-checkpoint failure for this checkpoint.
// Transport, malformed-proof and all other failures retain fail-fast semantics.
// The caller owns the deadline and cancellation: no task outlives this borrowed future.
async fn wait_user_tree_proof<Fut>(checkpoint_id: u64, user_id: u64, deadline: tokio::time::Instant, mut fetch: impl FnMut(u64, u64) -> Fut) -> Result<MerkleProofCore<Hash4>>
where Fut: Future<Output = anyhow::Result<MerkleProofCore<Hash4>>> {
    let mut waiting_for_index = false;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(if waiting_for_index { GuardianSignError::IndexCheckpointTimeout } else { GuardianSignError::CheckpointProofUnavailable });
        }
        match tokio::time::timeout_at(deadline, fetch(checkpoint_id, user_id)).await {
            Ok(Ok(path)) => return Ok(path),
            Ok(Err(error)) => match classify_user_tree_proof(&error, checkpoint_id) {
                UserTreeProofFailure::MissingCheckpointProof => {
                    if !waiting_for_index { tracing::warn!(checkpoint_id, user_id, "user tree proof not yet readable; waiting until caller deadline"); }
                    waiting_for_index = true;
                    tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + std::time::Duration::from_millis(250))).await;
                }
                UserTreeProofFailure::Other => return Err(GuardianSignError::CheckpointProofUnavailable),
            },
            Err(_) => return Err(if waiting_for_index { GuardianSignError::IndexCheckpointTimeout } else { GuardianSignError::CheckpointProofUnavailable }),
        }
    }
}

fn decode_endcap_proof(bytes: &[u8]) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F,plonky2::plonk::config::PoseidonGoldilocksConfig,2>> {
    use bincode::Options;
    if bytes.len() > MAX_BODY_BYTES { return Err(GuardianSignError::ProofMismatch); }
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(MAX_BODY_BYTES as u64).reject_trailing_bytes().deserialize(bytes).map_err(|_|GuardianSignError::ProofMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn missing_user_index(checkpoint_id: u64) -> anyhow::Error {
        psy_provider::lps::MissingCheckpointProof { checkpoint_id }.into()
    }

    #[tokio::test(start_paused = true)]
    async fn user_index_wait_succeeds_after_old_retry_window_at_fixed_checkpoint() {
        let start = tokio::time::Instant::now();
        let calls = std::cell::Cell::new(0);
        let proof = wait_user_tree_proof(17, 42, start + std::time::Duration::from_secs(3), |checkpoint, user| {
            assert_eq!((checkpoint, user), (17, 42));
            calls.set(calls.get() + 1);
            std::future::ready(if tokio::time::Instant::now() - start < std::time::Duration::from_secs(2) {
                Err(missing_user_index(checkpoint))
            } else {
                Ok(MerkleProofCore { root: Hash4::ZERO, index: user, value: Hash4::ZERO, siblings: vec![] })
            })
        }).await.unwrap();
        assert_eq!(proof.index, 42);
        assert_eq!(calls.get(), 9);
        assert_eq!(tokio::time::Instant::now() - start, std::time::Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn user_index_wait_expires_at_caller_deadline_without_another_request() {
        let start = tokio::time::Instant::now();
        let deadline = start + std::time::Duration::from_millis(1100);
        let calls = std::cell::Cell::new(0);
        let result = wait_user_tree_proof(17, 42, deadline, |checkpoint, _| {
            calls.set(calls.get() + 1);
            std::future::ready(Err(missing_user_index(checkpoint)))
        }).await;
        assert!(matches!(result, Err(GuardianSignError::IndexCheckpointTimeout)));
        assert_eq!(calls.get(), 5);
        assert_eq!(tokio::time::Instant::now(), deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn user_index_wait_does_not_retry_other_errors() {
        #[derive(Clone, Copy)]
        enum Case { Transport, VerifyFailed, WrongCheckpoint }
        for case in [Case::Transport, Case::VerifyFailed, Case::WrongCheckpoint] {
            let start = tokio::time::Instant::now();
            let calls = std::cell::Cell::new(0);
            let result = wait_user_tree_proof(17, 42, start + std::time::Duration::from_secs(30), |_, _| {
                calls.set(calls.get() + 1);
                let error = match case {
                    Case::Transport => anyhow!("connection refused"),
                    Case::VerifyFailed => anyhow!("user tree merkle proof verify failed"),
                    Case::WrongCheckpoint => missing_user_index(18),
                };
                std::future::ready(Err(error))
            }).await;
            assert!(matches!(result, Err(GuardianSignError::CheckpointProofUnavailable)));
            assert_eq!(calls.get(), 1);
            assert_eq!(tokio::time::Instant::now(), start);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn user_index_wait_outer_timeout_drops_retry_sleep_and_releases_lock() {
        let mutex = tokio::sync::Mutex::new(());
        let calls = std::cell::Cell::new(0);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), async {
            let _guard = mutex.lock().await;
            wait_user_tree_proof(17, 42, deadline, |checkpoint, _| {
                calls.set(calls.get() + 1);
                std::future::ready(Err(missing_user_index(checkpoint)))
            }).await
        }).await;
        assert!(result.is_err());
        assert!(mutex.try_lock().is_ok());
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn user_index_wait_deadline_drops_inflight_rpc_and_preserves_error_kind() {
        for index_missing in [false, true] {
            let mutex = tokio::sync::Mutex::new(());
            let calls = std::cell::Cell::new(0);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            let result = wait_user_tree_proof(17, 42, deadline, |checkpoint, _| {
                calls.set(calls.get() + 1);
                let first = calls.get() == 1;
                let mutex = &mutex;
                async move {
                    if index_missing && first { return Err(missing_user_index(checkpoint)); }
                    let _guard = mutex.lock().await;
                    std::future::pending::<anyhow::Result<MerkleProofCore<Hash4>>>().await
                }
            }).await;
            if index_missing { assert!(matches!(result, Err(GuardianSignError::IndexCheckpointTimeout))); }
            else { assert!(matches!(result, Err(GuardianSignError::CheckpointProofUnavailable))); }
            assert_eq!(calls.get(), if index_missing { 2 } else { 1 });
            assert_eq!(tokio::time::Instant::now(), deadline);
            assert!(mutex.try_lock().is_ok());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn user_index_wait_stops_if_retry_returns_non_index_error() {
        let start = tokio::time::Instant::now();
        let calls = std::cell::Cell::new(0);
        let result = wait_user_tree_proof(17, 42, start + std::time::Duration::from_secs(30), |checkpoint, _| {
            calls.set(calls.get() + 1);
            std::future::ready(Err(if calls.get() == 1 { missing_user_index(checkpoint) } else { anyhow!("user tree merkle proof verify failed") }))
        }).await;
        assert!(matches!(result, Err(GuardianSignError::CheckpointProofUnavailable)));
        assert_eq!(calls.get(), 2);
        assert_eq!(tokio::time::Instant::now() - start, std::time::Duration::from_millis(250));
    }

    fn recovery_commitment_fixture() -> (GuardianConfig, GuardianSignRequest, TxTrace, ContractCallData, Hash4) {
        use psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree;
        use psy_client_data::{dpn::proving_session::DPNProvingSessionSimpleMethodCall, qdata::{user::PsyUserLeaf, user_contract_state::{UserContractState, SignContext}, ups_signature::PsyUserProvingSessionSignatureDataCompact}};
        use psy_vm::{ups::state_reader::StateReaderResults, dpn::ops::state_cmd::data::{DPNStateCmd, DPNStateCmdGetSelfUserCurrentContractStateSlotHash}};
        let config = super::super::test_fixture::codec_guardian_config();
        let account = config.initial_account().unwrap();
        let fingerprint = multisig_fingerprint().unwrap();
        let public_key = config.account_public_key().unwrap();
        let members = [account.initial_policy.member_hashes[0], account.initial_policy.member_hashes[1], account.initial_policy.member_hashes[2]];
        let mut policy_tree = SimpleMerkleTree::<PsyHasher, Hash4>::new(4);
        // Policy storage contains the raw header, not the account identity commitment.
        let header = Hash4::from_values(u64::from(account.initial_policy.version), 2, 3, 0);
        for (index, value) in std::iter::once(header).chain(members).enumerate() { policy_tree.set_leaf(index as u64, value); }
        let mut contracts = SimpleMerkleTree::<PsyHasher, Hash4>::new(GLOBAL_CONTRACT_TREE_HEIGHT);
        contracts.set_leaf(u64::from(MULTISIG_POLICY_CONTRACT_ID), policy_tree.get_root());
        let leaf = PsyUserLeaf { public_key, user_state_tree_root: contracts.get_root(), user_id: F::from_canonical_u64(BRIDGE_USER_ID), nonce: F::ONE, ..Default::default() };
        let mut users = SimpleMerkleTree::<PsyHasher, Hash4>::new(GLOBAL_USER_TREE_HEIGHT);
        users.set_leaf(BRIDGE_USER_ID, leaf.qfhash::<PsyHasher>());
        let root = Hash4::from_values(5, 6, 7, 8);
        let state = StateReaderResults { state: UserContractState::new(root, leaf, policy_tree.get_root(), F::from_canonical_u32(MULTISIG_POLICY_CONTRACT_ID), F::from_canonical_u64(7)), user_tree_root: users.get_root(), checkpoint: None, aux_user_leaves: vec![], state_cmds: (0..4).map(|index| DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(DPNStateCmdGetSelfUserCurrentContractStateSlotHash { slot_index: F::from_canonical_u64(index) })).collect(), merkel_proofs: (0..4).flat_map(|index| [contracts.get_leaf(u64::from(MULTISIG_POLICY_CONTRACT_ID)), policy_tree.get_leaf(index)]).collect() };
        let method = psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition { name: "append_withdrawal".into(), method_id: APPEND_WITHDRAWAL.method_id, circuit_inputs: vec![0; APPEND_WITHDRAWAL.input_felt_count as usize], circuit_outputs: vec![], assertions: vec![], events: vec![], definitions: vec![], state_commands: vec![], state_command_resolution_indices: vec![] };
        let code = psy_client_data::qdata::contract::ContractCodeDefinition { state_tree_height: u16::from(psy_config::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT), functions: [method].iter().map(psy_vm::dpn::contract::dapen_fc_to_cfc_code_definition).collect() };
        let mut request = super::super::test_fixture::codec_request_fixture();
        let mut trace = request.decode_trace().unwrap();
        trace.contract_codes = vec![psy_prover::trace::TraceContractCode { contract_id: u64::from(crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID), code: bincode::serialize(&code).unwrap() }];
        request.session_nonce = 2;
        trace.meta.public_key = public_key;
        trace.anchor.start_checkpoint_id = 7;
        trace.anchor.global_state_roots.user_tree_root = users.get_root();
        trace.ups_start_witness.user_tree_proof = users.get_leaf(BRIDGE_USER_ID);
        trace.ups_start_witness.ups_header.session_start_context = psy_client_data::ups::ups_context_input::UserProvingSessionStartContext { checkpoint_id: F::from_canonical_u64(7), checkpoint_tree_root: root, checkpoint_leaf_hash: trace.anchor.checkpoint_leaf.qfhash::<PsyHasher>(), start_session_user_leaf: leaf };
        let mut end = leaf;
        end.last_checkpoint_id = F::from_canonical_u64(7);
        let sign_context = SignContext { checkpoint_tree_root: root, user_leaf: end };
        end.nonce = F::from_canonical_u64(2);
        trace.finalization.nonce = end.nonce;
        let core = &mut trace.finalization.submit_end_cap_input.core;
        core.checkpoint_id = end.last_checkpoint_id;
        core.new_user_leaf = end;
        core.state_transition = psy_client_data::qdata::ups_end_cap_result::UPSEndCapResultCompact { start_user_leaf_hash: leaf.qfhash::<PsyHasher>(), end_user_leaf_hash: end.qfhash::<PsyHasher>(), checkpoint_tree_root_hash: root, user_id: leaf.user_id };
        core.stats.guta_fees_collected = F::ONE;
        core.stats.da_fees_collected = F::ONE;
        core.stats.total_transactions = F::from_canonical_u64(2);
        let call = DPNProvingSessionSimpleMethodCall::new(F::from_canonical_u32(crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID), F::from_canonical_u32(APPEND_WITHDRAWAL.method_id), vec![F::ZERO; APPEND_WITHDRAWAL.input_felt_count as usize]);
        let burn = DPNProvingSessionSimpleMethodCall::new(F::ZERO, F::from_canonical_u32(TOKEN_BURN_METHOD_ID), vec![F::from_canonical_u64(2)]);
        let stack = PsyHasher::q_two_to_one(PsyHasher::q_two_to_one(Hash4::ZERO, call.qfhash::<PsyHasher>()), burn.qfhash::<PsyHasher>());
        let sig_data = PsyUserProvingSessionSignatureDataCompact { start_user_leaf_hash: leaf.qfhash::<PsyHasher>(), end_user_leaf_hash: end.qfhash::<PsyHasher>(), checkpoint_leaf_hash: trace.anchor.checkpoint_leaf.qfhash::<PsyHasher>(), tx_stack_hash: stack, tx_count: F::from_canonical_u64(2) };
        trace.finalization.sig_hash = sig_data.get_sig_action_for_user::<PsyHasher>(request.network_magic, leaf.user_id, end.nonce, sign_context).get_qhash::<PsyHasher>();
        let mut end_state = state.clone();
        end_state.state.user_leaf = sign_context.user_leaf;
        let witness = MultisigSignatureWitness { account: account.clone(), start_state: state, end_state, sig_data, sign_context, start_session_user_leaf: leaf, nonce: end.nonce };
        witness.policies().unwrap();
        trace.steps.push(TraceStep::ZkSign(psy_prover::trace::ZkSignStep { fingerprint, proof_tree_start_root: Hash4::ZERO, proof_tree_end_root: Hash4::ZERO, sign_circuit_source: psy_prover::trace::TraceSignCircuitSource::Multisig, sign_witness: serde_json::to_vec(&witness).unwrap(), public_key_param: account.public_key_param().unwrap(), sign_verifier_data_alt: psy_client_common::data::alt::AltVerifierOnlyCircuitData { constants_sigmas_cap: vec![], circuit_digest: Hash4::ZERO } }));
        let expected = ContractCallData::new(vec![ContractCallArgs { contract_id: u64::from(crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID), method_name: "append_withdrawal".into(), inputs: vec![0; APPEND_WITHDRAWAL.input_felt_count as usize] }]);
        (config, request, trace, expected, root)
    }

    #[test]
    fn recovered_calls_bind_to_signed_commitment_without_execution() {
        let (config, request, trace, mut calls, root) = recovery_commitment_fixture();
        verify_guardian_session_commitment(&config, &request, &trace, &calls, root).unwrap();
        calls.contract_calls[0].method_name = "set_chain_root".into();
        assert!(matches!(verify_guardian_session_commitment(&config, &request, &trace, &calls, root), Err(GuardianSignError::UnsupportedCall)));
        calls.contract_calls[0].method_name = "append_withdrawal".into();
        calls.contract_calls[0].inputs.push(1);
        assert!(matches!(verify_guardian_session_commitment(&config, &request, &trace, &calls, root), Err(GuardianSignError::UnsupportedCall)));
        calls.contract_calls[0].inputs.pop();
        let mut missing_code = trace.clone();
        missing_code.contract_codes.clear();
        assert!(matches!(verify_guardian_session_commitment(&config, &request, &missing_code, &calls, root), Err(GuardianSignError::UnsupportedCall)));
        let mut duplicate_code = trace.clone();
        duplicate_code.contract_codes.push(trace.contract_codes[0].clone());
        assert!(matches!(verify_guardian_session_commitment(&config, &request, &duplicate_code, &calls, root), Err(GuardianSignError::ProofMismatch)));
        let mut spliced = trace.clone();
        spliced.finalization.submit_end_cap_input.core.new_user_leaf.balance += F::ONE;
        assert!(verify_guardian_session_commitment(&config, &request, &spliced, &calls, root).is_err());
        assert!(verify_guardian_session_commitment(&config, &request, &trace, &calls, Hash4::ZERO).is_err());
        let mut wrong_fee = trace.clone();
        wrong_fee.finalization.submit_end_cap_input.core.stats.da_fees_collected += F::ONE;
        assert!(verify_guardian_session_commitment(&config, &request, &wrong_fee, &calls, root).is_err());
    }

    #[test]
    fn recovered_method_binding_ignores_unhashed_trace_names() {
        use psy_client_data::qdata::contract::ContractCodeDefinition;
        use psy_vm::dpn::contract::{cfc_code_definition_to_dapen_fc, dapen_fc_to_cfc_code_definition, hash_dpn_function};
        let (config, request, mut trace, mut calls, root) = recovery_commitment_fixture();
        let mut code: ContractCodeDefinition = bincode::deserialize(&trace.contract_codes[0].code).unwrap();
        let original_hashes: Vec<_> = code.functions.iter().map(|function| hash_dpn_function::<F>(&cfc_code_definition_to_dapen_fc(function).unwrap())).collect();
        for function in &mut code.functions {
            let mut method = cfc_code_definition_to_dapen_fc(function).unwrap();
            method.name = "renamed".into();
            *function = dapen_fc_to_cfc_code_definition(&method);
        }
        let renamed_hashes: Vec<_> = code.functions.iter().map(|function| hash_dpn_function::<F>(&cfc_code_definition_to_dapen_fc(function).unwrap())).collect();
        assert_eq!(original_hashes, renamed_hashes);
        trace.contract_codes[0].code = bincode::serialize(&code).unwrap();
        verify_guardian_session_commitment(&config, &request, &trace, &calls, root).unwrap();
        calls.contract_calls[0].method_name = "renamed".into();
        assert!(matches!(verify_guardian_session_commitment(&config, &request, &trace, &calls, root), Err(GuardianSignError::UnsupportedCall)));
        calls.contract_calls[0].method_name = "set_chain_root".into();
        assert!(matches!(verify_guardian_session_commitment(&config, &request, &trace, &calls, root), Err(GuardianSignError::UnsupportedCall)));
        calls.contract_calls[0].inputs.truncate(SET_CHAIN_ROOT.input_felt_count as usize);
        calls.contract_calls[0].contract_id = u64::from(crate::bridge::constants::DEPOSIT_TREE_CONTRACT_ID);
        assert!(matches!(verify_guardian_session_commitment(&config, &request, &trace, &calls, root), Err(GuardianSignError::UnsupportedCall)));
    }

    #[test]
    fn recovered_start_hash_matches_endcap_default_root_selector() {
        let mut leaf = psy_client_data::qstore::controllers::register_helpers::get_new_empty_user_leaf(F::from_canonical_u64(BRIDGE_USER_ID),Hash4::from_values(1,2,3,4));
        assert_ne!(leaf.qfhash::<PsyHasher>(),Hash4::ZERO);
        assert_eq!(guardian_proved_start_hash(&leaf),Hash4::ZERO);
        leaf.nonce = F::ONE;
        assert_eq!(guardian_proved_start_hash(&leaf),Hash4::ZERO);
        leaf.user_state_tree_root = Hash4::from_values(4,3,2,1);
        assert_eq!(guardian_proved_start_hash(&leaf),leaf.qfhash::<PsyHasher>());
    }

    #[test]
    fn proof_path_cannot_select_another_root_location_or_height() {
        let value = Hash4::from_values(1,2,3,4);
        let sibling = Hash4::from_values(5,6,7,8);
        let root = PsyHasher::q_two_to_one(value,sibling);
        let proof = MerkleProofCore { root,index:0,value,siblings:vec![sibling] };
        assert!(verify_path(&proof,root,0,value,1).is_ok());
        assert!(verify_path(&proof,Hash4::ZERO,0,value,1).is_err());
        assert!(verify_path(&proof,root,1,value,1).is_err());
        assert!(verify_path(&proof,root,0,value,2).is_err());
        let mut corrupt = proof; corrupt.siblings[0]=Hash4::ZERO;
        assert!(verify_path(&corrupt,root,0,value,1).is_err());
    }

    #[test]
    fn burn_key_namespaces_nonce_and_leaf_binds_destination() {
        let burn = WithdrawalBurnRecord { sender_user_id:7,token_contract_id:4,destination_chain_index:0,token:[0;8],amount:[0,0,0,0,0,0,0,1],recipient:[0,0,0,0,0,0,0,1],nonce:[1,2,3,4,5,6,7,8] };
        assert_ne!(withdrawal_key(&burn),PsyHasher::q_hash_many(&burn.nonce.map(F::from_canonical_u32)));
        let mut changed = burn.clone(); changed.destination_chain_index=1;
        assert_ne!(withdrawal_leaf(&burn),withdrawal_leaf(&changed));
        changed=burn.clone(); changed.amount=[0,0,0,0,0,0,0xffff_ffff,1];
        assert!(changed.amount_u64().is_err());
        changed.amount[7]=0; assert_eq!(changed.amount_u64().unwrap(),GOLDILOCKS_MODULUS-1);
    }

    #[test]
    fn malformed_proof_vector_length_rejects_without_trusting_allocation_size() {
        assert!(decode_endcap_proof(&u64::MAX.to_le_bytes()).is_err());
        assert!(decode_endcap_proof(&[0;16]).is_err());
    }

    #[test]
    fn historical_root_matches_saved_append_versions_after_later_checkpoints() {
        use psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree;
        let mut tree=SimpleMerkleTree::<PsyHasher,Hash4>::new(CHECKPOINT_TREE_HEIGHT);
        let mut roots=Vec::new();
        for checkpoint in 0..9 {
            roots.push(tree.set_leaf(checkpoint,Hash4::from_values(checkpoint+1,2,3,4)).new_root);
        }
        for checkpoint in 0..9 {
            let path=tree.get_leaf(checkpoint);
            assert!(path.verify::<PsyHasher>());
            assert_eq!(path.root,roots[8]);
            assert_eq!(historical_checkpoint_root(&path),roots[checkpoint as usize]);
            if checkpoint<8 { assert_ne!(historical_checkpoint_root(&path),path.root); }
        }
    }

    fn deposit_tree_state(chain_index: u8, count: u32, previous_count: u32, block_number: u64, block_hash: [u8; 32]) -> DepositTreeState {
        DepositTreeState {
            count, frontier: [Hash4::ZERO; 32], root: Hash4::from_values(count as u64, 0, 0, chain_index as u64),
            anchor: DepositAnchor { chain_index, block_number, block_hash: Hex(block_hash), old_count: previous_count, new_count: count },
            event_block: block_number, previous_count, previous_root: Hash4::ZERO,
            occupied_partial_page_hashes: vec![Hash4::ZERO; (count % 32) as usize],
        }
    }


    #[test]
    fn reserved_deposit_tree_state_prefers_request_reservation_over_included_anchor() {
        let mut history = GuardianHistory::new();
        history.deposit_tree_states.insert(0, deposit_tree_state(0, 2, 0, 90, [2; 32]));
        history.deposit_tree_states.insert(1, deposit_tree_state(1, 3, 1, 80, [3; 32]));
        let included = reserved_deposit_tree_state(&[], &history, 0).unwrap();
        assert_eq!(included.anchor.block_number, 90);
        let reservation = deposit_tree_state(0, 5, 2, 100, [1; 32]);
        let preferred = reserved_deposit_tree_state(std::slice::from_ref(&reservation), &history, 0).unwrap();
        assert_eq!(preferred.anchor.block_number, 100);
        assert_eq!(reserved_deposit_tree_state(std::slice::from_ref(&reservation), &history, 1).unwrap().anchor.block_number, 80);
        assert!(reserved_deposit_tree_state(&[], &history, 7).is_none());
    }


    #[test]
    fn compiled_contract_binding_rejects_unknown_method_and_contract() {
        assert_eq!(contract_height(crate::bridge::constants::DEPOSIT_TREE_CONTRACT_ID).unwrap(), u16::from(psy_config::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT));
        assert_eq!(contract_height(crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID).unwrap(), u16::from(psy_config::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT));
        assert_eq!(contract_height(psy_config::TOKEN_CONTRACT_ID).unwrap(), u16::from(psy_config::TOKEN_CONTRACT_STATE_TREE_HEIGHT));
        assert_eq!(contract_height(4).unwrap(), u16::from(psy_config::USDT_TOKEN_CONTRACT_STATE_TREE_HEIGHT));
        assert!(contract_height(9).is_err());
        assert_eq!(contract_method(crate::bridge::constants::DEPOSIT_TREE_CONTRACT_ID, "set_chain_root").unwrap().method_id, SET_CHAIN_ROOT.method_id);
        assert_eq!(contract_method(crate::bridge::constants::WITHDRAWAL_TREE_CONTRACT_ID, "append_withdrawal").unwrap().input_felt_count, APPEND_WITHDRAWAL.input_felt_count);
        assert_eq!(contract_method(u32::from(MULTISIG_POLICY_CONTRACT_ID), "set_policy").unwrap().input_felt_count, SET_POLICY.input_felt_count);
        assert!(contract_method(crate::bridge::constants::DEPOSIT_TREE_CONTRACT_ID, "append_withdrawal").is_err());
        assert_eq!(WITHDRAWAL_MAP_BASE, 8_589_934_680);
        assert_eq!(WITHDRAWAL_MAP_CAPACITY, 1_048_576);
    }

    #[test]
    fn fee_burn_dispatch_uses_canonical_token_method() {
        let burn = contract_method(psy_config::TOKEN_CONTRACT_ID, "burn").unwrap();
        assert_eq!(psy_config::TOKEN_CONTRACT_ID, 0);
        assert_eq!(burn.name, "burn");
        assert_eq!(burn.method_id, TOKEN_BURN_METHOD_ID);
        assert_eq!(burn.input_felt_count, 1);
        assert!(contract_method(4, "burn").is_err());
        assert!(contract_method(0, "transfer").is_err());
    }
}
