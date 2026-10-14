use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, ensure};
use plonky2::{field::{goldilocks_field::GoldilocksField as F, types::{Field, PrimeField64}}, hash::poseidon::PoseidonHash};
use psy_client_common::{args::{ContractCallArgs, ContractCallData}, data::{base_types::hash256::Hash256, qhashout::QHashOut}};
use psy_client_data::{config::store_config::PsyHasher, qdata::{checkpoint::{PsyCheckpointLeaf, PsyCheckpointGlobalStateRoots}, contract::PsyContractLeaf}, traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync}};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, TOKEN_BURN_METHOD_ID};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::{hasher::{FieldQHasher, MerkleZeroHasher}, qhashable::QFieldHashable}};
use psy_provider::{provider::RpcProvider, request::QIMTMembershipProofRPCRequest};
use psy_prover::{session::session::WalletSession, trace::{TxTrace, TraceStep}};
use psy_vm::ups::multisig::{MultisigPolicy, MultisigSignatureWitness, StoredMultisigPolicy};

use guardian_common::endcap::approved_endcap_max_proof_bytes;
use guardian_common::protocol::*;

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

pub struct GuardianVerificationContext<'a> {
    pub wallet: &'a WalletSession,
    pub provider: &'a RpcProvider,
    pub verified_checkpoint_id: u64,
    pub verified_checkpoint_tree_root: Hash4,
    pub l1_endpoints: &'a [ChainEndpoint],
    pub history: &'a GuardianHistory,
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

#[derive(Default)]
pub struct GuardianHistory {
    approved_artifacts: std::sync::Mutex<BTreeMap<([u8;32],[u8;32]),Option<ApprovedTokenMap>>>,
    pub(crate) deposit_prefixes: tokio::sync::Mutex<BTreeMap<([u8;32],String),super::verify_l1::VerifiedDepositPrefix>>,
    nonce: u64,
    ending_leaf: Option<Hash4>,
    chains: BTreeMap<u8,(u32,[Hash4;32],Hash4)>,
    deposits: BTreeMap<u8,(u32,Hash4)>,
    identities: BTreeSet<(u32,u32,[u32;8])>,
    nonces: BTreeSet<(u8,[u32;8])>,
}
impl GuardianHistory {
    pub async fn validate_authorization_artifacts(&self, authorization: &GuardianAuthorization, wallet: &WalletSession) -> Result<()> {
        for approved in &authorization.approved_contracts { self.approved_artifact(approved, wallet).await?; }
        Ok(())
    }

    pub(crate) async fn seed_deposit_prefix(&self, chain: &ChainAuthorization, endpoint: &ChainEndpoint, prefix: super::verify_l1::VerifiedDepositPrefix) -> anyhow::Result<()> {
        let approval = sha256(&serde_json::to_vec(chain).map_err(|_| GuardianSignError::AuthorizationMismatch)?);
        let mut prefixes = self.deposit_prefixes.lock().await;
        prefixes.insert((approval.0, endpoint.rpc_url.clone()), prefix);
        Ok(())
    }

    pub(crate) async fn deposit_prefix(&self, chain: &ChainAuthorization, endpoint: &ChainEndpoint) -> anyhow::Result<Option<super::verify_l1::VerifiedDepositPrefix>> {
        let approval = sha256(&serde_json::to_vec(chain).map_err(|_| GuardianSignError::AuthorizationMismatch)?);
        Ok(self.deposit_prefixes.lock().await.get(&(approval.0, endpoint.rpc_url.clone())).cloned())
    }

    async fn approved_artifact(&self, approved: &ApprovedContract, wallet: &WalletSession) -> Result<Option<ApprovedTokenMap>> {
        if sha256(approved.compiler_artifact_json.as_str().as_bytes())!=approved.compiler_artifact_sha256 { return Err(GuardianSignError::AuthorizationMismatch); }
        let leaf=approved.contract_leaf_json.decode()?;
        let key=(approved.compiler_artifact_sha256.0,sha256(&serde_json::to_vec(&(approved.contract_id,leaf)).map_err(|_|GuardianSignError::AuthorizationMismatch)?).0);
        {
            let cache=self.approved_artifacts.lock().map_err(|_|GuardianSignError::EvidenceUnavailable)?;
            if let Some(map)=cache.get(&key) { return Ok(map.clone()); }
        }
        let map=validate_approved_contract(approved, wallet).await?;
        self.approved_artifacts.lock().map_err(|_|GuardianSignError::EvidenceUnavailable)?.insert(key,map.clone());
        Ok(map)
    }
    pub fn new() -> Self { Self::default() }
    pub fn nonce(&self) -> u64 { self.nonce }
    pub fn contains_burn(&self, sender: u32, contract: u32, nonce: [u32;8]) -> bool { self.identities.contains(&(sender,contract,nonce)) }
    pub fn apply(&mut self, session: &GuardianSession) -> Result<()> {
        if self.nonce.checked_add(1) != Some(session.nonce) || self.ending_leaf.is_some_and(|leaf|leaf!=session.starting_leaf_hash) { return Err(GuardianSignError::HistoryUnavailable); }
        let request = session.record.request_json.decode()?;
        let call_data: ContractCallData = serde_json::from_value(request.trace_json.decode()?.call_data).map_err(|_|GuardianSignError::MalformedRequest)?;
        let mut deposits = Vec::with_capacity(request.deposit_anchors.len());
        for (anchor,call) in request.deposit_anchors.iter().zip(&call_data.contract_calls) {
            if call.contract_id!=2 || call.method_name!="set_chain_root" || call.inputs.len()!=10 || call.inputs[0]!=u64::from(anchor.chain_index) || call.inputs[1]!=u64::from(anchor.new_count) || self.deposits.get(&anchor.chain_index).map_or(0,|state|state.0)!=anchor.old_count { return Err(GuardianSignError::StateMismatch); }
            let mut limbs=[F::ZERO;4];
            for (limb,pair) in limbs.iter_mut().zip(call.inputs[2..].chunks_exact(2)) {
                if pair[0]>u32::MAX as u64 || pair[1]>u32::MAX as u64 { return Err(GuardianSignError::EvidenceMismatch); }
                let value=pair[0] | (pair[1]<<32);
                if value>=GOLDILOCKS_MODULUS { return Err(GuardianSignError::EvidenceMismatch); }
                *limb=F::from_canonical_u64(value);
            }
            deposits.push((anchor.chain_index,(anchor.new_count,Hash4::from_felt_slice(&limbs))));
        }
        if request.deposit_anchors.len()>call_data.contract_calls.len() { return Err(GuardianSignError::StateMismatch); }
        let mut staged = BTreeMap::new();
        let mut identities = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        for append in &session.withdrawal_appends {
            let burn = &append.burn;
            let identity = (burn.sender_user_id,burn.token_contract_id,burn.nonce);
            let nonce = (burn.destination_chain_index,burn.nonce);
            if self.identities.contains(&identity) || self.nonces.contains(&nonce) || !identities.insert(identity) || !nonces.insert(nonce) { return Err(GuardianSignError::WithdrawalNonceConflict); }
            let state = staged.entry(append.chain_index).or_insert_with(||self.chains.get(&append.chain_index).copied().unwrap_or((0,[Hash4::ZERO;32],<PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32))));
            if append.chain_index!=burn.destination_chain_index || append.append_index!=state.0 { return Err(GuardianSignError::StateMismatch); }
            let next = state.0.checked_add(1).ok_or(GuardianSignError::StateMismatch)?;
            state.2 = super::verify_l1::append_leaf(&mut state.1,state.0,withdrawal_leaf(burn));
            state.0 = next;
        }
        self.chains.extend(staged); self.identities.extend(identities); self.nonces.extend(nonces);
        self.deposits.extend(deposits);
        self.nonce = session.nonce; self.ending_leaf = Some(session.ending_leaf_hash);
        Ok(())
    }
}

pub fn verify_path(path: &MerkleProofCore<Hash4>, root: Hash4, index: u64, value: Hash4, height: usize) -> Result<()> {
    if height > 63 || index >= (1u64 << height) || path.siblings.len() != height || path.index != index || path.root != root || path.value != value || !path.verify::<PsyHasher>() {
        return Err(GuardianSignError::EvidenceMismatch);
    }
    Ok(())
}

pub fn verify_checkpoint(checkpoint_id: u64, leaf: &PsyCheckpointLeaf<F>, roots: &PsyCheckpointGlobalStateRoots<F>, path: &MerkleProofCore<Hash4>, verified_root: Hash4) -> Result<()> {
    if roots.qfhash::<PsyHasher>() != leaf.global_chain_root { return Err(GuardianSignError::EvidenceMismatch); }
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

fn approved_contract(authorization: &GuardianAuthorization, id: u32) -> Result<&ApprovedContract> {
    let mut matches = authorization.approved_contracts.iter().filter(|contract| contract.contract_id == id);
    let approved = matches.next().ok_or(GuardianSignError::AuthorizationMismatch)?;
    if matches.next().is_some() { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok(approved)
}

#[derive(Clone,Debug)]
pub struct ApprovedTokenMap {
    pub subslot_base: u64,
    pub capacity: u64,
}

pub async fn validate_approved_contract(approved: &ApprovedContract, wallet: &WalletSession) -> Result<Option<ApprovedTokenMap>> {
    let artifact=approved.compiler_artifact()?;
    let leaf=approved.contract_leaf_json.decode()?;
    if artifact.state_tree_height>32 || artifact.state_tree_height<4 || u64::from(artifact.state_tree_height)!=leaf.state_tree_height.to_canonical_u64() || artifact.abi.pointer("/contract/state_tree_height").and_then(serde_json::Value::as_u64)!=Some(u64::from(artifact.state_tree_height)) || artifact.abi["schema_version"]!="2.0.0" || artifact.circuit_definitions.is_empty() { return Err(GuardianSignError::AuthorizationMismatch); }
    let mut ids=BTreeSet::new(); let mut names=BTreeSet::new();
    let methods=artifact.abi.pointer("/contract/methods").and_then(serde_json::Value::as_array).ok_or(GuardianSignError::AuthorizationMismatch)?;
    if methods.len()!=artifact.circuit_definitions.len() { return Err(GuardianSignError::AuthorizationMismatch); }
    for definition in &artifact.circuit_definitions {
        if !ids.insert(definition.method_id) || !names.insert(&definition.name) { return Err(GuardianSignError::AuthorizationMismatch); }
        let mut matches=methods.iter().filter(|method|method["method_id"].as_u64()==Some(u64::from(definition.method_id)));
        let method=matches.next().ok_or(GuardianSignError::AuthorizationMismatch)?;
        let mutability=if definition.is_view_function() {"view"} else {"external"};
        if matches.next().is_some() || method["name"].as_str()!=Some(definition.name.as_str()) || method["input_felt_count"].as_u64()!=Some(definition.circuit_inputs.len() as u64) || method["output_felt_count"].as_u64()!=Some(definition.circuit_outputs.len() as u64) || method["state_mutability"].as_str()!=Some(mutability) { return Err(GuardianSignError::AuthorizationMismatch); }
    }
    let deployment=trusted_proxy_contract_root(wallet,u64::from(approved.contract_id),leaf.deployer.to_canonical_u64(),artifact.state_tree_height,&artifact.circuit_definitions).await?;
    if deployment.code_root!=leaf.code_root || deployment.function_tree_root!=leaf.function_tree_root { return Err(GuardianSignError::AuthorizationMismatch); }
    if approved.contract_id==6 && artifact.state_tree_height!=4 { return Err(GuardianSignError::PolicyMismatch); }
    if !matches!(approved.contract_id,0|4) { return Ok(None); }
    let state=artifact.abi.pointer("/contract/state").and_then(serde_json::Value::as_array).ok_or(GuardianSignError::AuthorizationMismatch)?;
    let mut fields=state.iter().filter(|field|field["name"]=="state_map");
    let field=fields.next().ok_or(GuardianSignError::AuthorizationMismatch)?;
    if fields.next().is_some() { return Err(GuardianSignError::AuthorizationMismatch); }
    let capacity=1048576u64;
    let expected_type=serde_json::json!({"kind":"map","map_kind":"map","key":{"kind":"primitive","name":"Hash"},"value":{"kind":"primitive","name":"Hash"},"capacity":capacity,"value_felt_size":4,"alignment_felts":4});
    if field["type"]!=expected_type { return Err(GuardianSignError::AuthorizationMismatch); }
    let base=field["offset"].as_u64().ok_or(GuardianSignError::AuthorizationMismatch)?;
    if base%4!=0 || field["felt_size"].as_u64()!=capacity.checked_mul(4) || base.checked_div(4).and_then(|base|base.checked_add(capacity)).is_none_or(|end|end>=(1u64<<artifact.state_tree_height)) { return Err(GuardianSignError::AuthorizationMismatch); }
    let withdraw=artifact.circuit_definitions.iter().find(|definition|definition.name=="withdraw").ok_or(GuardianSignError::AuthorizationMismatch)?;
    verify_withdraw_map_constants(withdraw,base,capacity)?;
    Ok(Some(ApprovedTokenMap {subslot_base:base,capacity}))
}
async fn trusted_proxy_contract_root(wallet: &WalletSession, contract_id: u64, deployer: u64, state_tree_height: u16, definitions: &[psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition]) -> Result<PsyContractLeaf<F>> {
    use psy_client_data::qdata::contract::ContractCodeDefinition;
    use psy_vm::dpn::contract::{dapen_fc_to_cfc_code_definition, hash_dpn_function};
    use psy_vm::ups::circuit_manager::UPSCircuitManager;
    let functions=definitions.iter().map(dapen_fc_to_cfc_code_definition).collect::<Vec<_>>();
    let code=ContractCodeDefinition { state_tree_height, functions };
    let manager=wallet.wallet.random_circuit_manager();
    let mut leaves=Vec::with_capacity(definitions.len()*2);
    let mut hashes=Vec::with_capacity(definitions.len());
    for (position, definition) in definitions.iter().enumerate() {
        let (fn_id, resolved)=manager.resolve_contract_function_by_method_name(contract_id, &code, definition.name.clone()).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
        if fn_id!=position as u64 || resolved!=*definition { return Err(GuardianSignError::AuthorizationMismatch); }
        let (fingerprint, _)=manager.get_contract_method_common_data(contract_id, fn_id as u32).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
        leaves.push(fingerprint);
        let inputs_outputs=((definition.circuit_outputs.len() as u64)<<32) | (definition.circuit_inputs.len() as u64);
        leaves.push(Hash4::from_values(u64::from(definition.method_id), inputs_outputs, 0, 0));
        hashes.push(hash_dpn_function::<F>(definition));
    }
    let code_root=psy_client_data::qblock::cmds::deploy_contract::get_code_root_by_code_hashes::<F, PsyHasher>(&hashes, psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT-1);
    let mut tree=psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree::<PsyHasher, Hash4>::new(psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT);
    for (index, leaf) in leaves.iter().enumerate() { tree.set_leaf(index as u64, *leaf); }
    Ok(PsyContractLeaf { deployer: F::from_canonical_u64(deployer), function_tree_root: tree.get_root(), code_root, state_tree_height: F::from_canonical_u16(state_tree_height), state_layout_root: Hash4::ZERO, state_layout_field_count: F::ZERO, state_layout_slot_count: F::ZERO })
}

fn verify_withdraw_map_constants(definition: &psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition, base: u64, capacity: u64) -> Result<()> {
    use psy_vm::dpn::ops::{op_types::{DPNOpType,DPNBuiltInDataType},state_cmd::data::DPNStateCmd};
    let mut constants=BTreeMap::new(); let mut wires=BTreeSet::new();
    for (position,definition) in definition.definitions.iter().enumerate() {
        if definition.index>u32::MAX as usize || !wires.insert(definition.get_combined_data_type_index()) { return Err(GuardianSignError::AuthorizationMismatch); }
        let value=match definition.op_type {
            DPNOpType::Constant | DPNOpType::ConstantU32 => {
                if definition.inputs.len()!=1 || definition.inputs[0]>=GOLDILOCKS_MODULUS || (definition.op_type==DPNOpType::ConstantU32 && definition.inputs[0]>u32::MAX as u64) { return Err(GuardianSignError::AuthorizationMismatch); }
                let expected=if definition.op_type==DPNOpType::Constant {DPNBuiltInDataType::Target} else {DPNBuiltInDataType::U32Target};
                if definition.data_type!=expected { return Err(GuardianSignError::AuthorizationMismatch); }
                definition.inputs[0]
            }
            DPNOpType::ConstantTrue | DPNOpType::ConstantFalse => {
                if definition.data_type!=DPNBuiltInDataType::Bool || definition.inputs.len()>1 { return Err(GuardianSignError::AuthorizationMismatch); }
                u64::from(definition.op_type==DPNOpType::ConstantTrue)
            }
            _ => continue,
        };
        constants.insert(definition.get_combined_data_type_index(),(position,value));
    }
    if definition.state_command_resolution_indices.len()!=definition.state_commands.len() { return Err(GuardianSignError::AuthorizationMismatch); }
    let mut writes=0; let mut reads=0;
    for (command,boundary) in definition.state_commands.iter().zip(&definition.state_command_resolution_indices) {
        if *boundary>definition.definitions.len() { return Err(GuardianSignError::AuthorizationMismatch); }
        let operands=match command {
            DPNStateCmd::SetIMTContractStateValue(command) => {writes+=1; Some((command.base_offset,command.capacity))},
            DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(command) => {reads+=1; Some((command.base_offset,command.capacity))},
            DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(command) => {reads+=1; Some((command.base_offset,command.capacity))},
            _ => None,
        };
        if let Some((base_wire,capacity_wire))=operands {
            for (wire,expected) in [(base_wire,base),(capacity_wire,capacity)] {
                if !constants.get(&wire).is_some_and(|(position,value)|position<boundary && *value==expected) { return Err(GuardianSignError::AuthorizationMismatch); }
            }
        }
    }
    if writes!=1 || reads==0 { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok(())
}

async fn verify_approved_contract(history: &GuardianHistory, approved: &ApprovedContract, leaf: &PsyContractLeaf<F>, wallet: &WalletSession) -> Result<Option<ApprovedTokenMap>> {
    if approved.contract_leaf_json.decode()?!=*leaf { return Err(GuardianSignError::AuthorizationMismatch); }
    history.approved_artifact(approved, wallet).await
}

pub async fn verify_withdrawal_burn(history: &GuardianHistory, authorization: &GuardianAuthorization, record: &WithdrawalBurnRecord, proof: &psy_provider::lps::WithdrawalBurnProof, verified_checkpoint_root: Hash4, wallet: &WalletSession) -> Result<()> {
    record.amount_u64()?;
    record.recipient_address()?;
    let token = record.token_address()?;
    if authorization.chain(record.destination_chain_index)?.token_mappings.iter().filter(|mapping| mapping.token == token && mapping.l2_contract_id == record.token_contract_id).count() != 1 { return Err(GuardianSignError::EvidenceMismatch); }
    verify_checkpoint(proof.checkpoint_id, &proof.checkpoint_leaf, &proof.global_roots, &proof.checkpoint_path, verified_checkpoint_root)?;
    let approved = approved_contract(authorization, record.token_contract_id)?;
    let map = verify_approved_contract(history,approved,&proof.contract_leaf,wallet).await?.ok_or(GuardianSignError::EvidenceMismatch)?;
    let (base,capacity)=(map.subslot_base/4,map.capacity);
    verify_path(&proof.global_contract_path, proof.global_roots.contract_tree_root, u64::from(record.token_contract_id), proof.contract_leaf.qfhash::<PsyHasher>(), GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
    if proof.user_leaf.user_id.to_canonical_u64() != u64::from(record.sender_user_id) { return Err(GuardianSignError::EvidenceMismatch); }
    verify_path(&proof.user_path, proof.global_roots.user_tree_root, u64::from(record.sender_user_id), proof.user_leaf.qfhash::<PsyHasher>(), GLOBAL_USER_TREE_HEIGHT as usize)?;
    verify_path(&proof.contract_path, proof.user_leaf.user_state_tree_root, u64::from(record.token_contract_id), proof.record_membership.merkle_proof.root, GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
    let membership = &proof.record_membership;
    let request = QIMTMembershipProofRPCRequest { checkpoint_id: proof.checkpoint_id, user_id: u64::from(record.sender_user_id), contract_id: record.token_contract_id, key: withdrawal_key(record), state_slot_base: base, capacity };
    request.validate_indices(membership.merkle_proof.index, membership.leaf.next_index.to_canonical_u64()).map_err(|_| GuardianSignError::EvidenceMismatch)?;
    if membership.leaf.key != request.key || membership.leaf.value != withdrawal_leaf(record) { return Err(GuardianSignError::EvidenceMismatch); }
    verify_path(&membership.merkle_proof, proof.contract_path.value, membership.merkle_proof.index, membership.leaf.qfhash::<PsyHasher>(), proof.contract_leaf.state_tree_height.to_canonical_u64() as usize)
}

pub async fn get_withdrawal_burn_proof(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization, checkpoint_id: u64, record: &WithdrawalBurnRecord) -> Result<psy_provider::lps::WithdrawalBurnProof> {
    if checkpoint_id > context.verified_checkpoint_id { return Err(GuardianSignError::EvidenceUnavailable); }
    let approved = approved_contract(authorization, record.token_contract_id)?;
    let map = verify_approved_contract(context.history,approved,&approved.contract_leaf_json.decode()?,context.wallet).await?.ok_or(GuardianSignError::EvidenceMismatch)?;
    let (base,capacity)=(map.subslot_base/4,map.capacity);
    let mut proof = context.provider.get_withdrawal_burn_proof(QIMTMembershipProofRPCRequest { checkpoint_id, user_id: u64::from(record.sender_user_id), contract_id: record.token_contract_id, key: withdrawal_key(record), state_slot_base: base, capacity }).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    proof.checkpoint_path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id, checkpoint_id).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    verify_withdrawal_burn(context.history,authorization,record,&proof,context.verified_checkpoint_tree_root,context.wallet).await?;
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
    let contract = context.provider.get_user_contract_tree_merkle_proof(checkpoint,trace.meta.user_id,contract_id).await.map_err(|error| { tracing::warn!(checkpoint, contract_id, error = %error, "contract inclusion proof unavailable"); GuardianSignError::EvidenceUnavailable })?;
    verify_path(&contract,user.user_state_tree_root,u64::from(contract_id),contract.value,GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
    let root = if contract.value == Hash4::ZERO { <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(height as usize) } else { contract.value };
    let end = start.checked_add(count as u64).ok_or(GuardianSignError::EvidenceMismatch)?;
    let mut values = Vec::with_capacity(count);
    let mut slot = start / 4;
    while slot * 4 < end {
        let proof = context.provider.get_user_contract_state_tree_merkle_proof(checkpoint,trace.meta.user_id,contract_id,height,slot).await.map_err(|error| { tracing::warn!(checkpoint, contract_id, slot, height, error = %error, "contract state proof unavailable"); GuardianSignError::EvidenceUnavailable })?;
        verify_path(&proof,root,slot,proof.value,height as usize)?;
        for (index,field) in proof.value.0.elements.iter().enumerate() { let subslot = slot * 4 + index as u64; if subslot >= start && subslot < end { values.push(field.to_canonical_u64()); } }
        slot += 1;
    }
    Ok(values)
}

async fn verify_chain_state(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization, trace: &TxTrace, contract: u32, chain: u8, count: u32, root: Hash4) -> Result<()> {
    let leaf = approved_contract(authorization,contract)?.contract_leaf_json.decode()?;
    let height = u8::try_from(leaf.state_tree_height.to_canonical_u64()).map_err(|_|GuardianSignError::EvidenceMismatch)?;
    let stored_count = read_subslots(context,trace,contract,65544 + u64::from(chain),1,height).await?;
    let stored_root = read_subslots(context,trace,contract,65804 + u64::from(chain)*8,8,height).await?;
    if stored_count != [u64::from(count)] || (stored_root != hash_words(root) && !(count == 0 && stored_root == [0;8])) { return Err(GuardianSignError::StateMismatch); }
    Ok(())
}

pub(super) fn trace_policy(trace: &TxTrace, authorization: &GuardianAuthorization) -> Result<MultisigSignatureWitness> {
    let mut signatures = trace.steps.iter().filter_map(|step| if let TraceStep::ZkSign(sign) = step { Some(sign) } else { None });
    let sign = signatures.next().ok_or(GuardianSignError::PolicyMismatch)?;
    if signatures.next().is_some() || !matches!(sign.sign_circuit_source,psy_prover::trace::TraceSignCircuitSource::Multisig) || sign.fingerprint != authorization.multisig_fingerprint { return Err(GuardianSignError::PolicyMismatch); }
    let witness: MultisigSignatureWitness = parse_canonical_json(&sign.sign_witness)?;
    let account = authorization.account_json.decode()?;
    if witness.account.contract_id != account.contract_id || witness.account.initial_policy != account.initial_policy || witness.nonce != trace.finalization.nonce || witness.start_session_user_leaf.public_key != authorization.account_public_key || witness.sign_context.user_leaf.public_key != authorization.account_public_key { return Err(GuardianSignError::PolicyMismatch); }
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
    Ok(ContractCallArgs { contract_id:6,method_name:"set_policy".into(),inputs })
}

async fn verify_guardian_session_evidence(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization, request: &GuardianSignRequest) -> Result<(VerifiedGuardianSession, ContractCallData, Hash4),GuardianAccountError> {
    authorization.validate(psy_config::GUTA_FEE,psy_config::DA_FEE,approved_endcap_max_proof_bytes()?)?;
    request.validate_authorization(authorization)?;
    let supplied = request.decode_trace()?;
    let checkpoint = supplied.anchor.start_checkpoint_id;
    if checkpoint > context.verified_checkpoint_id { return Err(GuardianSignError::EvidenceUnavailable.into()); }
    let checkpoint_path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id,checkpoint).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
    verify_checkpoint(checkpoint,&supplied.anchor.checkpoint_leaf,&supplied.anchor.global_state_roots,&checkpoint_path,context.verified_checkpoint_tree_root)?;
    let witness = trace_policy(&supplied,authorization)?;
    let (current_policy,ending_policy) = witness.policies().map_err(|_|GuardianSignError::PolicyMismatch)?;
    let mut calls = Vec::new();
    let mut appends = Vec::new();
    let mut identities = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut counts = BTreeMap::new();
    let start_hash = supplied.finalization.submit_end_cap_input.core.state_transition.start_user_leaf_hash;
    if context.history.nonce.checked_add(1)!=Some(request.session_nonce) || context.history.ending_leaf.is_some_and(|leaf|leaf!=start_hash) { return Err(GuardianSignError::HistoryUnavailable.into()); }
    for chain in &authorization.chains {
        let (count,_,root) = context.history.chains.get(&chain.chain_index).copied().unwrap_or((0,[Hash4::ZERO;32],<PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32)));
        verify_chain_state(context,authorization,&supplied,3,chain.chain_index,count,root).await?;
        let (count,root) = context.history.deposits.get(&chain.chain_index).copied().unwrap_or((0,<PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32)));
        verify_chain_state(context,authorization,&supplied,2,chain.chain_index,count,root).await?;
    }
    if request.operation == GuardianOperation::Bridge {
        if current_policy != ending_policy { return Err(GuardianSignError::PolicyMismatch.into()); }
        for anchor in &request.deposit_anchors {
            let endpoint = context.l1_endpoints.iter().find(|endpoint|endpoint.chain_index == anchor.chain_index).ok_or(GuardianSignError::EvidenceUnavailable)?;
            let (old_root,new_root) = super::verify_l1::verify_deposit_anchor(context.history,endpoint,authorization.chain(anchor.chain_index)?,anchor).await?;
            verify_chain_state(context,authorization,&supplied,2,anchor.chain_index,anchor.old_count,old_root).await?;
            let mut inputs = vec![u64::from(anchor.chain_index),u64::from(anchor.new_count)]; inputs.extend(hash_words(new_root));
            calls.push(ContractCallArgs { contract_id:2,method_name:"set_chain_root".into(),inputs });
        }
        let mut withdrawals = Vec::with_capacity(request.withdrawal_records.len());
        for burn in &request.withdrawal_records {
            if context.history.identities.contains(&(burn.sender_user_id,burn.token_contract_id,burn.nonce)) || context.history.nonces.contains(&(burn.destination_chain_index,burn.nonce)) || !identities.insert((burn.sender_user_id,burn.token_contract_id,burn.nonce)) || !nonces.insert((burn.destination_chain_index,burn.nonce)) { return Err(GuardianSignError::WithdrawalNonceConflict.into()); }
            get_withdrawal_burn_proof(context,authorization,checkpoint,burn).await?;
            let count = counts.entry(burn.destination_chain_index).or_insert_with(||context.history.chains.get(&burn.destination_chain_index).map_or(0,|state|state.0));
            appends.push(WithdrawalAppendRecord { chain_index:burn.destination_chain_index,append_index:*count,burn:burn.clone() });
            *count = count.checked_add(1).ok_or(GuardianSignError::StateMismatch)?;
            withdrawals.push(crate::bridge::propose_withdrawals::PendingWithdrawal { event_id:0,checkpoint_id:checkpoint,user_id:u64::from(burn.sender_user_id),sender_user_id:u64::from(burn.sender_user_id),contract_id:u64::from(burn.token_contract_id),destination_chain_index:u64::from(burn.destination_chain_index),token_address:burn.token,amount:burn.amount,recipient:burn.recipient,nonce:burn.nonce,leaf_hash:withdrawal_leaf(burn).to_string() });
        }
        calls.extend(crate::bridge::daemon::build_withdrawal_batch_calls(&withdrawals));
    } else { calls.push(policy_call(request.operation,&witness)?); }
    let expected = ContractCallData::new(calls);
    if serde_json::to_value(&expected).map_err(|_|GuardianSignError::MalformedRequest)? != request.trace_json.decode()?.call_data { return Err(GuardianSignError::UnsupportedCall.into()); }
    verify_trace_contracts(context.history,authorization,&supplied,context.wallet).await?;
    let fees: Vec<_> = supplied.steps.iter().filter_map(|step|if let TraceStep::BurnFee(step)=step {Some(step)} else {None}).collect();
    if fees.len()!=1 || fees[0].contract_id!=0 || fees[0].method_id!=TOKEN_BURN_METHOD_ID || fees[0].method_name!="burn" { return Err(GuardianSignError::UnsupportedCall.into()); }
    let message = Hash256::from(supplied.finalization.sig_hash).0;
    let ending_leaf_hash = supplied.finalization.submit_end_cap_input.core.new_user_leaf.qfhash::<PsyHasher>();
    validate_future_endcap_proof_size(&JsonText::from_value(request)?,&supplied.finalization.submit_end_cap_input,authorization.max_endcap_proof_bytes)?;
    Ok((VerifiedGuardianSession { trace:supplied,current_policy,ending_policy,starting_leaf_hash:start_hash,ending_leaf_hash,message,withdrawal_appends:appends }, expected, historical_checkpoint_root(&checkpoint_path)))
}

pub async fn verify_guardian_session(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization, request: &GuardianSignRequest) -> Result<VerifiedGuardianSession,GuardianAccountError> {
    let (verified, expected, historical_root) = verify_guardian_session_evidence(context,authorization,request).await?;
    let checkpoint = verified.trace.anchor.start_checkpoint_id;
    let mut builder = context.wallet.begin_trace_build_at_checkpoint(authorization.account_public_key,authorization.user_id,checkpoint,request.session_nonce,historical_root).await.map_err(|_|GuardianSignError::StateMismatch)?;
    for call in &expected.contract_calls { builder.trace_call(call.clone()).await.map_err(|_|GuardianSignError::StateMismatch)?; }
    let fee = builder.required_fee().map_err(|_|GuardianSignError::StateMismatch)?;
    if fee >= GOLDILOCKS_MODULUS || fee > authorization.max_fee { return Err(GuardianSignError::UnsupportedCall.into()); }
    let replayed = builder.finalize_tx_trace(expected.software_defined_call.clone()).await.map_err(|_|GuardianSignError::StateMismatch)?;
    if !traces_equal(&verified.trace,&replayed)? { return Err(GuardianSignError::StateMismatch.into()); }
    Ok(VerifiedGuardianSession { trace:replayed,..verified })
}

async fn verify_trace_contracts(history: &GuardianHistory, authorization: &GuardianAuthorization, trace: &TxTrace, wallet: &WalletSession) -> Result<()> {
    let mut codes = BTreeSet::new();
    for code in &trace.contract_codes {
        if !codes.insert(code.contract_id) { return Err(GuardianSignError::EvidenceMismatch); }
        let id = u32::try_from(code.contract_id).map_err(|_|GuardianSignError::EvidenceMismatch)?;
        let leaf = approved_contract(authorization,id)?.contract_leaf_json.decode()?;
        let definition: psy_client_data::qdata::contract::ContractCodeDefinition = bincode::deserialize(&code.code).map_err(|_|GuardianSignError::EvidenceMismatch)?;
        if u64::from(definition.state_tree_height)!=leaf.state_tree_height.to_canonical_u64() { return Err(GuardianSignError::EvidenceMismatch); }
        let hashes = definition.functions.iter().map(|function|psy_vm::dpn::contract::cfc_code_definition_to_dapen_fc(function).map(|definition|psy_vm::dpn::contract::hash_dpn_function::<F>(&definition))).collect::<std::result::Result<Vec<_>,_>>().map_err(|_|GuardianSignError::EvidenceMismatch)?;
        let root = psy_client_data::qblock::cmds::deploy_contract::get_code_root_by_code_hashes::<F,PsyHasher>(&hashes,psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT-1);
        if root != leaf.code_root { return Err(GuardianSignError::EvidenceMismatch); }
    }
    for step in &trace.steps {
        let Some(step) = step.as_cfc() else { continue; };
        if !codes.contains(&step.contract_id) { return Err(GuardianSignError::EvidenceMismatch); }
        let id = u32::try_from(step.contract_id).map_err(|_|GuardianSignError::UnsupportedCall)?;
        let approved = approved_contract(authorization,id)?;
        let inclusion = &step.cfc_inclusion_proof;
        let contract = &inclusion.contract_inclusion_proof;
        verify_approved_contract(history,approved,&contract.contract_leaf,wallet).await?;
        verify_path(&contract.contract_tree_merkle_proof,trace.anchor.global_state_roots.contract_tree_root,step.contract_id,contract.contract_leaf.qfhash::<PsyHasher>(),GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
        let fingerprint_index=step.fn_id.checked_mul(2).ok_or(GuardianSignError::EvidenceMismatch)?;
        verify_path(&inclusion.contract_function_merkle_proof,contract.contract_leaf.function_tree_root,u64::from(fingerprint_index),step.cfc_fingerprint,psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT as usize)?;
        if inclusion.get_method_id()!=step.method_id { return Err(GuardianSignError::EvidenceMismatch); }
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



async fn verify_session_leaf(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization, record: &GuardianSessionRecord, ending_leaf: &psy_client_data::qdata::user::PsyUserLeaf<F>) -> Result<()> {
    let id = record.included_checkpoint_id;
    if id > context.verified_checkpoint_id { return Err(GuardianSignError::EvidenceUnavailable); }
    let leaf = context.provider.get_checkpoint_leaf_data(id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
    let roots = context.provider.get_checkpoint_global_state_roots(id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
    let path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id,id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
    verify_checkpoint(id,&leaf,&roots,&path,context.verified_checkpoint_tree_root)?;
    if leaf.qfhash::<PsyHasher>() != record.included_checkpoint_hash { return Err(GuardianSignError::StateMismatch); }
    if ending_leaf.public_key != authorization.account_public_key || ending_leaf.user_id.to_canonical_u64()!=authorization.user_id { return Err(GuardianSignError::AccountIdentityConflict); }
    let user = context.provider.get_user_tree_merkle_proof(id,authorization.user_id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
    verify_path(&user,roots.user_tree_root,authorization.user_id,ending_leaf.qfhash::<PsyHasher>(),GLOBAL_USER_TREE_HEIGHT as usize)
}

// Recovery authenticates the operation commitment, not arbitrary execution-witness JSON.
// It must not execute the calls again against the live IMT allocator.
fn verify_guardian_session_commitment(authorization: &GuardianAuthorization, request: &GuardianSignRequest, trace: &TxTrace, expected: &ContractCallData, historical_root: Hash4) -> Result<()> {
    use psy_client_data::{dpn::proving_session::DPNProvingSessionSimpleMethodCall, qdata::{ups_signature::PsyUserProvingSessionSignatureDataCompact, user_contract_state::SignContext}, qstore::controllers::register_helpers::get_new_empty_user_leaf};
    let start = &trace.ups_start_witness.ups_header.session_start_context;
    let leaf = &start.start_session_user_leaf;
    let core = &trace.finalization.submit_end_cap_input.core;
    let checkpoint = trace.anchor.start_checkpoint_id;
    let user_id = F::from_canonical_u64(authorization.user_id);
    let nonce = F::from_canonical_u64(request.session_nonce);
    if start.checkpoint_id.to_canonical_u64()!=checkpoint || start.checkpoint_tree_root!=historical_root || start.checkpoint_leaf_hash!=trace.anchor.checkpoint_leaf.qfhash::<PsyHasher>() || leaf.user_id!=user_id || leaf.public_key!=authorization.account_public_key {
        return Err(GuardianSignError::StateMismatch);
    }
    let path = &trace.ups_start_witness.user_tree_proof;
    verify_path(path,trace.anchor.global_state_roots.user_tree_root,authorization.user_id,path.value,GLOBAL_USER_TREE_HEIGHT as usize)?;
    if path.value==Hash4::ZERO {
        if *leaf!=get_new_empty_user_leaf(user_id,authorization.account_public_key) || request.session_nonce!=1 { return Err(GuardianSignError::StateMismatch); }
        let registration = trace.ups_start_witness.user_registration_tree_proof.as_ref().ok_or(GuardianSignError::EvidenceMismatch)?;
        verify_path(registration,trace.anchor.global_state_roots.user_registration_tree_root,psy_crypto::common::user_id::get_registration_id_from_user_id(authorization.user_id),authorization.account_public_key,GLOBAL_USER_TREE_HEIGHT as usize)?;
    } else if trace.ups_start_witness.user_registration_tree_proof.is_some() || path.value!=leaf.qfhash::<PsyHasher>() {
        return Err(GuardianSignError::StateMismatch);
    }
    if leaf.nonce.to_canonical_u64().checked_add(1)!=Some(request.session_nonce) || core.state_transition.start_user_leaf_hash!=path.value || core.state_transition.start_user_leaf_hash!=guardian_proved_start_hash(leaf) || core.state_transition.checkpoint_tree_root_hash!=historical_root || core.state_transition.user_id!=user_id {
        return Err(GuardianSignError::StateMismatch);
    }
    if core.new_user_leaf.user_id!=user_id || core.new_user_leaf.public_key!=authorization.account_public_key || core.new_user_leaf.nonce!=nonce || core.new_user_leaf.last_checkpoint_id.to_canonical_u64()!=checkpoint || core.checkpoint_id.to_canonical_u64()!=checkpoint || core.new_user_leaf.qfhash::<PsyHasher>()!=core.state_transition.end_user_leaf_hash {
        return Err(GuardianSignError::StateMismatch);
    }
    let witness = trace_policy(trace,authorization)?;
    let mut end = core.new_user_leaf;
    end.nonce = leaf.nonce;
    let sign_context = SignContext { checkpoint_tree_root:historical_root,user_leaf:end };
    if witness.start_session_user_leaf!=*leaf || witness.sign_context!=sign_context || witness.start_state.state.checkpoint_id!=start.checkpoint_id || witness.end_state.state.checkpoint_id!=start.checkpoint_id || witness.nonce!=nonce {
        return Err(GuardianSignError::PolicyMismatch);
    }
    // The verified EndCap commits these fee fields and enforces the fee schedule.
    let fee = core.stats.guta_fees_collected.to_canonical_u64().checked_add(core.stats.da_fees_collected.to_canonical_u64()).ok_or(GuardianSignError::UnsupportedCall)?;
    if fee>=GOLDILOCKS_MODULUS || fee>authorization.max_fee { return Err(GuardianSignError::UnsupportedCall); }
    let mut stack = Hash4::ZERO;
    for call in &expected.contract_calls {
        let id = u32::try_from(call.contract_id).map_err(|_|GuardianSignError::UnsupportedCall)?;
        let artifact = approved_contract(authorization,id)?.compiler_artifact()?;
        let mut methods = artifact.circuit_definitions.iter().filter(|method|method.name==call.method_name);
        let method = methods.next().ok_or(GuardianSignError::UnsupportedCall)?;
        if methods.next().is_some() || call.inputs.len()!=method.circuit_inputs.len() || call.inputs.iter().any(|input|*input>=GOLDILOCKS_MODULUS) { return Err(GuardianSignError::UnsupportedCall); }
        let call = DPNProvingSessionSimpleMethodCall::new(F::from_canonical_u32(id),F::from_canonical_u32(method.method_id),call.inputs.iter().copied().map(F::from_canonical_u64).collect());
        stack = PsyHasher::q_two_to_one(stack,call.qfhash::<PsyHasher>());
    }
    let fee_call = DPNProvingSessionSimpleMethodCall::new(F::ZERO,F::from_canonical_u32(TOKEN_BURN_METHOD_ID),vec![F::from_canonical_u64(fee)]);
    stack = PsyHasher::q_two_to_one(stack,fee_call.qfhash::<PsyHasher>());
    let count = u64::try_from(expected.contract_calls.len()).ok().and_then(|count|count.checked_add(1)).filter(|count|*count<GOLDILOCKS_MODULUS).ok_or(GuardianSignError::UnsupportedCall)?;
    let sig_data = PsyUserProvingSessionSignatureDataCompact { start_user_leaf_hash:leaf.qfhash::<PsyHasher>(),end_user_leaf_hash:core.state_transition.end_user_leaf_hash,checkpoint_leaf_hash:start.checkpoint_leaf_hash,tx_stack_hash:stack,tx_count:F::from_canonical_u64(count) };
    if core.stats.total_transactions!=sig_data.tx_count || witness.sig_data!=sig_data { return Err(GuardianSignError::StateMismatch); }
    let message = sig_data.get_sig_action_for_user::<PsyHasher>(authorization.network_magic,user_id,nonce,sign_context).get_qhash::<PsyHasher>();
    if message!=trace.finalization.sig_hash { return Err(GuardianSignError::StateMismatch); }
    Ok(())
}

fn guardian_proved_start_hash(leaf: &psy_client_data::qdata::user::PsyUserLeaf<F>) -> Hash4 {
    // Match the EndCap circuit's default-state-root selector, not a trace flag.
    if leaf.user_state_tree_root==psy_config::get_default_user_state_tree_root::<F>() { Hash4::ZERO } else { leaf.qfhash::<PsyHasher>() }
}

pub async fn verify_session(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization, record: GuardianSessionRecord) -> Result<GuardianSession,GuardianAccountError> {
    use plonky2::plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs, circuit_data::VerifierCircuitData};
    let request = record.validate(authorization)?;
    // Included records verify through evidence plus proof/signature/inclusion binding; the
    // execution replay cannot reproduce a trace after the session's own transition is included.
    let (verified, expected_calls, historical_root) = verify_guardian_session_evidence(context,authorization,&request).await?;
    verify_guardian_session_commitment(authorization,&request,&verified.trace,&expected_calls,historical_root)?;
    let signatures = record.signatures_json.decode()?;
    psy_prover::signature::users::multisig_user::validate_policy_signatures(&signatures,&verified.current_policy,verified.trace.finalization.sig_hash).map_err(|_|GuardianSignError::PolicyMismatch)?;
    let input = record.endcap_input_json.decode()?;
    if serde_json::to_value(&input).map_err(|_|GuardianSignError::MalformedRequest)? != serde_json::to_value(&verified.trace.finalization.submit_end_cap_input).map_err(|_|GuardianSignError::MalformedRequest)? || record.included_checkpoint_id < verified.trace.anchor.start_checkpoint_id { return Err(GuardianSignError::StateMismatch.into()); }
    let bytes = record.proof_bytes(authorization.max_endcap_proof_bytes)?;
    let common = psy_plonky2_basic_helpers::lookalike::standard::get_end_cap_type_e_common_data::<PoseidonGoldilocksConfig,2>();
    let proof: ProofWithPublicInputs<F,PoseidonGoldilocksConfig,2> = decode_endcap_proof(&bytes,authorization.max_endcap_proof_bytes)?;
    if bincode::serialize(&proof).map_err(|_|GuardianSignError::EvidenceMismatch)? != bytes { return Err(GuardianSignError::EvidenceMismatch.into()); }
    let expected = input.core.get_proof_public_inputs_hash::<PsyHasher>();
    if proof.public_inputs.as_slice() != expected.0.elements { return Err(GuardianSignError::EvidenceMismatch.into()); }
    let mut verifier_only=None;
    for manager in context.wallet.wallet.circuit_managers() {
        let verifier=manager.ups_end_cap_circuit_verifier_config().await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
        let fingerprint=QHashOut(psy_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic::<2, F, PoseidonGoldilocksConfig>(&verifier));
        if fingerprint!=authorization.endcap_verifier_fingerprint { return Err(GuardianSignError::AuthorizationMismatch.into()); }
        verifier_only=Some(verifier);
    }
    let verifier_only=verifier_only.ok_or(GuardianSignError::EvidenceUnavailable)?;
    VerifierCircuitData { verifier_only, common }.verify(proof).map_err(|_| GuardianSignError::EvidenceMismatch)?;
    verify_session_leaf(context,authorization,&record,&input.core.new_user_leaf).await?;
    if input.core.new_user_leaf.nonce.to_canonical_u64()!=request.session_nonce { return Err(GuardianSignError::StateMismatch.into()); }
    Ok(GuardianSession { network_magic:request.network_magic,user_id:request.user_id,nonce:request.session_nonce,record,starting_leaf_hash:verified.starting_leaf_hash,ending_leaf_hash:verified.ending_leaf_hash,withdrawal_appends:verified.withdrawal_appends })
}

fn verify_saved_checkpoint(path: &MerkleProofCore<Hash4>, verified_root: Hash4, checkpoint_id: u64, saved_hash: Hash4) -> std::result::Result<(),GuardianAccountError> {
    verify_path(path,verified_root,checkpoint_id,path.value,CHECKPOINT_TREE_HEIGHT as usize)?;
    if path.value != saved_hash { return Err(GuardianAccountError::Conflict(HaltReason::CheckpointConflict)); }
    Ok(())
}

async fn verify_saved_request(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization, request: &GuardianSignRequest) -> std::result::Result<(),GuardianAccountError> {
    let trace = request.decode_trace()?;
    let id = trace.anchor.start_checkpoint_id;
    if id > context.verified_checkpoint_id { return Err(GuardianSignError::EvidenceUnavailable.into()); }
    let path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id,id).await.map_err(|error| { tracing::warn!(verified = context.verified_checkpoint_id, anchor_start = id, error = %error, "[anchor] saved request proof failed"); GuardianSignError::EvidenceUnavailable })?;
    // Authenticate the saved checkpoint before consulting its L1 deposit anchors.
    verify_saved_checkpoint(&path,context.verified_checkpoint_tree_root,id,trace.anchor.checkpoint_leaf.qfhash::<PsyHasher>())?;
    for anchor in &request.deposit_anchors {
        let endpoint = context.l1_endpoints.iter().find(|endpoint|endpoint.chain_index==anchor.chain_index).ok_or(GuardianSignError::EvidenceUnavailable)?;
        let hash = super::verify_l1::canonical_finalized_anchor_hash(endpoint,authorization.chain(anchor.chain_index)?,anchor).await?;
        if hash != anchor.block_hash { return Err(GuardianAccountError::Conflict(HaltReason::FinalityConflict)); }
    }
    Ok(())
}

pub async fn verify_guardian_saved_anchors(context: &GuardianVerificationContext<'_>, signed_records: &[GuardianSigned], approved_authorizations: &[GuardianAuthorization], sessions: &[GuardianSession]) -> std::result::Result<(),GuardianAccountError> {
    if sessions.windows(2).any(|pair|pair[0].nonce>=pair[1].nonce) { return Err(GuardianSignError::HistoryUnavailable.into()); }
    for session in sessions {
        let request = session.record.request_json.decode()?;
        let approved = approved_authorizations.iter().find(|approved|approved.version==request.authorization_version).ok_or(GuardianSignError::HistoryUnavailable)?;
        verify_saved_request(context,approved,&request).await?;
        let id = session.record.included_checkpoint_id;
        if id > context.verified_checkpoint_id { return Err(GuardianSignError::EvidenceUnavailable.into()); }
        let checkpoint = context.provider.get_checkpoint_leaf_data(id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
        let roots = context.provider.get_checkpoint_global_state_roots(id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
        let path = context.provider.get_checkpoint_tree_merkle_proof(context.verified_checkpoint_id,id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
        verify_checkpoint(id,&checkpoint,&roots,&path,context.verified_checkpoint_tree_root)?;
        if path.value != session.record.included_checkpoint_hash { return Err(GuardianAccountError::Conflict(HaltReason::CheckpointConflict)); }
        let user = context.provider.get_user_tree_merkle_proof(id,approved.user_id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
        verify_path(&user,roots.user_tree_root,approved.user_id,user.value,GLOBAL_USER_TREE_HEIGHT as usize)?;
        if user.value != session.ending_leaf_hash { return Err(GuardianAccountError::Conflict(HaltReason::IncludedTransitionMissing)); }
    }
    for signed in signed_records {
        signed.validate()?;
        let request = GuardianSignRequest::from_canonical_bytes(&signed.request_bytes)?;
        let retained: GuardianAuthorization = parse_canonical_json(&signed.authorization_bytes)?;
        let approved = approved_authorizations.iter().find(|approved|approved.version==retained.version).ok_or(GuardianSignError::HistoryUnavailable)?;
        if serde_json::to_value(approved).map_err(|_|GuardianSignError::AuthorizationMismatch)? != serde_json::to_value(&retained).map_err(|_|GuardianSignError::AuthorizationMismatch)? { return Err(GuardianSignError::AuthorizationMismatch.into()); }
        request.validate_authorization(approved)?;
        verify_saved_request(context,approved,&request).await?;
        if let Ok(index) = sessions.binary_search_by_key(&signed.nonce,|session|session.nonce) {
            if sessions[index].record.request_json.decode()?.canonical_bytes()? != signed.request_bytes { return Err(GuardianAccountError::Conflict(HaltReason::NonceConsumedDifferently)); }
        }
    }
    Ok(())
}

pub async fn verify_guardian_account(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization, signed_records: &[GuardianSigned], approved_authorizations: &[GuardianAuthorization], sessions: &[GuardianSession]) -> std::result::Result<(),GuardianAccountError> {
    verify_guardian_saved_anchors(context,signed_records,approved_authorizations,sessions).await?;
    let head_nonce = verified_account_nonce(context,authorization).await?;
    if context.history.nonce != head_nonce { return Err(GuardianSignError::HistoryUnavailable.into()); }
    Ok(())
}

#[derive(Debug)]
pub enum GuardianAccountError { Unavailable(GuardianSignError), Conflict(HaltReason) }
impl From<GuardianSignError> for GuardianAccountError { fn from(error: GuardianSignError) -> Self { Self::Unavailable(error) } }
impl std::fmt::Display for GuardianAccountError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(formatter,"{self:?}") }
}
impl std::error::Error for GuardianAccountError {}

pub async fn verified_account_nonce(context: &GuardianVerificationContext<'_>, authorization: &GuardianAuthorization) -> Result<u64> {
    let id = context.verified_checkpoint_id;
    let checkpoint = context.provider.get_checkpoint_leaf_data(id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
    let roots = context.provider.get_checkpoint_global_state_roots(id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
    let path = context.provider.get_checkpoint_tree_merkle_proof(id,id).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?;
    verify_checkpoint(id,&checkpoint,&roots,&path,context.verified_checkpoint_tree_root)?;
    let user = context.provider.get_user_leaf_data(id, authorization.user_id).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    let user_path = user_tree_proof(context.provider, id, authorization.user_id).await?;
    verify_path(&user_path,roots.user_tree_root,authorization.user_id,user_path.value,GLOBAL_USER_TREE_HEIGHT as usize)?;
    if user_path.value == Hash4::ZERO { return Ok(0); }
    if user_path.value != user.qfhash::<PsyHasher>() || user.public_key != authorization.account_public_key || user.user_id.to_canonical_u64()!=authorization.user_id { return Err(GuardianSignError::AccountIdentityConflict); }
    Ok(user.nonce.to_canonical_u64())
}
async fn user_tree_proof(provider: &psy_provider::provider::RpcProvider, checkpoint_id: u64, user_id: u64) -> Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
    for attempt in 0..8 {
        match provider.get_user_tree_merkle_proof(checkpoint_id, user_id).await {
            Ok(path) => return Ok(path),
            Err(error) if error.to_string() == format!("get_user_tree_merkle_proof rpc call failed `RpcError {{ code: ServerError(-32001), message: \"User tree proof not found for checkpoint_id {checkpoint_id}\", data: None }}`") && attempt < 7 => {
                tracing::warn!(checkpoint_id, attempt, "user tree proof not yet readable");
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(_) => return Err(GuardianSignError::EvidenceUnavailable),
        }
    }
    Err(GuardianSignError::EvidenceUnavailable)
}

fn decode_endcap_proof(bytes: &[u8], bound: u32) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F,plonky2::plonk::config::PoseidonGoldilocksConfig,2>> {
    use bincode::Options;
    if bytes.len() > bound as usize { return Err(GuardianSignError::EvidenceMismatch); }
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(u64::from(bound)).reject_trailing_bytes().deserialize(bytes).map_err(|_|GuardianSignError::EvidenceMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_commitment_fixture() -> (GuardianAuthorization, GuardianSignRequest, TxTrace, ContractCallData, Hash4) {
        use psy_crypto::hash::merkle::utils::simple_merkle_tree::SimpleMerkleTree;
        use psy_client_data::{dpn::proving_session::DPNProvingSessionSimpleMethodCall, qdata::{user::PsyUserLeaf,user_contract_state::{UserContractState,SignContext},ups_signature::PsyUserProvingSessionSignatureDataCompact}};
        use psy_vm::{ups::{multisig::MultisigAccount,state_reader::StateReaderResults},dpn::ops::state_cmd::data::{DPNStateCmd,DPNStateCmdGetSelfUserCurrentContractStateSlotHash}};
        let members = [Hash4::from_values(1,0,0,0),Hash4::from_values(2,0,0,0),Hash4::from_values(3,0,0,0)];
        let policy = StoredMultisigPolicy {header:Hash4::from_values(1,2,3,0),members}.policy().unwrap();
        let account = MultisigAccount {contract_id:6,initial_policy:policy};
        let fingerprint = Hash4::from_values(9,8,7,6);
        let public_key = PsyHasher::q_two_to_one(fingerprint,account.public_key_param().unwrap());
        let mut policy_tree = SimpleMerkleTree::<PsyHasher,Hash4>::new(4);
        for (index,value) in std::iter::once(Hash4::from_values(1,2,3,0)).chain(members).enumerate() { policy_tree.set_leaf(index as u64,value); }
        let mut contracts = SimpleMerkleTree::<PsyHasher,Hash4>::new(GLOBAL_CONTRACT_TREE_HEIGHT);
        contracts.set_leaf(6,policy_tree.get_root());
        let leaf = PsyUserLeaf {public_key,user_state_tree_root:contracts.get_root(),user_id:F::from_canonical_u64(BRIDGE_USER_ID),nonce:F::ONE,..Default::default()};
        let mut users = SimpleMerkleTree::<PsyHasher,Hash4>::new(GLOBAL_USER_TREE_HEIGHT);
        users.set_leaf(BRIDGE_USER_ID,leaf.qfhash::<PsyHasher>());
        let root = Hash4::from_values(5,6,7,8);
        let state = StateReaderResults {state:UserContractState::new(root,leaf,policy_tree.get_root(),F::from_canonical_u64(6),F::from_canonical_u64(7)),user_tree_root:users.get_root(),checkpoint:None,aux_user_leaves:vec![],state_cmds:(0..4).map(|index|DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(DPNStateCmdGetSelfUserCurrentContractStateSlotHash {slot_index:F::from_canonical_u64(index)})).collect(),merkel_proofs:(0..4).flat_map(|index|[contracts.get_leaf(6),policy_tree.get_leaf(index)]).collect()};
        let method = |name: &str,method_id| psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition {name:name.into(),method_id,circuit_inputs:vec![],circuit_outputs:vec![],assertions:vec![],events:vec![],definitions:vec![],state_commands:vec![],state_command_resolution_indices:vec![]};
        let artifact = CompilerArtifact {state_tree_height:4,circuit_definitions:vec![method("first",1),method("second",2)],abi:serde_json::json!({"schema_version":"2.0.0","contract":{"state_tree_height":4}})};
        let artifact_json = JsonText::from_value(&artifact).unwrap();
        let authorization = GuardianAuthorization {version:1,network_magic:90101,genesis_hash:Hex([1;32]),user_id:BRIDGE_USER_ID,account_json:JsonText::from_value(&account).unwrap(),account_public_key:public_key,multisig_fingerprint:fingerprint,deposit_contract_id:2,withdrawal_contract_id:3,fee_contract_id:0,guta_fee:1,da_fee:1,max_fee:100,max_endcap_proof_bytes:1,endcap_verifier_fingerprint:Hash4::from_values(1,1,1,1),approved_contracts:vec![ApprovedContract {contract_id:3,contract_leaf_json:JsonText::from_value(&PsyContractLeaf::<F>::default()).unwrap(),compiler_artifact_sha256:sha256(artifact_json.as_str().as_bytes()),compiler_artifact_json:artifact_json}],chains:vec![]};
        let mut request = super::super::test_fixture::codec_request_fixture();
        let mut trace = request.decode_trace().unwrap();
        request.session_nonce = 2;
        trace.meta.public_key = public_key;
        trace.anchor.start_checkpoint_id = 7;
        trace.anchor.global_state_roots.user_tree_root = users.get_root();
        trace.ups_start_witness.user_tree_proof = users.get_leaf(BRIDGE_USER_ID);
        trace.ups_start_witness.ups_header.session_start_context = psy_client_data::ups::ups_context_input::UserProvingSessionStartContext {checkpoint_id:F::from_canonical_u64(7),checkpoint_tree_root:root,checkpoint_leaf_hash:trace.anchor.checkpoint_leaf.qfhash::<PsyHasher>(),start_session_user_leaf:leaf};
        let mut end = leaf;
        end.last_checkpoint_id = F::from_canonical_u64(7);
        let sign_context = SignContext {checkpoint_tree_root:root,user_leaf:end};
        end.nonce = F::from_canonical_u64(2);
        trace.finalization.nonce = end.nonce;
        let core = &mut trace.finalization.submit_end_cap_input.core;
        core.checkpoint_id = end.last_checkpoint_id;
        core.new_user_leaf = end;
        core.state_transition = psy_client_data::qdata::ups_end_cap_result::UPSEndCapResultCompact {start_user_leaf_hash:leaf.qfhash::<PsyHasher>(),end_user_leaf_hash:end.qfhash::<PsyHasher>(),checkpoint_tree_root_hash:root,user_id:leaf.user_id};
        core.stats.guta_fees_collected = F::ONE;
        core.stats.da_fees_collected = F::ONE;
        core.stats.total_transactions = F::from_canonical_u64(2);
        let call = DPNProvingSessionSimpleMethodCall::new(F::from_canonical_u64(3),F::ONE,vec![]);
        let burn = DPNProvingSessionSimpleMethodCall::new(F::ZERO,F::from_canonical_u32(TOKEN_BURN_METHOD_ID),vec![F::from_canonical_u64(2)]);
        let stack = PsyHasher::q_two_to_one(PsyHasher::q_two_to_one(Hash4::ZERO,call.qfhash::<PsyHasher>()),burn.qfhash::<PsyHasher>());
        let sig_data = PsyUserProvingSessionSignatureDataCompact {start_user_leaf_hash:leaf.qfhash::<PsyHasher>(),end_user_leaf_hash:end.qfhash::<PsyHasher>(),checkpoint_leaf_hash:trace.anchor.checkpoint_leaf.qfhash::<PsyHasher>(),tx_stack_hash:stack,tx_count:F::from_canonical_u64(2)};
        trace.finalization.sig_hash = sig_data.get_sig_action_for_user::<PsyHasher>(authorization.network_magic,leaf.user_id,end.nonce,sign_context).get_qhash::<PsyHasher>();
        let mut end_state = state.clone();
        end_state.state.user_leaf = sign_context.user_leaf;
        let witness = MultisigSignatureWitness {account:account.clone(),start_state:state,end_state,sig_data,sign_context,start_session_user_leaf:leaf,nonce:end.nonce};
        trace.steps.push(TraceStep::ZkSign(psy_prover::trace::ZkSignStep {fingerprint,proof_tree_start_root:Hash4::ZERO,proof_tree_end_root:Hash4::ZERO,sign_circuit_source:psy_prover::trace::TraceSignCircuitSource::Multisig,sign_witness:serde_json::to_vec(&witness).unwrap(),public_key_param:account.public_key_param().unwrap(),sign_verifier_data_alt:psy_client_common::data::alt::AltVerifierOnlyCircuitData {constants_sigmas_cap:vec![],circuit_digest:Hash4::ZERO}}));
        let expected = ContractCallData::new(vec![ContractCallArgs {contract_id:3,method_name:"first".into(),inputs:vec![]}]);
        (authorization,request,trace,expected,root)
    }

    #[test]
    fn recovered_calls_bind_to_signed_commitment_without_execution() {
        let (authorization,request,trace,mut calls,root) = recovery_commitment_fixture();
        assert!(verify_guardian_session_commitment(&authorization,&request,&trace,&calls,root).is_ok());
        calls.contract_calls[0].method_name = "second".into();
        assert!(matches!(verify_guardian_session_commitment(&authorization,&request,&trace,&calls,root),Err(GuardianSignError::StateMismatch)));
        calls.contract_calls[0].method_name = "first".into();
        let mut spliced = trace.clone();
        spliced.finalization.submit_end_cap_input.core.new_user_leaf.balance += F::ONE;
        assert!(verify_guardian_session_commitment(&authorization,&request,&spliced,&calls,root).is_err());
        assert!(verify_guardian_session_commitment(&authorization,&request,&trace,&calls,Hash4::ZERO).is_err());
        let mut wrong_fee = trace.clone();
        wrong_fee.finalization.submit_end_cap_input.core.stats.da_fees_collected += F::ONE;
        assert!(verify_guardian_session_commitment(&authorization,&request,&wrong_fee,&calls,root).is_err());
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
        assert!(decode_endcap_proof(&u64::MAX.to_le_bytes(),1024).is_err());
        assert!(decode_endcap_proof(&[0;16],8).is_err());
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

    fn session(nonce: u64, start: Hash4, end: Hash4, appends: Vec<WithdrawalAppendRecord>) -> GuardianSession {
        GuardianSession { network_magic:90101,user_id:BRIDGE_USER_ID,nonce,starting_leaf_hash:start,ending_leaf_hash:end,withdrawal_appends:appends,record:GuardianSessionRecord {
            request_json:JsonText::from_value(&crate::guardian::test_fixture::codec_request_fixture()).unwrap(),
            signatures_json:JsonText::from_value(&psy_vm::ups::multisig::MultisigSignatures { member_indices:vec![],signatures:vec![] }).unwrap(),
            endcap_input_json:JsonText::from_value(&psy_client_data::guta::end_cap_input::SubmitUserEndCapNonProofInput::<F>::default()).unwrap(),
            endcap_proof_hex:"0x".into(),included_checkpoint_id:1,included_checkpoint_hash:Hash4::ZERO,
        } }
    }

    #[test]
    fn history_fold_matches_direct_append_and_rejects_duplicate_without_mutation() {
        let first = WithdrawalBurnRecord { sender_user_id:7,token_contract_id:4,destination_chain_index:0,token:[0;8],amount:[0,0,0,0,0,0,0,1],recipient:[0,0,0,0,0,0,0,1],nonce:[1;8] };
        let mut second=first.clone(); second.nonce=[2;8];
        let leaf1=Hash4::from_values(1,2,3,4); let leaf2=Hash4::from_values(5,6,7,8);
        let mut history=GuardianHistory::new();
        history.apply(&session(1,Hash4::ZERO,leaf1,vec![WithdrawalAppendRecord {chain_index:0,append_index:0,burn:first.clone()}])).unwrap();
        let before=history.chains.clone();
        let invalid=session(2,leaf1,leaf2,vec![WithdrawalAppendRecord {chain_index:0,append_index:1,burn:second.clone()},WithdrawalAppendRecord {chain_index:0,append_index:2,burn:first.clone()}]);
        assert!(history.apply(&invalid).is_err());
        assert_eq!(history.nonce(),1); assert_eq!(history.chains,before); assert!(!history.contains_burn(second.sender_user_id,second.token_contract_id,second.nonce));
        history.apply(&session(2,leaf1,leaf2,vec![WithdrawalAppendRecord {chain_index:0,append_index:1,burn:second.clone()}])).unwrap();
        let mut frontier=[Hash4::ZERO;32];
        super::super::verify_l1::append_leaf(&mut frontier,0,withdrawal_leaf(&first));
        let root=super::super::verify_l1::append_leaf(&mut frontier,1,withdrawal_leaf(&second));
        assert_eq!(history.chains.get(&0),Some(&(2,frontier,root)));
        let mut alias=second; alias.sender_user_id+=1;
        assert!(history.apply(&session(3,leaf2,Hash4::ZERO,vec![WithdrawalAppendRecord {chain_index:0,append_index:2,burn:alias}])).is_err());
        assert_eq!(history.nonce(),2);
    }

    #[test]
    fn saved_checkpoint_halts_only_for_authenticated_contradiction() {
        let value=Hash4::from_values(1,2,3,4);
        let mut siblings=Vec::new(); let mut zero=Hash4::ZERO; let mut root=value;
        for _ in 0..CHECKPOINT_TREE_HEIGHT {
            siblings.push(zero); root=PsyHasher::q_two_to_one(root,zero); zero=PsyHasher::q_two_to_one(zero,zero);
        }
        let mut path=MerkleProofCore {root,index:0,value,siblings};
        assert!(verify_saved_checkpoint(&path,root,0,value).is_ok());
        assert!(matches!(verify_saved_checkpoint(&path,root,0,Hash4::ZERO),Err(GuardianAccountError::Conflict(HaltReason::CheckpointConflict))));
        assert!(matches!(verify_saved_checkpoint(&path,Hash4::ZERO,0,value),Err(GuardianAccountError::Unavailable(GuardianSignError::EvidenceMismatch))));
        assert!(matches!(verify_saved_checkpoint(&path,root,1,value),Err(GuardianAccountError::Unavailable(GuardianSignError::EvidenceMismatch))));
        path.siblings[0]=value;
        assert!(matches!(verify_saved_checkpoint(&path,root,0,Hash4::ZERO),Err(GuardianAccountError::Unavailable(GuardianSignError::EvidenceMismatch))));
    }

    #[test]
    fn approved_map_operands_require_unique_preceding_typed_literals() {
        use psy_vm::dpn::{vm::def::DPNFunctionCircuitDefinition,ops::{op_types::{DPNBuiltInDataType as T,DPNOpType as O,DPNIndexedVarDef,encode_indexed_op_id},state_cmd::data::DPNStateCmd}};
        let base=8589934680; let capacity=1048576;
        let base_wire=encode_indexed_op_id(T::Target,0);
        let capacity_wire=encode_indexed_op_id(T::U32Target,0);
        let mut definition=DPNFunctionCircuitDefinition {name:"withdraw".into(),method_id:1,circuit_inputs:vec![],circuit_outputs:vec![],assertions:vec![],events:vec![],
            definitions:vec![DPNIndexedVarDef {data_type:T::Target,index:0,op_type:O::Constant,inputs:vec![base]},DPNIndexedVarDef {data_type:T::U32Target,index:0,op_type:O::ConstantU32,inputs:vec![capacity]}],
            state_commands:vec![DPNStateCmd::get_self_user_current_imt_contract_state_value(base_wire,capacity_wire,[0;4]),DPNStateCmd::set_imt_contract_state_value(0,base_wire,capacity_wire,[0;4],[0;4])],state_command_resolution_indices:vec![2,2]};
        assert!(verify_withdraw_map_constants(&definition,base,capacity).is_ok());
        definition.definitions.push(definition.definitions[0].clone());
        assert!(verify_withdraw_map_constants(&definition,base,capacity).is_err());
        definition.definitions.pop(); definition.state_command_resolution_indices[0]=1;
        assert!(verify_withdraw_map_constants(&definition,base,capacity).is_err());
        definition.state_command_resolution_indices[0]=2; definition.definitions[0].op_type=O::InputTarget;
        assert!(verify_withdraw_map_constants(&definition,base,capacity).is_err());
        definition.definitions[0].op_type=O::Constant; definition.definitions[0].inputs[0]=base+4;
        assert!(verify_withdraw_map_constants(&definition,base,capacity).is_err());
        definition.definitions[0].inputs[0]=GOLDILOCKS_MODULUS;
        assert!(verify_withdraw_map_constants(&definition,base,capacity).is_err());
    }

    #[tokio::test]
    #[ignore = "requires approved real compiler artifacts in GUARDIAN_COMPILER_ARTIFACTS"]
    async fn real_compiler_artifacts_validate_all_precompiles_and_reject_substitution() -> anyhow::Result<()> {
        let directory=std::path::PathBuf::from(std::env::var("GUARDIAN_COMPILER_ARTIFACTS")?);
        let network=psy_config::PsyConfigGoldilocks::builder().path("config.json").network(psy_config::CURRENT_NETWORK).build()?.get_current_network()?.clone();
        let wallet=WalletSession::new(&network).await?;
        let names=["token","mining_rewards","deposit_tree","withdrawal_tree","usdt_token","faucet","multisig_policy"];
        let history=GuardianHistory::new();
        for (contract_id,name) in names.iter().enumerate() {
            let text=std::fs::read_to_string(directory.join(name).join("target").join(format!("{name}.json")))?;
            let artifact_json=JsonText::<CompilerArtifact>::parse(text)?;
            let artifact=artifact_json.decode()?;
            let (_,deployment)=psy_prover::session::gen_contract_deploy_and_circuits_for_functions::<plonky2::plonk::config::PoseidonGoldilocksConfig,2>(0,artifact.state_tree_height.try_into()?,&artifact.circuit_definitions)?;
            let deployment=deployment.into_with_whitelist_root::<PsyHasher>()?;
            let leaf=PsyContractLeaf::<F> {deployer:F::from_canonical_u64(deployment.deployer),function_tree_root:deployment.function_whitelist_root,code_root:deployment.code_root,state_tree_height:F::from_canonical_u16(artifact.state_tree_height),state_layout_root:Hash4::ZERO,state_layout_field_count:F::ZERO,state_layout_slot_count:F::ZERO};
            let approved=ApprovedContract {contract_id:contract_id as u32,contract_leaf_json:JsonText::from_value(&leaf)?,compiler_artifact_sha256:sha256(artifact_json.as_str().as_bytes()),compiler_artifact_json:artifact_json};
            let map=history.approved_artifact(&approved,&wallet).await?;
            if matches!(contract_id,0|4) {
                let map=map.ok_or_else(||anyhow::anyhow!("token map descriptor missing"))?;
                assert_eq!(map.capacity,1048576);
                let field=artifact.abi["contract"]["state"].as_array().unwrap().iter().find(|field|field["name"]=="state_map").unwrap();
                assert_eq!(Some(map.subslot_base),field["offset"].as_u64());
                let mut changed=artifact.clone();
                let field=changed.abi["contract"]["state"].as_array_mut().unwrap().iter_mut().find(|field|field["name"]=="state_map").unwrap();
                field["offset"]=serde_json::json!(map.subslot_base+4);
                let mut substituted=approved.clone(); substituted.compiler_artifact_json=JsonText::from_value(&changed)?;
                substituted.compiler_artifact_sha256=sha256(substituted.compiler_artifact_json.as_str().as_bytes());
                assert!(validate_approved_contract(&substituted,&wallet).await.is_err(),"ABI offset substitution accepted for {name}");
            } else { assert!(map.is_none()); }
            if contract_id==6 { assert_eq!(artifact.state_tree_height,4); }
            let mut wrong_digest=approved.clone(); wrong_digest.compiler_artifact_sha256.0[0]^=1;
            assert!(history.approved_artifact(&wrong_digest,&wallet).await.is_err());
            let mut wrong_leaf=leaf; wrong_leaf.code_root.0.elements[0]+=F::ONE;
            let mut changed=approved.clone(); changed.contract_leaf_json=JsonText::from_value(&wrong_leaf)?;
            assert!(validate_approved_contract(&changed,&wallet).await.is_err(),"code-root substitution accepted for {name}");
            changed=approved.clone();
            let mut changed_artifact=artifact; changed_artifact.state_tree_height=changed_artifact.state_tree_height.saturating_add(1);
            changed.compiler_artifact_json=JsonText::from_value(&changed_artifact)?;
            changed.compiler_artifact_sha256=sha256(changed.compiler_artifact_json.as_str().as_bytes());
            assert!(validate_approved_contract(&changed,&wallet).await.is_err(),"height substitution accepted for {name}");
        }
        Ok(())
    }
}
