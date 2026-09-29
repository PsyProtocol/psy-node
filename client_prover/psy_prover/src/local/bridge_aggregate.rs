use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use plonky2::{field::{goldilocks_field::GoldilocksField as F, types::PrimeField64}, plonk::config::PoseidonGoldilocksConfig};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{api::reward::PsyProoffMinerRewardProofWithRewardPreimage, bridge_aggregate::{domain_hash, Domain, NetworkConfig, WithdrawalLeaf, RewardLeaf, GOLDILOCKS_MODULUS}, config::store_config::PsyHasher, traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync}};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::qhashable::QFieldHashable};
use psy_plonky2_common_circuits::bridge::withdrawal_inclusion::{WithdrawalInclusionCircuit, WithdrawalInclusionInputs, WithdrawalWitness};
use psy_plonky2_circuits::bridge::circuits::reward_inclusion::{RewardInclusionCircuit, RewardTagWitness};
use psy_provider::provider::RpcProvider;
use psy_ups_circuit::signature::reward_authorization::{RewardAuthorizationContext, RewardAuthorizationInput};
use psy_vm::{reward_authorization::RewardAuthorizationWitness, ups::multisig::{MultisigAccount, MultisigSignatures, StoredMultisigPolicy}};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("aggregation context changed; fresh witness and authorization required")]
    ContextChanged(AggregationContext),
    #[error("aggregation service rejected claim: {0}")]
    Rejected(String),
    #[error("invalid aggregation response: {0}")]
    InvalidResponse(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregationContext {
    pub version: u32,
    pub config_hash: String,
    pub end_checkpoint_id: String,
    pub end_checkpoint_root: [String; 4],
    pub context_id: String,
    pub max_proof_bytes: usize,
    pub max_records: usize,
}

#[derive(Deserialize)]
struct Envelope<T> { success: bool, data: Option<T>, error: Option<String> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorData { error_code: String, current_context: Option<AggregationContext> }
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimStatus {
    pub claim_id: String,
    pub state: String,
    pub context_id: String,
    pub statement_b: Option<String>,
    pub error_code: Option<String>,
    pub current_context: Option<AggregationContext>,
}

pub fn word(value: u64) -> [u8; 32] { let mut out = [0; 32]; out[24..].copy_from_slice(&value.to_be_bytes()); out }
pub fn digest(parts: &[&[u8]]) -> String { use tiny_keccak::{Hasher, Keccak}; let mut hash = Keccak::v256(); for part in parts { hash.update(part); } let mut out = [0; 32]; hash.finalize(&mut out); format!("0x{}", hex::encode(out)) }
fn decimal(value: &str) -> Result<u64> { let number: u64 = value.parse()?; anyhow::ensure!(number.to_string() == value, "noncanonical decimal"); Ok(number) }
pub fn hex32(value: &str) -> Result<[u8; 32]> { anyhow::ensure!(value.len() == 66 && value.starts_with("0x") && value[2..].bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "noncanonical hex32"); Ok(hex::decode(&value[2..])?.try_into().map_err(|_| ClaimError::InvalidResponse("hex32 width"))?) }
pub fn address(value: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    let bytes = if bytes.len() == 32 { anyhow::ensure!(bytes[..12] == [0; 12], "address exceeds160 bits"); &bytes[12..] } else { &bytes[..] };
    Ok(bytes.try_into().map_err(|_| anyhow::anyhow!("address must be20 bytes or zero-padded32 bytes"))?)
}
pub fn hash_words(hash: QHashOut<F>) -> [u64; 4] { hash.0.elements.map(|v| v.to_canonical_u64()) }
pub fn verify_path(path: &MerkleProofCore<QHashOut<F>>, root: QHashOut<F>, index: u64, value: QHashOut<F>, height: usize) -> Result<()> {
    anyhow::ensure!(height < 64 && index < (1u64 << height) && path.root == root && path.index == index && path.value == value && path.siblings.len() == height && path.verify::<PsyHasher>(), "chosen-end membership mismatch"); Ok(())
}
#[derive(Deserialize)]
struct WithdrawalProof { found: bool, checkpoint_id: Option<u64>, leaf_index: Option<u32>, siblings: Option<Vec<String>> }
fn poseidon_hex(value: &str) -> Result<[u64; 4]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    anyhow::ensure!(bytes.len() == 32, "withdrawal sibling width");
    let hash = std::array::from_fn(|i| u64::from_be_bytes(bytes[(3-i)*8..(4-i)*8].try_into().unwrap()));
    anyhow::ensure!(hash.iter().all(|v| *v < GOLDILOCKS_MODULUS), "noncanonical withdrawal sibling"); Ok(hash)
}
pub fn reward_record(checkpoint: u64, user_id: u32, recipient: [u8; 20], proof: &PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<F>>) -> Result<(RewardLeaf, RewardTagWitness)> {
    let tag = &proof.inner.tag_tree_proof;
    let height = u8::try_from(tag.siblings.len())?;
    anyhow::ensure!((2..=21).contains(&height), "reward proof must reach full GUTA root");
    let path_index = u32::try_from(tag.index)?;
    let record = RewardLeaf { claim_checkpoint_id: checkpoint, user_id, height, path_index, nullifier_index: ((1u32 << height) - 1).checked_add(path_index).context("reward nullifier overflow")?, recipient };
    record.validate()?;
    let mut siblings = [parth_core::pgoldilocks::QHashOut(QHashOut::<F>::ZERO.0); 21];
    let mut parent_tags = siblings;
    for (i, node) in tag.siblings.iter().enumerate() { siblings[i] = parth_core::pgoldilocks::QHashOut(node.sibling.0); parent_tags[i] = parth_core::pgoldilocks::QHashOut(node.parent_tag.0); }
    Ok((record, RewardTagWitness { tag_preimage: parth_core::pgoldilocks::QHashOut(proof.reward_tree_tag_preimage.0), leaf_left: parth_core::pgoldilocks::QHashOut(tag.leaf.left.0), leaf_right: parth_core::pgoldilocks::QHashOut(tag.leaf.right.0), leaf_tag: parth_core::pgoldilocks::QHashOut(tag.leaf.tag.0), siblings, parent_tags }))
}

pub async fn reward_membership(client: &ClaimClient, context: &AggregationContext, reward: &RewardLeaf) -> Result<RewardAuthorizationContext> {
    let (end, root) = client.validate_context(context)?;
    anyhow::ensure!(reward.claim_checkpoint_id <= end && reward.claim_checkpoint_id >= client.config.reward_cutover && reward.claim_checkpoint_id < client.config.reward_end_exclusive, "reward checkpoint outside configured claim interval or selected end");
    let (end_leaf, roots) = client.checkpoint(context).await?;
    let claim_leaf = client.provider.get_checkpoint_leaf_data(reward.claim_checkpoint_id).await?;
    let claim_path = client.provider.get_checkpoint_tree_merkle_proof(end, reward.claim_checkpoint_id).await?;
    let end_path = client.provider.get_checkpoint_tree_merkle_proof(end, end).await?;
    let root_hash = QHashOut::from_values(root[0], root[1], root[2], root[3]);
    verify_path(&claim_path, root_hash, reward.claim_checkpoint_id, claim_leaf.qfhash::<PsyHasher>(), psy_config::network_constants::CHECKPOINT_TREE_HEIGHT as usize)?;
    verify_path(&end_path, root_hash, end, end_leaf.qfhash::<PsyHasher>(), psy_config::network_constants::CHECKPOINT_TREE_HEIGHT as usize)?;
    let user = client.provider.get_user_leaf_data(end, reward.user_id as u64).await?;
    let user_path = client.provider.get_user_tree_merkle_proof(end, reward.user_id as u64).await?;
    verify_path(&user_path, roots.user_tree_root, reward.user_id as u64, user.qfhash::<PsyHasher>(), psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize)?;
    Ok(RewardAuthorizationContext { config_hash: client.config.config_hash()?, end_checkpoint_id: end, end_checkpoint_root: root, reward: reward.clone(), claim_checkpoint_leaf: claim_leaf, end_checkpoint_leaf: end_leaf, end_global_state_roots: roots, authorization_user_leaf: user, claim_checkpoint_path: claim_path.siblings, end_checkpoint_path: end_path.siblings, authorization_user_path: user_path.siblings })
}

pub async fn multisig_authorization(client: &ClaimClient, context: &AggregationContext, reward: &RewardLeaf, membership: &RewardAuthorizationContext, account: &MultisigAccount, signatures: &MultisigSignatures) -> Result<RewardAuthorizationWitness> {
    account.public_key_param()?;
    anyhow::ensure!(signatures.signatures.len() == 2 && signatures.member_indices.len() == 2 && signatures.member_indices[0] < signatures.member_indices[1] && signatures.member_indices[1] < 3, "multisig requires two ordered current-member signatures");
    let message = membership.message()?;
    anyhow::ensure!(signatures.signatures.iter().all(|signature| signature.message.0 == message), "multisig signatures must cover exact reward authorization message");
    let (end, _) = client.validate_context(context)?;
    let contract = client.provider.get_user_contract_tree_merkle_proof(end, reward.user_id as u64, account.contract_id).await?;
    verify_path(&contract, membership.authorization_user_leaf.user_state_tree_root, account.contract_id as u64, contract.value, psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
    let mut policy_slots = [QHashOut::ZERO; 4];
    let mut policy_slot_paths = [[QHashOut::ZERO; 4]; 4];
    for slot in 0..4 {
        let path = client.provider.get_user_contract_state_tree_merkle_proof(end, reward.user_id as u64, account.contract_id, 4, slot as u64).await?;
        verify_path(&path, contract.value, slot as u64, path.value, 4)?;
        policy_slots[slot] = path.value;
        policy_slot_paths[slot] = path.siblings.try_into().map_err(|_| anyhow::anyhow!("multisig policy path height"))?;
    }
    StoredMultisigPolicy { header: policy_slots[0], members: [policy_slots[1], policy_slots[2], policy_slots[3]] }.policy()?;
    Ok(RewardAuthorizationWitness::Multisig { contract_id: account.contract_id, initial_policy: account.initial_policy.clone(), policy_slots, contract_state_paths: std::array::from_fn(|_| contract.siblings.clone()), policy_slot_paths, member_indices: [signatures.member_indices[0], signatures.member_indices[1]], compressed_public_keys: [signatures.signatures[0].public_key, signatures.signatures[1].public_key], signatures_rs: [signatures.signatures[0].signature, signatures.signatures[1].signature] })
}

pub struct ClaimClient {
    pub config: NetworkConfig,
    pub provider: RpcProvider,
    pub http: reqwest::Client,
    pub url: String,
}
impl ClaimClient {
    pub fn new(config: NetworkConfig, provider: RpcProvider, services_url: &str) -> Result<Self> {
        config.validate()?;
        Ok(Self { config, provider, http: reqwest::Client::new(), url: services_url.trim_end_matches('/').to_owned() })
    }
}
impl ClaimClient {
    pub fn validate_context(&self, context: &AggregationContext) -> Result<(u64, [u64; 4])> {
        let id = decimal(&context.end_checkpoint_id)?;
        let mut root = [0; 4];
        for (out, text) in root.iter_mut().zip(&context.end_checkpoint_root) { *out = decimal(text)?; anyhow::ensure!(*out < GOLDILOCKS_MODULUS, "noncanonical context root"); }
        let config = self.config.config_hash()?;
        let root_bytes: Vec<u8> = root.iter().flat_map(|v| word(*v)).collect();
        anyhow::ensure!(context.version == 1 && context.max_proof_bytes == 16_777_216 && context.max_records == 1024 && hex32(&context.config_hash)? == config && context.context_id == digest(&[&domain_hash(Domain::Window), &config, &word(id), &root_bytes]), "context identity/configuration mismatch");
        Ok((id, root))
    }
    pub async fn response<T: serde::de::DeserializeOwned>(&self, mut response: reqwest::Response) -> Result<T> {
        let status = response.status();
        let body = response.bytes().await?;
        anyhow::ensure!(body.len() <= 24 * 1024 * 1024, "aggregation response exceeds24MiB");
        let envelope: Envelope<serde_json::Value> = serde_json::from_slice(&body)?;
        if !envelope.success {
            let error: ErrorData = serde_json::from_value(envelope.data.context("missing aggregation error data")?)?;
            if error.error_code == "ContextChanged" {
                let current = error.current_context.context("ContextChanged requires currentContext")?;
                self.validate_context(&current)?;
                return Err(ClaimError::ContextChanged(current).into());
            }
            anyhow::ensure!(error.current_context.is_none(), "unexpected currentContext on error");
            return Err(ClaimError::Rejected(error.error_code).into());
        }
        anyhow::ensure!(status.is_success() && envelope.error.is_none(), "inconsistent aggregation response");
        Ok(serde_json::from_value(envelope.data.context("missing aggregation response data")?)?)
    }
    pub async fn context(&self) -> Result<AggregationContext> {
        let context = self.response(self.http.get(format!("{}/api/v1/bridge/aggregation/context", self.url)).send().await?).await?;
        self.validate_context(&context)?;
        Ok(context)
    }
    pub async fn checkpoint(&self, context: &AggregationContext) -> Result<(psy_client_data::qdata::checkpoint::PsyCheckpointLeaf<F>, psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots<F>)> {
        let (id, root) = self.validate_context(context)?;
        anyhow::ensure!(hash_words(self.provider.get_checkpoint_tree_root(id).await?) == root, "published context differs from configured coordinator checkpoint");
        let leaf = self.provider.get_checkpoint_leaf_data(id).await?;
        let roots = self.provider.get_checkpoint_global_state_roots(id).await?;
        anyhow::ensure!(roots.qfhash::<PsyHasher>() == leaf.global_chain_root, "checkpoint global roots mismatch");
        let path = self.provider.get_checkpoint_tree_merkle_proof(id, id).await?;
        verify_path(&path, QHashOut::from_values(root[0], root[1], root[2], root[3]), id, leaf.qfhash::<PsyHasher>(), psy_config::network_constants::CHECKPOINT_TREE_HEIGHT as usize)?;
        Ok((leaf, roots))
    }
    async fn withdrawal_root(&self, context: &AggregationContext, chain: u8) -> Result<[u64; 4]> {
        let (id, _) = self.validate_context(context)?;
        let (_, roots) = self.checkpoint(context).await?;
        let user_id = self.config.bridge_user_id as u64;
        let user = self.provider.get_user_leaf_data(id, user_id).await?;
        verify_path(&self.provider.get_user_tree_merkle_proof(id, user_id).await?, roots.user_tree_root, user_id, user.qfhash::<PsyHasher>(), psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize)?;
        let contract = self.provider.get_user_contract_tree_merkle_proof(id, user_id, 3).await?;
        verify_path(&contract, user.user_state_tree_root, 3, contract.value, psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize)?;
        let mut words = [0u32; 8];
        for part in 0..2 {
            let slot = 16_451 + 2 * u64::from(chain) + part as u64;
            let path = self.provider.get_user_contract_state_tree_merkle_proof(id, user_id, 3, psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT, slot).await?;
            verify_path(&path, contract.value, slot, path.value, psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize)?;
            for (out, felt) in words[part * 4..part * 4 + 4].iter_mut().zip(path.value.0.elements) { *out = u32::try_from(felt.to_canonical_u64())?; }
        }
        let root = std::array::from_fn(|i| u64::from(words[2*i]) | (u64::from(words[2*i+1]) << 32));
        anyhow::ensure!(root.iter().all(|v| *v < GOLDILOCKS_MODULUS), "noncanonical withdrawal root");
        Ok(root)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionRequest {
    pub version: u32,
    pub context_id: String,
    pub kind: String,
    pub record: String,
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("fresh external reward authorization required for message {message}")]
pub struct FreshAuthorizationRequired {
    pub message: String,
    pub record: String,
    pub reward: RewardRecord,
    pub context: AggregationContext,
}
impl FreshAuthorizationRequired {
    pub fn new(context: &AggregationContext, authorization: &RewardAuthorizationContext) -> Result<Self> {
        let leaf = &authorization.reward;
        let reward = RewardRecord { claim_checkpoint_id: leaf.claim_checkpoint_id.to_string(), user_id: leaf.user_id.to_string(), height: leaf.height, path_index: leaf.path_index, nullifier_index: leaf.nullifier_index, recipient: format!("0x{}", hex::encode(leaf.recipient)) };
        let record = leaf.encode()?;
        let decoded = reward.canonical()?;
        anyhow::ensure!(&decoded == leaf && decoded.encode()? == record, "reward challenge echo differs from canonical record");
        Ok(Self { message: format!("0x{}", hex::encode(authorization.message()?)), record: STANDARD.encode(record), reward, context: context.clone() })
    }
}

pub struct ClaimCircuits {
    pub withdrawal: WithdrawalInclusionCircuit<PoseidonGoldilocksConfig, 2>,
    pub reward: RewardInclusionCircuit,
}
impl ClaimCircuits {
    pub fn build(config: &NetworkConfig, registry: &[psy_client_data::bridge_aggregate::CircuitSetEntry]) -> Result<Self> {
        config.validate()?;
        anyhow::ensure!(psy_client_data::bridge_aggregate::circuit_set_hash(registry)? == config.circuit_set_hash, "operator circuit registry differs from configuration");
        let withdrawal = WithdrawalInclusionCircuit::build();
        let reward = RewardInclusionCircuit::new(config.chains.len())?;
        let mut entries = reward.circuit_set_entries()?;
        entries.push(psy_plonky2_circuits::bridge::aggregate_circuits::circuit_set_entry(2, 0, 0, 32, &withdrawal.circuit_data, [0; 4])?);
        for entry in entries { anyhow::ensure!(registry.iter().find(|pin| (pin.family,pin.level,pin.variant) == (entry.family,entry.level,entry.variant)) == Some(&entry), "claim circuit differs from source registry"); }
        Ok(Self { withdrawal, reward })
    }
}

impl ClaimClient {
    pub fn admission(&self, context: &AggregationContext, kind: &str, record: &[u8], proof: &[u8]) -> Result<AdmissionRequest> {
        self.validate_context(context)?;
        anyhow::ensure!(matches!(kind, "withdrawal" | "reward") && !proof.is_empty() && proof.len() <= context.max_proof_bytes, "invalid claim proof/kind");
        Ok(AdmissionRequest { version: 1, context_id: context.context_id.clone(), kind: kind.to_owned(), record: STANDARD.encode(record), proof: STANDARD.encode(proof) })
    }
    pub async fn prove_withdrawal(&self, context: &AggregationContext, leaf: &WithdrawalLeaf, circuit: &WithdrawalInclusionCircuit<PoseidonGoldilocksConfig, 2>) -> Result<AdmissionRequest> {
        leaf.validate()?;
        anyhow::ensure!(self.config.chains.iter().any(|chain| chain.chain_index == leaf.chain_index), "unconfigured withdrawal destination");
        let (id, root) = self.validate_context(context)?;
        let withdrawal_root = self.withdrawal_root(context, leaf.chain_index).await?;
        let response = self.http.get(format!("{}/api/v1/bridge/withdrawal-claim-proof", self.url)).query(&[("contextId", context.context_id.clone()), ("checkpointId", id.to_string()), ("recipient", format!("0x{}", hex::encode(leaf.recipient))), ("token_address", format!("0x{}", hex::encode(leaf.token))), ("amount", format!("0x{}", hex::encode(leaf.amount))), ("nonce", format!("0x{}", hex::encode(leaf.nonce))), ("destination_chain_index", leaf.chain_index.to_string()), ("sender_user_id", leaf.sender_user_id.to_string())]).send().await?;
        let witness: WithdrawalProof = self.response(response).await?;
        anyhow::ensure!(witness.found && witness.checkpoint_id == Some(id), "withdrawal witness not found at chosen checkpoint");
        let siblings = witness.siblings.context("missing withdrawal siblings")?.iter().map(|s| poseidon_hex(s)).collect::<Result<Vec<_>>>()?.try_into().map_err(|_| anyhow::anyhow!("withdrawal requires32 siblings"))?;
        let proof = circuit.generate_proof(&WithdrawalInclusionInputs { config_hash: self.config.config_hash()?, end_checkpoint_id: id, end_checkpoint_root: root, withdrawal_root, leaf: leaf.clone(), witness: WithdrawalWitness { leaf_index: witness.leaf_index.context("missing withdrawal index")?, siblings } })?;
        let bytes = proof.to_bytes();
        circuit.verify_proof(proof)?;
        self.admission(context, "withdrawal", &leaf.encode()?, &bytes)
    }
    pub fn prove_reward(&self, context: &AggregationContext, authorization: &RewardAuthorizationContext, tag: &RewardTagWitness, proof: &psy_client_data::config::store_config::PsyProof, circuit: &RewardInclusionCircuit) -> Result<AdmissionRequest> {
        let (id, root) = self.validate_context(context)?;
        anyhow::ensure!(authorization.end_checkpoint_id == id && authorization.end_checkpoint_root == root && authorization.config_hash == self.config.config_hash()?, "reward authorization context mismatch");
        let proof = circuit.prove_with_authorization_proof(&self.config, authorization, tag, proof)?;
        let bytes = proof.to_bytes();
        circuit.verify(proof)?;
        self.admission(context, "reward", &authorization.reward.encode()?, &bytes)
    }
}

pub fn select_multisig_signatures<'a>(bundles: &'a [MultisigSignatures], message: &[u8; 32]) -> Result<Option<&'a MultisigSignatures>> {
    let mut matching = bundles.iter().filter(|bundle| bundle.signatures.len() == 2 && bundle.signatures.iter().all(|signature| &signature.message.0 == message));
    let selected = matching.next();
    anyhow::ensure!(matching.next().is_none(), "ambiguous duplicate reward signature bundles");
    if let Some(bundle) = selected { anyhow::ensure!(bundle.member_indices.len() == 2 && bundle.member_indices[0] < bundle.member_indices[1] && bundle.member_indices[1] < 3, "multisig requires two ordered current-member signatures"); }
    Ok(selected)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WithdrawalRecord {
    pub chain_index: u8,
    pub sender_user_id: String,
    pub recipient: String,
    pub token: String,
    pub amount: String,
    pub nonce: String,
}
impl WithdrawalRecord {
    pub fn canonical(&self) -> Result<WithdrawalLeaf> {
        let amount = decimal_word(&self.amount)?;
        let leaf = WithdrawalLeaf { chain_index: self.chain_index, sender_user_id: u32::try_from(decimal(&self.sender_user_id)?)?, recipient: address(&self.recipient)?, token: address(&self.token)?, amount, nonce: hex32(&self.nonce)? };
        leaf.validate()?;
        Ok(leaf)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardRecord {
    pub claim_checkpoint_id: String,
    pub user_id: String,
    pub height: u8,
    pub path_index: u32,
    pub nullifier_index: u32,
    pub recipient: String,
}
impl RewardRecord {
    pub fn canonical(&self) -> Result<RewardLeaf> {
        let leaf = RewardLeaf { claim_checkpoint_id: decimal(&self.claim_checkpoint_id)?, user_id: u32::try_from(decimal(&self.user_id)?)?, height: self.height, path_index: self.path_index, nullifier_index: self.nullifier_index, recipient: address(&self.recipient)? };
        leaf.validate()?;
        Ok(leaf)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateWithdrawalRequest {
    pub config: String,
    pub registry: String,
    pub services_url: String,
    pub context: AggregationContext,
    pub record: WithdrawalRecord,
    pub user_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardJob {
    pub realm_id: Option<String>,
    pub unique_pending_id: String,
    pub job: psy_client_common::job::id::QProvingJobDataIDWithRewardPreimage,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalRewardAuthorization {
    Secp { signature: psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature },
    PersonalSign { signature: psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature },
    Multisig { account: MultisigAccount, signatures: Vec<MultisigSignatures> },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregateRewardRequest {
    pub config: String,
    pub registry: String,
    pub services_url: String,
    pub context: AggregationContext,
    pub record: RewardRecord,
    pub user_id: String,
    pub job: RewardJob,
    pub external_authorization: Option<ExternalRewardAuthorization>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AggregateClaimResult {
    Admission { request: AdmissionRequest },
    FreshAuthorizationRequired { message: String, record: String, reward: RewardRecord, context: AggregationContext },
}
impl From<FreshAuthorizationRequired> for AggregateClaimResult {
    fn from(value: FreshAuthorizationRequired) -> Self { Self::FreshAuthorizationRequired { message: value.message, record: value.record, reward: value.reward, context: value.context } }
}

fn canonical_base64(value: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD.decode(value)?;
    anyhow::ensure!(STANDARD.encode(&bytes) == value, "noncanonical base64");
    Ok(bytes)
}
fn decimal_word(value: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(!value.is_empty() && (value == "0" || !value.starts_with('0')) && value.bytes().all(|digit| digit.is_ascii_digit()), "noncanonical uint256 decimal");
    let mut word = [0u8; 32];
    for digit in value.bytes() {
        let mut carry = u16::from(digit - b'0');
        for byte in word.iter_mut().rev() { let next = u16::from(*byte) * 10 + carry; *byte = next as u8; carry = next >> 8; }
        anyhow::ensure!(carry == 0, "uint256 decimal overflow");
    }
    Ok(word)
}
fn build_claim_client(session: &crate::session::WalletSession, config: &str, registry: &str, url: &str) -> Result<(ClaimClient, ClaimCircuits)> {
    let config = NetworkConfig::decode(&canonical_base64(config)?)?;
    let registry = psy_client_data::bridge_aggregate::decode_circuit_set(&canonical_base64(registry)?)?;
    let circuits = ClaimCircuits::build(&config, &registry)?;
    let mut provider = session.st_provider.clone();
    provider.current_user_id = 0;
    Ok((ClaimClient::new(config, provider, url)?, circuits))
}
pub async fn prove_aggregate_withdrawal(session: &crate::session::WalletSession, public_key: QHashOut<F>, request: AggregateWithdrawalRequest) -> Result<AggregateClaimResult> {
    let (client, circuits) = build_claim_client(session, &request.config, &request.registry, &request.services_url)?;
    let record = request.record.canonical()?;
    anyhow::ensure!(decimal(&request.user_id)? == record.sender_user_id as u64, "withdrawal selected user mismatch");
    session.wallet.get_user_by_public_key_hash(&public_key)?;
    let (end, _) = client.validate_context(&request.context)?;
    let (_, roots) = client.checkpoint(&request.context).await?;
    let user = client.provider.get_user_leaf_data(end, record.sender_user_id as u64).await?;
    verify_path(&client.provider.get_user_tree_merkle_proof(end, record.sender_user_id as u64).await?, roots.user_tree_root, record.sender_user_id as u64, user.qfhash::<PsyHasher>(), psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize)?;
    anyhow::ensure!(user.public_key == public_key, "withdrawal account differs from selected wallet");
    Ok(AggregateClaimResult::Admission { request: client.prove_withdrawal(&request.context, &record, &circuits.withdrawal).await? })
}
pub async fn prove_aggregate_reward(session: &crate::session::WalletSession, public_key: QHashOut<F>, request: AggregateRewardRequest) -> Result<AggregateClaimResult> {
    let (client, circuits) = build_claim_client(session, &request.config, &request.registry, &request.services_url)?;
    let record = request.record.canonical()?;
    anyhow::ensure!(decimal(&request.user_id)? == record.user_id as u64, "reward selected user mismatch");
    let pending = decimal(&request.job.unique_pending_id)?;
    let (checkpoint, mut proofs) = if let Some(realm) = &request.job.realm_id {
        let realm = decimal(realm)?;
        (client.provider.get_realm_checkpoint_id_for_unique_pending_id_by_realm_id(realm, pending).await?, client.provider.generate_realm_batch_proof_miner_reward_proofs_by_realm_id(realm, pending, vec![request.job.job.inner]).await?)
    } else {
        (client.provider.get_coordinator_checkpoint_id_for_unique_pending_id(pending).await?, client.provider.generate_coordinator_batch_proof_miner_reward_proofs(pending, vec![request.job.job.inner]).await?)
    };
    anyhow::ensure!(checkpoint == Some(record.claim_checkpoint_id) && proofs.len() == 1, "reward job checkpoint/proof count mismatch");
    let proof = proofs.pop().context("missing reward proof")?;
    anyhow::ensure!(proof.job_id == request.job.job.inner.job_data_id, "reward job identity mismatch");
    let tag_root = proof.tag_tree_proof.root;
    let (actual, tag) = reward_record(record.claim_checkpoint_id, record.user_id, record.recipient, &PsyProoffMinerRewardProofWithRewardPreimage { inner: proof, reward_tree_tag_preimage: request.job.job.reward_tree_tag_preimage })?;
    anyhow::ensure!(actual == record, "reward record differs from selected job witness");
    let context = reward_membership(&client, &request.context, &record).await?;
    anyhow::ensure!(context.claim_checkpoint_leaf.stats.pm_rewards_commitment.gutas_root == tag_root, "reward proof does not reach authenticated GUTA root");
    let internal = session.wallet.prove_reward_authorization(&public_key, &context, circuits.reward.authorization_circuits())?;
    let proof = match (internal, request.external_authorization) {
        (Some(proof), None) => proof,
        (Some(_), Some(_)) => anyhow::bail!("external authorization supplied for key-held account"),
        (None, None) => return Ok(FreshAuthorizationRequired::new(&request.context, &context)?.into()),
        (None, Some(external)) => {
            let message = context.message()?;
            let witness = match external {
                ExternalRewardAuthorization::Secp { signature } => { anyhow::ensure!(signature.message.0 == message, "stale reward signature"); RewardAuthorizationWitness::Secp { compressed_public_key: signature.public_key, signature_rs: signature.signature } },
                ExternalRewardAuthorization::PersonalSign { signature } => { anyhow::ensure!(signature.message.0 == message, "stale reward signature"); RewardAuthorizationWitness::PersonalSign { compressed_public_key: signature.public_key, signature_rs: signature.signature } },
                ExternalRewardAuthorization::Multisig { account, signatures } => {
                    let signatures = match select_multisig_signatures(&signatures, &message)? { Some(value) => value, None => return Ok(FreshAuthorizationRequired::new(&request.context, &context)?.into()) };
                    multisig_authorization(&client, &request.context, &record, &context, &account, signatures).await?
                }
            };
            circuits.reward.authorization_circuits().prove(&RewardAuthorizationInput { context: context.clone(), authorization: witness })?
        }
    };
    Ok(AggregateClaimResult::Admission { request: client.prove_reward(&request.context, &context, &tag, &proof, &circuits.reward)? })
}

impl ClaimClient {
    pub fn validate_status(&self, context: &AggregationContext, claim_id: &str, status: &ClaimStatus) -> Result<()> {
        anyhow::ensure!(status.claim_id == claim_id, "claim status identity mismatch");
        hex32(&status.context_id)?;
        if status.state == "queued" { anyhow::ensure!(status.context_id == context.context_id, "queued proof context mismatch"); }
        match status.state.as_str() {
            "refresh_required" => { let current = status.current_context.as_ref().context("refresh_required requires currentContext")?; self.validate_context(current)?; return Err(ClaimError::ContextChanged(current.clone()).into()); }
            "rejected" => { anyhow::ensure!(status.current_context.is_none(), "rejected status has currentContext"); return Err(ClaimError::Rejected(status.error_code.clone().context("rejected status requires errorCode")?).into()); }
            "queued" | "included" | "applied" => anyhow::ensure!(status.current_context.is_none() && status.error_code.is_none(), "invalid claim status fields"),
            _ => return Err(ClaimError::InvalidResponse("unknown claim state").into()),
        }
        if status.state != "queued" { hex32(status.statement_b.as_deref().context("included/applied requires statementB")?)?; }
        else { anyhow::ensure!(status.statement_b.is_none(), "queued claim has statementB"); }
        Ok(())
    }
}
