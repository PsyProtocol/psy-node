use std::collections::BTreeMap;

use alloy_primitives::{keccak256, U256};
use alloy_rpc_types_eth::Log;
use alloy_sol_types::SolEvent;
use plonky2::field::{goldilocks_field::GoldilocksField as F, types::{Field, PrimeField64}};
use psy_client_data::config::store_config::PsyHasher;
use psy_plonky2_common_circuits::bridge::deposit_batch_append_circuit::DepositLeafData;
use psy_crypto::hash::traits::hasher::{FieldQHasher, MerkleZeroHasher};
use serde_json::{json, Value};

use crate::bridge::deposit_logs::DepositRecorded;
use guardian_common::protocol::*;

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifiedDepositPrefix {
    pub(crate) count: u32,
    pub(crate) frontier: [Hash4;32],
    pub(crate) root: Hash4,
    pub(crate) anchor: DepositAnchor,
    pub(crate) event_block: u64,
    pub(crate) previous_count: u32,
    pub(crate) previous_root: Hash4,
    occupied_partial_page_hashes: Vec<Hash4>,
}
impl VerifiedDepositPrefix {
    pub(crate) fn empty(chain_index: u8) -> Self {
        Self { count: 0, frontier: [Hash4::ZERO;32], root: <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32), anchor: DepositAnchor { chain_index, block_number: 0, block_hash: Hex([0;32]), old_count: 0, new_count: 0 }, event_block: 0, previous_count: 0, previous_root: <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32), occupied_partial_page_hashes: Vec::new() }
    }
    fn extends(&self, anchor: &DepositAnchor) -> bool { self.count==anchor.old_count && self.anchor.block_number<=anchor.block_number && self.occupied_partial_page_hashes.len() == (self.count % 32) as usize }
    pub(crate) fn occupied_partial_page_hashes(&self) -> &[Hash4] { &self.occupied_partial_page_hashes }
    pub(crate) fn with_occupied(mut self, hashes: Vec<Hash4>) -> Self { self.occupied_partial_page_hashes = hashes; self }
    pub(crate) fn matches_opening(&self, chain_index: u8, count: u32, root: [u64;4]) -> bool { self.anchor.chain_index == chain_index && self.count == count && self.root.0.elements.map(|limb| limb.to_canonical_u64()) == root }
}

struct CustodyRpc<'a> { endpoint: &'a ChainEndpoint, client: reqwest::Client }
impl<'a> CustodyRpc<'a> {
    fn new(endpoint: &'a ChainEndpoint) -> Result<Self> {
        let url = url::Url::parse(&endpoint.rpc_url).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        if url.scheme() != "https" && !(url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))) { return Err(GuardianSignError::AuthorizationMismatch); }
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_| GuardianSignError::EvidenceUnavailable)?;
        Ok(Self { endpoint, client })
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut response = self.client.post(&self.endpoint.rpc_url).json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).send().await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
        if !response.status().is_success() || response.content_length().is_some_and(|length|length>MAX_BODY_BYTES as u64) { return Err(GuardianSignError::EvidenceUnavailable); }
        let mut body=Vec::new();
        while let Some(chunk)=response.chunk().await.map_err(|_|GuardianSignError::EvidenceUnavailable)? {
            if chunk.len()>MAX_BODY_BYTES.saturating_sub(body.len()) { return Err(GuardianSignError::EvidenceUnavailable); }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body).map_err(|_| GuardianSignError::EvidenceUnavailable)?;
        if value.get("error").is_some() || value.get("id") != Some(&json!(1)) { return Err(GuardianSignError::EvidenceUnavailable); }
        value.get("result").filter(|value| !value.is_null()).cloned().ok_or(GuardianSignError::EvidenceUnavailable)
    }
    async fn block(&self, number: Value) -> Result<Value> { self.call("eth_getBlockByNumber", json!([number,false])).await }
    async fn eth_call(&self, address: Hex20, signature: &str, argument: Option<u64>, block: &Value) -> Result<[u8;32]> {
        let mut data = keccak256(signature.as_bytes())[..4].to_vec();
        if let Some(argument) = argument { data.extend_from_slice(&U256::from(argument).to_be_bytes::<32>()); }
        let value = self.call("eth_call", json!([{"to":address,"data":format!("0x{}",hex::encode(data))},block])).await?;
        bytes32(&value)
    }
}
fn quantity(value: &Value) -> Result<u64> {
    let text = value.as_str().and_then(|s| s.strip_prefix("0x")).ok_or(GuardianSignError::EvidenceMismatch)?;
    u64::from_str_radix(text,16).map_err(|_| GuardianSignError::EvidenceMismatch)
}
fn bytes32(value: &Value) -> Result<[u8;32]> {
    let text = value.as_str().and_then(|s| s.strip_prefix("0x")).ok_or(GuardianSignError::EvidenceMismatch)?;
    let mut bytes = [0;32]; hex::decode_to_slice(text, &mut bytes).map_err(|_| GuardianSignError::EvidenceMismatch)?; Ok(bytes)
}
fn block_hash(block: &Value) -> Result<[u8;32]> { bytes32(&block["hash"]) }
fn block_id(number: u64) -> Value { json!(format!("0x{number:x}")) }

async fn verify_identity(rpc: &CustodyRpc<'_>, chain: &ChainAuthorization, block: &Value) -> Result<()> {
    if rpc.endpoint.chain_index != chain.chain_index { return Err(GuardianSignError::AuthorizationMismatch); }
    let chain_id: U256 = serde_json::from_value(rpc.call("eth_chainId", json!([])).await?).map_err(|_| GuardianSignError::EvidenceMismatch)?;
    if chain_id != chain.chain_id || block_hash(&rpc.block(block_id(0)).await?)? != chain.genesis_hash.0 { return Err(GuardianSignError::EvidenceMismatch); }
    let provider_word = rpc.eth_call(chain.bridge,"addressesProvider()",None,block).await?;
    if provider_word[..12] != [0;12] { return Err(GuardianSignError::EvidenceMismatch); }
    let provider = Hex::<20>(provider_word[12..].try_into().map_err(|_|GuardianSignError::EvidenceMismatch)?);
    let mut data = keccak256(b"getAddress(bytes32)")[..4].to_vec(); data.extend_from_slice(keccak256(b"STATE_MANAGER").as_slice());
    let manager = bytes32(&rpc.call("eth_call",json!([{"to":provider,"data":format!("0x{}",hex::encode(data))},block])).await?)?;
    if manager[..12] != [0;12] || manager[12..] != chain.state_manager.0 || U256::from_be_bytes(rpc.eth_call(chain.state_manager,"l1ChainIndex()",None,block).await?) != U256::from(chain.chain_index) { return Err(GuardianSignError::EvidenceMismatch); }
    for (address, expected, implementation, implementation_hash) in [
        (chain.bridge,chain.bridge_code_hash,chain.bridge_implementation,chain.bridge_implementation_code_hash),
        (chain.state_manager,chain.state_manager_code_hash,chain.state_manager_implementation,chain.state_manager_implementation_code_hash),
    ] {
        for (address, expected) in [(address,expected),(implementation,implementation_hash)] {
            let code = rpc.call("eth_getCode",json!([address,block])).await?;
            let code = hex::decode(code.as_str().and_then(|s|s.strip_prefix("0x")).ok_or(GuardianSignError::EvidenceMismatch)?).map_err(|_|GuardianSignError::EvidenceMismatch)?;
            if code.is_empty() || keccak256(&code).as_slice() != expected.0 { return Err(GuardianSignError::EvidenceMismatch); }
        }
        if address != implementation {
            let slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
            let value = bytes32(&rpc.call("eth_getStorageAt",json!([address,slot,block])).await?)?;
            if value[..12] != [0;12] || value[12..] != implementation.0 { return Err(GuardianSignError::EvidenceMismatch); }
        }
    }
    Ok(())
}

pub(crate) async fn verify_chain_identity(endpoint: &ChainEndpoint, chain: &ChainAuthorization) -> Result<()> {
    let rpc = CustodyRpc::new(endpoint)?;
    let head = rpc.block(json!("latest")).await?;
    let number = quantity(&head["number"])?;
    let hash = block_hash(&head)?;
    let block = json!({ "blockHash": format!("0x{}", hex::encode(hash)), "requireCanonical": true });
    verify_identity(&rpc, chain, &block).await?;
    if block_hash(&rpc.block(block_id(number)).await?)? != hash { return Err(GuardianSignError::EvidenceMismatch); }
    Ok(())
}

async fn verify_ancestor(rpc: &CustodyRpc<'_>, number: u64, hash: [u8;32], finalized: &Value) -> Result<()> {
    if number > quantity(&finalized["number"])? { return Err(GuardianSignError::EvidenceUnavailable); }
    let canonical=rpc.block(block_id(number)).await?;
    if quantity(&canonical["number"])?!=number || block_hash(&canonical)?!=hash { return Err(GuardianSignError::EvidenceMismatch); }
    Ok(())
}

pub async fn finalized_deposit_anchor(endpoint: &ChainEndpoint, chain: &ChainAuthorization, old_count: u32, new_count: u32) -> Result<DepositAnchor> {
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    let number = quantity(&finalized["number"])?;
    verify_identity(&rpc, chain, &block_id(number)).await?;
    if old_count >= new_count { return Err(GuardianSignError::EvidenceMismatch); }
    Ok(DepositAnchor { chain_index: chain.chain_index, block_number: number, block_hash: Hex(block_hash(&finalized)?), old_count, new_count })
}

pub async fn verify_finalized_anchor(endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<()> {
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    verify_identity(&rpc,chain,&block_id(anchor.block_number)).await?;
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&finalized).await
}

pub async fn canonical_finalized_anchor_hash(endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<Hex32> {
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    if anchor.block_number > quantity(&finalized["number"])? { return Err(GuardianSignError::EvidenceUnavailable); }
    let canonical = rpc.block(block_id(anchor.block_number)).await?;
    let hash = block_hash(&canonical)?;
    verify_identity(&rpc,chain,&block_id(anchor.block_number)).await?;
    verify_ancestor(&rpc,anchor.block_number,hash,&finalized).await?;
    Ok(Hex(hash))
}

fn verify_cached_anchor_hash(canonical: Hex32, saved: Hex32) -> Result<(),super::verify::GuardianAccountError> {
    if canonical!=saved { return Err(super::verify::GuardianAccountError::Conflict(HaltReason::FinalityConflict)); }
    Ok(())
}

pub async fn verify_deposit_anchor(history: &super::verify::GuardianHistory, endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<(Hash4, Hash4),super::verify::GuardianAccountError> {
    tokio::time::timeout(std::time::Duration::from_secs(120),verify_deposit_interval(history,endpoint,chain,anchor)).await.map_err(|_|GuardianSignError::EvidenceUnavailable)?
}

async fn verify_deposit_interval(history: &super::verify::GuardianHistory, endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<(Hash4, Hash4),super::verify::GuardianAccountError> {
    if anchor.chain_index != chain.chain_index || anchor.old_count >= anchor.new_count || anchor.block_number < chain.deployment_block { return Err(GuardianSignError::EvidenceMismatch.into()); }
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&finalized).await?;
    let pinned = json!({"blockHash":anchor.block_hash,"requireCanonical":true});
    verify_identity(&rpc,chain,&pinned).await?;
    let pending = U256::from_be_bytes(rpc.eth_call(chain.bridge,"pendingDepositCount()",None,&pinned).await?);
    if pending < U256::from(anchor.new_count) { return Err(GuardianSignError::EvidenceMismatch.into()); }
    let approval=sha256(&serde_json::to_vec(chain).map_err(|_|GuardianSignError::AuthorizationMismatch)?);
    let key=(approval.0,endpoint.rpc_url.clone());
    let mut prefixes=history.deposit_prefixes.lock().await;
    let cached=prefixes.get(&key);
    if let Some(prefix)=cached {
        let canonical=canonical_finalized_anchor_hash(endpoint,chain,&prefix.anchor).await?;
        verify_cached_anchor_hash(canonical,prefix.anchor.block_hash)?;
        if prefix.anchor==*anchor && prefix.previous_count==anchor.old_count { return Ok((prefix.previous_root,prefix.root)); }
    }
    let reusable=cached.filter(|prefix|prefix.extends(anchor));
    let from_count=reusable.map_or(0,|prefix|prefix.count);
    let mut frontier=reusable.map_or([Hash4::ZERO;32],|prefix|prefix.frontier);
    let mut root=reusable.map_or_else(||<PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32),|prefix|prefix.root);
    let mut old_root=root;
    let mut event_block=reusable.map_or(chain.deployment_block,|prefix|prefix.event_block);
    let mut occupied_partial_page_hashes=reusable.map_or_else(Vec::new,|prefix|prefix.occupied_partial_page_hashes.clone());
    let advance=cached.is_none_or(|prefix|anchor.new_count>prefix.count);
    let (mut events, latest_event_block) = fetch_deposit_events(&rpc,chain,anchor,from_count,event_block,&pinned).await?;
    event_block = latest_event_block;
    for index in from_count..anchor.new_count {
        let leaf = events.remove(&index).map(|(leaf, _)| leaf).ok_or(GuardianSignError::EvidenceUnavailable)?;
        root = append_verified_deposit_leaf(&mut frontier, &mut occupied_partial_page_hashes, index, leaf);
        if index + 1 == anchor.old_count { old_root = root; }
    }
    if occupied_partial_page_hashes.len() != (anchor.new_count % 32) as usize { return Err(GuardianSignError::EvidenceMismatch.into()); }
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&rpc.block(json!("finalized")).await?).await?;
    if advance { prefixes.insert(key,VerifiedDepositPrefix {count:anchor.new_count,frontier,root,anchor:anchor.clone(),event_block,previous_count:anchor.old_count,previous_root:old_root,occupied_partial_page_hashes}); }
    Ok((old_root,root))
}

fn append_verified_deposit_leaf(frontier: &mut [Hash4;32], occupied_partial_page_hashes: &mut Vec<Hash4>, index: u32, leaf: Hash4) -> Hash4 {
    occupied_partial_page_hashes.push(leaf);
    if (index + 1) % 32 == 0 { occupied_partial_page_hashes.clear(); }
    append_leaf(frontier, index, leaf)
}


async fn fetch_deposit_events(rpc: &CustodyRpc<'_>, chain: &ChainAuthorization, anchor: &DepositAnchor, from_count: u32, mut event_block: u64, pinned: &Value) -> Result<(BTreeMap<u32,(Hash4,DepositLeafData)>,u64)> {
    let mut events = BTreeMap::new();
    let mut start=event_block;
    while start <= anchor.block_number {
        let end = start.saturating_add(4999).min(anchor.block_number);
        let logs = rpc.call("eth_getLogs",json!([{"address":chain.bridge,"fromBlock":block_id(start),"toBlock":block_id(end),"topics":[format!("{:#x}",DepositRecorded::SIGNATURE_HASH)]}])).await?;
        let logs: Vec<Log> = serde_json::from_value(logs).map_err(|_|GuardianSignError::EvidenceMismatch)?;
        for log in logs {
            let decoded = log.log_decode::<DepositRecorded>().map_err(|_|GuardianSignError::EvidenceMismatch)?;
            let event = decoded.data();
            if event.index < from_count || event.index >= anchor.new_count { continue; }
            if log.address().as_slice() != chain.bridge.0 || log.removed || events.contains_key(&event.index) || log.log_index.is_none() { return Err(GuardianSignError::EvidenceMismatch.into()); }
            let number = log.block_number.ok_or(GuardianSignError::EvidenceMismatch)?;
            event_block=event_block.max(number);
            let hash = log.block_hash.ok_or(GuardianSignError::EvidenceMismatch)?;
            let transaction = log.transaction_hash.ok_or(GuardianSignError::EvidenceMismatch)?;
            let canonical = rpc.block(block_id(number)).await?;
            if number > anchor.block_number || block_hash(&canonical)?.as_slice() != hash.as_slice() { return Err(GuardianSignError::EvidenceMismatch.into()); }
            let receipt = rpc.call("eth_getTransactionReceipt",json!([transaction])).await?;
            if quantity(&receipt["status"])? != 1 || quantity(&receipt["blockNumber"])? != number || bytes32(&receipt["blockHash"])?.as_slice() != hash.as_slice() || bytes32(&receipt["transactionHash"])?.as_slice() != transaction.as_slice() { return Err(GuardianSignError::EvidenceMismatch.into()); }
            let receipt_logs: Vec<Log> = serde_json::from_value(receipt["logs"].clone()).map_err(|_|GuardianSignError::EvidenceMismatch)?;
            let original = serde_json::to_value(&log).map_err(|_|GuardianSignError::EvidenceMismatch)?;
            if receipt_logs.iter().filter(|candidate| serde_json::to_value(candidate).ok().as_ref() == Some(&original)).count() != 1 { return Err(GuardianSignError::EvidenceMismatch.into()); }
            if event.chainIndex != chain.chain_index || event.l2TokenContractId.as_slice()[..28] != [0;28] { return Err(GuardianSignError::EvidenceMismatch.into()); }
            let id = u32::from_be_bytes(event.l2TokenContractId.as_slice()[28..].try_into().map_err(|_|GuardianSignError::EvidenceMismatch)?);
            if chain.token_mappings.iter().filter(|mapping| mapping.token.0.as_slice() == event.token.as_slice() && mapping.l2_contract_id == id).count() != 1 { return Err(GuardianSignError::EvidenceMismatch.into()); }
            let mut words = Vec::with_capacity(41);
            for bytes in [event.shieldAddress.0, U256::from_be_slice(event.token.as_slice()).to_be_bytes::<32>(),event.l2TokenContractId.0,event.amount.to_be_bytes::<32>()] {
                words.extend(bytes.chunks_exact(4).map(|word|u32::from_be_bytes(word.try_into().unwrap())));
            }
            words.push(u32::from(event.chainIndex));
            words.extend(event.noteCommitment.as_slice().chunks_exact(4).map(|word|u32::from_be_bytes(word.try_into().unwrap())));
            let bytes: Vec<u8> = words.iter().flat_map(|word|word.to_be_bytes()).collect();
            let hash = keccak256(&bytes);
            if hash != event.leafHash || rpc.eth_call(chain.bridge,"depositLeafHashes(uint256)",Some(u64::from(event.index)),pinned).await?.as_slice() != hash.as_slice() { return Err(GuardianSignError::EvidenceMismatch.into()); }
            let leaf = PsyHasher::q_hash_many(&words.into_iter().map(F::from_canonical_u32).collect::<Vec<_>>());
            events.insert(event.index,(leaf,DepositLeafData {
                shield_address: bytes32_words(&event.shieldAddress.0),
                token: address_words(event.token.as_slice()),
                l2_token_contract_id: bytes32_words(&event.l2TokenContractId.0),
                amount: bytes32_words(&event.amount.to_be_bytes::<32>()),
                chain_index: u32::from(event.chainIndex),
                note_commitment: bytes32_words(event.noteCommitment.as_slice()),
            }));
        }
        if end == anchor.block_number { break; }
        start = end + 1;
    }
    Ok((events,event_block))
}

pub(crate) async fn fetch_deposit_records(endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<Vec<DepositLeafData>> {
    if anchor.chain_index != chain.chain_index || anchor.old_count >= anchor.new_count || anchor.block_number < chain.deployment_block { return Err(GuardianSignError::EvidenceMismatch); }
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&finalized).await?;
    let pinned = json!({"blockHash":anchor.block_hash,"requireCanonical":true});
    verify_identity(&rpc,chain,&pinned).await?;
    if U256::from_be_bytes(rpc.eth_call(chain.bridge,"pendingDepositCount()",None,&pinned).await?) < U256::from(anchor.new_count) { return Err(GuardianSignError::EvidenceMismatch); }
    let (mut events, _) = fetch_deposit_events(&rpc,chain,anchor,0,chain.deployment_block,&pinned).await?;
    let records = (0..anchor.new_count).map(|index| events.remove(&index).map(|(_, record)| record).ok_or(GuardianSignError::EvidenceUnavailable)).collect::<Result<Vec<_>>>()?;
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&rpc.block(json!("finalized")).await?).await?;
    Ok(records)
}

pub fn append_leaf(frontier: &mut [Hash4;32], index: u32, leaf: Hash4) -> Hash4 {
    let mut current = leaf;
    let mut zero = Hash4::ZERO;
    for (level, left) in frontier.iter_mut().enumerate() {
        if (index >> level) & 1 == 0 { *left = current; current = PsyHasher::q_two_to_one(current,zero); }
        else { current = PsyHasher::q_two_to_one(*left,current); }
        zero = PsyHasher::q_two_to_one(zero,zero);
    }
    current
}

fn bytes32_words(bytes: &[u8]) -> [u32; 8] {
    std::array::from_fn(|index| u32::from_be_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap()))
}

fn address_words(address: &[u8]) -> [u32; 8] {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(address);
    bytes32_words(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn startup_checks_live_chain_identity_without_replacing_authorization() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for conflict in ["none", "genesis", "code", "implementation", "reorg"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = ChainEndpoint { chain_index: 0, rpc_url: format!("http://{}", listener.local_addr().unwrap()) };
            let chain = ChainAuthorization {
                chain_index: 0, chain_id: U256::from(31337), genesis_hash: Hex([1;32]),
                bridge: Hex([2;20]), state_manager: Hex([3;20]),
                bridge_code_hash: Hex(keccak256([0x60,0x00]).into()),
                bridge_implementation: Hex([4;20]), bridge_implementation_code_hash: Hex(keccak256([0x60,0x00]).into()),
                state_manager_code_hash: Hex(keccak256([0x60,0x00]).into()),
                state_manager_implementation: Hex([5;20]), state_manager_implementation_code_hash: Hex(keccak256([0x60,0x00]).into()),
                deployment_block: 1, token_mappings: vec![],
            };
            let retained = serde_json::to_vec(&chain).unwrap();
            let server = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut bytes = Vec::new();
                    let request: Value = loop {
                        let mut chunk = [0;4096];
                        let count = stream.read(&mut chunk).await.unwrap();
                        assert!(count > 0);
                        bytes.extend_from_slice(&chunk[..count]);
                        if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                            let length: usize = headers.lines().find_map(|line| line.strip_prefix("content-length:")).unwrap().trim().parse().unwrap();
                            if bytes.len() >= end + 4 + length { break serde_json::from_slice(&bytes[end+4..end+4+length]).unwrap(); }
                        }
                    };
                    let word = |byte: u8| json!(format!("0x{}{}", "00".repeat(12), hex::encode([byte;20])));
                    let method = request["method"].as_str().unwrap();
                    let params = &request["params"];
                    let result = match method {
                        "eth_getBlockByNumber" => {
                            let genesis = params[0] == "0x0";
                            let hash = if genesis { if conflict == "genesis" { 9 } else { 1 } }
                                else if conflict == "reorg" && params[0] == "0xa" { 9 } else { 6 };
                            json!({ "number": if genesis { "0x0" } else { "0xa" }, "hash": format!("0x{}", hex::encode([hash;32])) })
                        },
                        "eth_chainId" => json!("0x7a69"),
                        "eth_call" => {
                            assert_eq!(params[1]["requireCanonical"], true);
                            let data = params[0]["data"].as_str().unwrap();
                            if data.starts_with("0xc72c4d10") { word(7) }
                            else if data.starts_with("0x21f8a721") { word(3) }
                            else { json!(format!("0x{}", "00".repeat(32))) }
                        },
                        "eth_getCode" => {
                            assert_eq!(params[1]["requireCanonical"], true);
                            json!(if conflict == "code" { "0x6001" } else { "0x6000" })
                        },
                        "eth_getStorageAt" => {
                            assert_eq!(params[2]["requireCanonical"], true);
                            word(if conflict == "implementation" { 9 } else if params[0] == format!("0x{}", hex::encode([2;20])) { 4 } else { 5 })
                        },
                        _ => panic!("unexpected RPC {method}"),
                    };
                    let body = json!({ "jsonrpc":"2.0", "id":1, "result":result }).to_string();
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let result = verify_chain_identity(&endpoint, &chain).await;
            server.abort();
            assert_eq!(result.is_ok(), conflict == "none", "{conflict}: {result:?}");
            assert_eq!(serde_json::to_vec(&chain).unwrap(), retained);
        }
    }

    #[test]
    fn custody_frontier_only_reuses_contiguous_forward_interval() {
        let anchor=DepositAnchor {chain_index:0,block_number:100,block_hash:Hex([1;32]),old_count:0,new_count:2};
        let prefix=VerifiedDepositPrefix {count:2,frontier:[Hash4::ZERO;32],root:Hash4::ZERO,anchor:anchor.clone(),event_block:99,previous_count:0,previous_root:Hash4::ZERO,occupied_partial_page_hashes:vec![Hash4::ZERO;2]};
        let mut next=DepositAnchor {old_count:2,new_count:3,block_number:101,..anchor};
        assert!(prefix.extends(&next));
        next.old_count=1; assert!(!prefix.extends(&next));
        next.old_count=2; next.block_number=99; assert!(!prefix.extends(&next));
        next.block_number=100; assert!(prefix.extends(&next));
    }

    #[test]
    fn warm_prefix_keeps_only_current_partial_page_hashes() {
        let anchor=DepositAnchor {chain_index:0,block_number:100,block_hash:Hex([1;32]),old_count:30,new_count:35};
        let prefix=VerifiedDepositPrefix {count:30,frontier:[Hash4::ZERO;32],root:Hash4::ZERO,anchor:anchor.clone(),event_block:90,previous_count:0,previous_root:Hash4::ZERO,occupied_partial_page_hashes:vec![Hash4::ZERO;30]};
        assert!(prefix.extends(&anchor));
        assert_eq!(prefix.occupied_partial_page_hashes().len(), 30);
        let completed=DepositAnchor {old_count:32,new_count:40,..anchor};
        let boundary=VerifiedDepositPrefix {count:32,occupied_partial_page_hashes:Vec::new(),..prefix.clone()};
        assert!(boundary.extends(&completed));
        assert!(boundary.occupied_partial_page_hashes().is_empty());
        let stale=VerifiedDepositPrefix {occupied_partial_page_hashes:vec![Hash4::ZERO;29],..prefix};
        assert!(!stale.extends(&anchor));
    }

    #[test]
    fn cached_finalized_hash_contradiction_preserves_typed_halt_reason() {
        use super::super::verify::GuardianAccountError;
        assert!(verify_cached_anchor_hash(Hex([1;32]),Hex([1;32])).is_ok());
        assert!(matches!(verify_cached_anchor_hash(Hex([2;32]),Hex([1;32])),Err(GuardianAccountError::Conflict(HaltReason::FinalityConflict))));
        let unavailable=GuardianAccountError::from(GuardianSignError::EvidenceUnavailable);
        assert!(matches!(unavailable,GuardianAccountError::Unavailable(GuardianSignError::EvidenceUnavailable)));
    }

    #[test]
    fn production_page_boundary_keeps_thirty_one_then_clears() {
        let mut frontier = [Hash4::ZERO;32];
        let mut occupied = Vec::new();
        for index in 0..33 {
            append_verified_deposit_leaf(&mut frontier, &mut occupied, index, Hash4::ZERO);
            assert_eq!(occupied.len(), ((index + 1) % 32) as usize);
        }
    }
}
