use std::collections::BTreeMap;

use alloy_primitives::{keccak256, U256};
use alloy_rpc_types_eth::Log;
use alloy_sol_types::SolEvent;
use plonky2::field::{goldilocks_field::GoldilocksField as F, types::Field};
use psy_client_data::config::store_config::PsyHasher;
use psy_plonky2_common_circuits::bridge::deposit_batch_append_circuit::DepositLeafData;
use psy_crypto::hash::traits::hasher::{FieldQHasher, MerkleZeroHasher};
use serde_json::{json, Value};

use crate::bridge::deposit_logs::DepositRecorded;
use guardian_common::protocol::*;
use psy_config::ChainEndpoint;

type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

// DepositTreeState lives in guardian_common::protocol; this module only stages it.

struct CustodyRpc<'a> { endpoint: &'a ChainEndpoint, client: reqwest::Client }
impl<'a> CustodyRpc<'a> {
    fn new(endpoint: &'a ChainEndpoint) -> Result<Self> {
        validate_endpoint(&endpoint.rpc_url, false, false)?;
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_| GuardianSignError::L1RpcUnavailable)?;
        Ok(Self { endpoint, client })
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut response = self.client.post(&self.endpoint.rpc_url).json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).send().await.map_err(|_| GuardianSignError::L1RpcUnavailable)?;
        if !response.status().is_success() || response.content_length().is_some_and(|length|length>MAX_BODY_BYTES as u64) { return Err(GuardianSignError::L1RpcUnavailable); }
        let mut body=Vec::new();
        while let Some(chunk)=response.chunk().await.map_err(|_|GuardianSignError::L1RpcUnavailable)? {
            if chunk.len()>MAX_BODY_BYTES.saturating_sub(body.len()) { return Err(GuardianSignError::L1RpcUnavailable); }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body).map_err(|_| GuardianSignError::L1ResponseMismatch)?;
        if value.get("error").is_some() || value.get("id") != Some(&json!(1)) { return Err(GuardianSignError::L1ResponseMismatch); }
        value.get("result").filter(|value| !value.is_null()).cloned().ok_or(GuardianSignError::L1ResponseMismatch)
    }
    async fn block(&self, number: Value) -> Result<Value> { self.call("eth_getBlockByNumber", json!([number,false])).await }
    async fn eth_call(&self, address: Hex20, signature: &str, argument: Option<u64>, block: &Value) -> Result<[u8;32]> {
        let mut data = keccak256(signature.as_bytes())[..4].to_vec();
        if let Some(argument) = argument { data.extend_from_slice(&U256::from(argument).to_be_bytes::<32>()); }
        let value = self.call("eth_call", json!([{"to":address,"data":format!("0x{}",hex::encode(data))},block])).await?;
        bytes32(&value)
    }
}
/// CustodyRpc::new admits exactly what the config gate
/// `guardian_common::protocol::validate_endpoint(.., false, false)` admits:
/// HTTPS anywhere, plaintext HTTP only to std loopback (127.0.0.0/8, `[::1]`,
/// exact domain `localhost`), no userinfo credentials, no fragment, no redirects.
#[cfg(test)]
mod custody_url_parity {
    use super::*;

    fn admits(rpc_url: &str) -> bool {
        CustodyRpc::new(&ChainEndpoint { chain_index: 0, rpc_url: rpc_url.to_owned() }).is_ok()
    }

    /// Config admits the whole 127.0.0.0/8 range; the custody guard must not narrow it.
    #[test]
    fn http_admits_whole_127_8_range() {
        assert!(admits("http://127.0.0.1:8545"));
        assert!(admits("http://127.5.5.5:8545"));
        assert!(admits("http://127.255.255.255:8545"));
        assert!(admits("http://localhost:8545"));
    }

    /// Bracketed IPv6 loopback resolves via `url::Host::Ipv6`, not bracketed
    /// `host_str()` text — the old guard rejected these config-permitted URLs.
    #[test]
    fn http_admits_bracketed_ipv6_loopback() {
        assert!(admits("http://[::1]:8545"));
        assert!(admits("https://[::1]:8545"));
    }

    #[test]
    fn rejects_remote_plaintext() {
        assert!(!admits("http://10.0.0.1:8545"));
        assert!(!admits("http://192.168.1.1:8545"));
        assert!(!admits("http://example.com:8545"));
        assert!(!admits("http://[2001:db8::1]:8545"));
        // IPv4-mapped: `Ipv6Addr::is_loopback()` is false, same as config.
        assert!(!admits("http://[::ffff:127.0.0.1]:8545"));
    }

    #[test]
    fn rejects_dns_and_string_spoofs() {
        // Domain hosts that substring/endswith "127" or "localhost" would admit.
        assert!(!admits("http://localhost.example.com:8545"));
        assert!(!admits("http://notlocalhost:8545"));
        assert!(!admits("http://example.com/?redirect=127.0.0.1"));
        assert!(!admits("http://[::2]:8545"));
    }

    #[test]
    fn rejects_credentials_fragment_and_other_schemes() {
        assert!(!admits("http://user:pass@localhost:8545"));
        assert!(!admits("http://user@127.0.0.1:8545"));
        assert!(!admits("https://example.com#fragment"));
        assert!(!admits("ftp://localhost:8545"));
        assert!(!admits("not a url"));
    }
}

fn quantity(value: &Value) -> Result<u64> {
    let text = value.as_str().and_then(|s| s.strip_prefix("0x")).ok_or(GuardianSignError::L1ResponseMismatch)?;
    u64::from_str_radix(text,16).map_err(|_| GuardianSignError::L1ResponseMismatch)
}
fn bytes32(value: &Value) -> Result<[u8;32]> {
    let text = value.as_str().and_then(|s| s.strip_prefix("0x")).ok_or(GuardianSignError::L1ResponseMismatch)?;
    let mut bytes = [0;32]; hex::decode_to_slice(text, &mut bytes).map_err(|_| GuardianSignError::L1ResponseMismatch)?; Ok(bytes)
}
fn block_hash(block: &Value) -> Result<[u8;32]> { bytes32(&block["hash"]) }
fn block_id(number: u64) -> Value { json!(format!("0x{number:x}")) }

async fn verify_l1_chain(rpc: &CustodyRpc<'_>, chain: &ChainAuthorization, block: &Value) -> Result<()> {
    if rpc.endpoint.chain_index != chain.chain_index { return Err(GuardianSignError::AuthorizationMismatch); }
    let chain_id: U256 = serde_json::from_value(rpc.call("eth_chainId", json!([])).await?).map_err(|_| GuardianSignError::L1ResponseMismatch)?;
    if chain_id != chain.chain_id || block_hash(&rpc.block(block_id(0)).await?)? != chain.genesis_hash.0 { return Err(GuardianSignError::AuthorizationMismatch); }
    let provider_word = rpc.eth_call(chain.bridge,"addressesProvider()",None,block).await?;
    if provider_word[..12] != [0;12] { return Err(GuardianSignError::L1ResponseMismatch)?; }
    let provider = Hex::<20>(provider_word[12..].try_into().map_err(|_|GuardianSignError::L1ResponseMismatch)?);
    let mut data = keccak256(b"getAddress(bytes32)")[..4].to_vec(); data.extend_from_slice(keccak256(b"STATE_MANAGER").as_slice());
    let manager = bytes32(&rpc.call("eth_call",json!([{"to":provider,"data":format!("0x{}",hex::encode(data))},block])).await?)?;
    if manager[..12] != [0;12] || manager[12..] != chain.state_manager.0 || U256::from_be_bytes(rpc.eth_call(chain.state_manager,"l1ChainIndex()",None,block).await?) != U256::from(chain.chain_index) { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok(())
}

async fn verify_ancestor(rpc: &CustodyRpc<'_>, number: u64, hash: [u8;32], finalized: &Value) -> Result<()> {
    if canonical_ancestor_header(rpc, number, finalized).await? != hash { return Err(GuardianSignError::DepositMismatch); }
    Ok(())
}

async fn canonical_ancestor_header(rpc: &CustodyRpc<'_>, number: u64, finalized: &Value) -> Result<[u8;32]> {
    if number > quantity(&finalized["number"])? { return Err(GuardianSignError::FinalityPending); }
    let canonical = rpc.block(block_id(number)).await?;
    if quantity(&canonical["number"])? != number { return Err(GuardianSignError::L1ResponseMismatch); }
    block_hash(&canonical)
}

pub async fn finalized_deposit_anchor(endpoint: &ChainEndpoint, chain: &ChainAuthorization, old_count: u32, new_count: u32) -> Result<DepositAnchor> {
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    let number = quantity(&finalized["number"])?;
    verify_l1_chain(&rpc, chain, &block_id(number)).await?;
    if old_count >= new_count { return Err(GuardianSignError::DepositMismatch); }
    Ok(DepositAnchor { chain_index: chain.chain_index, block_number: number, block_hash: Hex(block_hash(&finalized)?), old_count, new_count })
}

pub async fn verify_finalized_anchor(endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<()> {
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    verify_l1_chain(&rpc,chain,&block_id(anchor.block_number)).await?;
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&finalized).await
}

/// Header-only saved-anchor evidence: bounded chain identity (current chain id plus
/// genesis header) plus the canonical finalized ancestry at the anchor height — the
/// same `verify_ancestor` bound: the saved anchor must sit at or below the finalized
/// height or this fails closed with `FinalityPending`. Approved addresses are
/// config-immutable under the current digest, so no historical eth_call/logs run.
/// Returns the canonical hash; the caller MUST compare it with the saved hash via
/// `verify_cached_anchor_hash` (typed `FinalityConflict` halt) before use — this
/// comparison is mandatory, not optional.
pub(crate) async fn verify_saved_deposit_anchor_headers(endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<Hex32> {
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    saved_anchor_canonical_hash(&rpc, chain, anchor, &finalized).await
}

/// Bounded header-only canonical evidence for an anchor against an already fetched
/// `finalized` block: current chain id, genesis header, and canonical finalized
/// ancestry at the anchor height (fail-closed `FinalityPending` when the anchor sits
/// above finalized). No historical eth_call or eth_getLogs. Shared by the standalone
/// check above and the saved deposit-tree-state reuse gate in `verify_deposit_interval`, which
/// already holds `finalized` and must not refetch it.
async fn saved_anchor_canonical_hash(rpc: &CustodyRpc<'_>, chain: &ChainAuthorization, anchor: &DepositAnchor, finalized: &Value) -> Result<Hex32> {
    let chain_id: U256 = serde_json::from_value(rpc.call("eth_chainId", json!([])).await?).map_err(|_| GuardianSignError::L1ResponseMismatch)?;
    if chain_id != chain.chain_id || block_hash(&rpc.block(block_id(0)).await?)? != chain.genesis_hash.0 { return Err(GuardianSignError::AuthorizationMismatch); }
    Ok(Hex(canonical_ancestor_header(rpc, anchor.block_number, finalized).await?))
}

pub(crate) fn verify_cached_anchor_hash(canonical: Hex32, saved: Hex32) -> Result<(),super::verify::GuardianAccountError> {
    if canonical!=saved { return Err(super::verify::GuardianAccountError::Conflict(HaltReason::FinalityConflict)); }
    Ok(())
}

/// Selects the exact durable reservation for this anchor (`count == anchor.new_count`,
/// `state.anchor == anchor`, `previous_count == anchor.old_count`). Selection alone
/// proves nothing about the stored body: the count/frontier/root validation and the
/// saved-anchor header/hash recheck run inside `verify_deposit_interval` for BOTH
/// this exact replay and the warm extend, so a caller cannot skip them.
fn exact_reserved_deposit_tree_state<'a>(reserved: Option<&'a DepositTreeState>, anchor: &DepositAnchor) -> Option<&'a DepositTreeState> {
    reserved.filter(|state| state.count == anchor.new_count && state.anchor == *anchor && state.previous_count == anchor.old_count)
}

/// True when `state` is a saved deposit-tree-state reuse candidate for `anchor`: an exact
/// replay of the anchor's own reservation (`exact_reserved_deposit_tree_state`) or a warm
/// forward extension of an earlier one (`DepositTreeState::extends`). Both
/// kinds pass the same body/header gate in `verify_deposit_interval`.
fn saved_deposit_tree_state_candidate(state: &DepositTreeState, anchor: &DepositAnchor) -> bool {
    exact_reserved_deposit_tree_state(Some(state), anchor).is_some() || state.extends(anchor)
}

/// Returns `(old_root, new_root, staged_state)` for the anchor's deposit interval.
/// Saved deposit-tree-state reuse — exact replay or warm forward extend — is fully gated INSIDE:
/// core `DepositTreeState::validate()` (count/frontier/root fold) plus bounded
/// header-only canonical evidence (`verify_saved_deposit_anchor_headers` +
/// `verify_cached_anchor_hash`) against the SAVED anchor, before the carried
/// frontier is used; no historical eth_call or eth_getLogs runs against the old
/// state and the new-batch checks are unchanged. The returned roots bind the
/// actual request opening ONLY through the caller's mandatory
/// `verify_chain_state(.., anchor.chain_index, anchor.old_count, old_root)` —
/// `matches_opening` compares the tip `(chain_index, count, root)` and, with
/// `count == anchor.new_count` on an exact replay, can never certify the opening
/// at `old_count`.
pub async fn verify_deposit_anchor(reserved: Option<&DepositTreeState>, endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<(Hash4, Hash4, DepositTreeState),super::verify::GuardianAccountError> {
    tokio::time::timeout(std::time::Duration::from_secs(120),verify_deposit_interval(reserved,endpoint,chain,anchor)).await.map_err(|_|GuardianSignError::L1RpcUnavailable)?
}

async fn verify_deposit_interval(reserved: Option<&DepositTreeState>, endpoint: &ChainEndpoint, chain: &ChainAuthorization, anchor: &DepositAnchor) -> Result<(Hash4, Hash4, DepositTreeState),super::verify::GuardianAccountError> {
    if anchor.chain_index != chain.chain_index { return Err(GuardianSignError::AuthorizationMismatch.into()); }
    if anchor.old_count >= anchor.new_count || anchor.block_number < chain.deployment_block { return Err(GuardianSignError::DepositMismatch.into()); }
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    // ANY saved deposit-tree-state reuse — exact replay or warm forward extend — is gated here so
    // a caller cannot skip it: the stored body must pass core
    // `DepositTreeState::validate()` (count/partial-page bindings, hash
    // canonicity, `frontier_root(count, frontier) == root`) BEFORE any new batch
    // fetch, and the SAVED anchor — not the request anchor — must still sit on the
    // canonical chain: an L1 reorg that rewrote the saved anchor's block invalidates
    // the carried frontier/root even when this anchor is a fresh forward extension
    // of it. Both checks are bounded header-only evidence (chain id, genesis header,
    // finalized ancestry): no historical eth_call or eth_getLogs runs against the
    // old state, and the new-batch checks below are unchanged.
    let reusable = match reserved {
        Some(state) if saved_deposit_tree_state_candidate(state, anchor) => {
            state.validate()?;
            let canonical = saved_anchor_canonical_hash(&rpc, chain, &state.anchor, &finalized).await?;
            verify_cached_anchor_hash(canonical, state.anchor.block_hash)?;
            Some(state)
        }
        _ => None,
    };
    if let Some(state) = exact_reserved_deposit_tree_state(reusable, anchor) {
        // Exact replay binds the actual request opening ONLY through the caller's
        // mandatory `verify_chain_state(.., anchor.chain_index, anchor.old_count,
        // old_root)` — `matches_opening` compares the tip `(chain_index, count,
        // root)` and, with `count == anchor.new_count` here, can never certify the
        // opening at `old_count`.
        return Ok((state.previous_root, state.root, state.clone()));
    }
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&finalized).await?;
    let pinned = json!({"blockHash":anchor.block_hash,"requireCanonical":true});
    verify_l1_chain(&rpc,chain,&pinned).await?;
    let pending = U256::from_be_bytes(rpc.eth_call(chain.bridge,"pendingDepositCount()",None,&pinned).await?);
    if pending < U256::from(anchor.new_count) { return Err(GuardianSignError::DepositMismatch.into()); }
    let from_count=reusable.map_or(0,|state|state.count);
    let mut frontier=reusable.map_or([Hash4::ZERO;32],|state|state.frontier);
    let mut root=reusable.map_or_else(||<PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32),|state|state.root);
    let mut old_root=root;
    let mut event_block=reusable.map_or(chain.deployment_block,|state|state.event_block);
    let mut occupied_partial_page_hashes=reusable.map_or_else(Vec::new,|state|state.occupied_partial_page_hashes.clone());
    let (mut events, latest_event_block) = fetch_deposit_events(&rpc,chain,anchor,from_count,event_block,&pinned).await?;
    event_block = latest_event_block;
    for index in from_count..anchor.new_count {
        let leaf = events.remove(&index).map(|(leaf, _)| leaf).ok_or(GuardianSignError::DepositMismatch)?;
        root = append_verified_deposit_leaf(&mut frontier, &mut occupied_partial_page_hashes, index, leaf);
        if index + 1 == anchor.old_count { old_root = root; }
    }
    if occupied_partial_page_hashes.len() != (anchor.new_count % 32) as usize { return Err(GuardianSignError::DepositMismatch.into()); }
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&rpc.block(json!("finalized")).await?).await?;
    Ok((old_root,root,DepositTreeState {count:anchor.new_count,frontier,root,anchor:anchor.clone(),event_block,previous_count:anchor.old_count,previous_root:old_root,occupied_partial_page_hashes}))
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
        let logs: Vec<Log> = serde_json::from_value(logs).map_err(|_|GuardianSignError::L1ResponseMismatch)?;
        for log in logs {
            let decoded = log.log_decode::<DepositRecorded>().map_err(|_|GuardianSignError::L1ResponseMismatch)?;
            let event = decoded.data();
            if event.index < from_count || event.index >= anchor.new_count { continue; }
            if log.address().as_slice() != chain.bridge.0 || log.removed || events.contains_key(&event.index) || log.log_index.is_none() { return Err(GuardianSignError::DepositMismatch.into()); }
            let number = log.block_number.ok_or(GuardianSignError::DepositMismatch)?;
            event_block=event_block.max(number);
            let hash = log.block_hash.ok_or(GuardianSignError::DepositMismatch)?;
            let transaction = log.transaction_hash.ok_or(GuardianSignError::DepositMismatch)?;
            let canonical = rpc.block(block_id(number)).await?;
            if number > anchor.block_number || block_hash(&canonical)?.as_slice() != hash.as_slice() { return Err(GuardianSignError::DepositMismatch.into()); }
            let receipt = rpc.call("eth_getTransactionReceipt",json!([transaction])).await?;
            if quantity(&receipt["status"])? != 1 || quantity(&receipt["blockNumber"])? != number || bytes32(&receipt["blockHash"])?.as_slice() != hash.as_slice() || bytes32(&receipt["transactionHash"])?.as_slice() != transaction.as_slice() { return Err(GuardianSignError::DepositMismatch.into()); }
            let receipt_logs: Vec<Log> = serde_json::from_value(receipt["logs"].clone()).map_err(|_|GuardianSignError::L1ResponseMismatch)?;
            let original = serde_json::to_value(&log).map_err(|_|GuardianSignError::L1ResponseMismatch)?;
            if receipt_logs.iter().filter(|candidate| serde_json::to_value(candidate).ok().as_ref() == Some(&original)).count() != 1 { return Err(GuardianSignError::DepositMismatch.into()); }
            if event.chainIndex != chain.chain_index || event.l2TokenContractId.as_slice()[..28] != [0;28] { return Err(GuardianSignError::DepositMismatch.into()); }
            let id = u32::from_be_bytes(event.l2TokenContractId.as_slice()[28..].try_into().map_err(|_|GuardianSignError::DepositMismatch)?);
            if chain.token_mappings.iter().filter(|mapping| mapping.token.0.as_slice() == event.token.as_slice() && mapping.l2_contract_id == id).count() != 1 { return Err(GuardianSignError::DepositMismatch.into()); }
            let mut words = Vec::with_capacity(41);
            for bytes in [event.shieldAddress.0, U256::from_be_slice(event.token.as_slice()).to_be_bytes::<32>(),event.l2TokenContractId.0,event.amount.to_be_bytes::<32>()] {
                words.extend(bytes.chunks_exact(4).map(|word|u32::from_be_bytes(word.try_into().unwrap())));
            }
            words.push(u32::from(event.chainIndex));
            words.extend(event.noteCommitment.as_slice().chunks_exact(4).map(|word|u32::from_be_bytes(word.try_into().unwrap())));
            let bytes: Vec<u8> = words.iter().flat_map(|word|word.to_be_bytes()).collect();
            let hash = keccak256(&bytes);
            if hash != event.leafHash || rpc.eth_call(chain.bridge,"depositLeafHashes(uint256)",Some(u64::from(event.index)),pinned).await?.as_slice() != hash.as_slice() { return Err(GuardianSignError::DepositMismatch.into()); }
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
    if anchor.chain_index != chain.chain_index { return Err(GuardianSignError::AuthorizationMismatch); }
    if anchor.old_count >= anchor.new_count || anchor.block_number < chain.deployment_block { return Err(GuardianSignError::DepositMismatch); }
    let rpc = CustodyRpc::new(endpoint)?;
    let finalized = rpc.block(json!("finalized")).await?;
    verify_ancestor(&rpc,anchor.block_number,anchor.block_hash.0,&finalized).await?;
    let pinned = json!({"blockHash":anchor.block_hash,"requireCanonical":true});
    verify_l1_chain(&rpc,chain,&pinned).await?;
    if U256::from_be_bytes(rpc.eth_call(chain.bridge,"pendingDepositCount()",None,&pinned).await?) < U256::from(anchor.new_count) { return Err(GuardianSignError::DepositMismatch); }
    let (mut events, _) = fetch_deposit_events(&rpc,chain,anchor,0,chain.deployment_block,&pinned).await?;
    let records = (0..anchor.new_count).map(|index| events.remove(&index).map(|(_, record)| record).ok_or(GuardianSignError::DepositMismatch)).collect::<Result<Vec<_>>>()?;
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
    use alloy_primitives::{Address, B256};
    use alloy_sol_types::SolEvent;
    use plonky2::field::types::Field;
    use psy_crypto::hash::traits::hasher::FieldQHasher;
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;


    #[test]
    fn custody_frontier_only_reuses_contiguous_forward_interval() {
        let anchor=DepositAnchor {chain_index:0,block_number:100,block_hash:Hex([1;32]),old_count:0,new_count:2};
        let state=DepositTreeState {count:2,frontier:[Hash4::ZERO;32],root:Hash4::ZERO,anchor:anchor.clone(),event_block:99,previous_count:0,previous_root:Hash4::ZERO,occupied_partial_page_hashes:vec![Hash4::ZERO;2]};
        let mut next=DepositAnchor {old_count:2,new_count:3,block_number:101,..anchor};
        assert!(state.extends(&next));
        next.old_count=1; assert!(!state.extends(&next));
        next.old_count=2; next.block_number=99; assert!(!state.extends(&next));
        next.block_number=100; assert!(state.extends(&next));
        let batch=DepositTreeState {count:32,occupied_partial_page_hashes:Vec::new(),..state};
        let full=DepositAnchor {old_count:32,new_count:64,block_number:102,..anchor};
        assert!(batch.extends(&full));
    }

    #[test]
    fn warm_state_keeps_only_current_partial_page_hashes() {
        let anchor=DepositAnchor {chain_index:0,block_number:100,block_hash:Hex([1;32]),old_count:30,new_count:35};
        let state=DepositTreeState {count:30,frontier:[Hash4::ZERO;32],root:Hash4::ZERO,anchor:anchor.clone(),event_block:90,previous_count:0,previous_root:Hash4::ZERO,occupied_partial_page_hashes:vec![Hash4::ZERO;30]};
        assert!(state.extends(&anchor));
        assert_eq!(state.occupied_partial_page_hashes().len(), 30);
        let completed=DepositAnchor {old_count:32,new_count:40,..anchor};
        let boundary=DepositTreeState {count:32,occupied_partial_page_hashes:Vec::new(),..state.clone()};
        assert!(boundary.extends(&completed));
        assert!(boundary.occupied_partial_page_hashes().is_empty());
        let stale=DepositTreeState {occupied_partial_page_hashes:vec![Hash4::ZERO;29],..state};
        assert!(!stale.extends(&anchor));
    }

    #[test]
    fn cached_finalized_hash_contradiction_preserves_typed_halt_reason() {
        use super::super::verify::GuardianAccountError;
        assert!(verify_cached_anchor_hash(Hex([1;32]),Hex([1;32])).is_ok());
        assert!(matches!(verify_cached_anchor_hash(Hex([2;32]),Hex([1;32])),Err(GuardianAccountError::Conflict(HaltReason::FinalityConflict))));
        let unavailable=GuardianAccountError::from(GuardianSignError::L1RpcUnavailable);
        assert!(matches!(unavailable,GuardianAccountError::Unavailable(GuardianSignError::L1RpcUnavailable)));
    }

    #[test]
    fn exact_reserved_deposit_tree_state_requires_matching_anchor() {
        let anchor=DepositAnchor {chain_index:0,block_number:100,block_hash:Hex([1;32]),old_count:2,new_count:5};
        let exact=DepositTreeState {count:5,frontier:[Hash4::ZERO;32],root:Hash4::ZERO,anchor:anchor.clone(),event_block:99,previous_count:2,previous_root:Hash4::ZERO,occupied_partial_page_hashes:vec![Hash4::ZERO;5]};
        assert!(exact_reserved_deposit_tree_state(Some(&exact),&anchor).is_some());
        assert!(exact_reserved_deposit_tree_state(None,&anchor).is_none());
        let drifted=DepositTreeState {previous_count:1,..exact.clone()};
        assert!(exact_reserved_deposit_tree_state(Some(&drifted),&anchor).is_none());
        let mismatched_count=DepositTreeState {count:6,..exact.clone()};
        assert!(exact_reserved_deposit_tree_state(Some(&mismatched_count),&anchor).is_none());
        let stale_anchor=DepositTreeState {anchor:DepositAnchor {block_number:99,..anchor.clone()},..exact};
        assert!(exact_reserved_deposit_tree_state(Some(&stale_anchor),&anchor).is_none());
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
    #[test]
    fn forward_extend_rechecks_saved_anchor_hash_before_frontier_use() {
        use super::super::verify::GuardianAccountError;
        let saved_anchor=DepositAnchor {chain_index:0,block_number:100,block_hash:Hex([1;32]),old_count:0,new_count:30};
        let mut frontier=[Hash4::ZERO;32];
        let mut root=Hash4::ZERO;
        for index in 0..30 { root=append_leaf(&mut frontier,index,Hash4::ZERO); }
        let state=DepositTreeState {count:30,frontier,root,anchor:saved_anchor.clone(),event_block:99,previous_count:0,previous_root:<PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32),occupied_partial_page_hashes:vec![Hash4::ZERO;30]};
        assert!(state.validate().is_ok());
        let next=DepositAnchor {old_count:30,new_count:35,block_number:101,..saved_anchor};
        assert!(state.extends(&next) && saved_deposit_tree_state_candidate(&state,&next));
        // An L1 reorg that rewrote the saved block yields a different canonical hash: typed halt before the frontier is used.
        assert!(matches!(verify_cached_anchor_hash(Hex([2;32]),state.anchor.block_hash),Err(GuardianAccountError::Conflict(HaltReason::FinalityConflict))));
        assert!(verify_cached_anchor_hash(state.anchor.block_hash,state.anchor.block_hash).is_ok());
    }

    #[test]
    fn corrupt_saved_frontier_fails_reuse_validation_before_batch_fetch() {
        let anchor=DepositAnchor {chain_index:0,block_number:100,block_hash:Hex([1;32]),old_count:2,new_count:5};
        let mut frontier=[Hash4::ZERO;32];
        let mut opening=Hash4::ZERO;
        for index in 0..2 { opening=append_leaf(&mut frontier,index,Hash4::ZERO); }
        let mut root=opening;
        for index in 2..5 { root=append_leaf(&mut frontier,index,Hash4::ZERO); }
        let mut state=DepositTreeState {count:5,frontier,root,anchor:anchor.clone(),event_block:99,previous_count:2,previous_root:opening,occupied_partial_page_hashes:vec![Hash4::ZERO;5]};
        assert!(saved_deposit_tree_state_candidate(&state,&anchor) && state.validate().is_ok());
        // Flip a stored frontier limb: the fold no longer matches the stored root, so the gate rejects before any new batch fetch.
        state.frontier[0]=state.root;
        assert!(state.validate().is_err());
    }

    const CHAIN_INDEX: u8 = 1;
    const CHAIN_ID: u64 = 97;
    const DEPLOYMENT_BLOCK: u64 = 50;
    const HEIGHT_A: u64 = 1_000;
    const HEIGHT_B: u64 = 1_005;
    const SAVED_COUNT: u32 = 100;
    const NEW_COUNT: u32 = 105;
    const TOKEN_ID: u32 = 7;
    const GENESIS: [u8; 32] = [0x01; 32];
    const HASH_A: [u8; 32] = [0x0a; 32];
    const HASH_B: [u8; 32] = [0x0b; 32];
    const HASH_A_REORG: [u8; 32] = [0x0c; 32];
    const BRIDGE: [u8; 20] = [0x11; 20];
    const STATE_MANAGER: [u8; 20] = [0x22; 20];
    const PROVIDER: [u8; 20] = [0x33; 20];
    const TOKEN: [u8; 20] = [0x44; 20];

    fn hex_word(value: u64) -> String { format!("0x{value:064x}") }
    fn hex_addr(bytes: &[u8]) -> String { format!("0x{}", hex::encode(bytes)) }
    fn word_addr(bytes: &[u8]) -> String { format!("0x{:0>64}", hex::encode(bytes)) }
    fn hex32(bytes: &[u8; 32]) -> String { format!("0x{}", hex::encode(bytes)) }
    fn header(number: u64, hash: [u8; 32]) -> serde_json::Value {
        serde_json::json!({"number": format!("0x{number:x}"), "hash": hex32(&hash)})
    }
    fn parse_qty(value: &serde_json::Value) -> Option<u64> {
        value.as_str().and_then(|text| text.strip_prefix("0x")).and_then(|text| u64::from_str_radix(text, 16).ok())
    }
    fn height_of_hash(hash: &str) -> Option<u64> {
        if hash == hex32(&HASH_A) { Some(HEIGHT_A) } else if hash == hex32(&HASH_B) { Some(HEIGHT_B) } else { None }
    }
    fn pending_count_at_height(height: u64) -> u64 {
        match height { HEIGHT_A => u64::from(SAVED_COUNT), HEIGHT_B => u64::from(NEW_COUNT), _ => panic!("pending count is keyed only by L1 height") }
    }
    fn selector(signature: &str) -> String { format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4])) }
    fn get_address_data() -> String {
        let mut data = keccak256(b"getAddress(bytes32)")[..4].to_vec();
        data.extend_from_slice(keccak256(b"STATE_MANAGER").as_slice());
        format!("0x{}", hex::encode(data))
    }
    fn u32_arg(data: &str) -> Option<u32> {
        let raw = data.strip_prefix("0x")?;
        if raw.len() != 8 + 64 { return None; }
        let bytes = hex::decode(raw).ok()?;
        if bytes[4..32].iter().any(|byte| *byte != 0) { return None; }
        Some(u32::from_be_bytes(bytes[32..].try_into().ok()?))
    }
    fn call_height(block: &serde_json::Value) -> Option<u64> {
        block.as_str().and_then(|tag| if tag == "finalized" { Some(HEIGHT_B) } else { parse_qty(block) })
            .or_else(|| block.get("blockHash").and_then(|hash| hash.as_str()).and_then(height_of_hash))
    }
    fn method(call: &serde_json::Value) -> &str { call["method"].as_str().unwrap_or("") }
    fn is_header(call: &serde_json::Value) -> bool { matches!(method(call), "eth_chainId" | "eth_getBlockByNumber") }
    fn is_body(call: &serde_json::Value) -> bool { matches!(method(call), "eth_call" | "eth_getLogs" | "eth_getTransactionReceipt") }
    fn saw_block(calls: &[serde_json::Value], height: u64) -> bool {
        calls.iter().any(|call| method(call) == "eth_getBlockByNumber" && parse_qty(&call["params"][0]) == Some(height))
    }
    fn is_historical(call: &serde_json::Value) -> bool {
        match method(call) {
            "eth_call" => call_height(&call["params"][1]) == Some(HEIGHT_A),
            "eth_getLogs" => parse_qty(&call["params"][0]["toBlock"]).is_some_and(|end| end < HEIGHT_B),
            _ => false,
        }
    }

    fn saved_deposit_tree_state() -> DepositTreeState {
        let anchor = DepositAnchor { chain_index: CHAIN_INDEX, block_number: HEIGHT_A, block_hash: Hex(HASH_A), old_count: 0, new_count: SAVED_COUNT };
        let mut frontier = [Hash4::ZERO; 32];
        let mut root = Hash4::ZERO;
        for index in 0..SAVED_COUNT { root = append_leaf(&mut frontier, index, Hash4::ZERO); }
        let state = DepositTreeState {
            count: SAVED_COUNT, frontier, root, anchor, event_block: HEIGHT_A, previous_count: 0,
            previous_root: <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32),
            occupied_partial_page_hashes: vec![Hash4::ZERO; (SAVED_COUNT % 32) as usize],
        };
        state.validate().expect("saved state is a real frontier fold");
        state
    }
    fn next_anchor(saved: &DepositAnchor) -> DepositAnchor {
        DepositAnchor { block_number: HEIGHT_B, block_hash: Hex(HASH_B), old_count: SAVED_COUNT, new_count: NEW_COUNT, ..saved.clone() }
    }
    fn chain() -> ChainAuthorization {
        ChainAuthorization {
            chain_index: CHAIN_INDEX, chain_id: U256::from(CHAIN_ID), genesis_hash: Hex(GENESIS),
            bridge: Hex(BRIDGE), state_manager: Hex(STATE_MANAGER), deployment_block: DEPLOYMENT_BLOCK,
            token_mappings: vec![TokenMapping { token: Hex(TOKEN), l2_contract_id: TOKEN_ID }],
        }
    }

    fn deposit_event(index: u32) -> (DepositRecorded, Hash4) {
        let mut shield = [0u8; 32];
        shield[31] = u8::try_from(index).unwrap();
        let mut l2_id = [0u8; 32];
        l2_id[28..].copy_from_slice(&TOKEN_ID.to_be_bytes());
        let amount = U256::from(1_000u64 + u64::from(index));
        let mut note = [0u8; 32];
        note[0] = 0x4e;
        note[28..].copy_from_slice(&index.to_be_bytes());
        let mut words = Vec::with_capacity(41);
        for bytes in [shield, U256::from_be_slice(TOKEN.as_slice()).to_be_bytes::<32>(), l2_id, amount.to_be_bytes::<32>()] {
            words.extend(bytes.chunks_exact(4).map(|word| u32::from_be_bytes(word.try_into().unwrap())));
        }
        words.push(u32::from(CHAIN_INDEX));
        words.extend(note.chunks_exact(4).map(|word| u32::from_be_bytes(word.try_into().unwrap())));
        let packed: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let leaf_hash = keccak256(&packed);
        let poseidon = PsyHasher::q_hash_many(&words.into_iter().map(F::from_canonical_u32).collect::<Vec<_>>());
        (DepositRecorded {
            index, shieldAddress: B256::new(shield), token: Address::new(TOKEN), l2TokenContractId: B256::new(l2_id),
            amount, chainIndex: CHAIN_INDEX, noteCommitment: B256::new(note), leafHash: leaf_hash,
        }, poseidon)
    }

    struct PreparedBatch { server: ServerBatch, poseidon: Vec<Hash4> }
    struct ServerBatch {
        logs: Vec<serde_json::Value>,
        receipts: std::collections::BTreeMap<String, serde_json::Value>,
        leaf_hashes: std::collections::BTreeMap<u32, B256>,
    }

    fn prepare_new_batch() -> PreparedBatch {
        let mut logs = Vec::new();
        let mut receipts = std::collections::BTreeMap::new();
        let mut leaf_hashes = std::collections::BTreeMap::new();
        let mut poseidon = Vec::new();
        for index in SAVED_COUNT..NEW_COUNT {
            let (event, leaf) = deposit_event(index);
            assert_ne!(event.leafHash, B256::ZERO, "new-batch leaf hash is a real commitment");
            let mut transaction = [0u8; 32];
            transaction[0] = 0x71;
            transaction[28..].copy_from_slice(&index.to_be_bytes());
            let log = alloy_rpc_types_eth::Log {
                inner: alloy_primitives::Log { address: Address::new(BRIDGE), data: event.encode_log_data() },
                block_hash: Some(B256::new(HASH_B)), block_number: Some(HEIGHT_B), block_timestamp: None,
                transaction_hash: Some(B256::new(transaction)), transaction_index: Some(0),
                log_index: Some(u64::from(index)), removed: false,
            };
            let value = serde_json::to_value(&log).unwrap();
            let tx = value["transactionHash"].as_str().unwrap().to_owned();
            receipts.insert(tx.clone(), serde_json::json!({
                "status": "0x1", "blockNumber": format!("0x{HEIGHT_B:x}"), "blockHash": hex32(&HASH_B),
                "transactionHash": tx, "logs": [value.clone()],
            }));
            logs.push(value);
            leaf_hashes.insert(index, event.leafHash);
            poseidon.push(leaf);
        }
        assert_eq!(leaf_hashes.len(), poseidon.len());
        PreparedBatch { server: ServerBatch { logs, receipts, leaf_hashes }, poseidon }
    }

    fn fold_new(state: &DepositTreeState, leaves: &[Hash4]) -> (Hash4, Vec<Hash4>) {
        let mut frontier = state.frontier;
        let mut occupied = state.occupied_partial_page_hashes.clone();
        let mut root = state.root;
        for (offset, leaf) in leaves.iter().copied().enumerate() {
            root = append_verified_deposit_leaf(&mut frontier, &mut occupied, SAVED_COUNT + u32::try_from(offset).unwrap(), leaf);
        }
        (root, occupied)
    }

    struct L1Fixture {
        url: String,
        calls: Arc<Mutex<Vec<serde_json::Value>>>,
        reorg: Arc<AtomicBool>,
        tamper_leaf: Arc<AtomicBool>,
        server: tokio::task::JoinHandle<()>,
    }
    impl Drop for L1Fixture {
        fn drop(&mut self) { self.server.abort(); }
    }
    impl L1Fixture {
        fn calls(&self) -> Vec<serde_json::Value> { self.calls.lock().unwrap().clone() }
        fn clear(&self) { self.calls.lock().unwrap().clear(); }
        fn endpoint(&self) -> ChainEndpoint { ChainEndpoint { chain_index: CHAIN_INDEX, rpc_url: self.url.clone() } }
    }

    fn dispatch(request: &serde_json::Value, batch: &ServerBatch, reorg: bool, tamper: bool) -> Result<serde_json::Value, &'static str> {
        let params = &request["params"];
        match request["method"].as_str().unwrap_or("") {
            "eth_chainId" => Ok(serde_json::json!(format!("0x{CHAIN_ID:x}"))),
            "eth_getBlockByNumber" => {
                if params[1] != serde_json::json!(false) { return Err("full blocks are unused"); }
                let tag = params[0].as_str().ok_or("block tag")?;
                if tag == "finalized" { return Ok(header(HEIGHT_B, HASH_B)); }
                let number = parse_qty(&params[0]).ok_or("block number")?;
                let hash = match number {
                    0 => GENESIS,
                    HEIGHT_A => if reorg { HASH_A_REORG } else { HASH_A },
                    HEIGHT_B => HASH_B,
                    _ => return Err("unexpected block height"),
                };
                Ok(header(number, hash))
            }
            "eth_call" => {
                let to = params[0]["to"].as_str().ok_or("call target")?;
                let data = params[0]["data"].as_str().ok_or("call data")?;
                let height = call_height(&params[1]).ok_or("call block")?;
                if height != HEIGHT_B { return Err("historical eth_call is refused"); }
                if to == hex_addr(&BRIDGE) && data == selector("addressesProvider()") { return Ok(serde_json::json!(word_addr(&PROVIDER))); }
                if to == hex_addr(&PROVIDER) && data == get_address_data() { return Ok(serde_json::json!(word_addr(&STATE_MANAGER))); }
                if to == hex_addr(&STATE_MANAGER) && data == selector("l1ChainIndex()") { return Ok(serde_json::json!(hex_word(u64::from(CHAIN_INDEX)))); }
                if to == hex_addr(&BRIDGE) && data == selector("pendingDepositCount()") { return Ok(serde_json::json!(hex_word(pending_count_at_height(height)))); }
                if to == hex_addr(&BRIDGE) && data.starts_with(&selector("depositLeafHashes(uint256)")) {
                    let index = u32_arg(data).ok_or("leaf index")?;
                    if tamper { return Ok(serde_json::json!(word_addr(&[0xab; 32]))); }
                    let hash = batch.leaf_hashes.get(&index).ok_or("unknown leaf")?;
                    return Ok(serde_json::json!(format!("0x{}", hex::encode(hash))));
                }
                Err("unexpected eth_call")
            }
            "eth_getLogs" => {
                let filter = &params[0];
                if filter["address"].as_str() != Some(hex_addr(&BRIDGE).as_str()) { return Err("logs address"); }
                let start = parse_qty(&filter["fromBlock"]).ok_or("fromBlock")?;
                let end = parse_qty(&filter["toBlock"]).ok_or("toBlock")?;
                if end < HEIGHT_B || start > HEIGHT_B { return Err("historical eth_getLogs is refused"); }
                Ok(serde_json::json!(batch.logs))
            }
            "eth_getTransactionReceipt" => {
                let tx = params[0].as_str().ok_or("receipt hash")?;
                batch.receipts.get(tx).cloned().ok_or("unknown receipt")
            }
            _ => Err("unexpected method"),
        }
    }

    async fn serve_l1(batch: ServerBatch) -> L1Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let reorg = Arc::new(AtomicBool::new(false));
        let tamper_leaf = Arc::new(AtomicBool::new(false));
        let recorded = calls.clone();
        let reorg_flag = reorg.clone();
        let tamper_flag = tamper_leaf.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { break };
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                let mut length = 0usize;
                loop {
                    line.clear();
                    if socket.read_line(&mut line).await.unwrap() == 0 { break; }
                    if line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") { length = value.trim().parse().unwrap(); }
                    }
                }
                let mut body = vec![0; length];
                if length > 0 { socket.read_exact(&mut body).await.unwrap(); }
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                recorded.lock().unwrap().push(request.clone());
                let response = match dispatch(&request, &batch, reorg_flag.load(Ordering::Relaxed), tamper_flag.load(Ordering::Relaxed)) {
                    Ok(result) => serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}),
                    Err(message) => serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":message}}),
                };
                let payload = response.to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len());
                socket.into_inner().write_all(response.as_bytes()).await.unwrap();
            }
        });
        L1Fixture { url, calls, reorg, tamper_leaf, server }
    }

    #[tokio::test]
    async fn saved_deposit_tree_state_reuses_headers_and_new_batch_checks_real_l1_evidence() {
        let prepared = prepare_new_batch();
        let fixture = serve_l1(prepared.server).await;
        let endpoint = fixture.endpoint();
        let authorized = chain();
        let state = saved_deposit_tree_state();
        let next = next_anchor(&state.anchor);
        assert!(state.extends(&next) && exact_reserved_deposit_tree_state(Some(&state), &state.anchor).is_some());
        assert_eq!(pending_count_at_height(HEIGHT_A), u64::from(SAVED_COUNT));
        assert_eq!(pending_count_at_height(HEIGHT_B), u64::from(NEW_COUNT));

        let canonical = verify_saved_deposit_anchor_headers(&endpoint, &authorized, &state.anchor).await.unwrap();
        assert_eq!(canonical, Hex(HASH_A));
        assert!(verify_cached_anchor_hash(canonical, state.anchor.block_hash).is_ok());
        let headers = fixture.calls();
        assert!(headers.iter().all(is_header) && saw_block(&headers, HEIGHT_A) && !headers.iter().any(is_body));
        fixture.clear();

        let (old_root, new_root, staged) = verify_deposit_anchor(Some(&state), &endpoint, &authorized, &state.anchor).await.unwrap();
        assert_eq!((old_root, new_root), (state.previous_root, state.root));
        assert_eq!(&staged, &state);
        let restart = fixture.calls();
        assert!(restart.iter().all(is_header), "exact reserved restart is headers only: {restart:?}");
        assert!(saw_block(&restart, HEIGHT_A) && !saw_block(&restart, HEIGHT_B) && !restart.iter().any(is_body));
        fixture.clear();

        let (old_root, new_root, staged) = verify_deposit_anchor(Some(&state), &endpoint, &authorized, &next).await.unwrap();
        let (expected_root, expected_occupied) = fold_new(&state, &prepared.poseidon);
        assert_eq!(old_root, state.root);
        assert_eq!(new_root, expected_root);
        assert_eq!(staged.count, NEW_COUNT);
        assert_eq!(staged.previous_count, SAVED_COUNT);
        assert_eq!(staged.event_block, HEIGHT_B);
        assert_eq!(staged.occupied_partial_page_hashes, expected_occupied);
        let calls = fixture.calls();
        assert!(calls.iter().all(|call| !is_historical(call)), "old anchor forbids historical eth_call/logs: {calls:?}");
        let body_at = calls.iter().position(is_body).expect("new batch fetches evidence");
        assert!(calls[..body_at].iter().all(is_header) && saw_block(&calls[..body_at], HEIGHT_A));
        let logs: Vec<_> = calls.iter().filter(|call| method(call) == "eth_getLogs").collect();
        assert_eq!(logs.len(), 1);
        assert_eq!(parse_qty(&logs[0]["params"][0]["fromBlock"]), Some(HEIGHT_A));
        assert_eq!(parse_qty(&logs[0]["params"][0]["toBlock"]), Some(HEIGHT_B));
        let pending: Vec<_> = calls.iter().filter(|call| method(call) == "eth_call" && call["params"][0]["data"] == selector("pendingDepositCount()")).collect();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["params"][0]["data"].as_str().unwrap().len(), 10);
        assert_eq!(call_height(&pending[0]["params"][1]), Some(HEIGHT_B));
        let leaves: Vec<_> = calls.iter().filter(|call| method(call) == "eth_call" && call["params"][0]["data"].as_str().unwrap_or("").starts_with(&selector("depositLeafHashes(uint256)"))).collect();
        let indexes: Vec<_> = leaves.iter().map(|call| u32_arg(call["params"][0]["data"].as_str().unwrap()).unwrap()).collect();
        assert_eq!(indexes, (SAVED_COUNT..NEW_COUNT).collect::<Vec<_>>());
        assert!(leaves.iter().all(|call| call_height(&call["params"][1]) == Some(HEIGHT_B)));
        let receipts: std::collections::BTreeSet<_> = calls.iter().filter(|call| method(call) == "eth_getTransactionReceipt").map(|call| call["params"][0].as_str().unwrap().to_owned()).collect();
        assert_eq!(receipts.len(), usize::try_from(NEW_COUNT - SAVED_COUNT).unwrap());
    }

    #[tokio::test]
    async fn saved_anchor_reorg_is_typed_finality_conflict_before_new_fetch() {
        use super::super::verify::GuardianAccountError;
        let prepared = prepare_new_batch();
        let fixture = serve_l1(prepared.server).await;
        fixture.reorg.store(true, Ordering::Relaxed);
        let endpoint = fixture.endpoint();
        let state = saved_deposit_tree_state();
        let error = verify_deposit_anchor(Some(&state), &endpoint, &chain(), &next_anchor(&state.anchor)).await.unwrap_err();
        assert!(matches!(error, GuardianAccountError::Conflict(HaltReason::FinalityConflict)), "{error:?}");
        let calls = fixture.calls();
        assert!(calls.iter().all(is_header) && saw_block(&calls, HEIGHT_A) && !saw_block(&calls, HEIGHT_B) && !calls.iter().any(is_body), "{calls:?}");
    }

    #[tokio::test]
    async fn corrupt_saved_frontier_rejects_before_new_batch_fetch() {
        use super::super::verify::GuardianAccountError;
        let prepared = prepare_new_batch();
        let fixture = serve_l1(prepared.server).await;
        let endpoint = fixture.endpoint();
        let mut state = saved_deposit_tree_state();
        let next = next_anchor(&state.anchor);
        assert!(state.extends(&next) && state.validate().is_ok());
        // Count 100 = 0b1100100 folds frontier levels 2, 5, 6; an unused level-0 slot leaves the fold valid, so corrupt an occupied level-2 node.
        state.frontier[2] = state.root;
        assert!(state.validate().is_err());
        let error = verify_deposit_anchor(Some(&state), &endpoint, &chain(), &next).await.unwrap_err();
        assert!(matches!(error, GuardianAccountError::Unavailable(GuardianSignError::DepositMismatch)), "{error:?}");
        let calls = fixture.calls();
        assert!(calls.iter().all(|call| !is_body(call)), "no L1 new-batch fetch before frontier validation: {calls:?}");
        assert_eq!(calls.len(), 1);
        assert_eq!(method(&calls[0]), "eth_getBlockByNumber");
        assert_eq!(calls[0]["params"][0], "finalized");
    }

    #[tokio::test]
    async fn new_batch_rejects_leaf_hash_that_is_not_the_event_commitment() {
        use super::super::verify::GuardianAccountError;
        let prepared = prepare_new_batch();
        let fixture = serve_l1(prepared.server).await;
        fixture.tamper_leaf.store(true, Ordering::Relaxed);
        let endpoint = fixture.endpoint();
        let state = saved_deposit_tree_state();
        let error = verify_deposit_anchor(Some(&state), &endpoint, &chain(), &next_anchor(&state.anchor)).await.unwrap_err();
        assert!(matches!(error, GuardianAccountError::Unavailable(GuardianSignError::DepositMismatch)), "{error:?}");
        let calls = fixture.calls();
        assert!(calls.iter().any(|call| method(call) == "eth_call" && call["params"][0]["data"].as_str().unwrap_or("").starts_with(&selector("depositLeafHashes(uint256)"))));
        assert!(calls.iter().any(|call| method(call) == "eth_getTransactionReceipt"));
        assert!(calls.iter().all(|call| !is_historical(call)));
    }
}
