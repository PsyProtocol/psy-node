//! Thin wrapper over `psy_prover::session::WalletSession` — the real Psy wallet
//! engine. Every capability here maps 1:1 to a WalletSession method, so the MCP
//! server gets REAL client-side Plonky2 proving (not a mock): registration,
//! public/private transfers, and claim/UPS batching all go through the same
//! prove-proxy trace flow the CLI and web wallets use.
//!
//! Construction mirrors the proven CLI path
//! (psy_cli/psy_user_cli/src/subcommand/submit_end_cap_proof.rs):
//!   PsyConfigGoldilocks::from_file(config.json)
//!     → get_current_network()  (carries prove_proxy_url + api_services_url)
//!     → WalletSession::new(&rpc_config)
//!     → add_user(private_key, fingerprint)
//!     → exec_contract_call(pk_hash, ContractCallData) / claim_batch(...)

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use plonky2::field::{goldilocks_field::GoldilocksField as F, types::PrimeField64};
use psy_client_common::{
    args::{ContractCallArgs, ContractCallData},
    data::{alt::AltVerifierOnlyCircuitData, qhashout::QHashOut},
};
use psy_client_data::{
    privacy::private_note_inclusion::PrivateNoteInclusionInput,
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_crypto::{
    hash::{
        merkle::core::MerkleProofCore,
        traits::hasher::{FieldQHasher, PoseidonHasher},
    },
    shield_address::{derive_note_commitment, derive_shield_address},
};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Public alias so main.rs's drain pre-check can reuse the same derivation
/// without importing the psy_crypto dep directly.
pub fn derive_shield_address_pub(user_id: u64, r0: u64, r1: u64) -> QHashOut<F> {
    derive_shield_address(user_id, r0, r1)
}

const PRIVACY_R0_PREFIX: &[u8] = b"psy-privacy-v0-r0";
const PRIVACY_R1_PREFIX: &[u8] = b"psy-privacy-v0-r1";
const PRIVACY_NOSTR_PREFIX: &[u8] = b"psy-privacy-v0-nostr";
const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        normalized_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut outer_pad = [0x5cu8; BLOCK_SIZE];
    let mut inner_pad = [0x36u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_pad[i] ^= normalized_key[i];
        inner_pad[i] ^= normalized_key[i];
    }
    let inner_hash = Sha256::new().chain_update(inner_pad).chain_update(data).finalize();
    Sha256::new().chain_update(outer_pad).chain_update(inner_hash).finalize().into()
}

/// Wallet-compatible `psy-privacy-v0` receive-key derivation.
fn derive_receive_secrets(private_key_hex: &str, derive_index: u64) -> Result<(u64, u64, [u8; 32])> {
    let private_key = hex::decode(private_key_hex.trim_start_matches("0x"))
        .context("decode wallet private key for privacy derivation")?;
    let mut index = [0u8; 32];
    index[24..].copy_from_slice(&derive_index.to_be_bytes());

    let derive_scalar = |prefix: &[u8]| {
        let mut data = Vec::with_capacity(prefix.len() + index.len());
        data.extend_from_slice(prefix);
        data.extend_from_slice(&index);
        let mac = hmac_sha256(&private_key, &data);
        u64::from_be_bytes(mac[..8].try_into().expect("eight-byte HMAC prefix")) % GOLDILOCKS_MODULUS
    };
    let random0 = derive_scalar(PRIVACY_R0_PREFIX);
    let random1 = derive_scalar(PRIVACY_R1_PREFIX);

    let mut nostr_data = Vec::with_capacity(PRIVACY_NOSTR_PREFIX.len() + 16);
    nostr_data.extend_from_slice(PRIVACY_NOSTR_PREFIX);
    nostr_data.extend_from_slice(&random0.to_be_bytes());
    nostr_data.extend_from_slice(&random1.to_be_bytes());
    let nostr_secret = hmac_sha256(&private_key, &nostr_data);
    Ok((random0, random1, nostr_secret))
}

/// Normalize either legacy native proof bytes or current bincode proof bytes
/// into the strict envelope consumed by wallet WASM.
pub fn normalize_private_note_proof_envelope(raw: &str, contract_id: u64) -> Result<String> {
    let mut envelope: serde_json::Value = serde_json::from_str(raw).context("parse private-note proof envelope")?;
    let object = envelope.as_object_mut().ok_or_else(|| anyhow!("private-note proof envelope must be an object"))?;
    let encoded = object
        .get("note_proof_bincode_b64")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("private-note proof envelope is missing note_proof_bincode_b64"))?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).context("decode private-note proof base64")?;
    let circuit = PrivateNoteInclusionCircuit::<C, D>::new(
        psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize,
        psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
        psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
        NOTE_TREE_HEIGHT,
    );
    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&bytes).or_else(|bincode_error| {
        ProofWithPublicInputs::<F, C, D>::from_bytes(bytes, circuit.get_common_circuit_data_ref())
            .map_err(|native_error| anyhow!("private-note proof decode failed (bincode={bincode_error}; native={native_error})"))
    })?;
    let normalized = bincode::serialize(&proof).context("serialize private-note proof as bincode")?;
    let fingerprint = circuit.get_fingerprint().0.elements.map(|value| value.to_canonical_u64().to_string());
    object.insert(
        "note_proof_bincode_b64".into(),
        serde_json::Value::String(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, normalized)),
    );
    object.insert("note_proof_fingerprint".into(), serde_json::to_value(fingerprint)?);
    let verifier_data = AltVerifierOnlyCircuitData::from(circuit.get_verifier_config_ref());
    object.insert("note_verifier_data".into(), serde_json::to_value(verifier_data)?);
    object.insert("token_contract_id".into(), serde_json::Value::String(contract_id.to_string()));
    Ok(serde_json::to_string(&envelope)?)
}

use nostr::ToBech32;
use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};
use psy_client_data::config::store_config::{C, D};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_dpn_circuit::circuits::privacy::private_note_inclusion::PrivateNoteInclusionCircuit;
use psy_prover::session::{ClaimBatchItem, PrivateTransferClaim, WalletSession};
pub use qhash_to_u64x4 as qhash_to_u64x4_pub;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};

use crate::agent_account::{self, Capability, CapabilityRequest, Mandate};
pub use crate::network::NetworkId;

/// A private transfer that has been fully computed but NOT submitted. Holds the
/// exact on-chain call and the note material the recipient needs to claim. Kept
/// separate from submission because delivering the note (over Nostr) to the
/// recipient is what makes the funds claimable, and that delivery format must
/// be verified against recipient wallets before an agent settles real value —
/// see the `private_transfer` tool docs.
#[derive(Debug)]
pub struct PreparedPrivateTransfer {
    pub contract_id: u64,
    pub amount: u64,
    pub owner: [u64; 4],
    pub note_commitment: [u64; 4],
    pub note_secret: [u64; 4],
    pub nullifier_secret: [u64; 4],
    /// The `private_transfer` call inputs: [owner×4, amount,
    /// note_commitment×4].
    pub call_inputs: Vec<u64>,
}

/// Shield-address hex in ELEMENTS order (`0xL0:0xL1:0xL2:0xL3`, or the bare
/// 64-hex concatenation) — the convention the web wallets and the s2 Base58
/// form use. This is NOT `QHashOut`'s serde/Display hex: that one byte-reverses
/// the packed limbs, so reading it left-to-right yields [el3, el2, el1, el0].
/// Two conventions, two functions — never mix them. Cross-wallet private
/// transfers silently stranded funds on exactly this confusion (2026-08-15).
fn qhash_to_elements_hex(value: QHashOut<F>) -> String {
    let limbs = qhash_to_u64x4(value);
    limbs.iter().map(|l| format!("{l:016x}")).collect::<Vec<_>>().join(":")
}

fn shield_address_base58(value: QHashOut<F>) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut payload = Vec::with_capacity(38);
    payload.extend_from_slice(&[0x05, 0xd4]);
    for limb in qhash_to_u64x4(value) {
        payload.extend_from_slice(&limb.to_be_bytes());
    }
    let first = Sha256::digest(&payload);
    let second = Sha256::digest(first);
    payload.extend_from_slice(&second[..4]);

    let leading_zeroes = payload.iter().take_while(|byte| **byte == 0).count();
    let mut digits = vec![0u8];
    for byte in payload {
        let mut carry = byte as u32;
        for digit in &mut digits {
            carry += (*digit as u32) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut encoded = String::with_capacity(leading_zeroes + digits.len());
    encoded.extend(std::iter::repeat_n('1', leading_zeroes));
    encoded.extend(digits.iter().rev().map(|digit| ALPHABET[*digit as usize] as char));
    encoded
}

/// Parse a shield address in elements order: `0xL0:...:L3` canonical, a bare
/// 64-hex blob, or limb-per-colon hex. Returns the limbs as elements.
pub fn parse_shield_elements_hex_pub(raw: &str) -> Result<[u64; 4]> {
    let s = raw.trim();
    if s.contains(':') {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            anyhow::bail!("shielded address must have 4 limbs");
        }
        let mut out = [0u64; 4];
        for (i, p) in parts.iter().enumerate() {
            out[i] = u64::from_str_radix(p.trim().trim_start_matches("0x"), 16).with_context(|| format!("limb {i} is not hex"))?;
        }
        return Ok(out);
    }
    let clean = s.trim_start_matches("0x").trim_start_matches("0X");
    if clean.len() == 64 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u64; 4];
        for (i, limb) in clean.as_bytes().chunks(16).enumerate() {
            let limb = std::str::from_utf8(limb)?;
            out[i] = u64::from_str_radix(limb, 16).with_context(|| format!("limb {i}"))?;
        }
        return Ok(out);
    }
    // Base58Check shield (the web wallets' copy form): 2-byte version
    // 0x05d4 + 32 payload bytes (four BE u64 limbs, elements order) + 4-byte
    // sha256d checksum.
    // Do not gate this on a textual prefix: with this version and arbitrary
    // field payloads the first two characters can be s1, s2, or s3.
    if !s.is_empty() {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut n = [0u8; 64]; // little-endian base-256 digits
        let mut n_len = 0usize;
        for c in s.bytes() {
            let val = ALPHABET
                .iter()
                .position(|a| *a == c)
                .ok_or_else(|| anyhow::anyhow!("invalid base58 character"))? as u32;
            // n = n*58 + val: multiply LSB→MSB, carry propagates upward.
            let mut carry = val;
            for digit in n.iter_mut().take(n_len) {
                let x = (*digit as u32) * 58 + carry;
                *digit = (x & 0xff) as u8;
                carry = x >> 8;
            }
            while carry > 0 {
                if n_len >= n.len() {
                    anyhow::bail!("shielded address too long");
                }
                n[n_len] = (carry & 0xff) as u8;
                carry >>= 8;
                n_len += 1;
            }
        }
        // big-endian bytes = reverse of our little-endian accumulation
        let raw: Vec<u8> = n[..n_len].iter().rev().copied().collect();
        if raw.len() != 38 {
            anyhow::bail!("Base58Check shield address decoded to {} bytes, expected 38", raw.len());
        }
        anyhow::ensure!(raw[..2] == [0x05, 0xd4], "unsupported shield address version");
        let digest1 = Sha256::digest(&raw[..34]);
        let digest2 = Sha256::digest(digest1);
        anyhow::ensure!(raw[34..] == digest2[..4], "invalid shield address checksum");
        let payload = &raw[2..34];
        let mut out = [0u64; 4];
        for (i, chunk) in payload.chunks(8).enumerate() {
            let mut v: u64 = 0;
            for b in chunk {
                v = (v << 8) | *b as u64;
            }
            out[i] = v;
        }
        return Ok(out);
    }
    anyhow::bail!("invalid recipient shielded address (expected elements-order hex or Base58Check)");
}

pub fn qhash_to_u64x4(value: QHashOut<F>) -> [u64; 4] {
    [
        value.0.elements[0].to_canonical_u64(),
        value.0.elements[1].to_canonical_u64(),
        value.0.elements[2].to_canonical_u64(),
        value.0.elements[3].to_canonical_u64(),
    ]
}

/// True when a submission failed because the chain advanced while the wallet
/// was building the tx. The session snapshots the user leaf when the wallet
/// loads; any tx that settles afterwards (a claim landing, an earlier spend)
/// makes the next spend build on a stale leaf, and the chain rejects it with
/// one of these two messages. Both mean "rebuild on the latest state" — never
/// "already spent" — so re-syncing the user and retrying once is safe and
/// cannot double-settle.
fn is_stale_state_error(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("Invalid start_user_leaf_hash") || s.contains("stale nonce")
}

/// Token contract ids on the current chain (config-independent constants used
/// for the convenience transfer/balance helpers). Generic calls can target any
/// contract id directly.
pub const CONTRACT_PSY: u64 = 0;
pub const CONTRACT_USDT: u64 = 4;

/// How long to wait for the coordinator to mint a user id after registration.
/// Checkpoints on a public network are tens of seconds and registration needs
/// roughly two of them, so this allows generous headroom without hanging an
/// agent forever.
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(300);
const REGISTRATION_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The loaded user identity (public, non-secret).
///
/// `mandate` is set only for SDKey agent accounts: it is the set of
/// capabilities compiled into the identity's circuit. A plain key wallet has
/// none — its authority is unrestricted at the circuit level and bounded only
/// by policy.
#[derive(Clone, Debug)]
pub struct LoadedUser {
    pub pk_hash: QHashOut<F>,
    pub user_id: u64,
    /// Circuit fingerprint is part of the wallet identity and must survive reloads.
    pub fingerprint: QHashOut<F>,
    pub mandate: Option<Mandate>,
    /// Kept in memory (never serialized) so the wallet can re-derive its
    /// private receive identity — the shielded address' blinding factors
    /// must come from the key, or the address becomes linkable to the
    /// public user id.
    pub private_key: QHashOut<F>,
}

/// A freshly minted agent account plus whatever the caller's key-backup step
/// produced (typically the path the key was written to).
pub struct MintedAgentAccount<P> {
    pub user: LoadedUser,
    pub key_backup: P,
}

pub struct EndpointSummary {
    pub coordinator: Vec<String>,
    pub realm: Vec<String>,
    pub prove_proxy: Vec<String>,
    pub api_services: Vec<String>,
}

struct NetworkWallet {
    session: WalletSession,
    users: HashMap<String, LoadedUser>,
    active_user: Option<String>,
}

impl NetworkWallet {
    fn activate(&mut self, user: LoadedUser) {
        let pk_hash = user.pk_hash.to_string();
        self.users.insert(pk_hash.clone(), user);
        self.active_user = Some(pk_hash);
    }

    fn current_user(&self) -> Option<&LoadedUser> {
        self.active_user.as_ref().and_then(|pk_hash| self.users.get(pk_hash))
    }

    fn list_users(&self) -> Vec<&LoadedUser> {
        let mut users = self.users.values().collect::<Vec<_>>();
        users.sort_by_key(|user| user.user_id);
        users
    }

    fn select_user(&mut self, selector: &str) -> Option<LoadedUser> {
        let selected = if let Ok(user_id) = selector.parse::<u64>() {
            self.users.values().find(|user| user.user_id == user_id)
        } else {
            self.users.get(selector)
        }?
        .clone();
        self.active_user = Some(selected.pk_hash.to_string());
        Some(selected)
    }

    fn require_user(&self) -> Result<LoadedUser> {
        self.current_user()
            .cloned()
            .ok_or_else(|| anyhow!("no wallet loaded — call create_wallet/load first"))
    }

    fn require_user_id(&self, expected_user_id: u64) -> Result<LoadedUser> {
        let user = self.require_user()?;
        if user.user_id != expected_user_id {
            anyhow::bail!(
                "active wallet changed after authorization: expected Psy-{expected_user_id:08}, found Psy-{:08}; refusing to sign",
                user.user_id
            );
        }
        Ok(user)
    }

    async fn latest_checkpoint(&self) -> Result<u64> {
        Ok(self.session.st_provider.get_coordinator_latest_block_state().await?.checkpoint_id)
    }

    async fn claim_amount_from(&self, sender_user_id: u64) -> Result<u64> {
        let user = self.require_user()?;
        let checkpoint = self.latest_checkpoint().await?;
        self.session.st_provider.get_claim_amount(checkpoint, user.user_id, sender_user_id).await
    }

    async fn exec_call(&mut self, contract_id: u64, method_name: &str, inputs: Vec<u64>) -> Result<String> {
        let user = self.require_user()?;
        let call = ContractCallArgs {
            contract_id,
            method_name: method_name.to_string(),
            inputs,
        };
        let first = self
            .session
            .exec_contract_call(user.pk_hash, ContractCallData::new(vec![call.clone()]))
            .await;
        match first {
            Ok(leaf) => Ok(leaf.to_string()),
            Err(e) if is_stale_state_error(&e) => {
                let fingerprint = user.fingerprint;
                self.session.update_circuit_mgr(user.pk_hash).await.ok();
                self.session
                    .add_user(user.private_key, fingerprint)
                    .await
                    .context("re-syncing the user after a stale-state rejection")?;
                Ok(self
                    .session
                    .exec_contract_call(user.pk_hash, ContractCallData::new(vec![call]))
                    .await?
                    .to_string())
            }
            Err(e) => Err(e),
        }
    }

    async fn claim_batch(&mut self, claims: Vec<ClaimBatchItem>) -> Result<String> {
        let user = self.require_user()?;
        let first = self.session.claim_batch(user.pk_hash, claims.clone()).await;
        match first {
            Ok(leaf) => Ok(leaf.to_string()),
            Err(e) if is_stale_state_error(&e) => {
                let fingerprint = user.fingerprint;
                self.session.update_circuit_mgr(user.pk_hash).await.ok();
                self.session
                    .add_user(user.private_key, fingerprint)
                    .await
                    .context("re-syncing the user after a stale-state batch rejection")?;
                Ok(self.session.claim_batch(user.pk_hash, claims).await?.to_string())
            }
            Err(e) => Err(e),
        }
    }

    fn prepare_private_transfer(&self, recipient_shielded_hex: &str, amount: u64, contract_id: u64) -> Result<PreparedPrivateTransfer> {
        self.require_user()?;
        let owner = parse_shield_elements_hex_pub(recipient_shielded_hex.trim().trim_start_matches("0x").trim_start_matches("0X"))?;
        let mut rng = rand::thread_rng();
        let note_secret = [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()];
        let nullifier_secret = [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()];
        let note_commitment = qhash_to_u64x4(derive_note_commitment(nullifier_secret, note_secret));
        let mut call_inputs = Vec::with_capacity(9);
        call_inputs.extend_from_slice(&owner);
        call_inputs.push(amount);
        call_inputs.extend_from_slice(&note_commitment);
        Ok(PreparedPrivateTransfer {
            contract_id,
            amount,
            owner,
            note_commitment,
            note_secret,
            nullifier_secret,
            call_inputs,
        })
    }

    async fn resolve_fingerprint(&mut self, private_key: QHashOut<F>, sign_type: Option<&str>, fingerprint_hex: Option<&str>) -> Result<QHashOut<F>> {
        anyhow::ensure!(sign_type.is_none() || fingerprint_hex.is_none(), "pass sign_type or fingerprint, not both");
        if let Some(raw) = fingerprint_hex {
            return raw.trim().parse::<QHashOut<F>>().map_err(|_| anyhow!("invalid fingerprint (expected QHashOut hex)"));
        }
        match sign_type.unwrap_or("zk").trim().to_ascii_lowercase().as_str() {
            "zk" => Ok(self.session.get_zk_public_key(private_key).await?.fingerprint),
            "secp256k1" => Ok(self.session.get_secp_public_key(private_key).await?.fingerprint),
            "eth-personal-secp256k1" => Ok(self.session.get_eth_personal_secp_public_key(private_key).await?.fingerprint),
            "sd-key" => anyhow::bail!("sd-key accounts require mint_agent_account so their mandate can be backed up"),
            other => anyhow::bail!("unsupported sign_type `{other}`; use zk, secp256k1, or eth-personal-secp256k1"),
        }
    }

    async fn generate_keypair(&mut self, sign_type: Option<&str>, fingerprint_hex: Option<&str>) -> Result<(String, String)> {
        let private_key = self.session.get_random_keypair().await?.private_key;
        let fingerprint = self.resolve_fingerprint(private_key, sign_type, fingerprint_hex).await?;
        Ok((private_key.to_string(), fingerprint.to_string()))
    }
}

pub struct WalletManager {
    config: psy_config::PsyConfigGoldilocks,
    mcp_networks: HashMap<NetworkId, McpNetworkConfig>,
    default_network: NetworkId,
    networks: RwLock<HashMap<NetworkId, Arc<Mutex<NetworkWallet>>>>,
}

#[derive(Clone, Default, serde::Deserialize)]
struct McpNetworkConfig {
    #[serde(default)]
    l1_rpc_urls: Vec<String>,
    #[serde(default)]
    bridge_url: Vec<String>,
    #[serde(default)]
    l1_config_url: Option<String>,
    #[serde(default)]
    l1_bridge_address: Option<String>,
    #[serde(default)]
    l1_router_address: Option<String>,
    #[serde(default)]
    l1_erc20_gateway_address: Option<String>,
    #[serde(default)]
    l1_token_addresses: HashMap<String, String>,
}

fn l1_config_endpoint(config: &McpNetworkConfig) -> Result<Option<reqwest::Url>> {
    let Some(endpoint) = config.l1_config_url.as_deref() else {
        return Ok(None);
    };
    if let Ok(url) = reqwest::Url::parse(endpoint) {
        return Ok(Some(url));
    }
    let base = config
        .bridge_url
        .first()
        .ok_or_else(|| anyhow!("relative l1_config_url `{endpoint}` requires bridge_url"))?;
    let base = reqwest::Url::parse(base).with_context(|| format!("invalid bridge_url `{base}`"))?;
    Ok(Some(
        base.join(endpoint)
            .with_context(|| format!("resolve l1_config_url `{endpoint}` against `{base}`"))?,
    ))
}

fn required_l1_address(document: &serde_json::Value, key: &str) -> Result<String> {
    let address = document
        .pointer(&format!("/core/{key}"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            document.get("contracts")?.as_array()?.iter().find_map(|contract| {
                (contract.get("name")?.as_str()? == key)
                    .then(|| contract.get("address")?.as_str())
                    .flatten()
            })
        })
        .ok_or_else(|| anyhow!("L1 config is missing core.{key}"))?;
    address
        .parse::<alloy_primitives::Address>()
        .with_context(|| format!("L1 config core.{key} is not an Ethereum address"))?;
    Ok(address.to_string())
}

fn config_chain_id(document: &serde_json::Value) -> Result<u64> {
    let value = document
        .get("chainId")
        .or_else(|| document.pointer("/l1/chain_id"))
        .ok_or_else(|| anyhow!("L1 config is missing chainId/l1.chain_id"))?;
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    let raw = value.as_str().ok_or_else(|| anyhow!("L1 config chain ID must be a number or string"))?;
    if let Some(hex) = raw.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).context("parse hexadecimal L1 config chain ID");
    }
    raw.parse::<u64>().context("parse decimal L1 config chain ID")
}

fn apply_l1_config_document(network: &NetworkId, config: &mut McpNetworkConfig, document: &serde_json::Value) -> Result<u64> {
    if let Some(document_network) = document.get("network").and_then(serde_json::Value::as_str) {
        anyhow::ensure!(
            document_network == network.as_str(),
            "L1 config network mismatch: requested `{network}`, received `{document_network}`"
        );
    }
    let chain_id = config_chain_id(document)?;

    config.l1_bridge_address = Some(required_l1_address(document, "Bridge")?);
    config.l1_router_address = Some(required_l1_address(document, "Router")?);
    config.l1_erc20_gateway_address = Some(required_l1_address(document, "ERC20Gateway")?);

    let mut addresses = HashMap::new();
    if let Some(tokens) = document.pointer("/protocol/tokens").and_then(serde_json::Value::as_object) {
        for (name, token) in tokens {
            let symbol = token.get("symbol").and_then(serde_json::Value::as_str).unwrap_or(name);
            let address = token
                .get("l1Address")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("L1 config token `{name}` is missing l1Address"))?;
            address
                .parse::<alloy_primitives::Address>()
                .with_context(|| format!("L1 config token `{symbol}` has an invalid l1Address"))?;
            addresses.insert(symbol.to_string(), address.to_string());
        }
    } else if let Some(tokens) = document.get("tokens").and_then(serde_json::Value::as_array) {
        for token in tokens {
            let symbol = token
                .get("symbol")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("L1 config token is missing symbol"))?;
            let address = token
                .get("address")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow!("L1 config token `{symbol}` is missing address"))?;
            address
                .parse::<alloy_primitives::Address>()
                .with_context(|| format!("L1 config token `{symbol}` has an invalid address"))?;
            addresses.insert(symbol.to_string(), address.to_string());
        }
    }
    anyhow::ensure!(!addresses.is_empty(), "L1 config has no token addresses");
    config.l1_token_addresses = addresses;
    Ok(chain_id)
}

async fn load_l1_config(network: &NetworkId, config: &mut McpNetworkConfig) -> Result<()> {
    let Some(endpoint) = l1_config_endpoint(config)? else {
        return Ok(());
    };
    let response = reqwest::Client::new()
        .get(endpoint.clone())
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .with_context(|| format!("fetch L1 config from `{endpoint}`"))?
        .error_for_status()
        .with_context(|| format!("fetch L1 config from `{endpoint}`"))?;
    let document = response
        .json::<serde_json::Value>()
        .await
        .with_context(|| format!("parse L1 config from `{endpoint}`"))?;
    let configured_chain_id =
        apply_l1_config_document(network, config, &document).with_context(|| format!("validate L1 config from `{endpoint}`"))?;
    let rpc_url = config
        .l1_rpc_urls
        .first()
        .ok_or_else(|| anyhow!("network `{network}` has l1_config_url but no l1_rpc_urls"))?;
    let rpc_chain_id = crate::l1::L1Client::read_only(rpc_url.clone())
        .chain_id()
        .await
        .with_context(|| format!("read eth_chainId from `{rpc_url}`"))?;
    anyhow::ensure!(
        configured_chain_id == rpc_chain_id,
        "L1 config/RPC chain mismatch for `{network}`: config `{endpoint}` says {configured_chain_id}, RPC `{rpc_url}` says {rpc_chain_id}"
    );
    Ok(())
}

#[cfg(test)]
mod l1_config_tests {
    use super::*;

    #[test]
    fn relative_l1_config_url_uses_bridge_origin() {
        let config = McpNetworkConfig {
            bridge_url: vec!["http://127.0.0.1:5177/some/path".into()],
            l1_config_url: Some("/config.json".into()),
            ..Default::default()
        };
        assert_eq!(
            l1_config_endpoint(&config).unwrap().unwrap().as_str(),
            "http://127.0.0.1:5177/config.json"
        );
    }

    #[test]
    fn runtime_document_replaces_contract_and_token_addresses() {
        let network = NetworkId::new("localhost").unwrap();
        let mut config = McpNetworkConfig::default();
        let document = serde_json::json!({
            "network": "localhost",
            "chainId": "31337",
            "core": {
                "Bridge": "0x0000000000000000000000000000000000000001",
                "Router": "0x0000000000000000000000000000000000000002",
                "ERC20Gateway": "0x0000000000000000000000000000000000000003"
            },
            "protocol": {
                "tokens": {
                    "psy": {
                        "symbol": "PSY",
                        "l1Address": "0x0000000000000000000000000000000000000004"
                    }
                }
            }
        });

        apply_l1_config_document(&network, &mut config, &document).unwrap();

        assert_eq!(config.l1_router_address.as_deref(), Some("0x0000000000000000000000000000000000000002"));
        assert_eq!(
            config.l1_token_addresses.get("PSY").map(String::as_str),
            Some("0x0000000000000000000000000000000000000004")
        );
    }

    #[test]
    fn runtime_document_rejects_wrong_network() {
        let network = NetworkId::new("localhost").unwrap();
        let mut config = McpNetworkConfig::default();
        let error = apply_l1_config_document(&network, &mut config, &serde_json::json!({ "network": "sepolia", "chainId": 11155111 })).unwrap_err();
        assert!(error.to_string().contains("network mismatch"));
    }

    #[test]
    fn hosted_config_schema_is_supported() {
        let network = NetworkId::new("sepolia").unwrap();
        let mut config = McpNetworkConfig::default();
        let document = serde_json::json!({
            "environment": "staging",
            "l1": { "network": "sepolia", "chain_id": 11155111 },
            "contracts": [
                { "name": "Bridge", "address": "0x0000000000000000000000000000000000000011" },
                { "name": "Router", "address": "0x0000000000000000000000000000000000000012" },
                { "name": "ERC20Gateway", "address": "0x0000000000000000000000000000000000000013" }
            ],
            "tokens": [
                { "symbol": "PSY", "address": "0x0000000000000000000000000000000000000014" }
            ]
        });

        apply_l1_config_document(&network, &mut config, &document).unwrap();

        assert_eq!(config.l1_bridge_address.as_deref(), Some("0x0000000000000000000000000000000000000011"));
        assert_eq!(config.l1_token_addresses.get("PSY").map(String::as_str), Some("0x0000000000000000000000000000000000000014"));
    }

    #[test]
    fn config_chain_id_accepts_decimal_and_hex_strings() {
        assert_eq!(config_chain_id(&serde_json::json!({ "chainId": "31337" })).unwrap(), 31_337);
        assert_eq!(config_chain_id(&serde_json::json!({ "chainId": "0x7a69" })).unwrap(), 31_337);
        assert_eq!(config_chain_id(&serde_json::json!({ "l1": { "chain_id": 11155111 } })).unwrap(), 11_155_111);
    }
}

impl WalletManager {
    /// Build a session from a Psy config file (default `config.json`). This
    /// reads the coordinator/realm/prove-proxy/api_services endpoints for
    /// the currently selected network and warms the circuit metadata from
    /// the prove-proxy.
    pub async fn from_config(config_path: &str, network: Option<&str>) -> Result<Self> {
        let raw_config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(config_path).with_context(|| format!("failed to read Psy config `{config_path}`"))?)
                .with_context(|| format!("failed to parse Psy config `{config_path}`"))?;
        let mut mcp_networks: HashMap<NetworkId, McpNetworkConfig> = raw_config
            .get("networks")
            .and_then(|networks| networks.as_object())
            .map(|networks| {
                networks
                    .iter()
                    .filter_map(|(name, value)| {
                        let id = NetworkId::new(name).ok()?;
                        let config = serde_json::from_value(value.clone()).ok()?;
                        Some((id, config))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let psy_config =
            psy_config::PsyConfigGoldilocks::from_file(config_path).with_context(|| format!("failed to read Psy config `{config_path}`"))?;
        let network = NetworkId::new(network.unwrap_or_else(|| psy_config.current_network_name()))?;
        let mcp_network = mcp_networks
            .get_mut(&network)
            .with_context(|| format!("network `{network}` is not present in Psy config"))?;
        load_l1_config(&network, mcp_network).await?;
        let rpc_config = psy_config
            .get_network(network.as_str())
            .with_context(|| format!("network `{network}` is not present in Psy config"))?
            .clone();
        let session = WalletSession::new(&rpc_config)
            .await
            .context("failed to init WalletSession (prove-proxy / coordinator unreachable?)")?;
        let default_network = network.clone();
        let mut networks = HashMap::new();
        networks.insert(
            network.clone(),
            Arc::new(Mutex::new(NetworkWallet {
                session,
                users: HashMap::new(),
                active_user: None,
            })),
        );
        Ok(Self {
            config: psy_config,
            mcp_networks,
            default_network,
            networks: RwLock::new(networks),
        })
    }

    pub fn default_network(&self) -> &NetworkId {
        &self.default_network
    }

    /// The configured Nostr relay for private-note delivery on this network.
    pub fn nostr_relay(&self, network: &NetworkId) -> Option<String> {
        self.config
            .get_network(network.as_str())
            .ok()
            .and_then(|config| {
                let relay = config.nostr_relay_url.trim();
                (!relay.is_empty()).then(|| relay.to_string())
            })
    }

    pub fn endpoint_summary(&self, network: &NetworkId) -> Result<EndpointSummary> {
        let network = self.config.get_network(network.as_str())?;
        Ok(EndpointSummary {
            coordinator: network.coordinator_configs.iter().flat_map(|c| c.rpc_url.clone()).collect(),
            realm: network.realm_configs.iter().flat_map(|r| r.rpc_url.clone()).collect(),
            prove_proxy: network.prove_proxy_url.clone(),
            api_services: network.api_services_url.clone().unwrap_or_default(),
        })
    }

    pub fn api_services_url(&self, network: &NetworkId) -> Option<String> {
        self.config
            .get_network(network.as_str())
            .ok()?
            .api_services_url
            .as_ref()?
            .iter()
            .find(|url| !url.trim().is_empty())
            .cloned()
    }

    pub fn faucet_url(&self, network: &NetworkId) -> Option<String> {
        self.config
            .get_network(network.as_str())
            .ok()?
            .faucet_rpc_url
            .iter()
            .find(|url| !url.trim().is_empty())
            .cloned()
    }

    pub fn l1_rpc_url(&self, network: &NetworkId) -> Option<String> {
        self.mcp_networks
            .get(network)?
            .l1_rpc_urls
            .iter()
            .find(|url| !url.trim().is_empty())
            .cloned()
    }

    pub fn l1_bridge_address(&self, network: &NetworkId) -> Option<String> {
        self.mcp_networks.get(network)?.l1_bridge_address.clone()
    }

    pub fn l1_router_address(&self, network: &NetworkId) -> Option<String> {
        self.mcp_networks.get(network)?.l1_router_address.clone()
    }

    pub fn l1_erc20_gateway_address(&self, network: &NetworkId) -> Option<String> {
        self.mcp_networks.get(network)?.l1_erc20_gateway_address.clone()
    }

    pub fn l1_token_address(&self, network: &NetworkId, token: &str) -> Option<String> {
        self.mcp_networks
            .get(network)?
            .l1_token_addresses
            .iter()
            .find(|(symbol, _)| symbol.eq_ignore_ascii_case(token))
            .map(|(_, address)| address.clone())
    }

    /// Resolve the network for one MCP request and lazily create its
    /// independent wallet session. No session or user state is moved
    /// between networks.
    pub fn resolve_network(&self, requested: Option<&str>) -> Result<NetworkId> {
        let target = NetworkId::new(requested.unwrap_or(self.default_network.as_str()))?;
        self.config
            .get_network(target.as_str())
            .with_context(|| format!("network `{target}` is not present in Psy config"))?;
        Ok(target)
    }

    pub async fn ensure_network(&self, network: &NetworkId) -> Result<()> {
        if self.networks.read().await.contains_key(network) {
            return Ok(());
        }
        {
            let rpc_config = self
                .config
                .get_network(network.as_str())
                .with_context(|| format!("network `{network}` is not present in Psy config"))?
                .clone();
            let session = WalletSession::new(&rpc_config)
                .await
                .with_context(|| format!("failed to init WalletSession for network `{network}`"))?;
            self.networks.write().await.entry(network.clone()).or_insert_with(|| {
                Arc::new(Mutex::new(NetworkWallet {
                    session,
                    users: HashMap::new(),
                    active_user: None,
                }))
            });
        }
        Ok(())
    }

    pub async fn network_for(&self, requested: Option<&str>) -> Result<NetworkId> {
        let network = self.resolve_network(requested)?;
        self.ensure_network(&network).await?;
        Ok(network)
    }

    async fn state(&self, network: &NetworkId) -> Result<OwnedMutexGuard<NetworkWallet>> {
        let state = self
            .networks
            .read()
            .await
            .get(network)
            .cloned()
            .ok_or_else(|| anyhow!("network `{network}` is not initialized"))?;
        Ok(state.lock_owned().await)
    }

    async fn activate_user(&self, network: &NetworkId, user: LoadedUser) -> Result<()> {
        self.state(network).await?.activate(user);
        Ok(())
    }

    pub async fn list_users(&self, network: &NetworkId) -> Result<Vec<LoadedUser>> {
        Ok(self.state(network).await?.list_users().into_iter().cloned().collect())
    }

    /// Select a user already loaded in the active network. Accepts either the
    /// decimal user id or the public pk hash; private material is never needed.
    pub async fn select_user(&self, network: &NetworkId, selector: &str) -> Result<LoadedUser> {
        let selector = selector.trim();
        self.state(network)
            .await?
            .select_user(selector)
            .ok_or_else(|| anyhow!("user `{selector}` is not loaded on network `{network}`"))
    }

    /// Clear the implicit activation performed while restoring keys. Startup
    /// uses this before applying the persisted or explicitly configured choice.
    pub async fn clear_active_user(&self, network: &NetworkId) -> Result<()> {
        self.state(network).await?.active_user = None;
        Ok(())
    }

    /// Parse a private key from hex into the field type WalletSession expects.
    fn parse_key(private_key_hex: &str) -> Result<QHashOut<F>> {
        private_key_hex
            .trim()
            .parse::<QHashOut<F>>()
            .map_err(|_| anyhow!("invalid private key (expected a QHashOut hex string)"))
    }

    /// Register a fresh key on-chain and load it. Returns the resolved user id.
    ///
    /// Registration is asynchronous on Psy: `register_user` submits the
    /// request, but the coordinator only mints the user id once the
    /// registration lands in a checkpoint (the engine itself logs "please
    /// add this user after 2 checkpoints"). Resolving immediately therefore
    /// fails on any real network — it only appeared to work against a local
    /// devnet whose checkpoints are near-instant. We poll until the id
    /// exists, mirroring what the shipped web wallet's sign-in sequence
    /// does.
    pub async fn register(&self, network: &NetworkId, private_key_hex: &str, fingerprint_hex: &str) -> Result<LoadedUser> {
        let private_key = Self::parse_key(private_key_hex)?;
        let fingerprint = fingerprint_hex.trim().parse::<QHashOut<F>>().map_err(|_| anyhow!("invalid fingerprint (expected QHashOut hex)"))?;
        let pk_hash = self.state(network).await?.session.register_user(private_key, fingerprint).await?;
        let user_id = self.await_user_id(network, pk_hash, REGISTRATION_TIMEOUT).await?;
        let loaded = LoadedUser {
            pk_hash,
            user_id,
            fingerprint,
            mandate: None,
            private_key,
        };
        self.activate_user(network, loaded.clone()).await?;
        Ok(loaded)
    }

    /// Mint an **agent account**: an identity whose key is an SDKey circuit
    /// encoding `capabilities` (see `agent_account.rs`).
    ///
    /// The identity is derived from `(private_key, circuit_fingerprint)`, so
    /// the mandate is part of who the agent *is* — it cannot be widened
    /// after the fact, only replaced by minting a different account.
    ///
    /// Order is deliberate and must not be rearranged: resolve method ids →
    /// build the circuit → hand the caller the key for backup → register
    /// on-chain. `on_key_generated` runs after the key exists but **before**
    /// the chain learns the identity, so a crash can never produce a
    /// registered account whose key nobody holds (see `keystore.rs`).
    pub async fn mint_agent_account<F2, P>(
        &self,
        network: &NetworkId,
        requests: &[CapabilityRequest],
        calls_per_transaction: u64,
        back_up_key: F2,
    ) -> Result<MintedAgentAccount<P>>
    where
        F2: FnOnce(&str, &str, Option<&Mandate>) -> Result<P>,
    {
        if requests.is_empty() {
            return Err(anyhow!("a mandate needs at least one capability"));
        }

        // Resolve each method name to its on-chain id. Doing this first means a
        // typo fails fast, before any circuit is built or key generated.
        let mut capabilities = Vec::with_capacity(requests.len());
        for req in requests {
            let fn_id = self
                .state(network)
                .await?
                .session
                .wallet
                .random_circuit_manager()
                .get_fn_id(req.contract_id, req.method_name.clone())
                .await
                .with_context(|| {
                    format!(
                        "no method `{}` on contract {} (check the name and contract id)",
                        req.method_name, req.contract_id
                    )
                })?;
            let method_id = u32::try_from(fn_id)
                .map_err(|_| anyhow!("method id {fn_id} for `{}` exceeds the u32 range the circuit supports", req.method_name))?;
            capabilities.push(Capability {
                contract_id: req.contract_id,
                method_name: req.method_name.clone(),
                method_id,
            });
        }
        let capabilities = agent_account::dedupe(capabilities);
        agent_account::validate(&capabilities, calls_per_transaction)?;

        // Compile the mandate into a circuit. Its fingerprint IS the mandate's
        // public identity, and is what makes the constraint auditable.
        let (contract_ids, method_ids): (Vec<u64>, Vec<u32>) = capabilities.iter().map(|c| (c.contract_id, c.method_id)).unzip();
        let fingerprint = self
            .state(network)
            .await?
            .session
            .register_sd_key_circuit(&contract_ids, &method_ids, calls_per_transaction)
            .await
            .context("failed to build the agent's SDKey circuit")?;

        let mandate = Mandate {
            capabilities,
            calls_per_transaction,
            circuit_fingerprint: fingerprint.to_string(),
        };

        let keypair = self.state(network).await?.session.get_random_keypair().await?;
        let private_key_hex = keypair.private_key.to_string();
        // Record the MANDATE alongside the key. Without it the account can
        // never be reloaded — its identity comes from the software-defined
        // circuit, and rebuilding that circuit needs the contract ids, method
        // ids and calls-per-transaction, not just the fingerprint.
        let key_backup = back_up_key(&private_key_hex, &mandate.circuit_fingerprint, Some(&mandate))?;

        // Only now does the chain learn the identity. If anything below fails the
        // key is already durable, so the account is recoverable — the error says
        // where to look, since the caller's handle to the backup is lost with the
        // early return.
        let private_key = Self::parse_key(&private_key_hex)?;
        let pk_hash = self
            .state(network)
            .await?
            .session
            .register_user(private_key, fingerprint)
            .await
            .with_context(|| format!("agent key is backed up (circuit {}); registration failed", mandate.circuit_fingerprint))?;
        let user_id = self
            .await_user_id(network, pk_hash, REGISTRATION_TIMEOUT)
            .await
            .with_context(|| format!("agent key is backed up (circuit {})", mandate.circuit_fingerprint))?;

        let user = LoadedUser {
            pk_hash,
            user_id,
            fingerprint,
            mandate: Some(mandate),
            private_key,
        };
        self.activate_user(network, user.clone()).await?;
        Ok(MintedAgentAccount { user, key_backup })
    }

    /// The mandate of the loaded account, if it is an agent account.
    pub async fn current_mandate(&self, network: &NetworkId) -> Option<Mandate> {
        self.current_user(network).await.and_then(|u| u.mandate)
    }

    /// Poll until the coordinator has minted a user id for `pk_hash`.
    ///
    /// Transport failures are treated as "not yet" rather than fatal: a single
    /// blip during a multi-minute wait must not discard a key that is already
    /// registering on-chain. Only exhausting the deadline is an error, and its
    /// message tells the caller the registration may still be in flight — the
    /// key is safe either way (see keystore.rs).
    async fn await_user_id(&self, network: &NetworkId, pk_hash: QHashOut<F>, timeout: Duration) -> Result<u64> {
        let deadline = Instant::now() + timeout;
        let mut attempt: u32 = 0;
        loop {
            match self.resolve_user_id(network, pk_hash).await {
                Ok(user_id) => return Ok(user_id),
                Err(e) if Instant::now() >= deadline => {
                    return Err(anyhow!(
                        "registration did not confirm within {}s ({e}). It may still land in a later \
                         checkpoint — reload the backed-up key to pick it up.",
                        timeout.as_secs()
                    ))
                }
                Err(_) => {
                    attempt += 1;
                    if attempt == 1 || attempt % 6 == 0 {
                        tracing::info!(
                            "waiting for the coordinator to mint a user id (attempt {attempt}, {}s left)",
                            deadline.saturating_duration_since(Instant::now()).as_secs()
                        );
                    }
                    let wait = REGISTRATION_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now()));
                    if wait.is_zero() {
                        continue;
                    }
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    /// Load an already-registered key (idempotent add). Returns the user id.
    pub async fn load(&self, network: &NetworkId, private_key_hex: &str) -> Result<LoadedUser> {
        self.load_selected(network, private_key_hex, None, None).await
    }

    pub async fn load_selected(&self, network: &NetworkId, private_key_hex: &str, sign_type: Option<&str>, fingerprint_hex: Option<&str>) -> Result<LoadedUser> {
        let private_key = Self::parse_key(private_key_hex)?;
        let (pk_hash, fingerprint) = {
            let mut state = self.state(network).await?;
            let fingerprint = state.resolve_fingerprint(private_key, sign_type, fingerprint_hex).await?;
            let pk_hash = state.session.add_user(private_key, fingerprint).await?;
            (pk_hash, fingerprint)
        };
        let user_id = self.resolve_user_id(network, pk_hash).await?;
        let loaded = LoadedUser { pk_hash, user_id, fingerprint, mandate: None, private_key };
        self.activate_user(network, loaded.clone()).await?;
        Ok(loaded)
    }

    /// Restore a wallet from a key backup, re-registering the agent's circuit
    /// first when the backup records a mandate.
    ///
    /// The backup fingerprint is authoritative for ordinary wallets. Agent
    /// accounts additionally rebuild their SDKey circuit from the recorded
    /// mandate and verify that the rebuilt fingerprint is identical.
    pub async fn load_from_backup(&self, network: &NetworkId, backup: &crate::keystore::KeyBackup) -> Result<LoadedUser> {
        if let Some(backup_network) = backup.network.as_deref() {
            if backup_network != network.as_str() {
                return Err(anyhow!(
                    "key backup belongs to network `{backup_network}`, but this call uses `{network}`"
                ));
            }
        }
        let Some(mandate) = backup.mandate.clone() else {
            let private_key = Self::parse_key(&backup.private_key)?;
            let fingerprint = backup.fingerprint.trim().parse::<QHashOut<F>>()
                .map_err(|_| anyhow!("key backup has an invalid fingerprint"))?;
            let pk_hash = self.state(network).await?.session.add_user(private_key, fingerprint).await?;
            let user_id = self.resolve_user_id(network, pk_hash).await?;
            let loaded = LoadedUser { pk_hash, user_id, fingerprint, mandate: None, private_key };
            self.activate_user(network, loaded.clone()).await?;
            return Ok(loaded);
        };
        let private_key = Self::parse_key(&backup.private_key)?;
        let (contract_ids, method_ids): (Vec<u64>, Vec<u32>) = mandate.capabilities.iter().map(|c| (c.contract_id, c.method_id)).unzip();
        let fingerprint = self
            .state(network)
            .await?
            .session
            .register_sd_key_circuit(&contract_ids, &method_ids, mandate.calls_per_transaction)
            .await
            .context("failed to rebuild the agent's SDKey circuit from its recorded mandate")?;
        // A mismatch means the recorded mandate does not compile to the circuit
        // this key was registered under — restoring it would silently produce a
        // DIFFERENT identity, so refuse rather than resolve the wrong account.
        if fingerprint.to_string() != mandate.circuit_fingerprint {
            anyhow::bail!(
                "the recorded mandate rebuilds to circuit {} but this key was minted under {} — refusing to load a different identity",
                fingerprint,
                mandate.circuit_fingerprint
            );
        }
        let pk_hash = self.state(network).await?.session.add_user(private_key, fingerprint).await?;
        let user_id = self.resolve_user_id(network, pk_hash).await?;
        let loaded = LoadedUser {
            pk_hash,
            user_id,
            fingerprint,
            mandate: Some(mandate),
            private_key,
        };
        self.activate_user(network, loaded.clone()).await?;
        Ok(loaded)
    }

    async fn resolve_user_id(&self, network: &NetworkId, pk_hash: QHashOut<F>) -> Result<u64> {
        self.state(network)
            .await?
            .session
            .st_provider
            .get_user_ids_for_public_key(pk_hash)
            .await?
            .first()
            .copied()
            .ok_or_else(|| anyhow!("no on-chain user id for this key (not registered yet?)"))
    }

    pub async fn current_user(&self, network: &NetworkId) -> Option<LoadedUser> {
        self.state(network).await.ok()?.current_user().cloned()
    }

    pub async fn require_user(&self, network: &NetworkId) -> Result<LoadedUser> {
        self.state(network).await?.require_user()
    }

    // ── Reads (via the RpcProvider st_provider — the same reads WalletSession
    // uses) ──

    pub async fn latest_checkpoint(&self, network: &NetworkId) -> Result<u64> {
        self.state(network).await?.latest_checkpoint().await
    }

    /// Public claimable owed to the loaded user by a specific sender.
    pub async fn claim_amount_from(&self, network: &NetworkId, sender_user_id: u64) -> Result<u64> {
        self.state(network).await?.claim_amount_from(sender_user_id).await
    }

    // ── Spends (real proofs via exec_contract_call / claim_batch) ──

    /// Generic contract call — the primitive every spend builds on.
    /// Returns the submitted end-user-leaf-hash as a hex string.
    pub async fn exec_call(&self, network: &NetworkId, contract_id: u64, method_name: &str, inputs: Vec<u64>) -> Result<String> {
        self.state(network).await?.exec_call(contract_id, method_name, inputs).await
    }

    pub async fn exec_call_for(
        &self,
        network: &NetworkId,
        expected_user_id: u64,
        contract_id: u64,
        method_name: &str,
        inputs: Vec<u64>,
    ) -> Result<String> {
        let mut state = self.state(network).await?;
        state.require_user_id(expected_user_id)?;
        state.exec_call(contract_id, method_name, inputs).await
    }

    /// Public transfer: `simple_transfer(recipient_user_id, amount_nano)`.
    pub async fn transfer(&self, network: &NetworkId, to_user_id: u64, amount_nano: u64, contract_id: u64) -> Result<String> {
        self.exec_call(network, contract_id, "simple_transfer", vec![to_user_id, amount_nano])
            .await
    }

    pub async fn transfer_for(
        &self,
        network: &NetworkId,
        expected_user_id: u64,
        to_user_id: u64,
        amount_nano: u64,
        contract_id: u64,
    ) -> Result<String> {
        self.exec_call_for(network, expected_user_id, contract_id, "simple_transfer", vec![to_user_id, amount_nano])
            .await
    }

    /// Claim a batch (UPS): fuses N claims (+ optional trailing calls) into one
    /// recursive proof / one transaction. This is the real batching primitive.
    ///
    /// Like `exec_call`, a submission that fails because the chain advanced
    /// while the proof was being built (stale leaf / stale nonce) is re-synced
    /// and retried once — an agent paying a seller twice in a row is the normal
    /// shape, and the second payment must not die to a timing artifact.
    pub async fn claim_batch(&self, network: &NetworkId, claims: Vec<ClaimBatchItem>) -> Result<String> {
        self.state(network).await?.claim_batch(claims).await
    }

    pub async fn claim_batch_for(&self, network: &NetworkId, expected_user_id: u64, claims: Vec<ClaimBatchItem>) -> Result<String> {
        let mut state = self.state(network).await?;
        state.require_user_id(expected_user_id)?;
        state.claim_batch(claims).await
    }

    /// Claim all PUBLIC claimables owed by the given senders, fused into ONE
    /// UPS proof / one tx (a `simple_claim` per sender). Claiming is
    /// non-destructive: it only folds funds already addressed to this user
    /// into spendable balance. Private-note and deposit claiming need
    /// note/deposit material from the discovery layer (Nostr drain +
    /// inclusion proofs) and are not included here.
    pub async fn claim_all_public(&self, network: &NetworkId, sender_ids: Vec<u64>, contract_id: u64) -> Result<String> {
        if sender_ids.is_empty() {
            return Err(anyhow!(
                "no senders provided — pass the user ids that owe you public claims (see get_claimable)"
            ));
        }
        let items: Vec<ClaimBatchItem> = sender_ids
            .into_iter()
            .map(|sender| {
                ClaimBatchItem::Public(ContractCallArgs {
                    contract_id,
                    method_name: "simple_claim".to_string(),
                    inputs: vec![sender],
                })
            })
            .collect();
        self.claim_batch(network, items).await
    }

    /// Public transfer to MANY recipients, fused into ONE UPS proof / one tx —
    /// a `simple_transfer` per payment, through the same batching primitive
    /// `claim_all_public` uses. N recipients therefore cost one proof and one
    /// fee instead of N of each.
    ///
    /// Atomic by construction: the calls ride a single recursive proof, so
    /// either every payment settles or none does. There is no state in which
    /// some payees were paid and others were not, which is what lets the policy
    /// gate treat the batch as one all-or-nothing spend.
    pub async fn transfer_batch(&self, network: &NetworkId, payments: Vec<(u64, u64)>, contract_id: u64) -> Result<String> {
        if payments.is_empty() {
            return Err(anyhow!("no payments provided — pass at least one recipient and amount"));
        }
        let items: Vec<ClaimBatchItem> = payments
            .into_iter()
            .map(|(to_user_id, amount_nano)| {
                ClaimBatchItem::Public(ContractCallArgs {
                    contract_id,
                    method_name: "simple_transfer".to_string(),
                    inputs: vec![to_user_id, amount_nano],
                })
            })
            .collect();
        self.claim_batch(network, items).await
    }

    pub async fn transfer_batch_for(
        &self,
        network: &NetworkId,
        expected_user_id: u64,
        payments: Vec<(u64, u64)>,
        contract_id: u64,
    ) -> Result<String> {
        if payments.is_empty() {
            return Err(anyhow!("no payments provided — pass at least one recipient and amount"));
        }
        let items = payments
            .into_iter()
            .map(|(to_user_id, amount_nano)| {
                ClaimBatchItem::Public(ContractCallArgs {
                    contract_id,
                    method_name: "simple_transfer".to_string(),
                    inputs: vec![to_user_id, amount_nano],
                })
            })
            .collect();
        self.claim_batch_for(network, expected_user_id, items).await
    }

    /// Compute a private transfer WITHOUT submitting it: derive a fresh note
    /// and the exact `private_transfer` call. Does not touch the chain.
    /// Submission is deliberately separate — see
    /// `submit_prepared_private_transfer` and the funds-safety note in the
    /// `private_transfer` tool.
    pub async fn prepare_private_transfer(
        &self,
        network: &NetworkId,
        recipient_shielded_hex: &str,
        amount: u64,
        contract_id: u64,
    ) -> Result<PreparedPrivateTransfer> {
        self.state(network)
            .await?
            .prepare_private_transfer(recipient_shielded_hex, amount, contract_id)
    }

    /// Submit a prepared private transfer's on-chain settlement (real proof).
    /// DANGER: settlement alone does not make the funds claimable — the note
    /// material must be delivered to the recipient (over Nostr) in the exact
    /// format their wallet drains, or the funds are stranded. Only call this
    /// once delivery is wired and verified.
    pub async fn submit_prepared_private_transfer(&self, network: &NetworkId, prepared: &PreparedPrivateTransfer) -> Result<String> {
        self.exec_call(network, prepared.contract_id, "private_transfer", prepared.call_inputs.clone())
            .await
    }

    pub async fn submit_prepared_private_transfer_for(
        &self,
        network: &NetworkId,
        expected_user_id: u64,
        prepared: &PreparedPrivateTransfer,
    ) -> Result<String> {
        self.exec_call_for(
            network,
            expected_user_id,
            prepared.contract_id,
            "private_transfer",
            prepared.call_inputs.clone(),
        )
        .await
    }

    /// Generate a fresh keypair (private key hex + fingerprint hex) without
    /// touching the chain — the owner then registers it under a policy.
    pub async fn generate_keypair(&self, network: &NetworkId, sign_type: Option<&str>, fingerprint: Option<&str>) -> Result<(String, String)> {
        self.state(network).await?.generate_keypair(sign_type, fingerprint).await
    }
}

/// The note tree is 20 levels deep (2^20 notes per user/contract).
const NOTE_TREE_HEIGHT: usize = 20;

/// A private transfer that settled on chain AND carries the inclusion proof the
/// recipient needs. Both halves are required: settlement alone leaves the note
/// undiscoverable, and a note without its inclusion proof cannot be claimed.
#[derive(Debug)]
pub struct SettledPrivateTransfer {
    pub leaf_hash: String,
    pub prepared: PreparedPrivateTransfer,
    /// Poseidon(nullifier_secret) — safe to publish; the SECRET is not.
    pub nullifier_hash: [u64; 4],
    /// Checkpoint the note landed in — what the inclusion proof is bound to.
    pub checkpoint_id: u64,
    /// Serialized note-inclusion proof, carried to the recipient in the note.
    pub note_proof_json: String,
}

impl WalletManager {
    /// Settle a prepared private transfer and prove the note's inclusion.
    ///
    /// Ordering is load-bearing:
    ///   1. snapshot the pre-submit checkpoint and note count,
    ///   2. submit the on-chain `private_transfer` (this debits the balance),
    ///   3. wait for the checkpoint the note actually lands in,
    ///   4. rebuild the membership proof at THAT checkpoint and prove
    ///      inclusion.
    ///
    /// The caller must then deliver the note to the recipient. Until delivery
    /// lands the funds are debited but unclaimable, so a failure after step 2
    /// means "retry delivery", never "nothing happened".
    pub async fn settle_private_transfer(
        &self,
        network: &NetworkId,
        prepared: PreparedPrivateTransfer,
        note_root_slot: u64,
    ) -> Result<SettledPrivateTransfer> {
        let user_id = self.require_user(network).await?.user_id;
        self.settle_private_transfer_for(network, user_id, prepared, note_root_slot).await
    }

    pub async fn settle_private_transfer_for(
        &self,
        network: &NetworkId,
        expected_user_id: u64,
        prepared: PreparedPrivateTransfer,
        note_root_slot: u64,
    ) -> Result<SettledPrivateTransfer> {
        let user = self.require_user(network).await?;
        if user.user_id != expected_user_id {
            anyhow::bail!("active wallet changed after authorization; refusing private transfer");
        }
        let sender_user_id = user.user_id;
        let contract_id = prepared.contract_id;
        let amount = prepared.amount;

        let provider = self.state(network).await?.session.st_provider.with_user_id_owned(sender_user_id);
        let checkpoint_before = self.latest_checkpoint(network).await?;
        let baseline_count = Self::read_note_count(&provider, sender_user_id, contract_id, note_root_slot, checkpoint_before)
            .await
            .unwrap_or(0);

        let leaf_hash = self.submit_prepared_private_transfer_for(network, expected_user_id, &prepared).await?;

        let owner = QHashOut::<F>::from_values(prepared.owner[0], prepared.owner[1], prepared.owner[2], prepared.owner[3]);
        let note_commitment = QHashOut::<F>::from_values(
            prepared.note_commitment[0],
            prepared.note_commitment[1],
            prepared.note_commitment[2],
            prepared.note_commitment[3],
        );

        let mut checkpoint_id = 0u64;
        let mut membership = None;
        for _ in 0..120 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let latest = match self.latest_checkpoint(network).await {
                Ok(v) => v,
                Err(_) => continue, // transport blip is not a verdict
            };
            if latest <= checkpoint_before {
                continue;
            }
            let count = match Self::read_note_count(&provider, sender_user_id, contract_id, note_root_slot, latest).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            if count <= baseline_count {
                continue; // our note has not landed yet
            }
            let proof = Self::build_membership_proof(
                &provider,
                sender_user_id,
                contract_id,
                note_root_slot,
                amount,
                owner,
                note_commitment,
                latest,
            )
            .await?;
            let slot_proof = provider
                .get_user_contract_state_tree_merkle_proof(
                    latest,
                    sender_user_id,
                    contract_id as u32,
                    psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
                    note_root_slot,
                )
                .await?;
            // Only accept a checkpoint whose stored note root equals the root our
            // note produces — anything else builds a witness the circuit rejects.
            if proof.root == slot_proof.value {
                checkpoint_id = latest;
                membership = Some((proof, slot_proof));
                break;
            }
        }
        let (note_membership_proof, note_root_slot_proof) = membership.ok_or_else(|| {
            anyhow!(
                "private transfer submitted (leaf {leaf_hash}) but its note never appeared in a \
                     checkpoint — funds are debited and NOT yet claimable; retry proving before re-sending"
            )
        })?;

        let user_leaf = provider.get_user_leaf_data(checkpoint_id, sender_user_id).await?;
        let contract_proof = provider
            .get_user_contract_tree_merkle_proof(checkpoint_id, sender_user_id, contract_id as u32)
            .await?;
        let user_tree_proof = provider.get_user_tree_merkle_proof(checkpoint_id, sender_user_id).await?;
        let global_user_tree_root = user_tree_proof.root;

        let input = PrivateNoteInclusionInput {
            nullifier_secret: QHashOut::<F>::from_values(
                prepared.nullifier_secret[0],
                prepared.nullifier_secret[1],
                prepared.nullifier_secret[2],
                prepared.nullifier_secret[3],
            ),
            sender_user_id,
            contract_id,
            note_root_slot,
            user_leaf,
            owner,
            amount: F::from_canonical_u64(amount),
            note_secret: QHashOut::<F>::from_values(
                prepared.note_secret[0],
                prepared.note_secret[1],
                prepared.note_secret[2],
                prepared.note_secret[3],
            ),
            note_membership_proof,
            note_root_slot_proof,
            contract_proof,
            user_tree_proof,
            checkpoint_id: F::from_canonical_u64(checkpoint_id),
        };

        let (fingerprint, proof, verifier_data_alt) = self.state(network).await?.session.prove_private_note_inclusion(&input).await?;

        // The recipient does not parse a bare proof — every Psy wallet drains this
        // exact envelope (see the WASM binding's prove_private_note_inclusion_json
        // and claimables-private.ts::parseNoteProofEnvelope). Emitting anything
        // else delivers a note nobody can claim.
        //
        // `nullifier` is the HASH of the nullifier secret. The secret itself must
        // never be published — it stays with the sender as recovery material.
        let nullifier = PoseidonHasher::q_hash_many(&input.nullifier_secret.0.elements);
        let to_str_arr = |h: QHashOut<F>| -> [String; 4] {
            let e = h.0.elements;
            [
                e[0].to_canonical_u64().to_string(),
                e[1].to_canonical_u64().to_string(),
                e[2].to_canonical_u64().to_string(),
                e[3].to_canonical_u64().to_string(),
            ]
        };
        // `note_proof_bincode_b64` is a wire-format promise: the wallet WASM
        // selects strict bincode decoding whenever this field is present. Using
        // Plonky2's native `to_bytes()` here produced a valid proof under the
        // wrong encoding and every recipient rejected it as malformed.
        let proof_bytes = bincode::serialize(&proof).context("serialize private-note proof as bincode")?;
        let proof_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, proof_bytes);
        let note_proof_json = serde_json::json!({
            "nullifier": to_str_arr(nullifier),
            "owner": to_str_arr(owner),
            "amount": amount.to_string(),
            "user_tree_root": to_str_arr(global_user_tree_root),
            "checkpoint_id": checkpoint_id.to_string(),
            "note_root_slot": note_root_slot.to_string(),
            "note_proof_fingerprint": to_str_arr(fingerprint),
            "note_verifier_data": verifier_data_alt,
            "note_proof_bincode_b64": proof_b64,
        })
        .to_string();

        let nh = nullifier.0.elements;
        Ok(SettledPrivateTransfer {
            leaf_hash,
            prepared,
            nullifier_hash: [
                nh[0].to_canonical_u64(),
                nh[1].to_canonical_u64(),
                nh[2].to_canonical_u64(),
                nh[3].to_canonical_u64(),
            ],
            checkpoint_id,
            note_proof_json,
        })
    }

    /// Note count for (user, contract) — stored one slot below the note root.
    async fn read_note_count(
        provider: &psy_provider::provider::RpcProvider,
        sender_user_id: u64,
        contract_id: u64,
        note_root_slot: u64,
        checkpoint_id: u64,
    ) -> Result<u64> {
        let proof = provider
            .get_user_contract_state_tree_merkle_proof(
                checkpoint_id,
                sender_user_id,
                contract_id as u32,
                psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
                note_root_slot.saturating_sub(1),
            )
            .await?;
        Ok(proof.value.0.elements[3].to_canonical_u64())
    }

    /// Rebuild the append-only note-tree membership proof for the new note.
    /// Mirrors the contract's own insert (token main.psy `private_transfer`):
    /// the leaf sits at `note_index`, siblings come from the stored frontier
    /// for set bits and from the empty-subtree chain for clear ones.
    async fn build_membership_proof(
        provider: &psy_provider::provider::RpcProvider,
        sender_user_id: u64,
        contract_id: u64,
        note_root_slot: u64,
        amount: u64,
        owner: QHashOut<F>,
        note_commitment: QHashOut<F>,
        checkpoint_id: u64,
    ) -> Result<MerkleProofCore<QHashOut<F>>> {
        let note_index = Self::read_note_count(provider, sender_user_id, contract_id, note_root_slot, checkpoint_id)
            .await?
            .saturating_sub(1);

        let mut last_path: Vec<QHashOut<F>> = Vec::with_capacity(NOTE_TREE_HEIGHT);
        for level in 0..NOTE_TREE_HEIGHT as u64 {
            let proof = provider
                .get_user_contract_state_tree_merkle_proof(
                    checkpoint_id,
                    sender_user_id,
                    contract_id as u32,
                    psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
                    note_root_slot + 1 + level,
                )
                .await?;
            last_path.push(proof.value);
        }

        let value_hash = QHashOut::<F>::from_values(amount, 0, 0, 0);
        let inner = PoseidonHasher::q_two_to_one(owner, value_hash);
        let commitment = PoseidonHasher::q_two_to_one(inner, note_commitment);

        let mut siblings = Vec::with_capacity(NOTE_TREE_HEIGHT);
        let mut zero = QHashOut::<F>::from_values(0, 0, 0, 0);
        for level in 0..NOTE_TREE_HEIGHT {
            if (note_index >> level) & 1 == 0 {
                siblings.push(zero);
            } else {
                siblings.push(last_path[level]);
            }
            zero = PoseidonHasher::q_two_to_one(zero, zero);
        }
        Ok(MerkleProofCore::new_from_params::<PoseidonHasher>(note_index, commitment, siblings))
    }
}

/// The agent's private receive identity.
///
/// Derived deterministically from the wallet's own private key so it survives
/// restarts and never needs storing: the same key always yields the same
/// shielded address and the same Nostr identity. Senders need BOTH — the
/// shielded address owns the note, the npub is where the note is delivered.
#[derive(Debug, Clone)]
pub struct ReceiveIdentity {
    /// Shielded address as hex (what a payer passes as `to_shielded_address`).
    pub shield_address_hex: String,
    /// Wallet copy/share form (version 0x05d4 Base58Check).
    pub shield_address_base58: String,
    /// Blinding factors baked into the shielded address; required to claim.
    pub random0: u64,
    pub random1: u64,
    /// Nostr public key (npub) a payer delivers the note to.
    pub npub: String,
    /// Nostr secret key — needed to DECRYPT delivered notes. Never leaves here.
    pub nsec: String,
}

impl WalletManager {
    /// Derive this wallet's private receive identity.
    ///
    /// Uses the web wallet's `psy-privacy-v0` HMAC-SHA256 derivation at index
    /// 0. A lost r0/r1 makes every note sent to that address unclaimable,
    /// so they must be reproducible from the key alone and byte-compatible
    /// everywhere.
    pub async fn receive_identity(&self, network: &NetworkId) -> Result<ReceiveIdentity> {
        let user = self.require_user(network).await?;
        let (random0, random1, nostr_secret) = derive_receive_secrets(&user.private_key.to_string(), 0)?;
        let shield = derive_shield_address(user.user_id, random0, random1);
        let keys = nostr::Keys::new(nostr::SecretKey::from_slice(&nostr_secret).context("deriving the Nostr secret key")?);

        Ok(ReceiveIdentity {
            // Elements order — see qhash_to_elements_hex. Publishing the serde
            // (reversed) Display hex here is what made cross-wallet recipients
            // pack reversed note owners and lose the funds to the claim check.
            shield_address_hex: qhash_to_elements_hex(shield),
            shield_address_base58: shield_address_base58(shield),
            random0,
            random1,
            npub: keys.public_key().to_bech32().unwrap_or_else(|_| keys.public_key().to_string()),
            nsec: keys.secret_key().to_bech32().unwrap_or_else(|_| keys.secret_key().to_secret_hex()),
        })
    }
}

/// A private note that arrived for this wallet, parsed from the envelope a
/// sender delivers over Nostr.
#[derive(Debug, Clone)]
pub struct IncomingPrivateNote {
    pub nullifier: [u64; 4],
    pub owner: [u64; 4],
    pub amount: u64,
    pub user_tree_root: [u64; 4],
    pub checkpoint_id: u64,
    pub note_root_slot: u64,
    pub note_proof_bincode_b64: String,
}

fn parse_u64_arr(v: &serde_json::Value, key: &str) -> Result<[u64; 4]> {
    let arr = v
        .get(key)
        .and_then(|x| x.as_array())
        .ok_or_else(|| anyhow!("note envelope is missing `{key}`"))?;
    if arr.len() != 4 {
        return Err(anyhow!("note envelope `{key}` must have 4 limbs, got {}", arr.len()));
    }
    let mut out = [0u64; 4];
    for (i, item) in arr.iter().enumerate() {
        out[i] = match item {
            serde_json::Value::String(s) => s.parse().with_context(|| format!("`{key}[{i}]`"))?,
            serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| anyhow!("`{key}[{i}]` not a u64"))?,
            _ => return Err(anyhow!("`{key}[{i}]` must be a string or number")),
        };
    }
    Ok(out)
}

fn parse_u64_field(v: &serde_json::Value, key: &str) -> Result<u64> {
    match v.get(key) {
        Some(serde_json::Value::String(s)) => s.parse().with_context(|| format!("`{key}`")),
        Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| anyhow!("`{key}` not a u64")),
        _ => Err(anyhow!("note envelope is missing `{key}`")),
    }
}

impl IncomingPrivateNote {
    /// Parse the `note_proof` envelope every Psy wallet emits and drains.
    /// Accepts either the envelope itself or a whole `psy_private_payment`
    /// packet (whose `noteProofRaw` holds the envelope as a nested string).
    pub fn parse(raw: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(raw.trim()).context("note is not valid JSON")?;
        let env: serde_json::Value = match value.get("noteProofRaw") {
            Some(serde_json::Value::String(inner)) => serde_json::from_str(inner).context("noteProofRaw is not valid JSON")?,
            Some(other) => other.clone(),
            None => value,
        };
        Ok(Self {
            nullifier: parse_u64_arr(&env, "nullifier")?,
            owner: parse_u64_arr(&env, "owner")?,
            amount: parse_u64_field(&env, "amount")?,
            user_tree_root: parse_u64_arr(&env, "user_tree_root")?,
            checkpoint_id: parse_u64_field(&env, "checkpoint_id")?,
            note_root_slot: parse_u64_field(&env, "note_root_slot")?,
            note_proof_bincode_b64: env
                .get("note_proof_bincode_b64")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("note envelope is missing `note_proof_bincode_b64`"))?
                .to_string(),
        })
    }
}

impl WalletManager {
    /// Build a private-note claim without submitting it, so mixed batches can
    /// fuse the item with public claims and shield deposits in one UPS.
    ///
    /// The note carries the sender's inclusion proof; the claimer supplies the
    /// blinding factors its own shielded address was built from. If those do
    /// not match the note's owner the circuit rejects the claim outright
    /// ("receiver does not match claiming user"), so they are checked here
    /// first — a clear error beats a failed proof after a long wait.
    pub async fn build_private_note_claim(&self, network: &NetworkId, note: &IncomingPrivateNote, contract_id: u64) -> Result<ClaimBatchItem> {
        let identity = self.receive_identity(network).await?;
        let user = self.require_user(network).await?;

        let expected_owner = derive_shield_address(user.user_id, identity.random0, identity.random1);
        let owner_limbs = qhash_to_u64x4(expected_owner);
        if owner_limbs != note.owner {
            return Err(anyhow!(
                "this note is addressed to a different shielded address — it is not claimable by \
                 Psy-{:08} (note owner {:?}, this wallet {:?})",
                user.user_id,
                note.owner,
                owner_limbs
            ));
        }

        // Rebuild the note-inclusion circuit locally: decoding the proof needs its
        // common data, and the claim needs the circuit's fingerprint + verifier data.
        let circuit = PrivateNoteInclusionCircuit::<C, D>::new(
            psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize,
            psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
            psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
            NOTE_TREE_HEIGHT,
        );
        let proof_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, note.note_proof_bincode_b64.as_bytes())
            .context("note proof is not valid base64")?;
        let note_proof =
            ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), circuit.get_common_circuit_data_ref()).or_else(|native_err| {
                bincode::deserialize(&proof_bytes).map_err(|bin_err| anyhow!("note proof decode failed (native={native_err}; bincode={bin_err})"))
            })?;

        Ok(ClaimBatchItem::PrivateTransfer {
            contract_id,
            claim: PrivateTransferClaim {
                nullifier: note.nullifier,
                owner: note.owner,
                amount: note.amount,
                user_tree_root: note.user_tree_root,
                checkpoint_id: note.checkpoint_id,
                note_root_slot: note.note_root_slot,
                token_contract_id: contract_id,
                random0: identity.random0,
                random1: identity.random1,
                note_proof_fingerprint: circuit.get_fingerprint(),
                note_proof,
                note_verifier_data: circuit.get_verifier_config_ref().clone().into(),
            },
        })
    }

    /// Claim a private note that was sent to this wallet's shielded address.
    pub async fn claim_private_note(&self, network: &NetworkId, note: &IncomingPrivateNote, contract_id: u64) -> Result<String> {
        let item = self.build_private_note_claim(network, note, contract_id).await?;
        self.claim_batch(network, vec![item]).await
    }
}

/// Big-endian u32×8 limbs of a 256-bit value — the wire form the token
/// contract's `withdraw` takes for tokens, amounts, recipients and the nonce.
fn u256_to_u32x8_be(value: u128) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..8 {
        let shift = 32 * (7 - i);
        out[i] = if shift >= 128 { 0 } else { ((value >> shift) & 0xffff_ffff) as u64 };
    }
    out
}

/// Right-aligned bytes32 of an EVM address (or a full 32-byte hex), as u32×8
/// BE.
fn evm_addr_to_u32x8_be(hex: &str) -> Result<[u64; 8]> {
    let raw = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.len() != 40 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("`{hex}` is not a 20-byte EVM address"));
    }
    if raw.bytes().all(|b| b == b'0') {
        return Err(anyhow!("`{hex}` is the zero EVM address"));
    }
    let padded = format!("{:0>64}", raw);
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = u64::from_str_radix(&padded[i * 8..(i + 1) * 8], 16).map_err(|e| anyhow!("bad address word: {e}"))?;
    }
    Ok(out)
}

impl WalletManager {
    /// Withdraw to an L1 address: burns on Psy, then the bridge relayer settles
    /// the L1 leg (so this costs the agent no Ethereum gas).
    ///
    /// The deployed contract takes 33 inputs — the nonce is a FULL u32x8 word,
    /// not a single felt. Sending 26 fails before any proof with
    /// "expect 33 number of inputs, but got 26".
    pub async fn withdraw(
        &self,
        network: &NetworkId,
        dest_chain_index: u64,
        l1_token_address: &str,
        amount_nano: u64,
        l1_recipient: &str,
        nonce: u64,
        contract_id: u64,
    ) -> Result<String> {
        let token = evm_addr_to_u32x8_be(l1_token_address).context("l1_token_address")?;
        let recipient = evm_addr_to_u32x8_be(l1_recipient).context("l1_recipient")?;
        let amount = u256_to_u32x8_be(amount_nano as u128);
        let nonce_words = u256_to_u32x8_be(nonce as u128);

        let mut inputs = Vec::with_capacity(33);
        inputs.push(dest_chain_index);
        inputs.extend_from_slice(&token);
        inputs.extend_from_slice(&amount);
        inputs.extend_from_slice(&recipient);
        inputs.extend_from_slice(&nonce_words);
        debug_assert_eq!(inputs.len(), 33, "withdraw must submit exactly 33 inputs");

        self.exec_call(network, contract_id, "withdraw", inputs).await
    }

    pub async fn withdraw_for(
        &self,
        network: &NetworkId,
        expected_user_id: u64,
        dest_chain_index: u64,
        l1_token_address: &str,
        amount_nano: u64,
        l1_recipient: &str,
        nonce: u64,
        contract_id: u64,
    ) -> Result<String> {
        let token = evm_addr_to_u32x8_be(l1_token_address).context("l1_token_address")?;
        let recipient = evm_addr_to_u32x8_be(l1_recipient).context("l1_recipient")?;
        let amount = u256_to_u32x8_be(amount_nano as u128);
        let nonce_words = u256_to_u32x8_be(nonce as u128);
        let mut inputs = vec![dest_chain_index];
        inputs.extend_from_slice(&token);
        inputs.extend_from_slice(&amount);
        inputs.extend_from_slice(&recipient);
        inputs.extend_from_slice(&nonce_words);
        self.exec_call_for(network, expected_user_id, contract_id, "withdraw", inputs).await
    }
}

#[cfg(test)]
mod withdraw_encoding_tests {
    use super::*;

    #[test]
    fn withdraw_builds_exactly_33_inputs() {
        let token = evm_addr_to_u32x8_be("0xbBC0D21A312006eB0E902c279d5E53Dc8225cBB6").unwrap();
        let recipient = evm_addr_to_u32x8_be("0xfB11910FD59f62a9046884109905fa6f88B4be43").unwrap();
        let amount = u256_to_u32x8_be(50_000_000);
        let nonce = u256_to_u32x8_be(7);
        let total = 1 + token.len() + amount.len() + recipient.len() + nonce.len();
        assert_eq!(total, 33, "the deployed contract rejects anything but 33 inputs");
    }

    #[test]
    fn evm_address_is_right_aligned_in_bytes32() {
        // 20-byte address → 12 zero bytes of padding → first three words are 0.
        let w = evm_addr_to_u32x8_be("0xfB11910FD59f62a9046884109905fa6f88B4be43").unwrap();
        assert_eq!(&w[0..3], &[0, 0, 0]);
        assert_eq!(w[3], 0xfB11910F);
        assert_eq!(w[7], 0x88B4be43);
    }

    #[test]
    fn amount_is_big_endian_in_the_low_words() {
        let w = u256_to_u32x8_be(0x1_0000_0002);
        assert_eq!(&w[0..6], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(w[6], 1);
        assert_eq!(w[7], 2);
    }

    #[test]
    fn a_bare_hex_address_without_0x_is_accepted() {
        assert_eq!(
            evm_addr_to_u32x8_be("fB11910FD59f62a9046884109905fa6f88B4be43").unwrap(),
            evm_addr_to_u32x8_be("0xfB11910FD59f62a9046884109905fa6f88B4be43").unwrap()
        );
    }

    #[test]
    fn a_non_hex_address_is_rejected_rather_than_silently_padded() {
        assert!(evm_addr_to_u32x8_be("0xnot-an-address").is_err());
        assert!(evm_addr_to_u32x8_be("").is_err());
        assert!(evm_addr_to_u32x8_be("0x0").is_err());
        assert!(evm_addr_to_u32x8_be("0x0000000000000000000000000000000000000000").is_err());
    }
}

// ─── Shield deposits: L1 → Psy ───────────────────────────────────────────────

/// Everything needed to claim a deposit later. Persisted to disk BEFORE the L1
/// transaction is broadcast: the secrets exist nowhere else, and a deposit
/// whose secrets are lost is permanently unclaimable with no error anywhere.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DepositNote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub note_secret: [u64; 4],
    pub nullifier_secret: [u64; 4],
    /// The shielded address the funds land on (this wallet's own).
    pub shield_address_hex: String,
    pub l1_token_address: String,
    pub l2_token_contract_id: u64,
    pub amount_base_units: u64,
    pub source_chain_index: u32,
    /// The bridge's pendingDepositCount at broadcast — our expected index.
    pub expected_deposit_index: u64,
    pub l1_tx_hash: Option<String>,
    pub claimed: bool,
    #[serde(default)]
    pub delivered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit_proof_json: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nostr_event_ids: Vec<String>,
}

fn qhash_to_bytes32_be(h: QHashOut<F>) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in h.0.elements.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_canonical_u64().to_be_bytes());
    }
    out
}

/// Parse a bytes32 from psy-services' bridge endpoints.
///
/// The service serializes a QHashOut with the LIMBS REVERSED (element 3 first,
/// each limb big-endian). Verified empirically: parsing straight-through made
/// the locally derived deposit leaf equal the service's with all four limbs in
/// opposite order. The L1 wire format (qhash_to_bytes32_be) is straight-through
/// — the relayer derives the correct tree leaf from those words — so ONLY this
/// parser flips.
fn bytes32_hex_to_qhash(hex_str: &str) -> Result<QHashOut<F>> {
    let raw = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(raw).context("not hex")?;
    if bytes.len() != 32 {
        bail_anyhow(format!("expected 32 bytes, got {}", bytes.len()))?;
    }
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[3 - i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    Ok(QHashOut::<F>::from_values(limbs[0], limbs[1], limbs[2], limbs[3]))
}

/// Parse a QHashOut from its Display hex. Display is LIMB-REVERSED: element 3
/// first, each limb big-endian (pinned by the unit test below). Parsing it
/// straight-through silently reverses the elements — which is how one deposit
/// went to a mangled shield address the contract could never associate with
/// (user, r0, r1), stranding it at claim time.
fn qhash_from_display_hex(hex_str: &str) -> Result<QHashOut<F>> {
    let raw = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(raw).context("invalid shield address hex")?;
    if bytes.len() != 32 {
        bail_anyhow(format!("shield address must be 32 bytes, got {}", bytes.len()))?;
    }
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[3 - i] = u64::from_be_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    Ok(QHashOut::<F>::from_values(limbs[0], limbs[1], limbs[2], limbs[3]))
}

/// Parse psy-services' "internal" qhash hex: per limb, TWO u32 words with the
/// LOW u32 first (each u32 big-endian). Used by the service for `deposit_root`
/// and `siblings[]` — while `leaf_hash` in the SAME response uses the display
/// form. Two encodings, one JSON object; the web wallet documents both
/// (l2wallet.ts qhashHexToCanonicalU64x4 vs qhashHexFromDisplay).
fn qhash_from_internal_hex(hex_str: &str) -> Result<QHashOut<F>> {
    let raw = hex_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(raw).context("not hex")?;
    if bytes.len() != 32 {
        bail_anyhow(format!("expected 32 bytes, got {}", bytes.len()))?;
    }
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let lo = u32::from_be_bytes(bytes[i * 8..i * 8 + 4].try_into().unwrap()) as u64;
        let hi = u32::from_be_bytes(bytes[i * 8 + 4..i * 8 + 8].try_into().unwrap()) as u64;
        limbs[i] = lo | (hi << 32);
    }
    Ok(QHashOut::<F>::from_values(limbs[0], limbs[1], limbs[2], limbs[3]))
}

fn bail_anyhow(msg: String) -> Result<()> {
    Err(anyhow!(msg))
}

fn u64_to_u32x8_be(v: u64) -> [u32; 8] {
    let mut out = [0u32; 8];
    out[6] = (v >> 32) as u32;
    out[7] = (v & 0xffff_ffff) as u32;
    out
}

impl DepositNote {
    /// The bytes32 forms the Router call carries.
    pub fn l1_words(&self) -> Result<([u8; 32], [u8; 32])> {
        // shield_address_hex is ELEMENTS order (see receive_identity) — parse
        // with the elements parser, not the display-order one.
        let limbs = parse_shield_elements_hex_pub(&self.shield_address_hex)?;
        let shield = QHashOut::<F>::from_values(limbs[0], limbs[1], limbs[2], limbs[3]);
        let commitment = derive_note_commitment(self.nullifier_secret, self.note_secret);
        Ok((qhash_to_bytes32_be(shield), qhash_to_bytes32_be(commitment)))
    }

    pub fn path_in(dir: &std::path::Path, network: &str, expected_index: u64) -> Result<std::path::PathBuf> {
        Ok(crate::keystore::network_dir(dir, network)?
            .join("deposits")
            .join(format!("deposit-{expected_index}.json")))
    }

    /// Write atomically with owner-only permissions, fsynced — a torn secrets
    /// file is as fatal as a missing one.
    pub fn persist(&self, dir: &std::path::Path) -> Result<std::path::PathBuf> {
        let network = self.network.as_deref().ok_or_else(|| anyhow!("deposit note has no network"))?;
        let path = Self::path_in(dir, network, self.expected_deposit_index)?;
        let parent = path.parent().ok_or_else(|| anyhow!("deposit note path has no parent"))?;
        std::fs::create_dir_all(parent)?;
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("deposit note {path:?} unreadable"))?;
        Ok(serde_json::from_str(&text)?)
    }
}

/// Recovery material for a private note, persisted to the OWNER's keystore
/// BEFORE the on-chain settle: a note that settles and then fails to deliver
/// is debited-but-unclaimable, and the secrets that recover it must never
/// depend on the model's context window (which is exactly what gets compacted
/// away) or appear in a tool result (which the agent can read and exfiltrate).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PrivateNoteRecovery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub note_secret: [u64; 4],
    pub nullifier_secret: [u64; 4],
    pub note_commitment: [u64; 4],
    pub recipient_shielded_hex: String,
    pub recipient_npub: String,
    pub amount_nano: u64,
    pub contract_id: u64,
    /// Filled in once the transfer settles.
    pub tx_hash: Option<String>,
    pub checkpoint_id: Option<u64>,
    pub note_proof_json: Option<String>,
    /// True once the note reached the recipient over Nostr.
    pub delivered: bool,
}

impl PrivateNoteRecovery {
    pub fn path_in(dir: &std::path::Path, network: &str, note_commitment: &[u64; 4]) -> Result<std::path::PathBuf> {
        Ok(crate::keystore::network_dir(dir, network)?.join("private-notes").join(format!(
            "note-{:016x}{:016x}{:016x}{:016x}.json",
            note_commitment[0], note_commitment[1], note_commitment[2], note_commitment[3]
        )))
    }

    /// Same atomic 0600 fsynced write as DepositNote — a torn secrets file is
    /// as fatal as a missing one.
    pub fn persist(&self, dir: &std::path::Path) -> Result<std::path::PathBuf> {
        let network = self.network.as_deref().ok_or_else(|| anyhow!("private-note recovery has no network"))?;
        let path = Self::path_in(dir, network, &self.note_commitment)?;
        let parent = path.parent().ok_or_else(|| anyhow!("private-note path has no parent"))?;
        std::fs::create_dir_all(parent)?;
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }
}

impl WalletManager {
    pub async fn build_shield_deposit_delivery_proof(
        &self,
        network: &NetworkId,
        note: &DepositNote,
        service_proof: &serde_json::Value,
    ) -> Result<String> {
        let claim = self.build_shield_deposit_claim(network, note, service_proof).await?;
        let local_index = service_proof
            .get("chain_local_deposit_index")
            .and_then(|value| value.as_u64())
            .or_else(|| service_proof.get("deposit_index").and_then(|value| value.as_u64()))
            .ok_or_else(|| anyhow!("proof has no deposit index"))?;
        let deposit_leaf = bytes32_hex_to_qhash(
            service_proof
                .get("leaf_hash")
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow!("proof has no leaf_hash"))?,
        )?;
        let proved_count = service_proof
            .get("snapshot_deposit_count")
            .or_else(|| service_proof.get("tree_count"))
            .or_else(|| service_proof.get("proved_deposit_count"))
            .or_else(|| service_proof.get("proved_count"))
            .and_then(|value| value.as_u64())
            .unwrap_or(note.expected_deposit_index.saturating_add(1));
        let as_strings = |hash: QHashOut<F>| hash.0.elements.map(|value| value.to_canonical_u64().to_string());
        let proof_bytes = bincode::serialize(&claim.proof).context("serialize deposit inclusion proof as bincode")?;
        Ok(serde_json::json!({
            "type": "deposit_inclusion_proof",
            "version": 1,
            "shield_address": as_strings(claim.shield_address),
            "amount_u32x8": claim.amount.map(|value| value.to_string()),
            "token_address_u32x8": claim.token_address.map(|value| value.to_string()),
            "l2_token_contract_id": claim.l2_token_contract_id.map(|value| value.to_string()),
            "source_chain_index": note.source_chain_index.to_string(),
            "deposit_index": local_index.to_string(),
            "deposit_root": as_strings(claim.deposit_root),
            "nullifier": as_strings(claim.nullifier_hash),
            "nullifier_hash": as_strings(claim.nullifier_hash),
            "note_commitment": as_strings(claim.note_commitment),
            "deposit_leaf": as_strings(deposit_leaf),
            "proved_deposit_count": proved_count.to_string(),
            "checkpoint_id": service_proof.get("checkpoint_id").and_then(|value| value.as_str().map(str::to_string).or_else(|| value.as_u64().map(|number| number.to_string()))),
            "deposit_proof_fingerprint": as_strings(claim.proof_fingerprint),
            "deposit_proof_bincode_b64": base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                proof_bytes,
            ),
        })
        .to_string())
    }

    /// Claim a proved deposit into this wallet's balance.
    ///
    /// `proof` is psy-services' deposit-claim-proof response (`data`). The
    /// service's leaf is cross-checked against a locally derived commitment
    /// before proving: a mismatch means the secrets do not match the on-chain
    /// deposit, and proving anyway would waste minutes to fail in-circuit.
    pub async fn build_shield_deposit_claim(
        &self,
        network: &NetworkId,
        note: &DepositNote,
        proof: &serde_json::Value,
    ) -> Result<psy_prover::session::ShieldDepositClaim> {
        let identity = self.receive_identity(network).await?;

        let deposit_root = qhash_from_internal_hex(
            proof
                .get("deposit_root")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("proof has no deposit_root"))?,
        )?;
        let leaf = bytes32_hex_to_qhash(
            proof
                .get("leaf_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("proof has no leaf_hash"))?,
        )?;
        let siblings: Vec<QHashOut<F>> = proof
            .get("siblings")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("proof has no siblings"))?
            .iter()
            .map(|s| qhash_from_internal_hex(s.as_str().unwrap_or_default()))
            .collect::<Result<_>>()?;
        let local_index = proof
            .get("chain_local_deposit_index")
            .and_then(|v| v.as_u64())
            .or_else(|| proof.get("deposit_index").and_then(|v| v.as_u64()))
            .ok_or_else(|| anyhow!("proof has no deposit index"))?;
        let global_index = proof.get("deposit_index").and_then(|v| v.as_u64()).unwrap_or(local_index);

        // Local re-derivation of the leaf. The service is trusted for the tree,
        // never for which deposit is ours.
        // NOTE: this field has TWO historical encodings — old senders stored
        // the serde/DISPLAY hex (limb-reversed), new ones the elements form.
        // The elements parser takes both spellings of colon-hex identically, so
        // we cannot distinguish them by shape; the note's claim uses the
        // envelope's owner (not this field) for correctness, and this parse only
        // feeds display/derivation paths that re-derive from (user, r0, r1).
        let shield = parse_shield_elements_hex_pub(&note.shield_address_hex)
            .map(|l| QHashOut::<F>::from_values(l[0], l[1], l[2], l[3]))
            .or_else(|_| qhash_from_display_hex(&note.shield_address_hex))?;
        let token_words = {
            // reuse the withdraw-side EVM address parser (right-aligned bytes32)
            let w = evm_addr_to_u32x8_be(&note.l1_token_address)?;
            [
                w[0] as u32,
                w[1] as u32,
                w[2] as u32,
                w[3] as u32,
                w[4] as u32,
                w[5] as u32,
                w[6] as u32,
                w[7] as u32,
            ]
        };
        let l2_words = u64_to_u32x8_be(note.l2_token_contract_id);
        let amount_words = u64_to_u32x8_be(note.amount_base_units);
        let note_commitment = derive_note_commitment(note.nullifier_secret, note.note_secret);
        let derived_leaf =
            psy_crypto::shield_address::derive_deposit_commitment(shield, token_words, l2_words, amount_words, note.source_chain_index, {
                let e = note_commitment.0.elements;
                [
                    e[0].to_canonical_u64(),
                    e[1].to_canonical_u64(),
                    e[2].to_canonical_u64(),
                    e[3].to_canonical_u64(),
                ]
            });
        if derived_leaf != leaf {
            return Err(anyhow!(
                "the service's deposit leaf does not match these secrets \
                 (service {leaf}, derived {derived_leaf}) — wrong deposit index or wrong note file"
            ));
        }

        let deposit_proof = MerkleProofCore::new_from_params::<PoseidonHasher>(local_index, leaf, siblings);
        if deposit_proof.root != deposit_root {
            return Err(anyhow!(
                "deposit merkle proof does not reproduce the root \
                 (computed {}, service {deposit_root}) — refusing to build a witness the circuit rejects",
                deposit_proof.root
            ));
        }

        let to_felts = |w: [u64; 4]| {
            [
                F::from_canonical_u64(w[0]),
                F::from_canonical_u64(w[1]),
                F::from_canonical_u64(w[2]),
                F::from_canonical_u64(w[3]),
            ]
        };
        let input = psy_client_data::privacy::deposit_inclusion::DepositInclusionInput::<F> {
            nullifier_secret: to_felts(note.nullifier_secret),
            note_secret: to_felts(note.note_secret),
            shield_address: shield,
            deposit_index: global_index,
            token_address: token_words,
            l2_token_contract_id: l2_words,
            amount: amount_words,
            source_chain_index: note.source_chain_index,
            deposit_root,
            deposit_proof,
        };
        let (fingerprint, zk_proof, verifier_data) = self.state(network).await?.session.prove_shield_deposit_claim(&input).await?;

        let claim = psy_prover::session::ShieldDepositClaim {
            contract_id: note.l2_token_contract_id,
            l2_token_contract_id: l2_words,
            nullifier_hash: psy_crypto::shield_address::derive_nullifier_hash(note.nullifier_secret),
            shield_address: shield,
            token_address: token_words,
            amount: amount_words,
            source_chain_index: note.source_chain_index,
            deposit_root,
            note_commitment,
            deposit_index: global_index,
            r0: identity.random0,
            r1: identity.random1,
            proof_fingerprint: fingerprint,
            proof: zk_proof,
            verifier_data,
        };
        Ok(claim)
    }

    /// Claim a single shield deposit — the thin wrapper over the builder above.
    pub async fn claim_shield_deposit(&self, network: &NetworkId, note: &DepositNote, proof: &serde_json::Value) -> Result<String> {
        let claim = self.build_shield_deposit_claim(network, note, proof).await?;
        self.claim_batch(network, vec![ClaimBatchItem::ShieldDeposit(claim)]).await
    }

    /// Fuse public claims, public transfers, withdraws, shield-deposit claims
    /// and private-note claims into ONE UPS proof / one tx. The claim_batch
    /// primitive has always accepted mixed items — this is the thin method
    /// that builds the mixed `Vec<ClaimBatchItem>` instead of a
    /// single-variant one.
    pub async fn claim_batch_mixed(
        &self,
        network: &NetworkId,
        expected_user_id: Option<u64>,
        public_claims: Vec<(u64, u64)>,  // (sender_user_id, contract_id) — simple_claim
        transfers: Vec<(u64, u64, u64)>, // (to_user_id, amount, contract_id) — simple_transfer
        withdraws: Vec<WithdrawLeg>,
        deposits: Vec<(&DepositNote, &serde_json::Value)>,
        private_notes: Vec<(&IncomingPrivateNote, u64)>, // (note, contract_id)
    ) -> Result<String> {
        if public_claims.is_empty() && transfers.is_empty() && withdraws.is_empty() && deposits.is_empty() && private_notes.is_empty() {
            return Err(anyhow!("nothing to claim or execute"));
        }
        let mut items: Vec<ClaimBatchItem> = public_claims
            .into_iter()
            .map(|(sender, contract_id)| {
                ClaimBatchItem::Public(ContractCallArgs {
                    contract_id,
                    method_name: "simple_claim".to_string(),
                    inputs: vec![sender],
                })
            })
            .collect();
        for (to_user_id, amount, contract_id) in transfers {
            items.push(ClaimBatchItem::Public(ContractCallArgs {
                contract_id,
                method_name: "simple_transfer".to_string(),
                inputs: vec![to_user_id, amount],
            }));
        }
        for leg in &withdraws {
            items.push(build_withdraw_item(leg)?);
        }
        for (note, proof) in deposits {
            let claim = self.build_shield_deposit_claim(network, note, proof).await?;
            items.push(ClaimBatchItem::ShieldDeposit(claim));
        }
        for (note, contract_id) in private_notes {
            items.push(self.build_private_note_claim(network, note, contract_id).await?);
        }
        match expected_user_id {
            Some(user_id) => self.claim_batch_for(network, user_id, items).await,
            None => self.claim_batch(network, items).await,
        }
    }
}

/// One withdraw leg of a fused claim_batch — same 33-input contract call the
/// standalone `withdraw` builds, expressed as a batch item instead.
#[derive(Clone)]
pub struct WithdrawLeg {
    pub dest_chain_index: u64,
    pub l1_token_address: String,
    pub amount_nano: u64,
    pub l1_recipient: String,
    pub nonce: u64,
    pub contract_id: u64,
}

/// Build the `withdraw` contract call (exactly 33 inputs) as a batch item.
fn build_withdraw_item(leg: &WithdrawLeg) -> Result<ClaimBatchItem> {
    let token = evm_addr_to_u32x8_be(&leg.l1_token_address).context("l1_token_address")?;
    let recipient = evm_addr_to_u32x8_be(&leg.l1_recipient).context("l1_recipient")?;
    let amount = u256_to_u32x8_be(leg.amount_nano as u128);
    let nonce_words = u256_to_u32x8_be(leg.nonce as u128);
    let mut inputs = Vec::with_capacity(33);
    inputs.push(leg.dest_chain_index);
    inputs.extend_from_slice(&token);
    inputs.extend_from_slice(&amount);
    inputs.extend_from_slice(&recipient);
    inputs.extend_from_slice(&nonce_words);
    debug_assert_eq!(inputs.len(), 33, "withdraw must submit exactly 33 inputs");
    Ok(ClaimBatchItem::Public(ContractCallArgs {
        contract_id: leg.contract_id,
        method_name: "withdraw".to_string(),
        inputs,
    }))
}

#[cfg(test)]
mod qhash_encoding_tests {
    use super::*;

    /// Display is element-3-first (limb-reversed) — pinned here because parsing
    /// it straight-through mangles the shield address and strands deposits at
    /// the contract's shield == derive(user, r0, r1) assertion.
    #[test]
    fn display_hex_is_limb_reversed() {
        let h = derive_shield_address(204800, 1, 2);
        let rev: String = h.0.elements.iter().rev().map(|e| format!("{:016x}", e.to_canonical_u64())).collect();
        assert_eq!(h.to_string(), rev, "Display convention changed — re-audit every hex parse");
    }

    /// The display parser must invert Display exactly.
    #[test]
    fn display_parse_round_trips() {
        let h = derive_shield_address(204800, 7, 9);
        let back = qhash_from_display_hex(&h.to_string()).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn base58check_accepts_all_version_prefixes() {
        // 0x05d4 produces s1/s2/s3 depending on the payload's high bits.
        let cases = [
            ("s1FgCxeeRn4tAz3HZs3p5TYRKBpQueHT2cfczVJW8gydGt5BGgf", [0u64; 4]),
            ("s2E3o5NfMVQVjtq929rp47qomk8GjVhtRSCg7ZeT8WypXCfuTUT", [0x8000_0000_0000_0000, 0, 0, 0]),
            ("s3CRPC6gHCk7JoczUSfp2n9CEJS8ZM8KpFjjEdzQ8Lz1mSdKW9T", [u64::MAX; 4]),
        ];
        for (encoded, expected) in cases {
            assert_eq!(parse_shield_elements_hex_pub(encoded).unwrap(), expected);
        }
    }

    #[test]
    fn base58check_encoding_matches_wallet_vectors() {
        let cases = [
            ([0u64; 4], "s1FgCxeeRn4tAz3HZs3p5TYRKBpQueHT2cfczVJW8gydGt5BGgf"),
            ([0x8000_0000_0000_0000, 0, 0, 0], "s2E3o5NfMVQVjtq929rp47qomk8GjVhtRSCg7ZeT8WypXCfuTUT"),
        ];
        for (limbs, expected) in cases {
            let value = QHashOut::<F>::from_values(limbs[0], limbs[1], limbs[2], limbs[3]);
            assert_eq!(shield_address_base58(value), expected);
        }
    }

    #[test]
    fn base58check_rejects_bad_checksum() {
        let mut encoded = b"s2E3o5NfMVQVjtq929rp47qomk8GjVhtRSCg7ZeT8WypXCfuTUT".to_vec();
        *encoded.last_mut().unwrap() = b'1';
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(parse_shield_elements_hex_pub(&encoded).is_err());
    }

    #[test]
    fn receive_secrets_match_wallet_privacy_v0_vector() {
        let private_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let (r0, r1, nostr_secret) = derive_receive_secrets(private_key, 0).unwrap();
        assert_eq!(r0, 13_645_174_993_047_148_726);
        assert_eq!(r1, 4_511_703_442_179_585_548);
        assert_eq!(hex::encode(nostr_secret), "e8ac6b144dd32898bb614e516aa79b678f1687456c62db410be4397ab97f11fc");
    }
}

impl WalletManager {
    /// Spendable public balance for a token contract, read from the chain
    /// (contract state leaf 0, felt 0) at the latest checkpoint.
    pub async fn balance(&self, network: &NetworkId, contract_id: u64) -> Result<u64> {
        let user = self.require_user(network).await?;
        let checkpoint = self.latest_checkpoint(network).await?;
        let provider = self.state(network).await?.session.st_provider.with_user_id_owned(user.user_id);
        let proof = provider
            .get_user_contract_state_tree_merkle_proof(
                checkpoint,
                user.user_id,
                contract_id as u32,
                psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
                0,
            )
            .await?;
        Ok(proof.value.0.elements[0].to_canonical_u64())
    }
}
