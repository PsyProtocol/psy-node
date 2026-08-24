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

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::PrimeField64;
use rand::RngCore;
use psy_client_common::args::{ContractCallArgs, ContractCallData};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::privacy::private_note_inclusion::PrivateNoteInclusionInput;
use psy_client_data::traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync};
use psy_crypto::hash::merkle::core::MerkleProofCore;
use psy_crypto::hash::traits::hasher::{FieldQHasher, PoseidonHasher};
use psy_crypto::shield_address::{derive_note_commitment, derive_shield_address};

/// Public alias so main.rs's drain pre-check can reuse the same derivation
/// without importing the psy_crypto dep directly.
pub fn derive_shield_address_pub(user_id: u64, r0: u64, r1: u64) -> QHashOut<F> {
    derive_shield_address(user_id, r0, r1)
}

pub use qhash_to_u64x4 as qhash_to_u64x4_pub;

use plonky2::field::types::Field;
use nostr::ToBech32;
use psy_prover::session::{ClaimBatchItem, PrivateTransferClaim, WalletSession};
use psy_client_data::config::store_config::{C, D};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_dpn_circuit::circuits::privacy::private_note_inclusion::PrivateNoteInclusionCircuit;
use plonky2::plonk::proof::ProofWithPublicInputs;
use crate::agent_account::{self, Capability, CapabilityRequest, Mandate};

/// A private transfer that has been fully computed but NOT submitted. Holds the
/// exact on-chain call and the note material the recipient needs to claim. Kept
/// separate from submission because delivering the note (over Nostr) to the
/// recipient is what makes the funds claimable, and that delivery format must be
/// verified against recipient wallets before an agent settles real value — see
/// the `private_transfer` tool docs.
#[derive(Debug)]
pub struct PreparedPrivateTransfer {
    pub contract_id: u64,
    pub amount: u64,
    pub owner: [u64; 4],
    pub note_commitment: [u64; 4],
    pub note_secret: [u64; 4],
    pub nullifier_secret: [u64; 4],
    /// The `private_transfer` call inputs: [owner×4, amount, note_commitment×4].
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
    limbs
        .iter()
        .map(|l| format!("{l:016x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse a shield address in elements order: `0xL0:...:L3` canonical, a bare
/// 64-hex blob, or limb-per-colon hex. Returns the limbs as elements.
fn parse_shield_elements_hex(raw: &str) -> Result<[u64; 4]> {
    let s = raw.trim();
    if s.contains(':') {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            anyhow::bail!("shielded address must have 4 limbs");
        }
        let mut out = [0u64; 4];
        for (i, p) in parts.iter().enumerate() {
            out[i] = u64::from_str_radix(p.trim().trim_start_matches("0x"), 16)
                .with_context(|| format!("limb {i} is not hex"))?;
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
    // s2… Base58Check shield (the web wallets' copy form): 2-byte version
    // 0x05d4 + 32 payload bytes (four BE u64 limbs, elements order) + 4-byte
    // sha256d checksum.
    if s.starts_with("s2") {
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
        // Leading '1's would encode zero bytes — the s2 version prefix makes a
        // zero-leading payload impossible, so none to re-prepend.
        if raw.len() != 38 {
            anyhow::bail!("s2 address decoded to {} bytes, expected 38", raw.len());
        }
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
    anyhow::bail!("invalid recipient shielded address (expected elements-order hex or s2 base58check)");
}

pub fn qhash_to_u64x4(value: QHashOut<F>) -> [u64; 4] {
    [
        value.0.elements[0].to_canonical_u64(),
        value.0.elements[1].to_canonical_u64(),
        value.0.elements[2].to_canonical_u64(),
        value.0.elements[3].to_canonical_u64(),
    ]
}

/// True when a submission failed because the chain advanced while the wallet was
/// building the tx. The session snapshots the user leaf when the wallet loads;
/// any tx that settles afterwards (a claim landing, an earlier spend) makes the
/// next spend build on a stale leaf, and the chain rejects it with one of these
/// two messages. Both mean "rebuild on the latest state" — never "already
/// spent" — so re-syncing the user and retrying once is safe and cannot
/// double-settle.
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
/// `mandate` is set only for SDKey agent accounts: it is the set of capabilities
/// compiled into the identity's circuit. A plain key wallet has none — its
/// authority is unrestricted at the circuit level and bounded only by policy.
#[derive(Clone, Debug)]
pub struct LoadedUser {
    pub pk_hash: QHashOut<F>,
    pub user_id: u64,
    pub mandate: Option<Mandate>,
    /// Kept in memory (never serialized) so the wallet can re-derive its private
    /// receive identity — the shielded address' blinding factors must come from
    /// the key, or the address becomes linkable to the public user id.
    pub private_key: QHashOut<F>,
}

/// A freshly minted agent account plus whatever the caller's key-backup step
/// produced (typically the path the key was written to).
pub struct MintedAgentAccount<P> {
    pub user: LoadedUser,
    pub key_backup: P,
}

pub struct WalletManager {
    session: WalletSession,
    user: Option<LoadedUser>,
}

impl WalletManager {
    /// Build a session from a Psy config file (default `config.json`). This reads
    /// the coordinator/realm/prove-proxy/api_services endpoints for the currently
    /// selected network and warms the circuit metadata from the prove-proxy.
    pub async fn from_config(config_path: &str) -> Result<Self> {
        let psy_config = psy_config::PsyConfigGoldilocks::from_file(config_path)
            .with_context(|| format!("failed to read Psy config `{config_path}`"))?;
        let rpc_config = psy_config
            .get_current_network()
            .context("no current network in Psy config")?
            .clone();
        let session = WalletSession::new(&rpc_config)
            .await
            .context("failed to init WalletSession (prove-proxy / coordinator unreachable?)")?;
        Ok(Self { session, user: None })
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
    /// Registration is asynchronous on Psy: `register_user` submits the request,
    /// but the coordinator only mints the user id once the registration lands in
    /// a checkpoint (the engine itself logs "please add this user after 2
    /// checkpoints"). Resolving immediately therefore fails on any real network —
    /// it only appeared to work against a local devnet whose checkpoints are
    /// near-instant. We poll until the id exists, mirroring what the shipped web
    /// wallet's sign-in sequence does.
    pub async fn register(&mut self, private_key_hex: &str) -> Result<LoadedUser> {
        let private_key = Self::parse_key(private_key_hex)?;
        let fingerprint = self.session.get_zk_public_key(private_key).await?.fingerprint;
        let pk_hash = self.session.register_user(private_key, fingerprint).await?;
        let user_id = self.await_user_id(pk_hash, REGISTRATION_TIMEOUT).await?;
        let loaded = LoadedUser { pk_hash, user_id, mandate: None, private_key };
        self.user = Some(loaded.clone());
        Ok(loaded)
    }

    /// Mint an **agent account**: an identity whose key is an SDKey circuit
    /// encoding `capabilities` (see `agent_account.rs`).
    ///
    /// The identity is derived from `(private_key, circuit_fingerprint)`, so the
    /// mandate is part of who the agent *is* — it cannot be widened after the
    /// fact, only replaced by minting a different account.
    ///
    /// Order is deliberate and must not be rearranged: resolve method ids →
    /// build the circuit → hand the caller the key for backup → register
    /// on-chain. `on_key_generated` runs after the key exists but **before** the
    /// chain learns the identity, so a crash can never produce a registered
    /// account whose key nobody holds (see `keystore.rs`).
    pub async fn mint_agent_account<F2, P>(
        &mut self,
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
                .session
                .wallet
                .random_circuit_manager()
                .get_fn_id(req.contract_id, req.method_name.clone())
                .await
                .with_context(|| {
                    format!("no method `{}` on contract {} (check the name and contract id)", req.method_name, req.contract_id)
                })?;
            let method_id = u32::try_from(fn_id)
                .map_err(|_| anyhow!("method id {fn_id} for `{}` exceeds the u32 range the circuit supports", req.method_name))?;
            capabilities.push(Capability { contract_id: req.contract_id, method_name: req.method_name.clone(), method_id });
        }
        let capabilities = agent_account::dedupe(capabilities);
        agent_account::validate(&capabilities, calls_per_transaction)?;

        // Compile the mandate into a circuit. Its fingerprint IS the mandate's
        // public identity, and is what makes the constraint auditable.
        let (contract_ids, method_ids): (Vec<u64>, Vec<u32>) =
            capabilities.iter().map(|c| (c.contract_id, c.method_id)).unzip();
        let fingerprint = self
            .session
            .register_sd_key_circuit(&contract_ids, &method_ids, calls_per_transaction)
            .await
            .context("failed to build the agent's SDKey circuit")?;

        let mandate = Mandate {
            capabilities,
            calls_per_transaction,
            circuit_fingerprint: fingerprint.to_string(),
        };

        let keypair = self.session.get_random_keypair().await?;
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
            .session
            .register_user(private_key, fingerprint)
            .await
            .with_context(|| format!("agent key is backed up (circuit {}); registration failed", mandate.circuit_fingerprint))?;
        let user_id = self
            .await_user_id(pk_hash, REGISTRATION_TIMEOUT)
            .await
            .with_context(|| format!("agent key is backed up (circuit {})", mandate.circuit_fingerprint))?;

        let user = LoadedUser { pk_hash, user_id, mandate: Some(mandate), private_key };
        self.user = Some(user.clone());
        Ok(MintedAgentAccount { user, key_backup })
    }

    /// The mandate of the loaded account, if it is an agent account.
    pub fn current_mandate(&self) -> Option<&Mandate> {
        self.user.as_ref().and_then(|u| u.mandate.as_ref())
    }

    /// Poll until the coordinator has minted a user id for `pk_hash`.
    ///
    /// Transport failures are treated as "not yet" rather than fatal: a single
    /// blip during a multi-minute wait must not discard a key that is already
    /// registering on-chain. Only exhausting the deadline is an error, and its
    /// message tells the caller the registration may still be in flight — the
    /// key is safe either way (see keystore.rs).
    async fn await_user_id(&self, pk_hash: QHashOut<F>, timeout: Duration) -> Result<u64> {
        let deadline = Instant::now() + timeout;
        let mut attempt: u32 = 0;
        loop {
            match self.resolve_user_id(pk_hash).await {
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
    pub async fn load(&mut self, private_key_hex: &str) -> Result<LoadedUser> {
        let private_key = Self::parse_key(private_key_hex)?;
        let fingerprint = self.session.get_zk_public_key(private_key).await?.fingerprint;
        let pk_hash = self.session.add_user(private_key, fingerprint).await?;
        let user_id = self.resolve_user_id(pk_hash).await?;
        let loaded = LoadedUser { pk_hash, user_id, mandate: None, private_key };
        self.user = Some(loaded.clone());
        Ok(loaded)
    }

    /// Restore a wallet from a key backup, re-registering the agent's circuit
    /// first when the backup records a mandate.
    ///
    /// `load()` derives the identity from the DEFAULT zk fingerprint, which is
    /// correct for an ordinary wallet and wrong for a minted agent account:
    /// that identity is `(private_key, circuit_fingerprint)`, so add_user
    /// produced a different pk_hash and the user id never resolved. Following
    /// mint_agent_account's own "restart with PSY_MCP_KEY_FILE" instruction
    /// therefore could not work. Re-registering the circuit from the recorded
    /// mandate reproduces the same fingerprint and the same identity.
    pub async fn load_from_backup(&mut self, backup: &crate::keystore::KeyBackup) -> Result<LoadedUser> {
        let Some(mandate) = backup.mandate.clone() else {
            return self.load(&backup.private_key).await;
        };
        let private_key = Self::parse_key(&backup.private_key)?;
        let (contract_ids, method_ids): (Vec<u64>, Vec<u32>) = mandate
            .capabilities
            .iter()
            .map(|c| (c.contract_id, c.method_id))
            .unzip();
        let fingerprint = self
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
        let pk_hash = self.session.add_user(private_key, fingerprint).await?;
        let user_id = self.resolve_user_id(pk_hash).await?;
        let loaded = LoadedUser { pk_hash, user_id, mandate: Some(mandate), private_key };
        self.user = Some(loaded.clone());
        Ok(loaded)
    }

    async fn resolve_user_id(&self, pk_hash: QHashOut<F>) -> Result<u64> {
        self.session
            .st_provider
            .get_user_ids_for_public_key(pk_hash)
            .await?
            .first()
            .copied()
            .ok_or_else(|| anyhow!("no on-chain user id for this key (not registered yet?)"))
    }

    pub fn current_user(&self) -> Option<&LoadedUser> {
        self.user.as_ref()
    }

    pub fn require_user(&self) -> Result<&LoadedUser> {
        self.user
            .as_ref()
            .ok_or_else(|| anyhow!("no wallet loaded — call create_wallet/load first"))
    }

    // ── Reads (via the RpcProvider st_provider — the same reads WalletSession uses) ──

    pub async fn latest_checkpoint(&self) -> Result<u64> {
        Ok(self
            .session
            .st_provider
            .get_coordinator_latest_block_state()
            .await?
            .checkpoint_id)
    }

    /// Public claimable owed to the loaded user by a specific sender.
    pub async fn claim_amount_from(&self, sender_user_id: u64) -> Result<u64> {
        let user = self.require_user()?;
        let checkpoint = self.latest_checkpoint().await?;
        self.session
            .st_provider
            .get_claim_amount(checkpoint, user.user_id, sender_user_id)
            .await
    }

    // ── Spends (real proofs via exec_contract_call / claim_batch) ──

    /// Generic contract call — the primitive every spend builds on.
    /// Returns the submitted end-user-leaf-hash as a hex string.
    pub async fn exec_call(&mut self, contract_id: u64, method_name: &str, inputs: Vec<u64>) -> Result<String> {
        let user = self.require_user()?.clone();
        let call = ContractCallArgs {
            contract_id,
            method_name: method_name.to_string(),
            inputs,
        };
        // On this branch, exec_contract_call returns the end-user-leaf-hash
        // (QHashOut<F>) directly rather than a TxMetadata wrapper.
        let first = self
            .session
            .exec_contract_call(user.pk_hash, ContractCallData::new(vec![call.clone()]))
            .await;
        match first {
            Ok(leaf) => Ok(leaf.to_string()),
            // The session snapshots the user leaf when the wallet loads; any
            // transaction that settles afterwards (a claim landing, an earlier
            // spend) makes the next spend build on a stale leaf and the chain
            // rejects it with a stale-state error. That is staleness, not
            // failure: re-attach the user (which re-reads the live leaf) and
            // retry ONCE. Anything else propagates untouched.
            Err(e) if is_stale_state_error(&e) => {
                let fingerprint = self.session.get_zk_public_key(user.private_key).await?.fingerprint;
                self.session.update_circuit_mgr(user.pk_hash).await.ok();
                let _ = self
                    .session
                    .add_user(user.private_key, fingerprint)
                    .await
                    .context("re-syncing the user after a stale-state rejection")?;
                let leaf = self
                    .session
                    .exec_contract_call(user.pk_hash, ContractCallData::new(vec![call]))
                    .await?;
                Ok(leaf.to_string())
            }
            Err(e) => Err(e),
        }
    }

    /// Public transfer: `simple_transfer(recipient_user_id, amount_nano)`.
    pub async fn transfer(&mut self, to_user_id: u64, amount_nano: u64, contract_id: u64) -> Result<String> {
        self.exec_call(contract_id, "simple_transfer", vec![to_user_id, amount_nano]).await
    }

    /// Claim a batch (UPS): fuses N claims (+ optional trailing calls) into one
    /// recursive proof / one transaction. This is the real batching primitive.
    ///
    /// Like `exec_call`, a submission that fails because the chain advanced
    /// while the proof was being built (stale leaf / stale nonce) is re-synced
    /// and retried once — an agent paying a seller twice in a row is the normal
    /// shape, and the second payment must not die to a timing artifact.
    pub async fn claim_batch(&mut self, claims: Vec<ClaimBatchItem>) -> Result<String> {
        let user = self.require_user()?.clone();
        let first = self.session.claim_batch(user.pk_hash, claims.clone()).await;
        match first {
            Ok(leaf) => Ok(leaf.to_string()),
            Err(e) if is_stale_state_error(&e) => {
                let fingerprint = self.session.get_zk_public_key(user.private_key).await?.fingerprint;
                self.session.update_circuit_mgr(user.pk_hash).await.ok();
                let _ = self
                    .session
                    .add_user(user.private_key, fingerprint)
                    .await
                    .context("re-syncing the user after a stale-state batch rejection")?;
                let leaf = self.session.claim_batch(user.pk_hash, claims).await?;
                Ok(leaf.to_string())
            }
            Err(e) => Err(e),
        }
    }

    /// Claim all PUBLIC claimables owed by the given senders, fused into ONE UPS
    /// proof / one tx (a `simple_claim` per sender). Claiming is non-destructive:
    /// it only folds funds already addressed to this user into spendable balance.
    /// Private-note and deposit claiming need note/deposit material from the
    /// discovery layer (Nostr drain + inclusion proofs) and are not included here.
    pub async fn claim_all_public(&mut self, sender_ids: Vec<u64>, contract_id: u64) -> Result<String> {
        if sender_ids.is_empty() {
            return Err(anyhow!("no senders provided — pass the user ids that owe you public claims (see get_claimable)"));
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
        self.claim_batch(items).await
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
    pub async fn transfer_batch(&mut self, payments: Vec<(u64, u64)>, contract_id: u64) -> Result<String> {
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
        self.claim_batch(items).await
    }

    /// Compute a private transfer WITHOUT submitting it: derive a fresh note and
    /// the exact `private_transfer` call. Does not touch the chain. Submission is
    /// deliberately separate — see `submit_prepared_private_transfer` and the
    /// funds-safety note in the `private_transfer` tool.
    pub fn prepare_private_transfer(
        &self,
        recipient_shielded_hex: &str,
        amount: u64,
        contract_id: u64,
    ) -> Result<PreparedPrivateTransfer> {
        self.require_user()?;
        // Accept the address with or without the 0x prefix: wallets and explorers
        // show it both ways, and a rejected paste here is indistinguishable from
        // a wrong address to the caller.
        let normalized = recipient_shielded_hex
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        let owner = parse_shield_elements_hex(&normalized)?;

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

    /// Submit a prepared private transfer's on-chain settlement (real proof).
    /// DANGER: settlement alone does not make the funds claimable — the note
    /// material must be delivered to the recipient (over Nostr) in the exact
    /// format their wallet drains, or the funds are stranded. Only call this once
    /// delivery is wired and verified.
    pub async fn submit_prepared_private_transfer(&mut self, prepared: &PreparedPrivateTransfer) -> Result<String> {
        self.exec_call(prepared.contract_id, "private_transfer", prepared.call_inputs.clone()).await
    }

    /// Generate a fresh keypair (private key hex + fingerprint hex) without
    /// touching the chain — the owner then registers it under a policy.
    pub async fn generate_keypair(&self) -> Result<(String, String)> {
        let kp = self.session.get_random_keypair().await?;
        Ok((kp.private_key.to_string(), kp.public_key.fingerprint.to_string()))
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
    ///   4. rebuild the membership proof at THAT checkpoint and prove inclusion.
    ///
    /// The caller must then deliver the note to the recipient. Until delivery
    /// lands the funds are debited but unclaimable, so a failure after step 2
    /// means "retry delivery", never "nothing happened".
    pub async fn settle_private_transfer(
        &mut self,
        prepared: PreparedPrivateTransfer,
        note_root_slot: u64,
    ) -> Result<SettledPrivateTransfer> {
        let user = self.require_user()?;
        let sender_user_id = user.user_id;
        let contract_id = prepared.contract_id;
        let amount = prepared.amount;

        let provider = self.session.st_provider.with_user_id_owned(sender_user_id);
        let checkpoint_before = self.latest_checkpoint().await?;
        let baseline_count =
            Self::read_note_count(&provider, sender_user_id, contract_id, note_root_slot, checkpoint_before)
                .await
                .unwrap_or(0);

        let leaf_hash = self.submit_prepared_private_transfer(&prepared).await?;

        let owner = QHashOut::<F>::from_values(
            prepared.owner[0], prepared.owner[1], prepared.owner[2], prepared.owner[3]);
        let note_commitment = QHashOut::<F>::from_values(
            prepared.note_commitment[0], prepared.note_commitment[1],
            prepared.note_commitment[2], prepared.note_commitment[3]);

        let mut checkpoint_id = 0u64;
        let mut membership = None;
        for _ in 0..120 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let latest = match self.latest_checkpoint().await {
                Ok(v) => v,
                Err(_) => continue,                       // transport blip is not a verdict
            };
            if latest <= checkpoint_before {
                continue;
            }
            let count = match Self::read_note_count(
                &provider, sender_user_id, contract_id, note_root_slot, latest).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            if count <= baseline_count {
                continue;                                 // our note has not landed yet
            }
            let proof = Self::build_membership_proof(
                &provider, sender_user_id, contract_id, note_root_slot,
                amount, owner, note_commitment, latest).await?;
            let slot_proof = provider
                .get_user_contract_state_tree_merkle_proof(
                    latest, sender_user_id, contract_id as u32,
                    psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
                    note_root_slot)
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
            anyhow!("private transfer submitted (leaf {leaf_hash}) but its note never appeared in a \
                     checkpoint — funds are debited and NOT yet claimable; retry proving before re-sending")
        })?;

        let user_leaf = provider.get_user_leaf_data(checkpoint_id, sender_user_id).await?;
        let contract_proof = provider
            .get_user_contract_tree_merkle_proof(checkpoint_id, sender_user_id, contract_id as u32)
            .await?;
        let user_tree_proof = provider.get_user_tree_merkle_proof(checkpoint_id, sender_user_id).await?;
        let global_user_tree_root = user_tree_proof.root;

        let input = PrivateNoteInclusionInput {
            nullifier_secret: QHashOut::<F>::from_values(
                prepared.nullifier_secret[0], prepared.nullifier_secret[1],
                prepared.nullifier_secret[2], prepared.nullifier_secret[3]),
            sender_user_id,
            contract_id,
            note_root_slot,
            user_leaf,
            owner,
            amount: F::from_canonical_u64(amount),
            note_secret: QHashOut::<F>::from_values(
                prepared.note_secret[0], prepared.note_secret[1],
                prepared.note_secret[2], prepared.note_secret[3]),
            note_membership_proof,
            note_root_slot_proof,
            contract_proof,
            user_tree_proof,
            checkpoint_id: F::from_canonical_u64(checkpoint_id),
        };

        let (fingerprint, proof, _vd) = self.session.prove_private_note_inclusion(&input).await?;

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
        let proof_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD, proof.to_bytes());
        let note_proof_json = serde_json::json!({
            "nullifier": to_str_arr(nullifier),
            "owner": to_str_arr(owner),
            "amount": amount.to_string(),
            "user_tree_root": to_str_arr(global_user_tree_root),
            "checkpoint_id": checkpoint_id.to_string(),
            "note_root_slot": note_root_slot.to_string(),
            "note_proof_fingerprint": to_str_arr(fingerprint),
            "note_proof_bincode_b64": proof_b64,
        })
        .to_string();

        let nh = nullifier.0.elements;
        Ok(SettledPrivateTransfer {
            leaf_hash,
            prepared,
            nullifier_hash: [
                nh[0].to_canonical_u64(), nh[1].to_canonical_u64(),
                nh[2].to_canonical_u64(), nh[3].to_canonical_u64(),
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
                checkpoint_id, sender_user_id, contract_id as u32,
                psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
                note_root_slot.saturating_sub(1))
            .await?;
        Ok(proof.value.0.elements[3].to_canonical_u64())
    }

    /// Rebuild the append-only note-tree membership proof for the new note.
    /// Mirrors the contract's own insert (token main.psy `private_transfer`):
    /// the leaf sits at `note_index`, siblings come from the stored frontier for
    /// set bits and from the empty-subtree chain for clear ones.
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
        let note_index = Self::read_note_count(
            provider, sender_user_id, contract_id, note_root_slot, checkpoint_id)
            .await?
            .saturating_sub(1);

        let mut last_path: Vec<QHashOut<F>> = Vec::with_capacity(NOTE_TREE_HEIGHT);
        for level in 0..NOTE_TREE_HEIGHT as u64 {
            let proof = provider
                .get_user_contract_state_tree_merkle_proof(
                    checkpoint_id, sender_user_id, contract_id as u32,
                    psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
                    note_root_slot + 1 + level)
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
    /// The blinding factors are a Poseidon hash of the private key under a
    /// domain tag, not random: a lost r0/r1 makes every note sent to that
    /// address unclaimable, so they must be reproducible from the key alone.
    pub fn receive_identity(&self) -> Result<ReceiveIdentity> {
        let user = self.require_user()?;
        let sk = user.private_key.0.elements;

        let tag = |domain: u64| -> u64 {
            PoseidonHasher::q_hash_many(&[sk[0], sk[1], sk[2], sk[3], F::from_canonical_u64(domain)])
                .0
                .elements[0]
                .to_canonical_u64()
        };
        let random0 = tag(0x5348_4C44_5230); // "SHLDR0"
        let random1 = tag(0x5348_4C44_5231); // "SHLDR1"
        let shield = derive_shield_address(user.user_id, random0, random1);

        // Nostr key: a separate domain so the Psy key can never be recovered
        // from the published npub.
        let nostr_seed = PoseidonHasher::q_hash_many(&[
            sk[0], sk[1], sk[2], sk[3],
            F::from_canonical_u64(0x4E4F_5354_5200), // "NOSTR"
        ]);
        let mut seed = [0u8; 32];
        for (i, limb) in nostr_seed.0.elements.iter().enumerate() {
            seed[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_canonical_u64().to_be_bytes());
        }
        let keys = nostr::Keys::new(
            nostr::SecretKey::from_slice(&seed).context("deriving the Nostr secret key")?,
        );

        Ok(ReceiveIdentity {
            // Elements order — see qhash_to_elements_hex. Publishing the serde
            // (reversed) Display hex here is what made cross-wallet recipients
            // pack reversed note owners and lose the funds to the claim check.
            shield_address_hex: qhash_to_elements_hex(shield),
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
        let value: serde_json::Value = serde_json::from_str(raw.trim())
            .context("note is not valid JSON")?;
        let env: serde_json::Value = match value.get("noteProofRaw") {
            Some(serde_json::Value::String(inner)) => {
                serde_json::from_str(inner).context("noteProofRaw is not valid JSON")?
            }
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
    /// blinding factors its own shielded address was built from. If those do not
    /// match the note's owner the circuit rejects the claim outright ("receiver
    /// does not match claiming user"), so they are checked here first — a clear
    /// error beats a failed proof after a long wait.
    pub fn build_private_note_claim(
        &self,
        note: &IncomingPrivateNote,
        contract_id: u64,
    ) -> Result<ClaimBatchItem> {
        let identity = self.receive_identity()?;
        let user = self.require_user()?;

        let expected_owner = derive_shield_address(user.user_id, identity.random0, identity.random1);
        let owner_limbs = qhash_to_u64x4(expected_owner);
        if owner_limbs != note.owner {
            return Err(anyhow!(
                "this note is addressed to a different shielded address — it is not claimable by \
                 Psy-{:08} (note owner {:?}, this wallet {:?})",
                user.user_id, note.owner, owner_limbs
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
        let proof_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD, note.note_proof_bincode_b64.as_bytes())
            .context("note proof is not valid base64")?;
        let note_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            proof_bytes.clone(), circuit.get_common_circuit_data_ref())
            .or_else(|native_err| {
                bincode::deserialize(&proof_bytes)
                    .map_err(|bin_err| anyhow!("note proof decode failed (native={native_err}; bincode={bin_err})"))
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
    pub async fn claim_private_note(&mut self, note: &IncomingPrivateNote, contract_id: u64) -> Result<String> {
        let item = self.build_private_note_claim(note, contract_id)?;
        self.claim_batch(vec![item]).await
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

/// Right-aligned bytes32 of an EVM address (or a full 32-byte hex), as u32×8 BE.
fn evm_addr_to_u32x8_be(hex: &str) -> Result<[u64; 8]> {
    let raw = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.is_empty() || raw.len() > 64 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("`{hex}` is not a hex address"));
    }
    let padded = format!("{:0>64}", raw);
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = u64::from_str_radix(&padded[i * 8..(i + 1) * 8], 16)
            .map_err(|e| anyhow!("bad address word: {e}"))?;
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
        &mut self,
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

        self.exec_call(contract_id, "withdraw", inputs).await
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
    }
}

// ─── Shield deposits: L1 → Psy ───────────────────────────────────────────────

/// Everything needed to claim a deposit later. Persisted to disk BEFORE the L1
/// transaction is broadcast: the secrets exist nowhere else, and a deposit whose
/// secrets are lost is permanently unclaimable with no error anywhere.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DepositNote {
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
        let limbs = parse_shield_elements_hex(&self.shield_address_hex)?;
        let shield = QHashOut::<F>::from_values(limbs[0], limbs[1], limbs[2], limbs[3]);
        let commitment = derive_note_commitment(self.nullifier_secret, self.note_secret);
        Ok((qhash_to_bytes32_be(shield), qhash_to_bytes32_be(commitment)))
    }

    pub fn path_in(dir: &std::path::Path, expected_index: u64) -> std::path::PathBuf {
        dir.join(format!("deposit-{expected_index}.json"))
    }

    /// Write atomically with owner-only permissions, fsynced — a torn secrets
    /// file is as fatal as a missing one.
    pub fn persist(&self, dir: &std::path::Path) -> Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path_in(dir, self.expected_deposit_index);
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
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("deposit note {path:?} unreadable"))?;
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
    pub fn path_in(dir: &std::path::Path, note_commitment: &[u64; 4]) -> std::path::PathBuf {
        dir.join(format!(
            "note-{:016x}{:016x}{:016x}{:016x}.json",
            note_commitment[0], note_commitment[1], note_commitment[2], note_commitment[3]
        ))
    }

    /// Same atomic 0600 fsynced write as DepositNote — a torn secrets file is
    /// as fatal as a missing one.
    pub fn persist(&self, dir: &std::path::Path) -> Result<std::path::PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path_in(dir, &self.note_commitment);
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
    /// Claim a proved deposit into this wallet's balance.
    ///
    /// `proof` is psy-services' deposit-claim-proof response (`data`). The
    /// service's leaf is cross-checked against a locally derived commitment
    /// before proving: a mismatch means the secrets do not match the on-chain
    /// deposit, and proving anyway would waste minutes to fail in-circuit.
    pub async fn build_shield_deposit_claim(
        &self,
        note: &DepositNote,
        proof: &serde_json::Value,
    ) -> Result<psy_prover::session::ShieldDepositClaim> {
        let identity = self.receive_identity()?;

        let deposit_root = qhash_from_internal_hex(
            proof.get("deposit_root").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("proof has no deposit_root"))?,
        )?;
        let leaf = bytes32_hex_to_qhash(
            proof.get("leaf_hash").and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("proof has no leaf_hash"))?,
        )?;
        let siblings: Vec<QHashOut<F>> = proof
            .get("siblings").and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("proof has no siblings"))?
            .iter()
            .map(|s| qhash_from_internal_hex(s.as_str().unwrap_or_default()))
            .collect::<Result<_>>()?;
        let local_index = proof
            .get("chain_local_deposit_index").and_then(|v| v.as_u64())
            .or_else(|| proof.get("deposit_index").and_then(|v| v.as_u64()))
            .ok_or_else(|| anyhow!("proof has no deposit index"))?;
        let global_index = proof
            .get("deposit_index").and_then(|v| v.as_u64())
            .unwrap_or(local_index);

        // Local re-derivation of the leaf. The service is trusted for the tree,
        // never for which deposit is ours.
        // NOTE: this field has TWO historical encodings — old senders stored
        // the serde/DISPLAY hex (limb-reversed), new ones the elements form.
        // The elements parser takes both spellings of colon-hex identically, so
        // we cannot distinguish them by shape; the note's claim uses the
        // envelope's owner (not this field) for correctness, and this parse only
        // feeds display/derivation paths that re-derive from (user, r0, r1).
        let shield = parse_shield_elements_hex(&note.shield_address_hex)
            .map(|l| QHashOut::<F>::from_values(l[0], l[1], l[2], l[3]))
            .or_else(|_| qhash_from_display_hex(&note.shield_address_hex))?;
        let token_words = {
            // reuse the withdraw-side EVM address parser (right-aligned bytes32)
            let w = evm_addr_to_u32x8_be(&note.l1_token_address)?;
            [w[0] as u32, w[1] as u32, w[2] as u32, w[3] as u32,
             w[4] as u32, w[5] as u32, w[6] as u32, w[7] as u32]
        };
        let l2_words = u64_to_u32x8_be(note.l2_token_contract_id);
        let amount_words = u64_to_u32x8_be(note.amount_base_units);
        let note_commitment = derive_note_commitment(note.nullifier_secret, note.note_secret);
        let derived_leaf = psy_crypto::shield_address::derive_deposit_commitment(
            shield, token_words, l2_words, amount_words,
            note.source_chain_index, {
                let e = note_commitment.0.elements;
                [e[0].to_canonical_u64(), e[1].to_canonical_u64(),
                 e[2].to_canonical_u64(), e[3].to_canonical_u64()]
            },
        );
        if derived_leaf != leaf {
            return Err(anyhow!(
                "the service's deposit leaf does not match these secrets \
                 (service {leaf}, derived {derived_leaf}) — wrong deposit index or wrong note file"
            ));
        }

        let deposit_proof = MerkleProofCore::new_from_params::<PoseidonHasher>(
            local_index, leaf, siblings,
        );
        if deposit_proof.root != deposit_root {
            return Err(anyhow!(
                "deposit merkle proof does not reproduce the root \
                 (computed {}, service {deposit_root}) — refusing to build a witness the circuit rejects",
                deposit_proof.root
            ));
        }

        let to_felts = |w: [u64; 4]| [
            F::from_canonical_u64(w[0]), F::from_canonical_u64(w[1]),
            F::from_canonical_u64(w[2]), F::from_canonical_u64(w[3]),
        ];
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
        let (fingerprint, zk_proof, verifier_data) =
            self.session.prove_shield_deposit_claim(&input).await?;

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
    pub async fn claim_shield_deposit(
        &mut self,
        note: &DepositNote,
        proof: &serde_json::Value,
    ) -> Result<String> {
        let claim = self.build_shield_deposit_claim(note, proof).await?;
        self.claim_batch(vec![ClaimBatchItem::ShieldDeposit(claim)]).await
    }

    /// Fuse public claims, public transfers, withdraws, shield-deposit claims and
    /// private-note claims into ONE UPS proof / one tx. The claim_batch primitive
    /// has always accepted mixed items — this is the thin method that builds the
    /// mixed `Vec<ClaimBatchItem>` instead of a single-variant one.
    pub async fn claim_batch_mixed(
        &mut self,
        public_claims: Vec<(u64, u64)>, // (sender_user_id, contract_id) — simple_claim
        transfers: Vec<(u64, u64, u64)>, // (to_user_id, amount, contract_id) — simple_transfer
        withdraws: Vec<WithdrawLeg>,
        deposits: Vec<(&DepositNote, &serde_json::Value)>,
        private_notes: Vec<(&IncomingPrivateNote, u64)>, // (note, contract_id)
    ) -> Result<String> {
        if public_claims.is_empty() && transfers.is_empty() && withdraws.is_empty()
            && deposits.is_empty() && private_notes.is_empty() {
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
            let claim = self.build_shield_deposit_claim(note, proof).await?;
            items.push(ClaimBatchItem::ShieldDeposit(claim));
        }
        for (note, contract_id) in private_notes {
            items.push(self.build_private_note_claim(note, contract_id)?);
        }
        self.claim_batch(items).await
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
        let rev: String = h.0.elements.iter().rev()
            .map(|e| format!("{:016x}", e.to_canonical_u64()))
            .collect();
        assert_eq!(h.to_string(), rev, "Display convention changed — re-audit every hex parse");
    }

    /// The display parser must invert Display exactly.
    #[test]
    fn display_parse_round_trips() {
        let h = derive_shield_address(204800, 7, 9);
        let back = qhash_from_display_hex(&h.to_string()).unwrap();
        assert_eq!(h, back);
    }
}

impl WalletManager {
    /// Spendable public balance for a token contract, read from the chain
    /// (contract state leaf 0, felt 0) at the latest checkpoint.
    pub async fn balance(&self, contract_id: u64) -> Result<u64> {
        let user = self.require_user()?;
        let checkpoint = self.latest_checkpoint().await?;
        let provider = self.session.st_provider.with_user_id_owned(user.user_id);
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
