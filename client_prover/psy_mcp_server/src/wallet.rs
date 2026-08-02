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

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use plonky2::field::{goldilocks_field::GoldilocksField as F, types::PrimeField64};
use psy_client_common::{
    args::{ContractCallArgs, ContractCallData},
    data::qhashout::QHashOut,
};
use psy_crypto::shield_address::derive_note_commitment;
use psy_prover::session::{ClaimBatchItem, WalletSession};
use rand::RngCore;

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

fn qhash_to_u64x4(value: QHashOut<F>) -> [u64; 4] {
    [
        value.0.elements[0].to_canonical_u64(),
        value.0.elements[1].to_canonical_u64(),
        value.0.elements[2].to_canonical_u64(),
        value.0.elements[3].to_canonical_u64(),
    ]
}

/// Token contract ids on the current chain (config-independent constants used
/// for the convenience transfer/balance helpers). Generic calls can target any
/// contract id directly.
pub const CONTRACT_PSY: u64 = 0;
pub const CONTRACT_USDT: u64 = 4;

/// The loaded user identity (public, non-secret).
#[derive(Clone, Debug)]
pub struct LoadedUser {
    pub pk_hash: QHashOut<F>,
    pub user_id: u64,
}

pub struct WalletManager {
    session: WalletSession,
    user: Option<LoadedUser>,
}

impl WalletManager {
    /// Build a session from a Psy config file (default `config.json`). This
    /// reads the coordinator/realm/prove-proxy/api_services endpoints for
    /// the currently selected network and warms the circuit metadata from
    /// the prove-proxy.
    pub async fn from_config(config_path: &str) -> Result<Self> {
        let psy_config =
            psy_config::PsyConfigGoldilocks::from_file(config_path).with_context(|| format!("failed to read Psy config `{config_path}`"))?;
        let rpc_config = psy_config.get_current_network().context("no current network in Psy config")?.clone();
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
    pub async fn register(&mut self, private_key_hex: &str) -> Result<LoadedUser> {
        let private_key = Self::parse_key(private_key_hex)?;
        let fingerprint = self.session.get_zk_public_key(private_key).await?.fingerprint;
        let pk_hash = self.session.register_user(private_key, fingerprint).await?;
        let user_id = self.resolve_user_id(pk_hash).await?;
        let loaded = LoadedUser { pk_hash, user_id };
        self.user = Some(loaded.clone());
        Ok(loaded)
    }

    /// Load an already-registered key (idempotent add). Returns the user id.
    pub async fn load(&mut self, private_key_hex: &str) -> Result<LoadedUser> {
        let private_key = Self::parse_key(private_key_hex)?;
        let fingerprint = self.session.get_zk_public_key(private_key).await?.fingerprint;
        let pk_hash = self.session.add_user(private_key, fingerprint).await?;
        let user_id = self.resolve_user_id(pk_hash).await?;
        let loaded = LoadedUser { pk_hash, user_id };
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

    fn require_user(&self) -> Result<&LoadedUser> {
        self.user
            .as_ref()
            .ok_or_else(|| anyhow!("no wallet loaded — call create_wallet/load first"))
    }

    // ── Reads (via the RpcProvider st_provider — the same reads WalletSession
    // uses) ──

    pub async fn latest_checkpoint(&self) -> Result<u64> {
        Ok(self.session.st_provider.get_coordinator_latest_block_state().await?.checkpoint_id)
    }

    /// Public claimable owed to the loaded user by a specific sender.
    pub async fn claim_amount_from(&self, sender_user_id: u64) -> Result<u64> {
        let user = self.require_user()?;
        let checkpoint = self.latest_checkpoint().await?;
        self.session.st_provider.get_claim_amount(checkpoint, user.user_id, sender_user_id).await
    }

    // ── Spends (real proofs via exec_contract_call / claim_batch) ──

    /// Generic contract call — the primitive every spend builds on.
    /// Returns the submitted end-user-leaf-hash as a hex string.
    pub async fn exec_call(&self, contract_id: u64, method_name: &str, inputs: Vec<u64>) -> Result<String> {
        let user = self.require_user()?;
        let call = ContractCallArgs {
            contract_id,
            method_name: method_name.to_string(),
            inputs,
        };
        // On this branch, exec_contract_call returns the end-user-leaf-hash
        // (QHashOut<F>) directly rather than a TxMetadata wrapper.
        let leaf = self.session.exec_contract_call(user.pk_hash, ContractCallData::new(vec![call])).await?;
        Ok(leaf.to_string())
    }

    /// Public transfer: `simple_transfer(recipient_user_id, amount_nano)`.
    pub async fn transfer(&self, to_user_id: u64, amount_nano: u64, contract_id: u64) -> Result<String> {
        self.exec_call(contract_id, "simple_transfer", vec![to_user_id, amount_nano]).await
    }

    /// Claim a batch (UPS): fuses N claims (+ optional trailing calls) into one
    /// recursive proof / one transaction. This is the real batching primitive.
    pub async fn claim_batch(&self, claims: Vec<ClaimBatchItem>) -> Result<String> {
        let user = self.require_user()?;
        let leaf = self.session.claim_batch(user.pk_hash, claims).await?;
        Ok(leaf.to_string())
    }

    /// Claim all PUBLIC claimables owed by the given senders, fused into ONE
    /// UPS proof / one tx (a `simple_claim` per sender). Claiming is
    /// non-destructive: it only folds funds already addressed to this user
    /// into spendable balance. Private-note and deposit claiming need
    /// note/deposit material from the discovery layer (Nostr drain +
    /// inclusion proofs) and are not included here.
    pub async fn claim_all_public(&self, sender_ids: Vec<u64>, contract_id: u64) -> Result<String> {
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
        self.claim_batch(items).await
    }

    /// Compute a private transfer WITHOUT submitting it: derive a fresh note
    /// and the exact `private_transfer` call. Does not touch the chain.
    /// Submission is deliberately separate — see
    /// `submit_prepared_private_transfer` and the funds-safety note in the
    /// `private_transfer` tool.
    pub fn prepare_private_transfer(&self, recipient_shielded_hex: &str, amount: u64, contract_id: u64) -> Result<PreparedPrivateTransfer> {
        self.require_user()?;
        let owner_hash = QHashOut::<F>::from_str(recipient_shielded_hex).map_err(|e| anyhow!("invalid recipient shielded address: {e}"))?;
        let owner = qhash_to_u64x4(owner_hash);

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
    /// format their wallet drains, or the funds are stranded. Only call this
    /// once delivery is wired and verified.
    pub async fn submit_prepared_private_transfer(&self, prepared: &PreparedPrivateTransfer) -> Result<String> {
        self.exec_call(prepared.contract_id, "private_transfer", prepared.call_inputs.clone())
            .await
    }

    /// Generate a fresh keypair (private key hex + fingerprint hex) without
    /// touching the chain — the owner then registers it under a policy.
    pub async fn generate_keypair(&self) -> Result<(String, String)> {
        let kp = self.session.get_random_keypair().await?;
        Ok((kp.private_key.to_string(), kp.public_key.fingerprint.to_string()))
    }
}
