use std::{collections::BTreeSet, convert::Infallible, future::Future, path::{Path, PathBuf}, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use guardian_common::db::GuardianDb;
use guardian_common::protocol::{parse_canonical_json, sha256, validate_hash, ChainEndpoint, DepositTreeState, GuardianAccount, GuardianAccountState, GuardianConfig, GuardianRuntimeConfig, GuardianSessionRecord, GuardianSignError, GuardianSignErrorResponse, GuardianSignRequest, GuardianSessionsResponse, HaltReason, Hash4, Hex, Hex32, WithdrawalBurnRecord, GOLDILOCKS_MODULUS, MAX_BODY_BYTES};
use guardian_common::runtime::{create_db_file, load_network, load_signing_key, open_db_file};
use super::verify::{GuardianHistory, GuardianVerificationContext, GuardianAccountError};
use psy_client_common::data::base_types::hash256::Hash256;
use psy_client_data::{config::store_config::PsyHasher, traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync}};
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_provider::{provider::RpcProvider, request::{RequestParams, RpcRequest, RpcResponse, ResponseResult, Version, Id, QCheckpointTreeRootRPCRequest}};
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};

#[derive(Clone, Copy)]
pub(crate) struct GuardianCommittedHead { pub checkpoint_id: u64, pub checkpoint_tree_root: Hash4 }

async fn committed_rpc<T: serde::de::DeserializeOwned>(provider: &RpcProvider, url: &str, request: RequestParams<GoldilocksField>) -> Result<T, GuardianSignError> {
    let request = RpcRequest { jsonrpc: Version::V2, request, id: Id::Number(1) };
    let response = provider.client_for_url(url).map_err(|_| GuardianSignError::AuthorizationMismatch)?
        .post(url).json(&request).send().await.map_err(|_| GuardianSignError::L2RpcUnavailable)?;
    if !response.status().is_success() { return Err(GuardianSignError::L2RpcUnavailable); }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| GuardianSignError::L2RpcUnavailable)? {
        if chunk.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) { return Err(GuardianSignError::L2RpcUnavailable); }
        bytes.extend_from_slice(&chunk);
    }
    match serde_json::from_slice::<RpcResponse<T>>(&bytes).map_err(|_| GuardianSignError::L2RpcUnavailable)?.result {
        ResponseResult::Success(value) => Ok(value),
        ResponseResult::Error(_) => Err(GuardianSignError::L2RpcUnavailable),
    }
}

pub(crate) async fn load_guardian_committed_head(provider: &RpcProvider, url: &str) -> Result<GuardianCommittedHead, GuardianSignError> {
    let checkpoint_id = committed_rpc(provider, url, RequestParams::GetLatestCheckpointId).await?;
    let checkpoint_tree_root = committed_rpc(provider, url, RequestParams::GetCheckpointTreeRoot(QCheckpointTreeRootRPCRequest { checkpoint_id })).await?;
    validate_hash(checkpoint_tree_root)?;
    if checkpoint_id >= GOLDILOCKS_MODULUS { return Err(GuardianSignError::ProofMismatch); }
    Ok(GuardianCommittedHead { checkpoint_id, checkpoint_tree_root })
}


type HttpResponse = Response<Full<Bytes>>;
static SIGN_REQUESTS: Semaphore = Semaphore::const_new(4);
/// Observer passes and sign preparation keep their existing user-bounded deadlines;
/// the explicit instants are threaded into verification for precise timeout codes.
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(30);
const SIGN_PREPARE_TIMEOUT: Duration = Duration::from_secs(600);

struct GuardianService {
    config: GuardianRuntimeConfig,
    network: psy_config::NetworkConfigGoldilocks,
    stable: Arc<GuardianConfig>,
    wallet: psy_prover::session::session::WalletSession,
    signer: GuardianSigner,
    history_client: reqwest::Client,
    history: super::verify::GuardianHistory,
}
impl GuardianService {

    async fn save_account_result(&mut self, result: Result<(), GuardianAccountError>) -> Result<(), GuardianSignError> {
        save_guardian_account_result(&mut self.signer.db, psy_config::parse_magic_hex(&self.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?, self.stable.user_id(), result).await
    }

    async fn fetch_history(&self, after: u64) -> Result<GuardianSessionRecord, GuardianSignError> {
        for origin in &self.config.history_urls {
            let mut url = url::Url::parse(origin).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
            url.set_path("/v1/sessions");
            url.query_pairs_mut().append_pair("after_nonce", &after.to_string()).append_pair("limit", "1");
            let response = self.history_client.get(url).send().await;
            let Ok(mut response) = response else { continue; };
            if !response.status().is_success() { continue; }
            let mut bytes = Vec::new();
            let mut failed = false;
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) if chunk.len() <= MAX_BODY_BYTES.saturating_sub(bytes.len()) => bytes.extend_from_slice(&chunk),
                    Ok(None) => break,
                    _ => { failed = true; break; }
                }
            }
            if failed { continue; }
            let Ok(page) = parse_canonical_json::<GuardianSessionsResponse>(&bytes) else { continue; };
            if page.validate_page(after, 1).is_err() { continue; }
            if let Some(record) = page.sessions.into_iter().next() { return Ok(record); }
        }
        Err(GuardianSignError::SessionHistoryUnavailable)
    }

    /// Rebuilds the bounded RAM snapshot from the journal: the durable account row
    /// plus the included deposit prefixes are the single authoritative source. No
    /// session replay and no manual nonce mirroring; missing durable material or a
    /// stale authorization digest fails closed.
    async fn restore_history(&mut self, account: &GuardianAccount) -> Result<GuardianHistory, GuardianSignError> {
        let network_magic = psy_config::parse_magic_hex(&self.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let deposit_tree_states = self.signer.db.load_deposit_tree_states(network_magic, self.stable.user_id()).await?;
        restored_history(account, deposit_tree_states, &self.stable)
    }

    /// Journal membership of the current request's batch keys only, via point queries.
    async fn current_request_conflicts(&mut self, request: &GuardianSignRequest) -> Result<(BTreeSet<(u32, u32, [u32; 8])>, BTreeSet<(u8, [u32; 8])>), GuardianSignError> {
        let network_magic = psy_config::parse_magic_hex(&self.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let user = self.stable.user_id();
        let mut withdrawal_burns = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        for record in &request.withdrawal_records {
            if self.signer.db.contains_included_withdrawal_burn(network_magic, user, record.sender_user_id, record.token_contract_id, record.nonce).await? {
                withdrawal_burns.insert((record.sender_user_id, record.token_contract_id, record.nonce));
            }
            if self.signer.db.contains_withdrawal_nonce(network_magic, user, record.destination_chain_index, record.nonce).await? {
                nonces.insert((record.destination_chain_index, record.nonce));
            }
        }
        Ok((withdrawal_burns, nonces))
    }

    /// Included deposit anchors are re-bound to current L1 headers the same way as
    /// signed-but-unincluded reservations: chain identity, genesis, and finalized
    /// ancestry only. The set is the retained one-per-chain snapshot, never a history
    /// scan. Unavailable evidence fails the tick; a contradicting canonical hash halts.
    async fn check_included_deposit_anchors(&mut self) -> Result<(), GuardianSignError> {
        let network_magic = psy_config::parse_magic_hex(&self.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let included = self.signer.db.load_deposit_tree_states(network_magic, self.stable.user_id()).await?;
        self.save_account_result(verify_included_deposit_anchors(&self.stable, &included).await).await
    }

    /// The signed-but-unincluded reservations are checked with the header-only L1
    /// helper; there is no row-wise saved-anchor replay at startup. Unavailable
    /// evidence fails the tick and is retried; a contradicting canonical hash halts.
    async fn check_pending_signed_anchors(&mut self) -> Result<(), GuardianSignError> {
        let network_magic = psy_config::parse_magic_hex(&self.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let pending = self.signer.db.load_signed(network_magic, self.stable.user_id(), Some(self.history.nonce()), 64).await?;
        if pending.is_empty() { return Ok(()); }
        self.save_account_result(super::verify::verify_pending_signed_anchors(&self.stable, &pending).await).await
    }

    async fn observe(&mut self, deadline: tokio::time::Instant) -> Result<GuardianCommittedHead, GuardianSignError> {
        let network_magic = psy_config::parse_magic_hex(&self.network.magic).map_err(|_| GuardianSignError::AuthorizationMismatch)?;
        let stable = Arc::clone(&self.stable);
        let saved = self.signer.db.load_account(network_magic, stable.user_id()).await?;
        if saved.state == GuardianAccountState::Halted { return Err(GuardianSignError::AccountHalted); }
        let provider = &self.wallet.st_provider;
        let head = load_guardian_committed_head(provider, &self.config.l2_rpc_url).await?;
        if head.checkpoint_id < saved.last_checkpoint_id {
            self.signer.db.halt_account(network_magic, stable.user_id(), HaltReason::CheckpointConflict).await?;
            return Err(GuardianSignError::AccountHalted);
        }
        // The durable checkpoint leaf is re-proven against the current committed head.
        let saved_path = provider.get_checkpoint_tree_merkle_proof(head.checkpoint_id, saved.last_checkpoint_id).await.map_err(|_| GuardianSignError::CheckpointProofUnavailable)?;
        if saved_path.root != head.checkpoint_tree_root || saved_path.index != saved.last_checkpoint_id || !saved_path.verify::<PsyHasher>() {
            return Err(GuardianSignError::ProofMismatch);
        }
        if saved_path.value != saved.last_checkpoint_hash {
            self.signer.db.halt_account(network_magic, stable.user_id(), HaltReason::CheckpointConflict).await?;
            return Err(GuardianSignError::AccountHalted);
        }
        // Saved last_checkpoint_hash is already proven against this head. Checkpoint 0 is not re-compared.
        self.history = self.restore_history(&saved).await?;
        tracing::info!(nonce = self.history.nonce(), "[observe] bounded history restored");
        // The snapshot is proven against the saved checkpoint, itself proven against the
        // current head: a contradictory or missing durable frontier halts at startup. A
        // fresh bootstrap account has no included state yet; its zeros are first proven
        // atomically at the first import.
        if saved.imported_nonce.is_some() {
            let no_withdrawal_burns = BTreeSet::new();
            let no_nonces = BTreeSet::new();
            let context = GuardianVerificationContext { wallet: &self.wallet, provider: &self.wallet.st_provider, network: &self.network, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_chains: &self.config.l1_rpc_urls, history: &self.history,
                reserved_deposit_tree_states: &[], conflicting_withdrawal_burns: &no_withdrawal_burns, conflicting_nonces: &no_nonces };
            self.save_account_result(super::verify::verify_restored_history(&context, &stable, saved.last_checkpoint_id).await).await?;
        }
        // Included anchors are account-wide, not a property of the next request. A
        // withdrawal-only tick still has to halt when a retained deposit anchor left
        // the canonical chain.
        self.check_included_deposit_anchors().await?;
        self.check_pending_signed_anchors().await?;
        tracing::info!("[observe] pending signed anchors verified");
        let no_withdrawal_burns = BTreeSet::new();
        let no_nonces = BTreeSet::new();
        let target = {
            let context = GuardianVerificationContext { wallet: &self.wallet, provider: &self.wallet.st_provider, network: &self.network, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_chains: &self.config.l1_rpc_urls, history: &self.history,
                reserved_deposit_tree_states: &[], conflicting_withdrawal_burns: &no_withdrawal_burns, conflicting_nonces: &no_nonces };
            super::verify::verified_account_nonce(&context, &stable, deadline).await?
        };
        let mut imported = self.history.nonce();
        while imported < target {
            let record = self.fetch_history(imported).await?;
            let request = record.request_json.decode()?;
            if request.session_nonce != imported.checked_add(1).ok_or(GuardianSignError::SessionHistoryUnavailable)? { return Err(GuardianSignError::SessionHistoryUnavailable); }
            let (conflicting_withdrawal_burns, conflicting_nonces) = self.current_request_conflicts(&request).await?;
            let context = GuardianVerificationContext { wallet: &self.wallet, provider: &self.wallet.st_provider, network: &self.network, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_chains: &self.config.l1_rpc_urls, history: &self.history,
                reserved_deposit_tree_states: &[], conflicting_withdrawal_burns: &conflicting_withdrawal_burns, conflicting_nonces: &conflicting_nonces };
            let result = super::verify::verify_session(&context, &stable, record, &self.history).await;
            let (session, deposit_tree_states) = save_guardian_account_result(&mut self.signer.db, network_magic, stable.user_id(), result).await?;
            // The already-verified included checkpoint leaf is supplied to the atomic import.
            self.signer.db.import_session(&session, &deposit_tree_states, session.record.included_checkpoint_id, session.record.included_checkpoint_hash).await?;
            // After commit the RAM snapshot is restored from the journal, not mirrored.
            let account = self.signer.db.load_account(network_magic, stable.user_id()).await?;
            self.history = self.restore_history(&account).await?;
            imported = self.history.nonce();
        }
        if self.history.nonce() != target { return Err(GuardianSignError::SessionHistoryUnavailable); }
        let rechecked = load_guardian_committed_head(&self.wallet.st_provider, &self.config.l2_rpc_url).await?;
        let old_root: Hash4 = committed_rpc(&self.wallet.st_provider, &self.config.l2_rpc_url,
            RequestParams::GetCheckpointTreeRoot(QCheckpointTreeRootRPCRequest { checkpoint_id: head.checkpoint_id })).await?;
        if rechecked.checkpoint_id < head.checkpoint_id || old_root != head.checkpoint_tree_root {
            self.signer.db.halt_account(network_magic, stable.user_id(), HaltReason::CheckpointConflict).await?;
            return Err(GuardianSignError::AccountHalted);
        }
        Ok(head)
    }
}

async fn save_guardian_account_result<T>(db: &mut GuardianDb, network: u64, user: u64, result: Result<T, GuardianAccountError>) -> Result<T, GuardianSignError> {
    match result {
        Ok(value) => Ok(value),
        Err(GuardianAccountError::Unavailable(error)) => Err(error),
        Err(GuardianAccountError::Conflict(reason)) => {
            db.halt_account(network, user, reason).await?;
            Err(GuardianSignError::AccountHalted)
        }
    }
}

/// Pure mapping of durable state to the bounded snapshot: nonce and leaf from the
/// imported account row, withdrawal heads from the account, deposit heads from the
/// included deposit-tree states (at most three). Anything incoherent — a stale authorization
/// digest, a nonce without its leaf, or an unbounded deposit-tree-state set — fails closed.
fn restored_history(account: &GuardianAccount, deposit_tree_states: Vec<DepositTreeState>, config: &GuardianConfig) -> Result<GuardianHistory, GuardianSignError> {
    if account.account_public_key != config.account_public_key()? { return Err(GuardianSignError::AccountIdentityConflict); }
    if account.imported_ending_leaf.is_none() != account.imported_nonce.is_none() { return Err(GuardianSignError::DatabaseUnavailable); }
    if deposit_tree_states.len() > 3 { return Err(GuardianSignError::DatabaseUnavailable); }
    let mut history = GuardianHistory { nonce: account.imported_nonce.unwrap_or(0), ending_leaf: account.imported_ending_leaf, ..GuardianHistory::new() };
    for (chain_index, count, frontier, root) in account.withdrawal_chains.iter().copied() {
        if frontier.iter().any(|hash| validate_hash(*hash).is_err()) || validate_hash(root).is_err()
            || (guardian_common::protocol::frontier_root(count, &frontier) != root && !(count == 0 && root == Hash4::ZERO))
            || history.chains.insert(chain_index, (count, frontier, root)).is_some() { return Err(GuardianSignError::DatabaseUnavailable); }
    }
    for state in deposit_tree_states {
        if state.validate().is_err()
            || history.deposits.insert(state.anchor.chain_index, (state.count, state.root)).is_some()
            || history.deposit_tree_states.insert(state.anchor.chain_index, state).is_some() { return Err(GuardianSignError::DatabaseUnavailable); }
    }
    Ok(history)
}
fn enroll_guardian_account(wallet: &mut psy_prover::wallet::memory_wallet::PsyMemoryWallet, account: psy_vm::ups::multisig::MultisigAccount, fingerprint: Hash4, public_key: Hash4) -> Result<(), GuardianSignError> {
    let identity = wallet.register_recorded_multisig_user(account, fingerprint).map_err(|_| GuardianSignError::AccountIdentityConflict)?;
    if identity.fingerprint != fingerprint || identity.qfhash::<PsyHasher>() != public_key {
        return Err(GuardianSignError::AccountIdentityConflict);
    }
    Ok(())
}

fn journal_parts(runtime: &GuardianRuntimeConfig) -> Result<(PathBuf, PathBuf), GuardianSignError> {
    let path = Path::new(&runtime.db_path);
    let relative = path.file_name().map(PathBuf::from).ok_or(GuardianSignError::AuthorizationMismatch)?;
    let directory = path.parent().filter(|parent| !parent.as_os_str().is_empty()).ok_or(GuardianSignError::AuthorizationMismatch)?.to_path_buf();
    Ok((directory, relative))
}

fn member_hash_of(public_key: [u8; 33]) -> Hash4 {
    use plonky2::hash::poseidon::PoseidonPermutation;
    use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
    hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(psy_client_common::data::secp256k1::CompressedPublicKey::new_from_slice(&public_key))
}

fn key_matches_policy(policy: &psy_vm::ups::multisig::MultisigPolicy, guardian_id: u8, public_key: [u8; 33]) -> bool {
    let slot = usize::from(guardian_id.saturating_sub(1));
    policy.member_count == 3 && slot < 3 && policy.member_hashes.get(slot) == Some(&member_hash_of(public_key))
}

/// The journal binds the compressed signing key, not a genesis member slot.
/// A rotated key is absent from the initial policy and is authorized later against
/// the current proved policy at sign and cache release.
fn journal_key_bound(guardian_id: u8, public_key: [u8; 33]) -> Result<(), GuardianSignError> {
    if !(1..=3).contains(&guardian_id) || !matches!(public_key[0], 2 | 3) { return Err(GuardianSignError::AccountIdentityConflict); }
    Ok(())
}

/// Authorizes the configured key against the current policy proved in the request
/// witness. The initial policy only pins account identity; membership after rotation
/// is the proved current policy.
fn authorize_current_proved_policy(request: &GuardianSignRequest, config: &GuardianConfig, public_key: [u8; 33]) -> Result<(Hash4, u8), GuardianSignError> {
    let witness = super::verify::trace_policy(&request.decode_trace()?, config)?;
    let (policy, _) = witness.policies().map_err(|_| GuardianSignError::PolicyMismatch)?;
    if !key_matches_policy(&policy, 1, public_key) && !key_matches_policy(&policy, 2, public_key) && !key_matches_policy(&policy, 3, public_key) {
        return Err(GuardianSignError::PolicyMismatch);
    }
    let commitment = policy.commitment().map_err(|_| GuardianSignError::PolicyMismatch)?;
    let member_hash = member_hash_of(public_key);
    let member_index = policy.member_hashes[..usize::from(policy.member_count)].iter().position(|member| *member == member_hash).ok_or(GuardianSignError::PolicyMismatch)? as u8;
    Ok((commitment, member_index))
}

/// Binds the configured signing key, then initializes a fresh table-less journal.
/// The checkpoint-0 leaf is read once, only when runtime tables are absent, and
/// becomes last_checkpoint_hash. An existing journal is left unchanged: its saved
/// checkpoint, nonce, and account key stay the continuity record. The key is bound
/// by the journal signer row; it is not required to still occupy its initial member
/// slot. Any authentication failure leaves the journal without runtime tables.
async fn initialize_runtime_after_authentication(db: &mut GuardianDb, provider: &RpcProvider, network_magic: u64, config: &GuardianConfig, guardian_id: u8, public_key: [u8; 33]) -> Result<(), GuardianSignError> {
    journal_key_bound(guardian_id, public_key)?;
    let _account = config.initial_account()?;
    if !db.runtime_initialized()? {
        let genesis = provider.get_checkpoint_leaf_data(0).await.map_err(|_| GuardianSignError::CheckpointProofUnavailable)?;
        let created = GuardianAccount { network_magic, user_id: config.user_id(),
            state: GuardianAccountState::Active, last_checkpoint_id: 0, last_checkpoint_hash: genesis.qfhash::<PsyHasher>(), imported_nonce: None,
            account_public_key: config.account_public_key()?, imported_ending_leaf: None, withdrawal_chains: Vec::new(),
            halt_reason: None };
        db.initialize_runtime(&created).await?;
    }
    Ok(())
}


pub async fn run(rpc_config: &Path, guardian_root: &Path, local_documents: &[PathBuf], guardian_id: u8) -> Result<(), GuardianSignError> {
    if !(1..=3).contains(&guardian_id) { return Err(GuardianSignError::AccountIdentityConflict); }
    let loaded = match guardian_common::protocol::GuardianConfig::load(rpc_config, guardian_root, local_documents).await {
        Ok(loaded) => loaded,
        Err(error) => {
            if let Some(code) = error.downcast_ref::<GuardianSignError>() { return Err(*code); }
            tracing::error!(error = %error, "guardian config rejected");
            return Err(GuardianSignError::AuthorizationMismatch);
        }
    };
    let runtime = loaded.build_runtime_config(guardian_id)?;
    let key = load_signing_key(&runtime)?;
    let public_key = key.compressed_public_key();
    journal_key_bound(guardian_id, public_key)?;
    let stable = Arc::new(loaded);
    let network_magic = stable.network_magic()?;
    let provider = load_network(&stable)?;
    let mut wallet = psy_prover::session::session::WalletSession::new_with_provider(&stable.network, provider, None).await.map_err(|_| GuardianSignError::KeyUnavailable)?;
    let fingerprint = guardian_common::protocol::multisig_fingerprint()?;
    enroll_guardian_account(&mut wallet.wallet, stable.initial_account()?, fingerprint, stable.account_public_key()?)?;
    let (db_directory, db_relative) = journal_parts(&runtime)?;
    let mut db = match create_db_file(&db_directory, &db_relative) {
        Ok((file, parent)) => {
            let db = GuardianDb::create(file, public_key, Arc::clone(&stable)).await?;
            parent.sync_all().map_err(|_| GuardianSignError::DatabaseUnavailable)?;
            db
        }
        Err(_) => GuardianDb::open(open_db_file(&db_directory, &db_relative)?, public_key, Arc::clone(&stable)).await?,
    };
    initialize_runtime_after_authentication(&mut db, &wallet.st_provider, network_magic, &stable, guardian_id, public_key).await?;
    db.load_account(network_magic, stable.user_id()).await?;
    let history_client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(30))
        .build().map_err(|_| GuardianSignError::KeyUnavailable)?;
    let history = super::verify::GuardianHistory::new();
    let config = runtime.clone();
    let network = stable.network.clone();
    let service = Arc::new(tokio::sync::Mutex::new(GuardianService { config, network, stable, wallet,
        signer: GuardianSigner { db, key, public_key }, history_client, history }));
    let listener = TcpListener::bind(&runtime.listen_address).await.map_err(|_| GuardianSignError::ListenerUnavailable)?;
    let observer_service = service.clone();
    let (stop, mut stopping) = tokio::sync::watch::channel(false);
    let observer = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut warned = None;
        loop {
            tokio::select! {
                _ = stopping.changed() => break,
                _ = interval.tick() => {
                    let mut service = observer_service.lock().await;
                    let deadline = tokio::time::Instant::now() + OBSERVE_TIMEOUT;
                    let observed = tokio::time::timeout_at(deadline, service.observe(deadline)).await;
                    let observer_error = match observed { Err(_) => Some(GuardianSignError::ObserverTimeout), Ok(result) => result.err() };
                    warn_observer_authorization(&mut warned, observer_error);
                }
            }
        }
    });
    let shutdown_service = service.clone();
    let result = serve_http(listener, move |request| {
        let service = service.clone();
        async move { handle_request(service, request).await }
    }).await;
    let _ = stop.send(true);
    let _ = observer.await;
    let signing_drained = SIGN_REQUESTS.acquire_many(4).await.map_err(|_| GuardianSignError::DatabaseUnavailable)?;
    let drained = shutdown_service.lock().await;
    drop(drained);
    drop(signing_drained);
    result
}

async fn handle_request(service: Arc<tokio::sync::Mutex<GuardianService>>, request: Request<Incoming>) -> HttpResponse {
    if request.method() == hyper::Method::GET && request.uri().path() == "/v1/sessions" {
        let Ok((after, limit)) = history_query(request.uri().query()) else { return error_response(None, GuardianSignError::MalformedRequest); };
        let mut service = service.lock().await;
        let user = service.stable.user_id();
        let Ok(network_magic) = psy_config::parse_magic_hex(&service.network.magic) else { return error_response(None, GuardianSignError::AuthorizationMismatch); };
        let result = service.signer.db.load_sessions(network_magic, user, Some(after), 2).await;
        return match result {
            Ok(mut records) => {
                let has_more = records.len() > 1;
                records.truncate(1.min(limit as usize));
                let next_after_nonce = records.last().map(|record| record.nonce).unwrap_or(after);
                let page = GuardianSessionsResponse { sessions: records.into_iter().map(|session| session.record).collect(), next_after_nonce, has_more };
                match page.to_bytes() { Ok(body) => json_response(200, body), Err(error) => error_response(None, error) }
            }
            Err(error) => error_response(None, error),
        };
    }
    if request.method() != hyper::Method::POST || request.uri().path() != "/v1/sign-session" || request.uri().query().is_some() {
        return error_response(None, GuardianSignError::MalformedRequest);
    }
    let body = match tokio::time::timeout(Duration::from_secs(30), read_body(request.into_body())).await {
        Ok(Ok(body)) => body,
        _ => return error_response(None, GuardianSignError::MalformedRequest),
    };
    let request = match GuardianSignRequest::parse(&body) { Ok(request) => request, Err(error) => return error_response(None, error) };
    let request_id = match request.request_id() { Ok(id) => id, Err(error) => return error_response(None, error) };
    let permit = match SIGN_REQUESTS.try_acquire() {
        Ok(permit) => permit,
        Err(_) => return error_response(Some(request_id), GuardianSignError::SigningBusy),
    };
    let signing = tokio::spawn(async move {
    let _permit = permit;
    let lock_deadline = tokio::time::Instant::now() + SIGN_PREPARE_TIMEOUT;
    let mut service = tokio::time::timeout_at(lock_deadline, service.lock()).await.map_err(|_| GuardianSignError::SigningPreparationTimeout)?;
    let cached = {
        let existing = service.signer.db.lookup_signed(request.network_magic, request.user_id, request.session_nonce).await?;
        let canonical_bytes = request.canonical_bytes()?;
        existing.filter(|signed| signed.request_bytes == canonical_bytes && signed.signature.is_some())
    };
    let result = if cached.is_some() {
        let prepare_deadline = tokio::time::Instant::now() + SIGN_PREPARE_TIMEOUT;
        let observed = tokio::time::timeout_at(prepare_deadline, service.observe(prepare_deadline)).await;
        match observed {
            Ok(Ok(_)) if service.history.nonce() < request.session_nonce && service.history.nonce().checked_add(1) == Some(request.session_nonce) => {
                let GuardianService { signer, stable, config, .. } = &mut *service;
                authorize_cached_response(&mut signer.db, &request, signer.public_key, stable).await
            }
            Ok(Ok(_)) => Err(GuardianSignError::NonceConflict),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(GuardianSignError::SigningPreparationTimeout),
        }
    } else {
        let prepare_deadline = tokio::time::Instant::now() + SIGN_PREPARE_TIMEOUT;
        let prepared = tokio::time::timeout_at(prepare_deadline, async {
            for burn in &request.withdrawal_records {
                service.wallet.st_provider.get_realm_url(u64::from(burn.sender_user_id)).map_err(|_| GuardianSignError::L2RpcUnavailable)?;
            }
            let canonical_bytes = request.canonical_bytes()?;
            let existing = service.signer.db.lookup_signed(request.network_magic, request.user_id, request.session_nonce).await?;
            if existing.as_ref().is_some_and(|signed| signed.request_bytes != canonical_bytes) { return Err(GuardianSignError::NonceConflict); }
            let head = service.observe(prepare_deadline).await?;
            // No deposit-tree-state rebuild: the bounded snapshot comes from the journal; consumed
            // nonces and nonce gaps fail closed instead of replaying old sessions.
            if service.history.nonce() >= request.session_nonce { return Err(GuardianSignError::NonceConflict); }
            if service.history.nonce().checked_add(1) != Some(request.session_nonce) { return Err(GuardianSignError::SessionHistoryUnavailable); }
            let (conflicting_withdrawal_burns, conflicting_nonces) = service.current_request_conflicts(&request).await?;
            let stable = Arc::clone(&service.stable);
            let context = GuardianVerificationContext { wallet: &service.wallet, provider: &service.wallet.st_provider, network: &service.network, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_chains: &service.config.l1_rpc_urls, history: &service.history,
                reserved_deposit_tree_states: existing.as_ref().map(|signed| signed.deposit_tree_states.as_slice()).unwrap_or(&[]),
                conflicting_withdrawal_burns: &conflicting_withdrawal_burns, conflicting_nonces: &conflicting_nonces };
            let result = super::verify::verify_guardian_session(&context, &stable, &request).await;
            let (verified, deposit_tree_states) = save_guardian_account_result(&mut service.signer.db, request.network_magic, request.user_id, result).await?;
            Ok::<_, GuardianSignError>((verified, deposit_tree_states))
        }).await;
        match prepared {
            Ok(Ok((verified, deposit_tree_states))) => {
                let GuardianService { signer, .. } = &mut *service;
                signer.sign_verified(&request, &verified, deposit_tree_states).await
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(GuardianSignError::SigningPreparationTimeout),
        }
    };
    result
    });
    let result = signing.await.unwrap_or(Err(GuardianSignError::DatabaseUnavailable));
    match result { Ok(body) => json_response(200, body), Err(error) => error_response(Some(request_id), error) }
}

/// Re-authorizes a cached signature against durable account state before release.
/// The account's retained included deposit anchors are re-bound first — a
/// withdrawal-only cache has no reservation anchors of its own and must not skip
/// that account-wide check. The stored reservation is then re-bound the same way.
/// The current proved policy authorizes the signing key. The fee was already
/// checked by the trace replay that verified this exact reservation.
/// No historical evidence is replayed; a contradicting canonical hash halts.
/// `authorize_response` owns the halt gate and the request-bytes binding.
async fn authorize_cached_response(db: &mut GuardianDb, request: &GuardianSignRequest, public_key: [u8; 33], config: &GuardianConfig) -> Result<Vec<u8>, GuardianSignError> {
    request.validate_authorization(config)?;
    let account = db.load_account(request.network_magic, request.user_id).await?;
    if account.state == GuardianAccountState::Halted { return Err(GuardianSignError::AccountHalted); }
    if account.account_public_key != config.account_public_key()? || account.imported_nonce.is_some_and(|nonce| nonce.checked_add(1) != Some(request.session_nonce) && nonce >= request.session_nonce) { return Err(GuardianSignError::AccountIdentityConflict); }
    let canonical_bytes = request.canonical_bytes()?;
    let included = db.load_deposit_tree_states(request.network_magic, request.user_id).await?;
    save_guardian_account_result(db, request.network_magic, request.user_id, verify_included_deposit_anchors(config, &included).await).await?;
    let stored = db.lookup_signed(request.network_magic, request.user_id, request.session_nonce).await?
        .filter(|signed| signed.request_bytes == canonical_bytes)
        .ok_or(GuardianSignError::DatabaseUnavailable)?;
    for state in &stored.deposit_tree_states {
        state.validate()?;
        let chain = config.chain(state.anchor.chain_index)?;
        let canonical = super::verify_l1::verify_saved_deposit_anchor_headers(chain, &state.anchor).await?;
        save_guardian_account_result::<()>(db, request.network_magic, request.user_id, super::verify_l1::verify_cached_anchor_hash(canonical, state.anchor.block_hash).map(|()| ())).await?;
    }
    for burn in &request.withdrawal_records {
        super::verify_l1::verify_withdrawal_token(config.chain(burn.destination_chain_index)?, burn).await?;
    }
    let (commitment, member_index) = authorize_current_proved_policy(request, config, public_key)?;
    db.authorize_response(request.network_magic, request.user_id, request.session_nonce, &canonical_bytes, |signed, _config| {
        let response = guardian_common::protocol::GuardianSignResponse {
            request_id: sha256(&signed.request_bytes), network_magic: signed.network_magic, user_id: signed.user_id,
            session_nonce: signed.nonce, policy_commitment: commitment, member_index,
            message: Hex(signed.message), public_key: Hex(public_key),
            signature: Hex(signed.signature.ok_or(GuardianSignError::DatabaseUnavailable)?),
        };
        serde_json::to_vec(&response).map_err(|_| GuardianSignError::DatabaseUnavailable)
    }).await
}

struct GuardianSigner {
    db: GuardianDb,
    key: psy_provider::wallet::secp_wallet::Wallet,
    public_key: [u8; 33],
}

impl GuardianSigner {
    async fn sign_verified(
        &mut self,
        request: &GuardianSignRequest,
        verified: &super::verify::VerifiedGuardianSession,
        deposit_tree_states: Vec<DepositTreeState>,
    ) -> Result<Vec<u8>, GuardianSignError> {
        use guardian_common::protocol::{GuardianSigned, GuardianSignResponse};
        if !key_matches_policy(&verified.current_policy, 1, self.public_key) && !key_matches_policy(&verified.current_policy, 2, self.public_key) && !key_matches_policy(&verified.current_policy, 3, self.public_key) {
            return Err(GuardianSignError::PolicyMismatch);
        }
        let commitment = verified.current_policy.commitment().map_err(|_| GuardianSignError::PolicyMismatch)?;
        let member_hash = member_hash_of(self.public_key);
        let member_index = verified.current_policy.member_hashes[..usize::from(verified.current_policy.member_count)].iter().position(|member| *member == member_hash)
            .ok_or(GuardianSignError::PolicyMismatch)? as u8;
        let signed = GuardianSigned {
            network_magic: request.network_magic, user_id: request.user_id, nonce: request.session_nonce,
            request_bytes: request.canonical_bytes()?, starting_leaf_hash: verified.starting_leaf_hash,
            ending_leaf_hash: verified.ending_leaf_hash, message: verified.message,
            deposit_tree_states, signature: None,
        };
        let reserved = self.db.reserve_guardian_nonce(&signed).await?;
        if reserved.signature.is_none() {
            let signature = self.key.sign_prehash_raw(&reserved.message).map_err(|_| GuardianSignError::KeyUnavailable)?;
            self.db.save_guardian_signature(reserved.network_magic, reserved.user_id, reserved.nonce, &reserved.request_bytes, signature).await?;
        }
        self.db.authorize_response(request.network_magic, request.user_id, request.session_nonce, &signed.request_bytes, |signed, _authorization| {
            let response = GuardianSignResponse {
                request_id: sha256(&signed.request_bytes), network_magic: signed.network_magic, user_id: signed.user_id,
                session_nonce: signed.nonce, policy_commitment: commitment, member_index,
                message: Hex(signed.message), public_key: Hex(self.public_key),
                signature: Hex(signed.signature.ok_or(GuardianSignError::DatabaseUnavailable)?),
            };
            serde_json::to_vec(&response).map_err(|_| GuardianSignError::DatabaseUnavailable)
        }).await
    }
}

/// Header-only recheck of every retained included deposit anchor. Chain count is
/// the bound: one state per authorized chain, and never a session replay.
async fn verify_included_deposit_anchors(config: &GuardianConfig, included: &[DepositTreeState]) -> Result<(), GuardianAccountError> {
    if included.len() > config.l1_chains.len() { return Err(GuardianSignError::DatabaseUnavailable.into()); }
    let mut seen = BTreeSet::new();
    for state in included {
        state.validate()?;
        if !seen.insert(state.anchor.chain_index) { return Err(GuardianSignError::DatabaseUnavailable.into()); }
        let chain = config.chain(state.anchor.chain_index)?;
        let canonical = super::verify_l1::verify_saved_deposit_anchor_headers(chain, &state.anchor).await?;
        super::verify_l1::verify_cached_anchor_hash(canonical, state.anchor.block_hash)?;
    }
    Ok(())
}

fn warn_observer_authorization(warned: &mut Option<GuardianSignError>, error: Option<GuardianSignError>) {
    let Some(error) = error else { *warned = None; return; };
    if error == GuardianSignError::KeyUnavailable { *warned = None; return; }
    if warned.is_some_and(|previous| previous == error) { return; }
    *warned = Some(error);
    tracing::warn!(code = %error, "guardian observer authorization failed");
}

fn error_response(request_id: Option<Hex32>, code: GuardianSignError) -> HttpResponse {
    tracing::warn!(code = %code, "guardian sign request refused");
    let body = serde_json::to_vec(&GuardianSignErrorResponse::new(request_id, code))
        .expect("guardian error response is serializable");
    json_response(code.http_status(), body)
}

fn json_response(status: u16, body: Vec<u8>) -> HttpResponse {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = StatusCode::from_u16(status).expect("guardian status is valid");
    response.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    response.headers_mut().insert(hyper::header::CACHE_CONTROL, hyper::header::HeaderValue::from_static("no-store"));
    response
}

async fn read_body(mut body: Incoming) -> Result<Vec<u8>, GuardianSignError> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| GuardianSignError::MalformedRequest)?;
        if let Ok(data) = frame.into_data() {
            if data.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) {
                return Err(GuardianSignError::MalformedRequest);
            }
            bytes.extend_from_slice(&data);
        } else {
            return Err(GuardianSignError::MalformedRequest);
        }
    }
    Ok(bytes)
}

fn history_query(query: Option<&str>) -> Result<(u64, u32), GuardianSignError> {
    let mut after = None;
    let mut limit = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
        match key.as_ref() {
            "after_nonce" if after.is_none() => after = Some(value.parse::<u64>().map_err(|_| GuardianSignError::MalformedRequest)?),
            "limit" if limit.is_none() => limit = Some(value.parse::<u32>().map_err(|_| GuardianSignError::MalformedRequest)?),
            _ => return Err(GuardianSignError::MalformedRequest),
        }
    }
    match (after, limit) {
        (Some(after), Some(limit @ 1..=64)) => Ok((after, limit)),
        _ => Err(GuardianSignError::MalformedRequest),
    }
}


async fn serve_http<F, Fut>(listener: TcpListener, handler: F) -> Result<(), GuardianSignError>
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = HttpResponse> + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(4));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|_| GuardianSignError::SignalHandlerUnavailable)?;
                break;
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, _) = accepted.map_err(|_| GuardianSignError::ListenerUnavailable)?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { drop(socket); continue; };
                let handler = handler.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let service = hyper::service::service_fn(move |request| {
                        let handler = handler.clone();
                        async move { Ok::<_, Infallible>(handler(request).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(10))
                        .max_buf_size(16 * 1024)
                        .serve_connection(TokioIo::new(socket), service).await;
                });
            }
        }
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
    Ok(())
}

pub async fn serve_relayer_history(
    listen_address: &str,
    db: Arc<crate::bridge::guardian_client::RelayerDb>,
) -> Result<(), GuardianSignError> {
    let listener = TcpListener::bind(listen_address).await.map_err(|_| GuardianSignError::ListenerUnavailable)?;
    serve_http(listener, move |request| {
        let db = db.clone();
        async move {
            if request.method() != hyper::Method::GET || request.uri().path() != "/v1/sessions" {
                return error_response(None, GuardianSignError::MalformedRequest);
            }
            let result = history_query(request.uri().query()).and_then(|(after, limit)| {
                let page = db.sessions(after, limit as u8).map_err(|_| GuardianSignError::DatabaseUnavailable)?;
                page.validate_page(after, limit as u8)?;
                page.to_bytes()
            });
            match result {
                Ok(body) => json_response(200, body),
                Err(error) => error_response(None, error),
            }
        }
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_common::protocol::BRIDGE_USER_ID;
    /// Builds the exact policy member hash for a compressed signer key.
    fn member_hash(public_key: [u8; 33]) -> Hash4 {
        use plonky2::hash::poseidon::PoseidonPermutation;
        use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
        hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(psy_client_common::data::secp256k1::CompressedPublicKey::new_from_slice(&public_key))
    }

    /// Canonical configuration approval whose first policy slot is the given signer key.
    fn approval_config(public_key: [u8; 33]) -> Arc<GuardianConfig> {
        let mut config = crate::guardian::test_fixture::codec_guardian_config();
        let mut members = config.network.guardian_initial_member_hashes.expect("fixture members");
        members[0] = member_hash(public_key);
        config.network.guardian_initial_member_hashes = Some(members);
        Arc::new(config)
    }

    /// Rebuilds envelope commitments whenever a test changes the trace payload.
    fn set_request_trace(request: &mut GuardianSignRequest, trace: &psy_prover::trace::TxTrace) {
        let call_data = request.trace_json.decode().unwrap().call_data;
        let generated = psy_prover::trace::GeneratedTxTraceJson::from_trace(trace, call_data).unwrap();
        request.trace_json = guardian_common::protocol::JsonText::from_value(&generated).unwrap();
    }

    /// Embeds a proved current-policy witness. `member` occupies slot 0; the other
    /// two slots stay the configured initial members so the account identity holds.
    /// The stored header is the raw `[version, 2, 3, 0]` value, not the Poseidon commitment.
    fn with_validtrace_policy(config: &GuardianConfig, request: &mut GuardianSignRequest, member: Hash4) {
        use plonky2::field::types::Field;
        use psy_client_data::qdata::{user::PsyUserLeaf, user_contract_state::{SignContext, UserContractState}};
        use psy_crypto::hash::merkle::{core::MerkleProofCore, utils::simple_merkle_tree::SimpleMerkleTree};
        use psy_prover::trace::{TraceSignCircuitSource, TraceStep, ZkSignStep};
        use psy_vm::{dpn::ops::state_cmd::data::{DPNStateCmd, DPNStateCmdGetSelfUserCurrentContractStateSlotHash}, ups::{multisig::{MultisigSignatureWitness, MULTISIG_POLICY_CONTRACT_ID}, state_reader::StateReaderResults}};
        let account = config.initial_account().unwrap();
        let fingerprint = guardian_common::protocol::multisig_fingerprint().unwrap();
        let account_key = config.account_public_key().unwrap();
        let mut policy = account.initial_policy.clone();
        policy.member_hashes[0] = member;
        let members = [policy.member_hashes[0], policy.member_hashes[1], policy.member_hashes[2]];
        let header = Hash4::from_values(u64::from(policy.version), 2, 3, 0);
        let mut policy_tree = SimpleMerkleTree::<PsyHasher, Hash4>::new(4);
        for (index, value) in std::iter::once(header).chain(members).enumerate() { policy_tree.set_leaf(index as u64, value); }
        let mut contracts = SimpleMerkleTree::<PsyHasher, Hash4>::new(psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT);
        contracts.set_leaf(u64::from(MULTISIG_POLICY_CONTRACT_ID), policy_tree.get_root());
        let mut trace = request.decode_trace().unwrap();
        trace.meta.public_key = account_key;
        let leaf = PsyUserLeaf { public_key: account_key, user_state_tree_root: contracts.get_root(), user_id: GoldilocksField::from_canonical_u64(BRIDGE_USER_ID), nonce: GoldilocksField::from_canonical_u64(request.session_nonce.saturating_sub(1)), ..Default::default() };
        let root = Hash4::from_values(5, 6, 7, 8);
        let state = StateReaderResults { state: UserContractState::new(root, leaf, policy_tree.get_root(), GoldilocksField::from_canonical_u32(MULTISIG_POLICY_CONTRACT_ID), GoldilocksField::from_canonical_u64(trace.anchor.start_checkpoint_id)), user_tree_root: Hash4::ZERO, checkpoint: None, aux_user_leaves: vec![], state_cmds: (0..4).map(|index| DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(DPNStateCmdGetSelfUserCurrentContractStateSlotHash { slot_index: GoldilocksField::from_canonical_u64(index) })).collect(), merkel_proofs: (0..4).flat_map(|index| [contracts.get_leaf(u64::from(MULTISIG_POLICY_CONTRACT_ID)), policy_tree.get_leaf(index)]).collect::<Vec<MerkleProofCore<Hash4>>>() };
        let mut end = leaf;
        end.nonce = GoldilocksField::from_canonical_u64(request.session_nonce);
        let sign_context = SignContext { checkpoint_tree_root: root, user_leaf: end };
        let mut end_state = state.clone();
        end_state.state.user_leaf = end;
        let witness = MultisigSignatureWitness { account, start_state: state, end_state, sig_data: Default::default(), sign_context, start_session_user_leaf: leaf, nonce: end.nonce };
        trace.finalization.nonce = end.nonce;
        trace.steps.push(TraceStep::ZkSign(ZkSignStep { fingerprint, proof_tree_start_root: Hash4::ZERO, proof_tree_end_root: Hash4::ZERO, sign_circuit_source: TraceSignCircuitSource::Multisig, sign_witness: serde_json::to_vec(&witness).unwrap(), public_key_param: witness.account.public_key_param().unwrap(), sign_verifier_data_alt: psy_client_common::data::alt::AltVerifierOnlyCircuitData { constants_sigmas_cap: vec![], circuit_digest: Hash4::ZERO } }));
        set_request_trace(request, &trace);
    }


    /// Journal file name inside the protected guardian root.
    const JOURNAL: &str = "guardian-journal.redb";

    /// Fresh protected guardian root with a first-startup journal, opened once through
    /// the core `GuardianDb::create` entry point; returns the database and root for cleanup.
    /// The journal handle is created directly, mirroring the `guardian_common` db tests,
    /// because the protected-path contract rejects traversal through world-writable
    /// `/tmp`; production creates journals via `create_db_file` under operator-owned roots.
    async fn open_approval_journal(public_key: [u8; 33], name: &str, config: Arc<GuardianConfig>) -> (GuardianDb, PathBuf) {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let root = std::env::temp_dir().join(format!("guardian-service-{name}-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(root.join(JOURNAL)).unwrap();
        let db = GuardianDb::create(file, public_key, Arc::clone(&config)).await.unwrap();
        std::fs::File::open(&root).unwrap().sync_all().unwrap();
        (db, root)
    }

    /// Reopens the fixture journal by handle; protected-path traversal is not under test here.
    fn reopen_journal(root: &Path) -> std::fs::File {
        std::fs::OpenOptions::new().read(true).write(true).open(root.join(JOURNAL)).unwrap()
    }

    fn unreachable_provider() -> RpcProvider {
        RpcProvider { client: Arc::new(reqwest::Client::builder().no_proxy().build().unwrap()), endpoint_clients: None,
            realm_configs: std::collections::HashMap::new(), coordinator_configs: std::collections::HashMap::new(), users_per_realm: 1048576, current_user_id: 0 }
    }



    #[tokio::test]
    #[ignore = "requires post-implementation QA approval"]
    async fn authenticated_conflict_halts_durably_but_unavailable_account_does_not() {
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let config = approval_config(public_key);
        let (mut db, root) = open_approval_journal(public_key, "halt-durable", Arc::clone(&config)).await;
        let account = GuardianAccount { network_magic: 90101, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::ZERO, imported_nonce: None,
            account_public_key: config.account_public_key().unwrap(), imported_ending_leaf: None, withdrawal_chains: Vec::new(), halt_reason: None };
        db.initialize_runtime(&account).await.unwrap();
        assert_eq!(save_guardian_account_result::<()>(&mut db, 90101, BRIDGE_USER_ID,
            Err(GuardianAccountError::Unavailable(GuardianSignError::L2RpcUnavailable))).await, Err(GuardianSignError::L2RpcUnavailable));
        assert_eq!(db.load_account(90101, BRIDGE_USER_ID).await.unwrap().state, GuardianAccountState::Active);
        assert_eq!(save_guardian_account_result::<()>(&mut db, 90101, BRIDGE_USER_ID,
            Err(GuardianAccountError::Unavailable(GuardianSignError::ProofMismatch))).await, Err(GuardianSignError::ProofMismatch));
        assert_eq!(db.load_account(90101, BRIDGE_USER_ID).await.unwrap().state, GuardianAccountState::Active);
        assert_eq!(save_guardian_account_result::<()>(&mut db, 90101, BRIDGE_USER_ID,
            Err(GuardianAccountError::Conflict(HaltReason::FinalityConflict))).await, Err(GuardianSignError::AccountHalted));
        drop(db);
        let file = reopen_journal(&root);
        let mut db = GuardianDb::open(file, public_key, Arc::clone(&config)).await.unwrap();
        let retained = db.load_account(90101, BRIDGE_USER_ID).await.unwrap();
        assert_eq!(retained.state, GuardianAccountState::Halted);
        assert_eq!(retained.halt_reason, Some(HaltReason::FinalityConflict));
        assert!(db.save_account(&account).await.is_err());
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn committed_head_reads_marker_then_that_exact_root() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let root = Hash4::from_values(1, 2, 3, 4);
        let server = tokio::spawn(async move {
            for (method, result) in [("psy_get_latest_checkpoint_id", serde_json::json!(7)), ("psy_get_checkpoint_tree_root", serde_json::to_value(root).unwrap())] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut byte = [0]; stream.read_exact(&mut byte).await.unwrap(); bytes.push(byte[0]);
                    if bytes.ends_with(b"\r\n\r\n") { break bytes.len(); }
                };
                let headers = String::from_utf8(bytes.clone()).unwrap();
                let length: usize = headers.lines().find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|n| n.trim().parse().unwrap())).unwrap();
                bytes.resize(header_end + length, 0);
                stream.read_exact(&mut bytes[header_end..]).await.unwrap();
                let request: serde_json::Value = serde_json::from_slice(&bytes[header_end..]).unwrap();
                assert_eq!(request["method"], method);
                if method == "psy_get_checkpoint_tree_root" { assert_eq!(request["params"]["checkpoint_id"], 7); }
                let body = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"result":result})).unwrap();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
        });
        let provider = RpcProvider { client: Arc::new(reqwest::Client::builder().no_proxy().build().unwrap()), endpoint_clients: None,
            realm_configs: std::collections::HashMap::new(), coordinator_configs: std::collections::HashMap::new(), users_per_realm: 1048576, current_user_id: 0 };
        let head = load_guardian_committed_head(&provider, &url).await.unwrap();
        assert_eq!(head.checkpoint_id, 7);
        assert_eq!(head.checkpoint_tree_root, root);
        server.await.unwrap();
    }

    #[test]
    fn startup_enrollment_makes_approved_multisig_identity_available_and_rejects_wrong_pins() {
        use psy_prover::wallet::memory_wallet::PsyMemoryWallet;
        use psy_vm::ups::multisig::{MultisigAccount, MultisigPolicy, MULTISIG_POLICY_CONTRACT_ID};
        let mut members = [Hash4::ZERO; 8];
        for (index, member) in members[..3].iter_mut().enumerate() {
            *member = Hash4::from_values(index as u64 + 1, 0, 0, 0);
        }
        let account = MultisigAccount { contract_id: MULTISIG_POLICY_CONTRACT_ID, initial_policy: MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes: members } };
        let mut enrolled = PsyMemoryWallet::new(Vec::new());
        let identity = enrolled.register_multisig_user(account.clone()).unwrap();
        let public_key = identity.qfhash::<PsyHasher>();
        let mut startup = PsyMemoryWallet::new(Vec::new());
        assert!(startup.get_multisig_user(&public_key).is_err());
        enroll_guardian_account(&mut startup, account.clone(), identity.fingerprint, public_key).unwrap();
        assert_eq!(startup.get_multisig_user(&public_key).unwrap().account().public_key_param().unwrap(), account.public_key_param().unwrap());
        let mut wrong_key = PsyMemoryWallet::new(Vec::new());
        assert_eq!(enroll_guardian_account(&mut wrong_key, account.clone(), identity.fingerprint, Hash4::ZERO), Err(GuardianSignError::AccountIdentityConflict));
        let mut wrong_fingerprint = PsyMemoryWallet::new(Vec::new());
        assert_eq!(enroll_guardian_account(&mut wrong_fingerprint, account, Hash4::ZERO, public_key), Err(GuardianSignError::AccountIdentityConflict));
    }

    #[test]
    fn raw_signing_is_deterministic_low_s_and_message_bound() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[1; 32]).unwrap();
        let verifier = k256::ecdsa::VerifyingKey::from_sec1_bytes(&key.compressed_public_key()).unwrap();
        let message = [7; 32];
        let signature = key.sign_prehash_raw(&message).unwrap();
        assert_eq!(signature, key.sign_prehash_raw(&message).unwrap());
        let signature = k256::ecdsa::Signature::from_slice(&signature).unwrap();
        assert!(signature.normalize_s().is_none());
        assert!(verifier.verify_prehash(&message, &signature).is_ok());
        assert!(verifier.verify_prehash(&[8; 32], &signature).is_err());
    }

    #[test]
    fn history_query_rejects_duplicate_or_unbounded_pages() {
        for query in ["after_nonce=0&limit=0", "after_nonce=0&limit=65", "after_nonce=0&limit=1&limit=2", "after_nonce=0&limit=1&cursor=2", "limit=1"] {
            assert_eq!(history_query(Some(query)), Err(GuardianSignError::MalformedRequest));
        }
        assert_eq!(history_query(Some("after_nonce=18446744073709551615&limit=64")), Ok((u64::MAX, 64)));
    }

    #[test]
    fn observer_warns_journal_failure_once_until_quiet_or_success_reset() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        struct LogCapture(Arc<Mutex<Vec<u8>>>);
        impl Write for LogCapture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.0.lock().expect("log").write(buf) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        fn codes(logged: &str) -> Vec<GuardianSignError> {
            logged.split("code=").skip(1).map(|part| match part.split_whitespace().next().unwrap() {
                "DatabaseUnavailable" => GuardianSignError::DatabaseUnavailable,
                "AccountHalted" => GuardianSignError::AccountHalted,
                other => panic!("unexpected observer code {other}"),
            }).collect()
        }
        let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).without_time().with_ansi(false)
            .with_writer(move || LogCapture(writer.clone())).finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut warned = None;
            for error in [Some(GuardianSignError::DatabaseUnavailable), Some(GuardianSignError::DatabaseUnavailable), Some(GuardianSignError::KeyUnavailable), Some(GuardianSignError::DatabaseUnavailable), None, Some(GuardianSignError::DatabaseUnavailable), Some(GuardianSignError::AccountHalted), Some(GuardianSignError::AccountHalted)] {
                warn_observer_authorization(&mut warned, error);
            }
        });
        let logged = String::from_utf8(captured.lock().expect("log").clone()).unwrap();
        assert_eq!(codes(&logged), [
            GuardianSignError::DatabaseUnavailable, GuardianSignError::DatabaseUnavailable,
            GuardianSignError::DatabaseUnavailable, GuardianSignError::AccountHalted,
        ]);
    }
    /// Header-only L1: chain id, genesis, finalized tip, and the saved anchor height.
    /// A reorg flag rewrites only that saved height; no body methods are served.
    async fn serve_header_l1(chain_id: u64, genesis: [u8; 32], height: u64, saved: [u8; 32], canonical: [u8; 32], reorg: bool) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { break };
                let mut socket = tokio::io::BufReader::new(socket);
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
                let params = &request["params"];
                let result = match request["method"].as_str().unwrap_or("") {
                    "eth_chainId" => Some(serde_json::json!(format!("0x{chain_id:x}"))),
                    "eth_getBlockByNumber" if params[1] == false => {
                        let tag = params[0].as_str().unwrap_or("");
                        let (number, hash) = if tag == "finalized" { (height, canonical) }
                            else if let Ok(number) = u64::from_str_radix(tag.trim_start_matches("0x"), 16) {
                                let hash = if number == 0 { genesis } else if number == height { if reorg { canonical } else { saved } } else { break };
                                (number, hash)
                            } else { break };
                        Some(serde_json::json!({"number": format!("0x{number:x}"), "hash": format!("0x{}", hex::encode(hash))}))
                    }
                    _ => None,
                };
                let response = match result {
                    Some(result) => serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}),
                    None => serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header-only fixture"}}),
                };
                let payload = response.to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len());
                let _ = socket.into_inner().write_all(response.as_bytes()).await;
            }
        });
        (url, server)
    }

    fn included_deposit(chain_index: u8, block_hash: [u8; 32]) -> DepositTreeState {
        let mut frontier = [Hash4::ZERO; 32];
        let root = crate::guardian::verify_l1::append_leaf(&mut frontier, 0, Hash4::ZERO);
        DepositTreeState {
            count: 1, frontier, root,
            anchor: guardian_common::protocol::DepositAnchor { chain_index, block_number: 100, block_hash: Hex(block_hash), old_count: 0, new_count: 1 },
            event_block: 99, previous_count: 0, previous_root: DepositTreeState::empty(chain_index).root,
            occupied_partial_page_hashes: vec![Hash4::ZERO],
        }
    }

    #[tokio::test]
    async fn imported_deposit_reorg_halts_withdrawal_only_cache_without_releasing_signature() {
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let mut config = (*approval_config(public_key)).clone();
        let saved_hash = [0x0a; 32];
        let reorg_hash = [0x0c; 32];
        let chain_id = config.chain(0).unwrap().chain_id.try_into().unwrap_or(1);
        let (url, server) = serve_header_l1(chain_id, [2; 32], 100, saved_hash, reorg_hash, true).await;
        config.l1_chains.iter_mut().find(|chain| chain.chain_index == 0).unwrap().rpc_url = url;
        let config = Arc::new(config);
        let chain = config.chain(0).unwrap();
        let mut request = crate::guardian::test_fixture::codec_request_fixture();
        request.operation = guardian_common::protocol::GuardianOperation::Bridge;
        let deposit = included_deposit(chain.chain_index, saved_hash);
        request.deposit_anchors = vec![deposit.anchor.clone()];
        let account = GuardianAccount { network_magic: request.network_magic, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::ZERO, imported_nonce: None,
            account_public_key: config.account_public_key().unwrap(), imported_ending_leaf: None, withdrawal_chains: Vec::new(), halt_reason: None };
        let (mut db, root) = open_approval_journal(public_key, "included-reorg", Arc::clone(&config)).await;
        db.initialize_runtime(&account).await.unwrap();
        let mut trace = request.decode_trace().unwrap();
        trace.meta.public_key = account.account_public_key;
        trace.finalization.nonce = plonky2::field::goldilocks_field::GoldilocksField(1);
        set_request_trace(&mut request, &trace);
        let session = guardian_common::protocol::GuardianSession {
            network_magic: request.network_magic, user_id: request.user_id, nonce: 1,
            record: guardian_common::protocol::GuardianSessionRecord {
                request_json: guardian_common::protocol::JsonText::from_value(&request).unwrap(),
                signatures_json: guardian_common::protocol::JsonText::parse("{\"member_indices\":[],\"signatures\":[]}".into()).unwrap(),
                endcap_input_json: guardian_common::protocol::JsonText::from_value(&trace.finalization.submit_end_cap_input).unwrap(),
                endcap_proof_hex: "0x00".into(), included_checkpoint_id: 1, included_checkpoint_hash: Hash4::ZERO,
            },
            starting_leaf_hash: Hash4::ZERO, ending_leaf_hash: Hash4::ZERO, withdrawal_appends: vec![],
        };
        db.import_session(&session, &[deposit], 1, Hash4::ZERO).await.unwrap();
        request.session_nonce = 2;
        request.deposit_anchors.clear();
        request.withdrawal_records = vec![guardian_common::protocol::WithdrawalBurnRecord {
            sender_user_id: 1, token_contract_id: 0, destination_chain_index: 0,
            token: [0, 0, 0, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b, 0x0b0b0b0b],
            amount: [0, 0, 0, 0, 0, 0, 0, 1], recipient: [0, 0, 0, 0, 0, 0, 0, 1], nonce: [0, 0, 0, 0, 0, 0, 0, 7],
        }];
        trace.finalization.nonce = plonky2::field::goldilocks_field::GoldilocksField(2);
        set_request_trace(&mut request, &trace);
        let signed = guardian_common::protocol::GuardianSigned {
            network_magic: request.network_magic, user_id: request.user_id, nonce: 2,
            request_bytes: request.canonical_bytes().unwrap(), starting_leaf_hash: Hash4::ZERO,
            ending_leaf_hash: Hash4::ZERO, message: [3; 32], deposit_tree_states: Vec::new(), signature: None,
        };
        db.reserve_guardian_nonce(&signed).await.unwrap();
        db.save_guardian_signature(signed.network_magic, signed.user_id, signed.nonce, &signed.request_bytes, [3; 64]).await.unwrap();
        assert_eq!(authorize_cached_response(&mut db, &request, public_key, &config).await, Err(GuardianSignError::AccountHalted));
        let halted = db.load_account(request.network_magic, request.user_id).await.unwrap();
        assert_eq!(halted.state, GuardianAccountState::Halted);
        assert_eq!(halted.halt_reason, Some(HaltReason::FinalityConflict));
        assert!(db.lookup_signed(signed.network_magic, signed.user_id, signed.nonce).await.unwrap().unwrap().signature.is_some());
        drop(db);
        let file = reopen_journal(&root);
        let mut db = GuardianDb::open(file, public_key, Arc::clone(&config)).await.unwrap();
        let retained = db.load_account(request.network_magic, request.user_id).await.unwrap();
        assert_eq!(retained.state, GuardianAccountState::Halted);
        assert_eq!(retained.halt_reason, Some(HaltReason::FinalityConflict));
        assert_eq!(authorize_cached_response(&mut db, &request, public_key, &config).await, Err(GuardianSignError::AccountHalted));
        drop(db);
        server.abort();
        std::fs::remove_dir_all(root).unwrap();
    }


    #[tokio::test]
    async fn halted_account_fails_closed_for_cached_sign_response() {
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let config = approval_config(public_key);
        let mut request = crate::guardian::test_fixture::codec_request_fixture();
        let account = GuardianAccount { network_magic: request.network_magic, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::ZERO, imported_nonce: None,
            account_public_key: config.account_public_key().unwrap(), imported_ending_leaf: None, withdrawal_chains: Vec::new(), halt_reason: None };
        let (mut db, root) = open_approval_journal(public_key, "cached-halt", Arc::clone(&config)).await;
        db.initialize_runtime(&account).await.unwrap();
        let policy = config.initial_account().unwrap().initial_policy;
        with_validtrace_policy(&config, &mut request, policy.member_hashes[0]);
        let signed = guardian_common::protocol::GuardianSigned {
            network_magic: request.network_magic, user_id: request.user_id, nonce: request.session_nonce,
            request_bytes: request.canonical_bytes().unwrap(), starting_leaf_hash: Hash4::ZERO,
            ending_leaf_hash: Hash4::ZERO, message: [3; 32], deposit_tree_states: Vec::new(), signature: None,
        };
        db.reserve_guardian_nonce(&signed).await.unwrap();
        db.save_guardian_signature(signed.network_magic, signed.user_id, signed.nonce, &signed.request_bytes, [3; 64]).await.unwrap();
        let response: guardian_common::protocol::GuardianSignResponse = parse_canonical_json(&authorize_cached_response(&mut db, &request, public_key, &config).await.unwrap()).unwrap();
        assert_eq!(response.policy_commitment, policy.commitment().unwrap());
        db.halt_account(signed.network_magic, signed.user_id, HaltReason::AppendHistoryMismatch).await.unwrap();
        assert_eq!(authorize_cached_response(&mut db, &request, public_key, &config).await, Err(GuardianSignError::AccountHalted));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn wrong_account_trace_rejects_then_valid_policy_witness_releases() {
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let config = approval_config(public_key);
        let (mut db, root) = open_approval_journal(public_key, "wrong-account-trace", Arc::clone(&config)).await;
        let mut request = crate::guardian::test_fixture::codec_request_fixture();
        let account = GuardianAccount { network_magic: request.network_magic, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::ZERO, imported_nonce: None,
            account_public_key: config.account_public_key().unwrap(), imported_ending_leaf: None, withdrawal_chains: Vec::new(), halt_reason: None };
        db.initialize_runtime(&account).await.unwrap();
        let mut wrong = request.clone();
        wrong.session_nonce = request.session_nonce.saturating_add(1);
        let mut wrong_trace = request.decode_trace().unwrap();
        wrong_trace.finalization.nonce = GoldilocksField(wrong.session_nonce);
        set_request_trace(&mut wrong, &wrong_trace);
        let mut foreign = guardian_common::protocol::GuardianSigned {
            network_magic: wrong.network_magic, user_id: wrong.user_id, nonce: wrong.session_nonce,
            request_bytes: wrong.canonical_bytes().unwrap(),
            starting_leaf_hash: Hash4::ZERO, ending_leaf_hash: Hash4::ZERO, message: [3; 32],
            deposit_tree_states: Vec::new(), signature: None,
        };
        assert!(matches!(db.reserve_guardian_nonce(&foreign).await, Err(GuardianSignError::AccountIdentityConflict)));
        assert!(db.lookup_signed(foreign.network_magic, foreign.user_id, foreign.nonce).await.unwrap().is_none());
        wrong_trace.meta.public_key = account.account_public_key;
        set_request_trace(&mut wrong, &wrong_trace);
        foreign.request_bytes = wrong.canonical_bytes().unwrap();
        assert!(matches!(db.reserve_guardian_nonce(&foreign).await, Err(GuardianSignError::SessionHistoryUnavailable)));
        assert!(db.lookup_signed(foreign.network_magic, foreign.user_id, foreign.nonce).await.unwrap().is_none());
        let policy = config.initial_account().unwrap().initial_policy;
        with_validtrace_policy(&config, &mut request, policy.member_hashes[0]);
        let bound = guardian_common::protocol::GuardianSigned {
            network_magic: request.network_magic, user_id: request.user_id, nonce: request.session_nonce,
            request_bytes: request.canonical_bytes().unwrap(), starting_leaf_hash: Hash4::ZERO,
            ending_leaf_hash: Hash4::ZERO, message: [3; 32], deposit_tree_states: Vec::new(), signature: None,
        };
        db.reserve_guardian_nonce(&bound).await.unwrap();
        db.save_guardian_signature(bound.network_magic, bound.user_id, bound.nonce, &bound.request_bytes, [3; 64]).await.unwrap();
        let response: guardian_common::protocol::GuardianSignResponse = parse_canonical_json(&authorize_cached_response(&mut db, &request, public_key, &config).await.unwrap()).unwrap();
        assert_eq!(response.policy_commitment, policy.commitment().unwrap());
        assert_eq!(response.member_index, 0);
        let mut changed = (*config).clone();
        changed.network.guardian_initial_member_hashes.as_mut().unwrap().swap(0, 1);
        assert!(matches!(authorize_cached_response(&mut db, &request, public_key, &changed).await, Err(GuardianSignError::AccountIdentityConflict | GuardianSignError::PolicyMismatch)));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restored_history_maps_account_and_deposit_tree_states_and_fails_closed() {
        let config = Arc::new(crate::guardian::test_fixture::codec_guardian_config());
        let identity = config.account_public_key().unwrap();
        // A fresh account restores the empty snapshot; nothing is replayed from genesis.
        let fresh = GuardianAccount { network_magic: 90101, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::ZERO, imported_nonce: None,
            account_public_key: identity, imported_ending_leaf: None, withdrawal_chains: Vec::new(), halt_reason: None };
        let history = restored_history(&fresh, Vec::new(), &config).unwrap();
        assert_eq!(history.nonce(), 0);
        // The imported account row and included deposit-tree states are the single authoritative source;
        // every frontier must fold to its stored root at the stored count.
        let mut frontier = [Hash4::ZERO; 32];
        let mut chain_root = Hash4::ZERO;
        for leaf in 0..2u32 { chain_root = crate::guardian::verify_l1::append_leaf(&mut frontier, leaf, Hash4::from_values(leaf as u64 + 1, 0, 0, 0)); }
        let imported = GuardianAccount { imported_nonce: Some(3), imported_ending_leaf: Some(Hash4::from_values(7, 7, 7, 7)),
            withdrawal_chains: vec![(0, 2, frontier, chain_root), (1, 0, [Hash4::ZERO; 32], Hash4::ZERO)],
            ..fresh.clone() };
        let mut state_frontier = [Hash4::ZERO; 32];
        let mut state_root = Hash4::ZERO;
        for leaf in 0..4u32 { state_root = crate::guardian::verify_l1::append_leaf(&mut state_frontier, leaf, Hash4::from_values(leaf as u64 + 1, 1, 1, 1)); }
        let deposit_tree_state = DepositTreeState { count: 4, frontier: state_frontier, root: state_root,
            anchor: guardian_common::protocol::DepositAnchor { chain_index: 0, block_number: 100, block_hash: Hex([1; 32]), old_count: 2, new_count: 4 },
            event_block: 99, previous_count: 2, previous_root: Hash4::ZERO, occupied_partial_page_hashes: vec![Hash4::ZERO; 4] };
        let history = restored_history(&imported, vec![deposit_tree_state.clone()], &config).unwrap();
        assert_eq!(history.nonce(), 3);
        assert_eq!(history.ending_leaf, Some(Hash4::from_values(7, 7, 7, 7)));
        assert_eq!(history.chains.get(&0), Some(&(2, frontier, chain_root)));
        assert_eq!(history.chains.get(&1), Some(&(0, [Hash4::ZERO; 32], Hash4::ZERO)));
        assert_eq!(history.deposits.get(&0), Some(&(4, state_root)));
        assert!(history.deposit_tree_states.get(&0).is_some());
        // A stale digest, a torn nonce/leaf pair, or an unbounded deposit-tree-state set fails closed.
        let stale = GuardianAccount { account_public_key: Hash4::from_values(9, 9, 9, 9), ..imported.clone() };
        assert!(matches!(restored_history(&stale, Vec::new(), &config), Err(GuardianSignError::AccountIdentityConflict)));
        let torn = GuardianAccount { imported_ending_leaf: None, ..imported.clone() };
        assert!(matches!(restored_history(&torn, Vec::new(), &config), Err(GuardianSignError::DatabaseUnavailable)));
        assert!(restored_history(&imported, vec![deposit_tree_state; 4], &config).is_err());
    }

    #[tokio::test]
    async fn unavailable_checkpoint_leaves_tableless_journal() {
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let config = approval_config(public_key);
        let (mut db, root) = open_approval_journal(public_key, "auth-failure", Arc::clone(&config)).await;
        let provider = unreachable_provider();
        assert_eq!(initialize_runtime_after_authentication(&mut db, &provider, 90101, &config, 2, public_key).await.unwrap_err(), GuardianSignError::CheckpointProofUnavailable);
        assert_eq!(initialize_runtime_after_authentication(&mut db, &provider, 90101, &config, 1, public_key).await.unwrap_err(), GuardianSignError::CheckpointProofUnavailable);
        drop(db);
        let file = reopen_journal(&root);
        let db = GuardianDb::open(file, public_key, Arc::clone(&config)).await.unwrap();
        assert!(!db.runtime_initialized().unwrap());
        drop(db);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn initialized_runtime_reopen_retains_state() {
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let config = approval_config(public_key);
        let account = GuardianAccount { network_magic: config.network_magic().unwrap(), user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::ZERO, imported_nonce: None,
            account_public_key: config.account_public_key().unwrap(), imported_ending_leaf: None, withdrawal_chains: Vec::new(), halt_reason: None };
        let (mut db, root) = open_approval_journal(public_key, "initialized-reopen", Arc::clone(&config)).await;
        db.initialize_runtime(&account).await.unwrap();
        drop(db);
        let file = reopen_journal(&root);
        let mut db = GuardianDb::open(file, public_key, Arc::clone(&config)).await.unwrap();
        assert!(db.runtime_initialized().unwrap());
        let retained = db.load_account(account.network_magic, BRIDGE_USER_ID).await.unwrap();
        assert_eq!(retained.state, GuardianAccountState::Active);
        assert_eq!(retained.imported_nonce, None);
        assert_eq!(retained.halt_reason, None);
        drop(db);
        let stranger = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[4; 32]).unwrap();
        let file = reopen_journal(&root);
        assert!(matches!(GuardianDb::open(file, stranger.compressed_public_key(), Arc::clone(&config)).await, Err(GuardianSignError::AccountIdentityConflict)));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn partial_runtime_tables_are_rejected_without_repair_through_open() {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let config = approval_config(public_key);
        let root = std::env::temp_dir().join(format!("guardian-service-partial-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(root.join(JOURNAL)).unwrap();
        let mut database = redb::Database::builder().create_file(file).unwrap();
        {
            let tx = database.begin_write().unwrap();
            tx.open_table::<(), [u8; 33]>(redb::TableDefinition::new("guardian_signer")).unwrap().insert((), &public_key).unwrap();
            tx.commit().unwrap();
        }
        drop(database);
        std::fs::File::open(&root).unwrap().sync_all().unwrap();
        let before = std::fs::read(root.join(JOURNAL)).unwrap();
        for _ in 0..2 {
            let file = reopen_journal(&root);
            assert!(matches!(GuardianDb::open(file, public_key, Arc::clone(&config)).await, Err(GuardianSignError::LegacyJournalSchema)));
        }
        assert_eq!(std::fs::read(root.join(JOURNAL)).unwrap(), before);
        std::fs::remove_dir_all(root).unwrap();
    }
}
