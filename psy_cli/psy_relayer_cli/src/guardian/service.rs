use std::{convert::Infallible, future::Future, io::ErrorKind, path::{Component, Path, PathBuf}, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};

use guardian_common::db::GuardianDb;
use guardian_common::endcap::approved_endcap_max_proof_bytes;
use guardian_common::protocol::{parse_canonical_json, sha256, validate_hash, GuardianAccount, GuardianAccountState, GuardianAuthorization, GuardianRuntimeConfig, GuardianSessionRecord, GuardianSignError, GuardianSignErrorResponse, GuardianSignRequest, GuardianSessionsResponse, HaltReason, Hash4, Hex, Hex32, GOLDILOCKS_MODULUS, MAX_BODY_BYTES};
use guardian_common::runtime::{create_db_file, load_authorization_archive, load_network, load_signing_key, open_db_file, resolve_operator_db_path, AuthorizationArchive};
use super::verify::{GuardianVerificationContext, GuardianAccountError};
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
        .post(url).json(&request).send().await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    if !response.status().is_success() { return Err(GuardianSignError::EvidenceUnavailable); }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| GuardianSignError::EvidenceUnavailable)? {
        if chunk.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) { return Err(GuardianSignError::EvidenceUnavailable); }
        bytes.extend_from_slice(&chunk);
    }
    match serde_json::from_slice::<RpcResponse<T>>(&bytes).map_err(|_| GuardianSignError::EvidenceUnavailable)?.result {
        ResponseResult::Success(value) => Ok(value),
        ResponseResult::Error(_) => Err(GuardianSignError::EvidenceUnavailable),
    }
}

pub(crate) async fn load_guardian_committed_head(provider: &RpcProvider, url: &str) -> Result<GuardianCommittedHead, GuardianSignError> {
    let checkpoint_id = committed_rpc(provider, url, RequestParams::GetLatestCheckpointId).await?;
    let checkpoint_tree_root = committed_rpc(provider, url, RequestParams::GetCheckpointTreeRoot(QCheckpointTreeRootRPCRequest { checkpoint_id })).await?;
    validate_hash(checkpoint_tree_root)?;
    if checkpoint_id >= GOLDILOCKS_MODULUS { return Err(GuardianSignError::EvidenceMismatch); }
    Ok(GuardianCommittedHead { checkpoint_id, checkpoint_tree_root })
}

async fn verify_genesis(provider: &RpcProvider, head: GuardianCommittedHead, authorization: &GuardianAuthorization) -> Result<(), GuardianSignError> {
    let leaf = provider.get_checkpoint_leaf_data(0).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    let roots = provider.get_checkpoint_global_state_roots(0).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    let path = provider.get_checkpoint_tree_merkle_proof(head.checkpoint_id, 0).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    super::verify::verify_checkpoint(0, &leaf, &roots, &path, head.checkpoint_tree_root)?;
    if Hash256::from(leaf.qfhash::<PsyHasher>()).0 != authorization.genesis_hash.0 { return Err(GuardianSignError::AccountIdentityConflict); }
    let root = provider.get_checkpoint_tree_root(0).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    let path = provider.get_checkpoint_tree_merkle_proof(0, 0).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    super::verify::verify_checkpoint(0, &leaf, &roots, &path, root)
}

type HttpResponse = Response<Full<Bytes>>;
static SIGN_REQUESTS: Semaphore = Semaphore::const_new(4);

struct GuardianService {
    config: GuardianRuntimeConfig,
    archive: AuthorizationArchive,
    authorizations: Vec<GuardianAuthorization>,
    wallet: psy_prover::session::session::WalletSession,
    signer: GuardianSigner,
    history_client: reqwest::Client,
    history: super::verify::GuardianHistory,
}
impl GuardianService {
    async fn observe_saved_anchors(&mut self, head: GuardianCommittedHead) -> Result<(), GuardianSignError> {
        tracing::info!("[anchors] enter");
        let authorization = self.archive.active().0.clone();
        let mut after = None;
        loop {
            let page = self.signer.db.load_sessions(authorization.network_magic, authorization.user_id, after, 1).await?;
            if page.is_empty() { tracing::info!("[anchors] sessions exhausted"); break; }
            after = page.last().map(|entry| entry.nonce);
            let context = GuardianVerificationContext { wallet: &self.wallet, provider: &self.wallet.st_provider, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_endpoints: &self.config.l1_rpc_urls, history: &self.history };
            let result = super::verify::verify_guardian_saved_anchors(&context, &[], &self.authorizations, &page).await;
            self.save_account_result(result).await?;
        }
        after = None;
        loop {
            let page = self.signer.db.load_signed(authorization.network_magic, authorization.user_id, after, 1).await?;
            if page.is_empty() { tracing::info!("[anchors] signed exhausted"); break; }
            tracing::info!(count = page.len(), "[anchors] verifying signed records");
            after = page.last().map(|entry| entry.nonce);
            for signed in &page {
                let request = GuardianSignRequest::from_canonical_bytes(&signed.request_bytes)?;
                if signed.authorization_bytes != self.archive.resolve(request.authorization_version)?.1 { return Err(GuardianSignError::AuthorizationMismatch); }
                let canonical = self.signer.db.load_sessions(authorization.network_magic, authorization.user_id, signed.nonce.checked_sub(1), 1).await?;
                if let Some(session) = canonical.first().filter(|session| session.nonce == signed.nonce) {
                    if session.record.request_json.decode()?.canonical_bytes()? != signed.request_bytes {
                        self.signer.db.halt_account(authorization.network_magic, authorization.user_id, HaltReason::NonceConsumedDifferently).await?;
                        return Err(GuardianSignError::AccountHalted);
                    }
                }
            }
            let context = GuardianVerificationContext { wallet: &self.wallet, provider: &self.wallet.st_provider, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_endpoints: &self.config.l1_rpc_urls, history: &self.history };
            let saved = self.signer.db.load_account(authorization.network_magic, authorization.user_id).await?;
            let unimported = page.iter().all(|signed| saved.imported_nonce.is_none_or(|imported| imported < signed.nonce));
            let result = super::verify::verify_guardian_saved_anchors(&context, &page, &self.authorizations, &[]).await;
            match result {
                Ok(()) => {}
                Err(GuardianAccountError::Unavailable(GuardianSignError::EvidenceUnavailable)) if unimported => {
                    // The saved session was never included; its L1 anchor evidence may no longer be
                    // readable. The signature is inert until included and a rebuilt request re-signs.
                    tracing::warn!(nonces = ?page.iter().map(|signed| signed.nonce).collect::<Vec<_>>(), "skipping anchor re-verification for un-included saved signatures with unavailable evidence");
                }
                Err(error) => self.save_account_result(Err(error)).await?,
            }
        }
        Ok(())
    }

    async fn save_account_result(&mut self, result: Result<(), GuardianAccountError>) -> Result<(), GuardianSignError> {
        let authorization = &self.archive.active().0;
        save_guardian_account_result(&mut self.signer.db, authorization.network_magic, authorization.user_id, result).await
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
        Err(GuardianSignError::HistoryUnavailable)
    }

    async fn observe(&mut self) -> Result<GuardianCommittedHead, GuardianSignError> {
        let authorization = self.archive.active().0.clone();
        let saved = self.signer.db.load_account(authorization.network_magic, authorization.user_id).await?;
        if saved.state == GuardianAccountState::Halted { return Err(GuardianSignError::AccountHalted); }
        let provider = &self.wallet.st_provider;
        let head = load_guardian_committed_head(provider, &self.config.l2_rpc_url).await?;
        if head.checkpoint_id < saved.last_checkpoint_id {
            self.signer.db.halt_account(authorization.network_magic, authorization.user_id, HaltReason::CheckpointConflict).await?;
            return Err(GuardianSignError::AccountHalted);
        }
        let saved_path = provider.get_checkpoint_tree_merkle_proof(head.checkpoint_id, saved.last_checkpoint_id).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
        if saved_path.root != head.checkpoint_tree_root || saved_path.index != saved.last_checkpoint_id || !saved_path.verify::<PsyHasher>() {
            return Err(GuardianSignError::EvidenceMismatch);
        }
        if saved_path.value != saved.last_checkpoint_hash {
            self.signer.db.halt_account(authorization.network_magic, authorization.user_id, HaltReason::CheckpointConflict).await?;
            return Err(GuardianSignError::AccountHalted);
        }
        verify_genesis(provider, head, &authorization).await?;
        tracing::info!(checkpoint_id = head.checkpoint_id, "[observe] genesis verified");
        self.observe_saved_anchors(head).await?;
        tracing::info!("[observe] saved anchors verified");
        loop {
            let page = self.signer.db.load_sessions(authorization.network_magic, authorization.user_id, Some(self.history.nonce()), 1).await?;
            let Some(retained) = page.into_iter().next() else { break; };
            let request = retained.record.request_json.decode()?;
            let approved = &self.archive.resolve(request.authorization_version)?.0;
            let context = GuardianVerificationContext { wallet: &self.wallet, provider: &self.wallet.st_provider, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_endpoints: &self.config.l1_rpc_urls, history: &self.history };
            let result = super::verify::verify_session(&context, approved, retained.record).await;
            let verified = save_guardian_account_result(&mut self.signer.db, authorization.network_magic, authorization.user_id, result).await?;
            if verified.starting_leaf_hash != retained.starting_leaf_hash || verified.ending_leaf_hash != retained.ending_leaf_hash || verified.withdrawal_appends != retained.withdrawal_appends {
                return Err(GuardianSignError::JournalUnavailable);
            }
            self.history.apply(&verified)?;
        }
        let target = {
            let context = GuardianVerificationContext { wallet: &self.wallet, provider: &self.wallet.st_provider, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_endpoints: &self.config.l1_rpc_urls, history: &self.history };
            super::verify::verified_account_nonce(&context, &authorization).await?
        };
        let mut imported = self.history.nonce();
        while imported < target {
            let record = self.fetch_history(imported).await?;
            let request = record.request_json.decode()?;
            if request.session_nonce != imported.checked_add(1).ok_or(GuardianSignError::HistoryUnavailable)? { return Err(GuardianSignError::HistoryUnavailable); }
            let approved = &self.archive.resolve(request.authorization_version)?.0;
            let context = GuardianVerificationContext { wallet: &self.wallet, provider: &self.wallet.st_provider, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_endpoints: &self.config.l1_rpc_urls, history: &self.history };
            let result = super::verify::verify_session(&context, approved, record).await;
            let session = save_guardian_account_result(&mut self.signer.db, authorization.network_magic, authorization.user_id, result).await?;
            let session = self.signer.db.import_session(&session).await?;
            self.history.apply(&session)?;
            imported = session.nonce;
        }
        if self.history.nonce() != target { return Err(GuardianSignError::HistoryUnavailable); }
        let rechecked = load_guardian_committed_head(&self.wallet.st_provider, &self.config.l2_rpc_url).await?;
        let old_root: Hash4 = committed_rpc(&self.wallet.st_provider, &self.config.l2_rpc_url,
            RequestParams::GetCheckpointTreeRoot(QCheckpointTreeRootRPCRequest { checkpoint_id: head.checkpoint_id })).await?;
        if rechecked.checkpoint_id < head.checkpoint_id || old_root != head.checkpoint_tree_root {
            self.signer.db.halt_account(authorization.network_magic, authorization.user_id, HaltReason::CheckpointConflict).await?;
            return Err(GuardianSignError::AccountHalted);
        }
        let leaf = self.wallet.st_provider.get_checkpoint_leaf_data(head.checkpoint_id).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
        let mut account = self.signer.db.load_account(authorization.network_magic, authorization.user_id).await?;
        account.last_checkpoint_id = head.checkpoint_id;
        account.last_checkpoint_hash = leaf.qfhash::<PsyHasher>();
        account.authorization_version = authorization.version;
        self.signer.db.save_account(&account).await?;
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

fn enroll_guardian_account(wallet: &mut psy_prover::wallet::memory_wallet::PsyMemoryWallet, account: psy_vm::ups::multisig::MultisigAccount, fingerprint: Hash4, public_key: Hash4) -> Result<(), GuardianSignError> {
    let identity = wallet.register_recorded_multisig_user(account, fingerprint).map_err(|_| GuardianSignError::AccountIdentityConflict)?;
    if identity.fingerprint != fingerprint || identity.qfhash::<PsyHasher>() != public_key {
        return Err(GuardianSignError::AccountIdentityConflict);
    }
    Ok(())
}

fn resolve_db_path(config_path: &Path, db_path: &Path) -> Result<(PathBuf, PathBuf), GuardianSignError> {
    let raw = db_path.as_os_str().as_encoded_bytes();
    if raw.is_empty() || raw.ends_with(b"/") { return Err(GuardianSignError::AuthorizationMismatch); }
    resolve_operator_db_path(config_path, db_path)
}

fn authenticate_key_slot(account: &psy_vm::ups::multisig::MultisigAccount, guardian_id: u8, public_key: [u8; 33]) -> Result<(), GuardianSignError> {
    use plonky2::hash::poseidon::PoseidonPermutation;
    use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
    let compressed = psy_client_common::data::secp256k1::CompressedPublicKey::new_from_slice(&public_key);
    let member = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(compressed);
    let expected = account.initial_policy.member_hashes.get(usize::from(guardian_id.checked_sub(1).ok_or(GuardianSignError::AuthorizationMismatch)?))
        .ok_or(GuardianSignError::AuthorizationMismatch)?;
    if member != *expected { return Err(GuardianSignError::AccountIdentityConflict); }
    Ok(())
}

async fn open_or_create_journal(directory: &Path, relative: &Path, public_key: [u8; 33], account: &GuardianAccount) -> Result<GuardianDb, GuardianSignError> {
    match open_db_file(directory, relative) {
        Ok(file) => {
            if file.metadata().map_err(|_| GuardianSignError::KeyUnavailable)?.len() == 0 {
                return Err(GuardianSignError::JournalUnavailable);
            }
            GuardianDb::open(file, public_key).await
        }
        Err(GuardianSignError::KeyUnavailable) if final_component_missing(directory, relative) => {
            let (file, parent) = create_db_file(directory, relative)?;
            let db = GuardianDb::create(file, public_key, account).await?;
            parent.sync_all().map_err(|_| GuardianSignError::JournalUnavailable)?;
            Ok(db)
        }
        Err(error) => Err(error),
    }
}

fn final_component_missing(directory: &Path, relative: &Path) -> bool {
    let path = directory.join(relative);
    match path.symlink_metadata() {
        Err(error) if error.kind() == ErrorKind::NotFound => path.parent().is_some_and(|parent| parent.is_dir()),
        _ => false,
    }
}


pub async fn run(config_path: &Path, guardian_id: u8, db_path: &Path) -> Result<(), GuardianSignError> {
    if !(1..=3).contains(&guardian_id) { return Err(GuardianSignError::AuthorizationMismatch); }
    let (db_directory, db_relative) = resolve_db_path(config_path, db_path)?;
    let proof_bound = approved_endcap_max_proof_bytes()?;
    let loaded = guardian_common::protocol::GuardianConfig::load(config_path)?;
    let archive = load_authorization_archive(config_path, proof_bound)?;
    let runtime = loaded.build_runtime_config(config_path, guardian_id, db_path, &archive.index)?;
    runtime.validate(&archive.active().0, &archive.index)?;
    let active = archive.active().0.clone();
    let provider = load_network(&loaded, &active)?;
    let mut wallet = psy_prover::session::session::WalletSession::new_with_provider(&loaded.network, provider, Some(active.endcap_verifier_fingerprint)).await.map_err(|_| GuardianSignError::KeyUnavailable)?;
    enroll_guardian_account(&mut wallet.wallet, active.account_json.decode()?, active.multisig_fingerprint, active.account_public_key)?;
    let key = load_signing_key(&runtime)?;
    let public_key = key.compressed_public_key();
    authenticate_key_slot(&active.account_json.decode()?, guardian_id, public_key)?;
    let head = tokio::time::timeout(Duration::from_secs(30), load_guardian_committed_head(&wallet.st_provider, &runtime.l2_rpc_url)).await
        .map_err(|_| GuardianSignError::EvidenceUnavailable)??;
    verify_genesis(&wallet.st_provider, head, &active).await?;
    let genesis = wallet.st_provider.get_checkpoint_leaf_data(0).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    let created = GuardianAccount { network_magic: active.network_magic, user_id: active.user_id,
        state: GuardianAccountState::Active, last_checkpoint_id: 0, last_checkpoint_hash: genesis.qfhash::<PsyHasher>(), imported_nonce: None,
        authorization_version: active.version, halt_reason: None };
    let mut db = open_or_create_journal(&db_directory, &db_relative, public_key, &created).await?;
    db.load_account(active.network_magic, active.user_id).await?;
    let history_client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(30))
        .build().map_err(|_| GuardianSignError::KeyUnavailable)?;
    let authorizations = archive.authorizations();
    let history = super::verify::GuardianHistory::new();
    for authorization in &authorizations {
        history.validate_authorization_artifacts(authorization, &wallet).await?;
    }
    let config = runtime.clone();
    let service = Arc::new(tokio::sync::Mutex::new(GuardianService { config, archive, authorizations, wallet,
        signer: GuardianSigner { db, key, public_key }, history_client, history }));
    let listener = TcpListener::bind(&runtime.listen_address).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
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
                    let observed = tokio::time::timeout(Duration::from_secs(30), service.observe()).await;
                    let observer_error = match observed { Err(_) => Some(GuardianSignError::EvidenceUnavailable), Ok(result) => result.err() };
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
    let signing_drained = SIGN_REQUESTS.acquire_many(4).await.map_err(|_| GuardianSignError::JournalUnavailable)?;
    let drained = shutdown_service.lock().await;
    drop(drained);
    drop(signing_drained);
    result
}

async fn handle_request(service: Arc<tokio::sync::Mutex<GuardianService>>, request: Request<Incoming>) -> HttpResponse {
    if request.method() == hyper::Method::GET && request.uri().path() == "/v1/sessions" {
        let Ok((after, limit)) = history_query(request.uri().query()) else { return error_response(None, GuardianSignError::MalformedRequest); };
        let mut service = service.lock().await;
        let authorization = service.archive.active().0.clone();
        let result = service.signer.db.load_sessions(authorization.network_magic, authorization.user_id, Some(after), 2).await;
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
        Err(_) => return error_response(Some(request_id), GuardianSignError::EvidenceUnavailable),
    };
    let signing = tokio::spawn(async move {
    let _permit = permit;
    let mut service = tokio::time::timeout(Duration::from_secs(600), service.lock()).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    let cached = {
        let existing = service.signer.db.lookup_signed(request.network_magic, request.user_id, request.session_nonce).await?;
        let canonical_bytes = request.canonical_bytes()?;
        if request.authorization_version != service.archive.index.active_version && existing.as_ref().is_none_or(|signed| signed.request_bytes != canonical_bytes) {
            return Err(GuardianSignError::AuthorizationMismatch);
        }
        existing.filter(|signed| signed.request_bytes == canonical_bytes && signed.signature.is_some())
    };
    let result = if cached.is_some() {
        let public_key = service.signer.public_key;
        authorize_cached_response(&mut service.signer.db, &request, public_key).await
    } else {
        let prepared = tokio::time::timeout(Duration::from_secs(600), async {
            for burn in &request.withdrawal_records {
                service.wallet.st_provider.get_realm_url(u64::from(burn.sender_user_id)).map_err(|_| GuardianSignError::EvidenceUnavailable)?;
            }
            let canonical_bytes = request.canonical_bytes()?;
            let existing = service.signer.db.lookup_signed(request.network_magic, request.user_id, request.session_nonce).await?;
            let head = service.observe().await?;
            let mut prefix = None;
            if service.history.nonce() >= request.session_nonce {
                if existing.as_ref().is_none_or(|signed| signed.request_bytes != canonical_bytes || signed.signature.is_none()) {
                    return Err(GuardianSignError::NonceConflict);
                }
                let mut history = super::verify::GuardianHistory::new();
                while history.nonce().checked_add(1).is_some_and(|nonce| nonce < request.session_nonce) {
                    let page = service.signer.db.load_sessions(request.network_magic, request.user_id, Some(history.nonce()), 1).await?;
                    let session = page.first().ok_or(GuardianSignError::HistoryUnavailable)?;
                    history.apply(session)?;
                }
                prefix = Some(history);
            }
            let (authorization, bytes) = service.archive.resolve(request.authorization_version)?;
            let context = GuardianVerificationContext { wallet: &service.wallet, provider: &service.wallet.st_provider, verified_checkpoint_id: head.checkpoint_id,
                verified_checkpoint_tree_root: head.checkpoint_tree_root, l1_endpoints: &service.config.l1_rpc_urls, history: prefix.as_ref().unwrap_or(&service.history) };
            let result = super::verify::verify_guardian_session(&context, authorization, &request).await;
            let bytes = bytes.clone();
            let verified = save_guardian_account_result(&mut service.signer.db, request.network_magic, request.user_id, result).await?;
            Ok::<_, GuardianSignError>((verified, bytes))
        }).await;
        match prepared {
            Ok(Ok((verified, bytes))) => {
                let GuardianService { signer, .. } = &mut *service;
                signer.sign_verified(&request, &bytes, &verified).await
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(GuardianSignError::EvidenceUnavailable),
        }
    };
    result
    });
    let result = signing.await.unwrap_or(Err(GuardianSignError::JournalUnavailable));
    match result { Ok(body) => json_response(200, body), Err(error) => error_response(Some(request_id), error) }
}

/// Re-authorizes a cached signature against durable account state before release;
/// `authorize_response` owns the halt gate and the request-bytes binding.
async fn authorize_cached_response(db: &mut GuardianDb, request: &GuardianSignRequest, public_key: [u8; 33]) -> Result<Vec<u8>, GuardianSignError> {
    let canonical_bytes = request.canonical_bytes()?;
    db.authorize_response(request.network_magic, request.user_id, request.session_nonce, &canonical_bytes, |signed| {
        let authorization: GuardianAuthorization = parse_canonical_json(&signed.authorization_bytes).map_err(|_| GuardianSignError::JournalUnavailable)?;
        let account = authorization.account_json.decode().map_err(|_| GuardianSignError::JournalUnavailable)?;
        let commitment = account.initial_policy.commitment().map_err(|_| GuardianSignError::PolicyMismatch)?;
        let compressed = psy_client_common::data::secp256k1::CompressedPublicKey::new_from_slice(&public_key);
        let member_hash = psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<GoldilocksField, plonky2::hash::poseidon::PoseidonPermutation<GoldilocksField>>(compressed);
        let member_index = account.initial_policy.member_hashes[..3].iter().position(|member| *member == member_hash).ok_or(GuardianSignError::PolicyMismatch)? as u8;
        let response = guardian_common::protocol::GuardianSignResponse {
            request_id: sha256(&signed.request_bytes), network_magic: signed.network_magic, user_id: signed.user_id,
            session_nonce: signed.nonce, policy_commitment: commitment, member_index,
            message: Hex(signed.message), public_key: Hex(public_key),
            signature: Hex(signed.signature.ok_or(GuardianSignError::JournalUnavailable)?),
        };
        serde_json::to_vec(&response).map_err(|_| GuardianSignError::JournalUnavailable)
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
        authorization_bytes: &[u8],
        verified: &super::verify::VerifiedGuardianSession,
    ) -> Result<Vec<u8>, GuardianSignError> {
        use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonPermutation};
        use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
        use guardian_common::protocol::{GuardianSigned, GuardianSignResponse};
        let public_key = psy_client_common::data::secp256k1::CompressedPublicKey::new_from_slice(&self.public_key);
        let member_hash = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(public_key);
        let commitment = verified.current_policy.commitment().map_err(|_| GuardianSignError::PolicyMismatch)?;
        let member_index = verified.current_policy.member_hashes[..3].iter().position(|member| *member == member_hash)
            .ok_or(GuardianSignError::PolicyMismatch)? as u8;
        let signed = GuardianSigned {
            network_magic: request.network_magic, user_id: request.user_id, nonce: request.session_nonce,
            request_bytes: request.canonical_bytes()?,
            authorization_bytes: authorization_bytes.to_vec(), starting_leaf_hash: verified.starting_leaf_hash,
            ending_leaf_hash: verified.ending_leaf_hash, message: verified.message, signature: None,
        };
        let reserved = self.db.reserve_guardian_nonce(&signed).await?;
        if reserved.signature.is_none() {
            let signature = self.key.sign_prehash_raw(&reserved.message).map_err(|_| GuardianSignError::KeyUnavailable)?;
            self.db.save_guardian_signature(reserved.network_magic, reserved.user_id, reserved.nonce, &reserved.request_bytes, signature).await?;
        }
        self.db.authorize_response(request.network_magic, request.user_id, request.session_nonce, &signed.request_bytes, |signed| {
            let response = GuardianSignResponse {
                request_id: sha256(&signed.request_bytes), network_magic: signed.network_magic, user_id: signed.user_id,
                session_nonce: signed.nonce, policy_commitment: commitment, member_index,
                message: Hex(signed.message), public_key: Hex(self.public_key),
                signature: Hex(signed.signature.ok_or(GuardianSignError::JournalUnavailable)?),
            };
            serde_json::to_vec(&response).map_err(|_| GuardianSignError::JournalUnavailable)
        }).await
    }
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
                signal.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
                break;
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (socket, _) = accepted.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
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
    archive: Arc<crate::bridge::guardian_client::RelayerArchive>,
) -> Result<(), GuardianSignError> {
    let listener = TcpListener::bind(listen_address).await.map_err(|_| GuardianSignError::EvidenceUnavailable)?;
    serve_http(listener, move |request| {
        let archive = archive.clone();
        async move {
            if request.method() != hyper::Method::GET || request.uri().path() != "/v1/sessions" {
                return error_response(None, GuardianSignError::MalformedRequest);
            }
            let result = history_query(request.uri().query()).and_then(|(after, limit)| {
                let page = archive.sessions(after, limit as u8)
                    .map_err(|_| GuardianSignError::HistoryUnavailable)?;
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


    #[tokio::test]
    #[ignore = "requires post-implementation QA approval"]
    async fn authenticated_conflict_halts_durably_but_unavailable_account_does_not() {
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!("guardian-service-{}-{}.redb", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).unwrap();
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let account = GuardianAccount { network_magic: 90101, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::ZERO, imported_nonce: None, authorization_version: 1, halt_reason: None };
        let mut db = GuardianDb::create(file, public_key, &account).await.unwrap();
        assert_eq!(save_guardian_account_result::<()>(&mut db, 90101, BRIDGE_USER_ID,
            Err(GuardianAccountError::Unavailable(GuardianSignError::EvidenceUnavailable))).await, Err(GuardianSignError::EvidenceUnavailable));
        assert_eq!(db.load_account(90101, BRIDGE_USER_ID).await.unwrap().state, GuardianAccountState::Active);
        assert_eq!(save_guardian_account_result::<()>(&mut db, 90101, BRIDGE_USER_ID,
            Err(GuardianAccountError::Unavailable(GuardianSignError::EvidenceMismatch))).await, Err(GuardianSignError::EvidenceMismatch));
        assert_eq!(db.load_account(90101, BRIDGE_USER_ID).await.unwrap().state, GuardianAccountState::Active);
        assert_eq!(save_guardian_account_result::<()>(&mut db, 90101, BRIDGE_USER_ID,
            Err(GuardianAccountError::Conflict(HaltReason::FinalityConflict))).await, Err(GuardianSignError::AccountHalted));
        drop(db);
        let file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let mut db = GuardianDb::open(file, public_key).await.unwrap();
        let retained = db.load_account(90101, BRIDGE_USER_ID).await.unwrap();
        assert_eq!(retained.state, GuardianAccountState::Halted);
        assert_eq!(retained.halt_reason, Some(HaltReason::FinalityConflict));
        assert!(db.save_account(&account).await.is_err());
        drop(db);
        std::fs::remove_file(path).unwrap();
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
                "JournalUnavailable" => GuardianSignError::JournalUnavailable,
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
            for error in [Some(GuardianSignError::JournalUnavailable), Some(GuardianSignError::JournalUnavailable), Some(GuardianSignError::KeyUnavailable), Some(GuardianSignError::JournalUnavailable), None, Some(GuardianSignError::JournalUnavailable), Some(GuardianSignError::AccountHalted), Some(GuardianSignError::AccountHalted)] {
                warn_observer_authorization(&mut warned, error);
            }
        });
        let logged = String::from_utf8(captured.lock().expect("log").clone()).unwrap();
        assert_eq!(codes(&logged), [
            GuardianSignError::JournalUnavailable, GuardianSignError::JournalUnavailable,
            GuardianSignError::JournalUnavailable, GuardianSignError::AccountHalted,
        ]);
    }

    #[tokio::test]
    async fn halted_account_fails_closed_for_cached_sign_response() {
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!("guardian-cached-{}-{}.redb", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).unwrap();
        let key = psy_provider::wallet::secp_wallet::Wallet::from_bytes(&[3; 32]).unwrap();
        let public_key = key.compressed_public_key();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let account = GuardianAccount { network_magic: request.network_magic, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
            last_checkpoint_id: 0, last_checkpoint_hash: Hash4::ZERO, imported_nonce: None, authorization_version: 1, halt_reason: None };
        let mut db = GuardianDb::create(file, public_key, &account).await.unwrap();
        let signed = guardian_common::protocol::GuardianSigned {
            network_magic: request.network_magic, user_id: request.user_id, nonce: request.session_nonce,
            request_bytes: request.canonical_bytes().unwrap(), authorization_bytes: vec![2],
            starting_leaf_hash: Hash4::ZERO, ending_leaf_hash: Hash4::ZERO, message: [3; 32], signature: None,
        };
        db.reserve_guardian_nonce(&signed).await.unwrap();
        db.save_guardian_signature(signed.network_magic, signed.user_id, signed.nonce, &signed.request_bytes, [3; 64]).await.unwrap();
        assert_eq!(authorize_cached_response(&mut db, &request, public_key).await.unwrap_err(), GuardianSignError::JournalUnavailable);
        db.halt_account(signed.network_magic, signed.user_id, HaltReason::AppendHistoryMismatch).await.unwrap();
        assert_eq!(authorize_cached_response(&mut db, &request, public_key).await, Err(GuardianSignError::AccountHalted));
        std::fs::remove_file(path).unwrap();
    }
}
