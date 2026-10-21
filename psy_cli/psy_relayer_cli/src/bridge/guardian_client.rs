use std::{fs::{self, File, OpenOptions}, io::Write, path::{Path, PathBuf}, time::Duration};

use anyhow::{Context, ensure};
use futures::{stream::FuturesUnordered, StreamExt};
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};
use psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature;
use psy_prover::signature::users::multisig_user::validate_policy_signatures;
use psy_vm::ups::multisig::{MultisigPolicy, MultisigSignatures};

use guardian_common::endcap::approved_endcap_max_proof_bytes;
use guardian_common::protocol::{self, GuardianAuthorization, GuardianClientConfig as SharedGuardianClientConfig, GuardianSignRequest, GuardianSignResponse, GuardianSignErrorResponse, GuardianSessionRecord, GuardianSessionsResponse, JsonText, MAX_BODY_BYTES};
use guardian_common::runtime::load_authorization_archive;

pub(crate) struct LoadedGuardianConfig {
    pub root: guardian_common::protocol::GuardianConfig,
    pub archive: guardian_common::runtime::AuthorizationArchive,
    pub config_dir: PathBuf,
}

impl LoadedGuardianConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let root = guardian_common::protocol::GuardianConfig::load(path)?;
        let archive = load_authorization_archive(path, approved_endcap_max_proof_bytes()?)?;
        let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
        let config_dir = absolute.parent().filter(|parent| !parent.as_os_str().is_empty()).context("guardian config directory missing")?.to_path_buf();
        Ok(Self { root, archive, config_dir })
    }

    pub fn client(&self) -> &SharedGuardianClientConfig { &self.root.client }

    pub fn authorization(&self) -> anyhow::Result<&GuardianAuthorization> {
        Ok(&self.archive.active().0)
    }

    pub fn historical_authorization(&self, version: u32) -> anyhow::Result<&GuardianAuthorization> {
        Ok(&self.archive.resolve(version)?.0)
    }

    pub async fn serve_history(&self) -> anyhow::Result<()> {
        crate::guardian::service::serve_relayer_history(
            &self.client().listen_address.to_string(),
            std::sync::Arc::new(RelayerArchive::open(&self.config_dir.join(&self.client().archive_path))?),
        ).await.map_err(Into::into)
    }
}

pub(crate) struct GuardianClient {
    http: reqwest::Client,
    endpoints: [url::Url; 3],
}

impl GuardianClient {
    pub fn new(config: &SharedGuardianClientConfig) -> anyhow::Result<Self> {
        let endpoints = config.endpoints.iter().map(|text| {
            let url = url::Url::parse(text)?;
            ensure!(url.scheme() == "http" && url.host().is_some() && url.username().is_empty() && url.password().is_none() && (url.path() == "/" || url.path().is_empty()) && url.query().is_none() && url.fragment().is_none() && url.port().unwrap_or(80) != 0, "guardian endpoint must be a fixed HTTP origin");
            Ok(url)
        }).collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(endpoints[0] != endpoints[1] && endpoints[0] != endpoints[2] && endpoints[1] != endpoints[2], "guardian origins must be distinct");
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(620)).build()?;
        Ok(Self { http, endpoints: endpoints.try_into().map_err(|_| anyhow::anyhow!("three guardian endpoints required"))? })
    }

    pub async fn session_record(&self, after_nonce: u64) -> anyhow::Result<Option<GuardianSessionRecord>> {
        let nonce = after_nonce.checked_add(1).context("history nonce overflow")?;
        let mut selected: Option<GuardianSessionRecord> = None;
        let mut saw_conflict = false;
        for origin in &self.endpoints {
            let mut url = origin.clone();
            url.set_path("/v1/sessions");
            url.query_pairs_mut().append_pair("after_nonce", &after_nonce.to_string()).append_pair("limit", "1");
            let Ok(mut response) = self.http.get(url).send().await else { continue };
            if !response.status().is_success() { continue; }
            let mut body = Vec::new();
            let mut failed = false;
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) if body.len().checked_add(chunk.len()).is_some_and(|n| n <= MAX_BODY_BYTES) => body.extend_from_slice(&chunk),
                    Ok(None) => break,
                    _ => { failed = true; break; }
                }
            }
            if failed { continue; }
            let Ok(page) = protocol::parse_canonical_json::<GuardianSessionsResponse>(&body) else { continue };
            if page.validate_page(after_nonce, 1).is_err() { continue; }
            let Some(record) = page.sessions.into_iter().next() else { continue };
            let Ok(request) = record.request_json.decode() else { saw_conflict = true; continue };
            if request.session_nonce != nonce { saw_conflict = true; continue; }
            match &selected {
                Some(saved) if serde_json::to_vec(saved)? != serde_json::to_vec(&record)? => saw_conflict = true,
                Some(_) => {}
                None => selected = Some(record),
            }
        }
        if saw_conflict { anyhow::bail!("authenticated guardian history conflict"); }
        Ok(selected)
    }

    pub async fn collect(&self, request_json: &JsonText<GuardianSignRequest>, policy: &MultisigPolicy, sighash: QHashOut<GoldilocksField>) -> anyhow::Result<MultisigSignatures> {
        let request = request_json.decode()?;
        policy.validate()?;
        let message = Hash256::from(sighash);
        let mut pending = FuturesUnordered::new();
        for origin in &self.endpoints {
            let url = origin.join("v1/sign-session")?;
            let http = &self.http;
            let bytes = request_json.as_str();
            pending.push(async move {
                let mut response = http.post(url).header(reqwest::header::CONTENT_TYPE, "application/json").body(bytes.to_owned()).send().await?;
                let status = response.status();
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    ensure!(body.len().checked_add(chunk.len()).is_some_and(|n| n <= MAX_BODY_BYTES), "guardian response exceeds transport bound");
                    body.extend_from_slice(&chunk);
                }
                if !status.is_success() {
                    let error: GuardianSignErrorResponse = protocol::parse_canonical_json(&body)?;
                    anyhow::bail!("guardian refused request: {}", error.code);
                }
                Ok::<_, anyhow::Error>(protocol::parse_canonical_json::<GuardianSignResponse>(&body)?)
            });
        }
        let mut accepted = Vec::with_capacity(3);
        while let Some(response) = pending.next().await {
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(error = %error, "guardian sign response rejected");
                    continue;
                }
            };
            let signature = match verify_response(&request, policy, message, &response) {
                Ok(signature) => signature,
                Err(error) => {
                    tracing::warn!(member = response.member_index, error = %error, "guardian sign response failed local verification");
                    continue;
                }
            };
            accepted.push((response.member_index, signature));
            if let Some(signatures) = select_signatures(&mut accepted, policy, sighash) { return Ok(signatures); }
        }
        Err(protocol::GuardianSignError::EvidenceUnavailable.into())
    }
}

fn select_signatures(accepted: &mut [(u8, PsyCompressedSecp256K1Signature)], policy: &MultisigPolicy, sighash: QHashOut<GoldilocksField>) -> Option<MultisigSignatures> {
    accepted.sort_by_key(|member| member.0);
    for first in 0..accepted.len() {
        for second in first + 1..accepted.len() {
            let signatures = MultisigSignatures {
                member_indices: vec![accepted[first].0, accepted[second].0],
                signatures: vec![accepted[first].1, accepted[second].1],
            };
            if validate_policy_signatures(&signatures, policy, sighash).is_ok() { return Some(signatures); }
        }
    }
    None
}

fn verify_response(request: &GuardianSignRequest, policy: &MultisigPolicy, message: Hash256, response: &GuardianSignResponse) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
    ensure!(response.request_id == request.request_id()? && response.network_magic == request.network_magic && response.user_id == request.user_id && response.session_nonce == request.session_nonce, "guardian response context mismatch");
    ensure!(response.policy_commitment == policy.commitment()? && response.member_index < 3 && response.message.0 == message.0, "guardian response policy/message mismatch");
    Ok(PsyCompressedSecp256K1Signature { public_key: response.public_key.0, signature: response.signature.0, message })
}

pub(crate) struct RelayerArchive { path: PathBuf }

impl RelayerArchive {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(path)?;
        Ok(Self { path: path.to_owned() })
    }

    pub fn lock(&self) -> anyhow::Result<File> {
        let lock = OpenOptions::new().read(true).write(true).create(true).open(self.path.join("account.lock"))?;
        lock.try_lock().context("another relayer owns the account session")?;
        Ok(lock)
    }

    pub fn save_request(&self, request: &JsonText<GuardianSignRequest>) -> anyhow::Result<()> {
        let parsed = request.decode()?;
        parsed.validate()?;
        if let Some(pending) = self.pending_request()? {
            ensure!(pending.as_str() == request.as_str(), "another immutable guardian request is inflight");
            save_immutable(&self.path.join("pending.json"), request.as_str().as_bytes())?;
            return Ok(());
        }
        let directory = self.path.join(parsed.session_nonce.to_string());
        fs::create_dir_all(&directory)?;
        save_immutable(&directory.join("request.json"), request.as_str().as_bytes())?;
        save_immutable(&self.path.join("pending.json"), request.as_str().as_bytes())
    }

    pub fn load_session(&self, nonce: u64, request_id: protocol::Hex32) -> anyhow::Result<(JsonText<GuardianSignRequest>, Option<GuardianSessionRecord>)> {
        let directory = self.path.join(nonce.to_string());
        let bytes = match fs::read_to_string(directory.join("request.json")) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                for name in ["included.json", "endcap.bin", "signatures.json"] {
                    match fs::symlink_metadata(directory.join(name)) {
                        Ok(_) => anyhow::bail!("guardian request missing with retained session evidence"),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error).context("reading archived guardian evidence metadata"),
                    }
                }
                return Err(error).context("guardian request not yet archived");
            }
            Err(error) => return Err(error).context("reading archived guardian request"),
        };
        let request_json = JsonText::<GuardianSignRequest>::parse(bytes)?;
        let request = request_json.decode()?;
        ensure!(request.session_nonce == nonce, "archived guardian request nonce mismatch");
        ensure!(request.request_id()? == request_id, "archived guardian request identity mismatch");
        let record = match fs::read(directory.join("included.json")) {
            Ok(bytes) => {
                let record: GuardianSessionRecord = protocol::parse_canonical_json(&bytes)?;
                ensure!(record.request_json.as_str() == request_json.as_str(), "included request differs from archived guardian request");
                Some(record)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("reading archived guardian inclusion"),
        };
        Ok((request_json, record))
    }

    pub fn pending_request(&self) -> anyhow::Result<Option<JsonText<GuardianSignRequest>>> {
        match fs::read_to_string(self.path.join("pending.json")) {
            Ok(bytes) => Ok(Some(JsonText::parse(bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut pending = None;
                for entry in fs::read_dir(&self.path)? {
                    let entry = entry?;
                    if entry.file_name().to_str().and_then(|name| name.parse::<u64>().ok()).is_none() || entry.path().join("included.json").exists() { continue; }
                    let request = entry.path().join("request.json");
                    if request.exists() {
                        ensure!(pending.is_none(), "multiple unresolved account requests in archive");
                        pending = Some(JsonText::parse(fs::read_to_string(request)?)?);
                    }
                }
                Ok(pending)
            },
            Err(error) => Err(error.into()),
        }
    }

    pub fn save_signatures(&self, nonce: u64, signatures: &MultisigSignatures) -> anyhow::Result<()> {
        ensure!(signatures.member_indices.len() == 2 && signatures.signatures.len() == 2 && signatures.member_indices[0] < signatures.member_indices[1] && signatures.member_indices[1] < 3, "exactly two sorted signatures required");
        save_immutable(&self.path.join(nonce.to_string()).join("signatures.json"), &serde_json::to_vec(signatures)?)
    }

    pub fn signatures(&self, nonce: u64) -> anyhow::Result<Option<MultisigSignatures>> {
        read_optional(&self.path.join(nonce.to_string()).join("signatures.json"))
    }

    pub fn save_proof(&self, nonce: u64, proof: &[u8], max_bytes: u32) -> anyhow::Result<()> {
        ensure!(!proof.is_empty() && proof.len() <= max_bytes as usize, "EndCap exceeds approved proof bound");
        save_immutable(&self.path.join(nonce.to_string()).join("endcap.bin"), proof)
    }

    pub fn proof(&self, nonce: u64) -> anyhow::Result<Option<Vec<u8>>> {
        match fs::read(self.path.join(nonce.to_string()).join("endcap.bin")) {
            Ok(bytes) => Ok(Some(bytes)), Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None), Err(e) => Err(e.into()),
        }
    }

    pub fn save_record(&self, record: &GuardianSessionRecord, authorization: &GuardianAuthorization) -> anyhow::Result<()> {
        let request = record.validate(authorization)?;
        let (archived, _) = self.load_session(request.session_nonce, request.request_id()?)?;
        ensure!(archived.as_str() == record.request_json.as_str(), "included request differs from archived request");
        // Repairing an older receipt must not consume another request's marker.
        let remove_pending = match fs::read_to_string(self.path.join("pending.json")) {
            Ok(bytes) => JsonText::<GuardianSignRequest>::parse(bytes)?.as_str() == record.request_json.as_str(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        save_immutable(&self.path.join(request.session_nonce.to_string()).join("included.json"), &serde_json::to_vec(record)?)?;
        if remove_pending { self.remove_pending_marker()?; }
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }

    fn remove_pending_marker(&self) -> anyhow::Result<()> {
        match fs::remove_file(self.path.join("pending.json")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("removing pending guardian request"),
        }
    }

    pub fn sessions(&self, after_nonce: u64, limit: u8) -> anyhow::Result<GuardianSessionsResponse> {
        ensure!((1..=64).contains(&limit), "history limit must be 1..64");
        let nonce = after_nonce.checked_add(1).context("history nonce overflow")?;
        let path = self.path.join(nonce.to_string()).join("included.json");
        let mut response = GuardianSessionsResponse { sessions: Vec::new(), next_after_nonce: after_nonce, has_more: false };
        match fs::read(path) {
            Ok(bytes) => {
                response.sessions.push(protocol::parse_canonical_json(&bytes)?);
                response.next_after_nonce = nonce;
                response.has_more = nonce.checked_add(1).is_some_and(|next| self.path.join(next.to_string()).join("included.json").is_file());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        response.validate_page(after_nonce, limit)?;
        Ok(response)
    }
}

fn read_optional<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)), Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None), Err(e) => Err(e.into()),
    }
}

fn save_immutable(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if path.exists() {
        ensure!(fs::read(path)? == bytes, "immutable relayer archive conflict");
        return Ok(());
    }
    let staged = path.with_extension("staged");
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::hard_link(&staged, path)?;
    File::open(path.parent().context("archive parent missing")?)?.sync_all()?;
    fs::remove_file(staged)?;
    Ok(())
}

pub(crate) async fn prove_pending_request(
    wallet: &mut psy_prover::session::WalletSession,
    client: &GuardianClient,
    archive: &RelayerArchive,
    authorization: &GuardianAuthorization,
    request_json: &JsonText<GuardianSignRequest>,
) -> anyhow::Result<Vec<u8>> {
    use psy_prover::trace::{TraceStep, TraceSignCircuitSource};
    use psy_vm::ups::multisig::MultisigSignatureWitness;
    let request = request_json.decode()?;
    request.validate_authorization(authorization)?;
    let trace = request.decode_trace()?;
    protocol::validate_future_endcap_proof_size(request_json, &trace.finalization.submit_end_cap_input, authorization.max_endcap_proof_bytes)?;
    let witness = match trace.steps.last() {
        Some(TraceStep::ZkSign(step)) if matches!(step.sign_circuit_source, TraceSignCircuitSource::Multisig) => serde_json::from_slice::<MultisigSignatureWitness>(&step.sign_witness)?,
        _ => anyhow::bail!("guardian request is not a multisig trace"),
    };
    let (policy, _) = witness.policies()?;
    archive.save_request(request_json)?;
    let signatures = match archive.signatures(request.session_nonce)? {
        Some(signatures) => signatures,
        None => {
            let signatures = client.collect(request_json, &policy, trace.finalization.sig_hash).await?;
            archive.save_signatures(request.session_nonce, &signatures)?;
            signatures
        }
    };
    validate_policy_signatures(&signatures, &policy, trace.finalization.sig_hash)?;
    wallet.inject_multisig_signatures(trace.meta.public_key, signatures).await?;
    if let Some(proof) = archive.proof(request.session_nonce)? {
        ensure!(!proof.is_empty() && proof.len() <= authorization.max_endcap_proof_bytes as usize, "saved proof exceeds approved bound");
        return Ok(proof);
    }
    let schedule = wallet.prepare_trace_proof_schedule(&trace).await?;
    let mut outputs = vec![wallet.prove_ups_start_job(trace.meta.public_key, &trace).await?];
    for seed in &schedule.seeds {
        outputs.push(wallet.prove_cfc_job_with_seed(trace.meta.public_key, &trace, seed).await?);
    }
    outputs.push(wallet.prove_zksign_job(trace.meta.public_key, &trace).await?);
    let output = wallet.prove_endcap_job_from_outputs(trace.meta.public_key, &trace, &schedule, outputs).await?;
    let proof = match output {
        psy_prover::session::TraceProofJobOutput::EndCap { proof, .. } => proof,
        _ => anyhow::bail!("EndCap proving returned another proof kind"),
    };
    archive.save_proof(request.session_nonce, &proof, authorization.max_endcap_proof_bytes)?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_session_lookup_distinguishes_absence_from_orphaned_evidence() {
        let (path, archive) = archive();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let request_id = request.request_id().unwrap();
        let error = archive.load_session(request.session_nonce, request_id).unwrap_err();
        assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::NotFound);
        let directory = path.join(request.session_nonce.to_string());
        fs::create_dir(&directory).unwrap();
        for name in ["included.json", "endcap.bin", "signatures.json"] {
            fs::write(directory.join(name), b"interrupted archive").unwrap();
            let error = archive.load_session(request.session_nonce, request_id).unwrap_err();
            assert!(error.downcast_ref::<std::io::Error>().is_none());
            fs::remove_file(directory.join(name)).unwrap();
        }
        fs::write(directory.join("request.json"), b"malformed request").unwrap();
        let error = archive.load_session(request.session_nonce, request_id).unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_none());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn exact_session_lookup_ignores_pending_and_rejects_identity_or_inclusion_corruption() {
        let (path, archive) = archive();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let request_id = request.request_id().unwrap();
        let original = JsonText::from_value(&request).unwrap();
        archive.save_request(&original).unwrap();
        fs::remove_file(path.join("pending.json")).unwrap();
        let (loaded, record) = archive.load_session(request.session_nonce, request_id).unwrap();
        assert_eq!(loaded.as_str(), original.as_str());
        assert!(record.is_none());
        fs::write(path.join("pending.json"), b"unrelated pending corruption").unwrap();
        assert_eq!(archive.load_session(request.session_nonce, request_id).unwrap().0.as_str(), original.as_str());
        let mut changed_id = request_id;
        changed_id.0[0] ^= 1;
        assert!(archive.load_session(request.session_nonce, changed_id).is_err());
        let other_nonce = request.session_nonce.checked_add(1).unwrap();
        fs::create_dir(path.join(other_nonce.to_string())).unwrap();
        fs::write(path.join(other_nonce.to_string()).join("request.json"), original.as_str()).unwrap();
        assert!(archive.load_session(other_nonce, request_id).is_err());
        fs::write(path.join(request.session_nonce.to_string()).join("included.json"), b"malformed inclusion").unwrap();
        let error = archive.load_session(request.session_nonce, request_id).unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_none());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn structurally_valid_request_archive_recovers_without_releasing_nonce() {
        let (path, archive) = archive();
        let lock = archive.lock().unwrap();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        let original = JsonText::from_value(&request).unwrap();
        archive.save_request(&original).unwrap();
        let mut changed = request.clone();
        changed.authorization_version += 1;
        assert!(archive.save_request(&JsonText::from_value(&changed).unwrap()).is_err());
        fs::remove_file(path.join("pending.json")).unwrap();
        assert_eq!(archive.pending_request().unwrap().unwrap().as_str(), original.as_str());
        archive.save_request(&original).unwrap();
        let signatures = MultisigSignatures { member_indices: vec![0, 2], signatures: vec![PsyCompressedSecp256K1Signature { public_key: [2; 33], signature: [1; 64], message: Hash256([0; 32]) }; 2] };
        archive.save_signatures(request.session_nonce, &signatures).unwrap();
        archive.save_proof(request.session_nonce, b"retention-only-proof-bytes", 100).unwrap();
        drop(lock);
        let reopened = RelayerArchive::open(&path).unwrap();
        let lock = reopened.lock().unwrap();
        assert_eq!(reopened.pending_request().unwrap().unwrap().as_str(), original.as_str());
        assert_eq!(reopened.signatures(request.session_nonce).unwrap().unwrap().member_indices, vec![0, 2]);
        assert_eq!(reopened.proof(request.session_nonce).unwrap().unwrap(), b"retention-only-proof-bytes");
        assert!(reopened.save_proof(request.session_nonce, b"different", 100).is_err());
        assert!(reopened.pending_request().unwrap().is_some());
        drop(lock);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn collector_requires_two_distinct_authorized_signatures_on_same_message() {
        use plonky2::hash::poseidon::PoseidonPermutation;
        use psy_client_common::data::secp256k1::CompressedPublicKey;
        use psy_crypto::signature::secp256k1::wallet::{hash_no_pad_compressed_public_key, secp256k1_sign};
        let sighash = QHashOut::from_values(1, 2, 3, 4);
        let members: Vec<_> = (1u8..=3).map(|byte| {
            let signature = secp256k1_sign(k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap(), sighash).unwrap();
            let hash = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(CompressedPublicKey(signature.public_key));
            (hash, signature)
        }).collect();
        let mut policy = MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes: [QHashOut::ZERO; 8] };
        for (index, member) in members.iter().enumerate() { policy.member_hashes[index] = member.0; }
        assert!(select_signatures(&mut [(0, members[0].1)], &policy, sighash).is_none());
        assert!(select_signatures(&mut [(0, members[0].1), (0, members[0].1)], &policy, sighash).is_none());
        assert!(select_signatures(&mut [(0, members[0].1), (1, members[2].1)], &policy, sighash).is_none());
        assert!(select_signatures(&mut [(0, members[0].1), (2, members[2].1)], &policy, QHashOut::from_values(4, 3, 2, 1)).is_none());
        let mut invalid = members[0].1;
        invalid.signature = [0; 64];
        let accepted = select_signatures(&mut [(0, invalid), (2, members[2].1), (0, members[0].1)], &policy, sighash).unwrap();
        assert_eq!(accepted.member_indices, vec![0, 2]);
        validate_policy_signatures(&accepted, &policy, sighash).unwrap();
    }

    fn archive() -> (PathBuf, RelayerArchive) {
        let path = std::env::temp_dir().join(format!("guardian-archive-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let archive = RelayerArchive::open(&path).unwrap();
        (path, archive)
    }

    #[test]
    fn immutable_archive_rejects_replacement_and_survives_reopen() {
        let (path, archive) = archive();
        let lock = archive.lock().unwrap();
        assert!(RelayerArchive::open(&path).unwrap().lock().is_err());
        let target = path.join("retained.bin");
        save_immutable(&target, b"first").unwrap();
        save_immutable(&target, b"first").unwrap();
        assert!(save_immutable(&target, b"second").is_err());
        drop(lock);
        let reopened = RelayerArchive::open(&path).unwrap();
        let lock = reopened.lock().unwrap();
        assert_eq!(fs::read(target).unwrap(), b"first");
        drop(lock);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn staged_write_interruption_does_not_replace_retained_bytes() {
        let (path, archive) = archive();
        let lock = archive.lock().unwrap();
        let target = path.join("proof.bin");
        fs::write(target.with_extension("staged"), b"partial").unwrap();
        save_immutable(&target, b"complete").unwrap();
        assert_eq!(fs::read(target).unwrap(), b"complete");
        assert!(archive.sessions(7, 0).is_err());
        let page = archive.sessions(7, 1).unwrap();
        assert_eq!(page.next_after_nonce, 7);
        assert!(!page.has_more);
        drop(lock);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn missing_prefix_is_not_skipped_and_corrupt_pending_is_not_released() {
        let (path, archive) = archive();
        let lock = archive.lock().unwrap();
        fs::create_dir(path.join("2")).unwrap();
        fs::write(path.join("2/included.json"), b"not a canonical record").unwrap();
        let first = archive.sessions(0, 64).unwrap();
        assert!(first.sessions.is_empty());
        assert_eq!(first.next_after_nonce, 0);
        assert!(archive.sessions(1, 1).is_err());
        fs::write(path.join("pending.json"), b"corrupt request").unwrap();
        assert!(archive.pending_request().is_err());
        assert_eq!(fs::read(path.join("pending.json")).unwrap(), b"corrupt request");
        drop(lock);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn lost_receipt_save_tolerates_absent_pending_marker_only() {
        let (path, archive) = archive();
        let lock = archive.lock().unwrap();
        let request = crate::guardian::test_fixture::codec_request_fixture();
        archive.save_request(&JsonText::from_value(&request).unwrap()).unwrap();
        let pending = path.join("pending.json");
        fs::remove_file(&pending).unwrap();
        let record = GuardianSessionRecord {
            request_json: JsonText::from_value(&request).unwrap(),
            signatures_json: JsonText::from_value(&MultisigSignatures { member_indices: vec![0, 2], signatures: vec![PsyCompressedSecp256K1Signature { public_key: [2; 33], signature: [1; 64], message: Hash256([0; 32]) }; 2] }).unwrap(),
            endcap_input_json: JsonText::from_value(&psy_client_data::guta::end_cap_input::SubmitUserEndCapNonProofInput::<GoldilocksField>::default()).unwrap(),
            endcap_proof_hex: "0x00".to_owned(), included_checkpoint_id: 1, included_checkpoint_hash: QHashOut::from_values(1, 2, 3, 4),
        };
        let authorization = GuardianAuthorization {
            version: request.authorization_version, network_magic: request.network_magic, genesis_hash: request.genesis_hash, user_id: request.user_id,
            account_json: JsonText::from_value(&psy_vm::ups::multisig::MultisigAccount { contract_id: psy_vm::ups::multisig::MULTISIG_POLICY_CONTRACT_ID, initial_policy: MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes: [QHashOut::from_values(1, 2, 3, 4); 8] } }).unwrap(), account_public_key: QHashOut::ZERO, multisig_fingerprint: QHashOut::ZERO,
            deposit_contract_id: 2, withdrawal_contract_id: 3, fee_contract_id: 0, guta_fee: 0, da_fee: 0, max_fee: 0, max_endcap_proof_bytes: 1, endcap_verifier_fingerprint: QHashOut::from_values(1, 2, 3, 4), chains: vec![], approved_contracts: vec![], approved_withdrawal_params: None, approved_next_members: None,
        };
        archive.save_record(&record, &authorization).unwrap();
        let saved = fs::read(path.join("1/included.json")).unwrap();
        fs::remove_file(path.join("1/included.json")).unwrap();
        archive.save_record(&record, &authorization).unwrap();
        assert_eq!(fs::read(path.join("1/included.json")).unwrap(), saved);
        archive.save_record(&record, &authorization).unwrap();
        assert!(!pending.exists());
        archive.remove_pending_marker().unwrap();
        fs::create_dir(&pending).unwrap();
        assert!(archive.remove_pending_marker().is_err());
        assert!(pending.is_dir());
        drop(lock);
        fs::remove_dir_all(path).unwrap();
    }
}
