use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use psy_client_common::args::DPNSoftwareDefinedCallData;
use psy_client_data::{config::store_config::PsyHasher, qstore::controllers::proving_session::PsyReadLocalProvingSessionStore};
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::QSubmitEndCapRPCRequest,
};
use psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager;

use super::*;
use crate::wide_private as w;
async fn slot(p: &RpcProvider, cp: u64, user: u64, cid: u64, offset: u64) -> Result<u64> {
    let h = p.get_user_contract_state_tree_leaf_hash(cp, user, cid as u32, 32, offset / 4).await?;
    Ok(h.0.elements[(offset % 4) as usize].to_canonical_u64())
}

async fn checkpoint_root(p:&RpcProvider,checkpoint:u64,expected:[u64;4])->Result<()> {
    // This exact metadata RPC fails for an unavailable checkpoint. Tree lookups
    // may fall back to an earlier root and must not cause terminal rejection.
    let roots=p.get_checkpoint_global_state_roots(checkpoint).await?;
    anyhow::ensure!(w::words(roots.user_tree_root)==expected,"invalid-native-ft-checkpoint: user root differs from chain");
    Ok(())
}

#[cfg(test)]
mod adapter_tests {
    use super::*;
    #[test]
    fn status_lock_subprocess_probe() {
        if let Some(directory) = std::env::var_os("PSY_STATUS_LOCK_TEST_DIRECTORY") {
            assert!(w::operation_lock_in(Path::new(&directory), 7).is_err(), "status must exclude another process's recovery");
        }
    }

    #[tokio::test]
    async fn status_holds_wallet_lock_across_rpc_and_preserves_recovered_delivery() -> Result<()> {
        use std::sync::Arc;
        use tokio::sync::Notify;
        let tmp = tempfile::tempdir()?;
        let id = "a".repeat(64);
        let path = tmp.path().join(format!("out-{id}.json"));
        w::save(&path, &serde_json::json!({"sender":7,"status":"broadcast_intent","end_leaf":"b".repeat(64),"checkpoint_before":1,"delivery":null}), true)?;
        let started = Arc::new(Notify::new()); let release = Arc::new(Notify::new());
        let task = tokio::spawn({ let dir=tmp.path().to_owned(); let id=id.clone(); let started=started.clone(); let release=release.clone(); async move {
            status_record(&dir,&id,"out",7,|_,_| async move {started.notify_one();release.notified().await;Ok(2)}).await
        }});
        started.notified().await;
        assert!(w::operation_lock_in(tmp.path(),7).is_err());
        let child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact","wallet::wide_private::adapter_tests::status_lock_subprocess_probe","--nocapture"])
            .env("PSY_STATUS_LOCK_TEST_DIRECTORY",tmp.path()).output()?;
        anyhow::ensure!(child.status.success() && String::from_utf8_lossy(&child.stdout).contains("1 passed"), "cross-process status lock check did not execute successfully: {}", String::from_utf8_lossy(&child.stderr));
        release.notify_one(); task.await??;
        // Recovery runs after the status writer releases its lock. A later
        // status query must neither regress ready nor regenerate ciphertext.
        let delivery = serde_json::json!({"ciphertexts":["immutable-ciphertext"],"ephemeral_pubkey":"c".repeat(64)});
        { let _recovery = w::operation_lock_in(tmp.path(),7)?;
          let mut value: serde_json::Value=w::read(&path)?;
          value["status"]="ready".into();value["delivery"]=delivery.clone();w::save(&path,&value,false)?; }
        let status=status_record(tmp.path(),&id,"out",7,|_,_| async {anyhow::bail!("ready must not reconfirm")}).await?;
        assert_eq!(status["status"],"ready");
        let final_record:serde_json::Value=w::read(&path)?;assert_eq!(final_record["delivery"],delivery);
        Ok(())
    }

    #[tokio::test]
    async fn checkpoint_lag_is_retryable_and_observed_mismatch_is_terminal()->Result<()> {
        use tokio::{net::TcpListener,io::{AsyncReadExt,AsyncWriteExt}};
        let listener=TcpListener::bind("127.0.0.1:0").await?;let base=format!("http://{}",listener.local_addr()?);
        let provider=RpcProvider{client:std::sync::Arc::new(reqwest::Client::new()),realm_configs:Default::default(),coordinator_configs:std::collections::HashMap::from([(0,vec![base])]),users_per_realm:1024,current_user_id:0};
        let task=tokio::spawn(async move {
            for index in 0..3 {
                let (mut stream,_)=listener.accept().await.unwrap();let mut buffer=vec![0;8192];let mut n=0;
                loop {let read=stream.read(&mut buffer[n..]).await.unwrap();assert!(read>0);n+=read;if let Some(end)=buffer[..n].windows(4).position(|w|w==b"\r\n\r\n") {let headers=String::from_utf8_lossy(&buffer[..end]);let len:usize=headers.lines().find_map(|l|l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v|v.trim().parse().ok())).unwrap();if n>=end+4+len{break;}}}
                let raw=String::from_utf8_lossy(&buffer[..n]);assert!(raw.contains("psy_get_checkpoint_global_state_roots"));assert!(!raw.contains("psy_get_user_tree_root"));
                let response=if index==0 {serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Checkpoint not yet indexed"}})}else{
                    let root=w::hash(&[2;4]);serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"contract_tree_root":root,"deposit_tree_root":root,"user_tree_root":root,"withdrawal_tree_root":root,"user_registration_tree_root":root}})
                }.to_string();
                let header=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len());stream.write_all(header.as_bytes()).await.unwrap();stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let expected=w::words(w::hash(&[2;4]));
        let lag=checkpoint_root(&provider,77,expected).await.unwrap_err().to_string();assert!(!lag.contains("invalid-native-ft-checkpoint:"));
        checkpoint_root(&provider,77,expected).await?;
        assert!(checkpoint_root(&provider,77,[3;4]).await.unwrap_err().to_string().contains("invalid-native-ft-checkpoint:"));
        task.await?;Ok(())
    }
    #[test]
    fn same_amount_uses_contract_adapter_and_matches_native_abi() {
        let owner = [11, 12, 13, 14];
        let hashes = [[21, 22, 23, 24], [0; 4]];
        let single = transfer_inputs(w::Profile::SingleFeltNativeV1, owner, [123, 0], hashes).unwrap();
        let wide = transfer_inputs(w::Profile::U124PrivateV1, owner, [123, 0], hashes).unwrap();
        let artifact: serde_json::Value = serde_json::from_str(include_str!("../../../token.json")).unwrap();
        let method = |name: &str| {
            artifact["circuit_definitions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["name"] == name)
                .unwrap()["circuit_inputs"]
                .as_array()
                .unwrap()
                .len()
        };
        assert_eq!(single.len(), method("private_transfer"));
        assert_eq!(wide.len(), 14);
        assert_eq!(single, [11, 12, 13, 14, 123, 21, 22, 23, 24]);
        assert_eq!(wide, [11, 12, 13, 14, 123, 0, 21, 22, 23, 24, 0, 0, 0, 0]);
        let mut packet = w::Packet {
            kind: w::Profile::SingleFeltNativeV1.kind().into(),
            contract_id: 0,
            owner,
            amount: [123, 0],
            checkpoint: 77,
            user_tree_root: [31, 32, 33, 34],
            nullifiers: [[41, 42, 43, 44], [0; 4]],
            proofs: [None, None],
        };
        let paths = [(101..166).collect(), vec![0; 65]];
        let single_claim = claim_inputs(w::Profile::SingleFeltNativeV1, &packet, 81, 82, &paths).unwrap();
        assert_eq!(single_claim.len(), method("private_claim"));
        assert_eq!(
            &single_claim[..17],
            &[41, 42, 43, 44, 11, 12, 13, 14, 123, 31, 32, 33, 34, 77, 2147483649, 81, 82]
        );
        assert_eq!(&single_claim[17..], paths[0]);
        assert!(claim_inputs(w::Profile::U124PrivateV1, &packet, 81, 82, &paths).is_err());
        packet.kind = w::Profile::U124PrivateV1.kind().into();
        packet.contract_id = 2457;
        let wide_claim = claim_inputs(w::Profile::U124PrivateV1, &packet, 81, 82, &paths).unwrap();
        assert_eq!(wide_claim.len(), 151);
        assert_eq!(&wide_claim[..13], &[11, 12, 13, 14, 123, 0, 31, 32, 33, 34, 77, 81, 82]);
        assert!(claim_inputs(w::Profile::SingleFeltNativeV1, &packet, 81, 82, &paths).is_err());
    }
    #[test]
    fn native_offsets_match_compiled_artifact_and_public_claim_cannot_wrap() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!("../../../token.json")).unwrap();
        let constants = |name: &str| {
            artifact["circuit_definitions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|x| x["name"] == name)
                .unwrap()["definitions"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|d| d["op_type"] == 1)
                .flat_map(|d| d["inputs"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()))
                .collect::<Vec<_>>()
        };
        let p = w::Profile::SingleFeltNativeV1;
        let transfer = constants("private_transfer");
        assert!(transfer.contains(&p.counts()[0]));
        assert!(transfer.contains(&p.paths()[0]));
        assert!(transfer.contains(&(4 * p.roots()[0])));
        assert!(constants("private_claim").contains(&p.roots()[0]));
        assert_ne!(p.roots(), w::Profile::SingleFeltPsy20V1.roots());
        assert_eq!(single_public_credit(p, 10, 100, 90).unwrap(), 10);
        assert_eq!(single_public_credit(p, p.maximum() - 1, 2, 1).unwrap(), 1);
        assert!(single_public_credit(p, p.maximum() - 1, 3, 1).is_err());
        assert!(single_public_credit(p, 0, 1, 2).is_err());
        assert!(single_public_credit(p, 0, 1, 1).is_err());
        assert!(single_public_credit(p, 0, w::P, 0).is_err());
    }
}
async fn balance(p: &RpcProvider, cp: u64, user: u64, a: &w::Asset) -> Result<u128> {
    let low = slot(p, cp, user, a.contract_id, 0).await?;
    let high = if a.profile.is_wide() {
        slot(p, cp, user, a.contract_id, 1).await?
    } else {
        0
    };
    a.profile.decode([low, high])
}
fn transfer_inputs(profile: w::Profile, owner: [u64; 4], amount: [u64; 2], hashes: [[u64; 4]; 2]) -> Result<Vec<u64>> {
    anyhow::ensure!(profile.decode(amount)? > 0, "zero private amount");
    let mut inputs = owner.to_vec();
    if profile.is_wide() {
        inputs.extend(amount);
        inputs.extend(hashes[0]);
        inputs.extend(hashes[1]);
    } else {
        inputs.push(amount[0]);
        inputs.extend(hashes[0]);
    }
    Ok(inputs)
}
fn claim_inputs(profile: w::Profile, packet: &w::Packet, r0: u64, r1: u64, paths: &[Vec<u64>; 2]) -> Result<Vec<u64>> {
    anyhow::ensure!(
        packet.kind == profile.kind() && profile.decode(packet.amount)? > 0,
        "claim profile mismatch"
    );
    anyhow::ensure!(paths.iter().all(|p| p.len() == 65), "invalid claim proof paths");
    let mut inputs = vec![];
    if profile.is_wide() {
        inputs.extend(packet.owner);
        inputs.extend(packet.amount);
        inputs.extend(packet.user_tree_root);
        inputs.extend([packet.checkpoint, r0, r1]);
        inputs.extend(packet.nullifiers[0]);
        inputs.extend(packet.nullifiers[1]);
        inputs.extend(paths[0].clone());
        inputs.extend(paths[1].clone());
    } else {
        inputs.extend(packet.nullifiers[0]);
        inputs.extend(packet.owner);
        inputs.push(packet.amount[0]);
        inputs.extend(packet.user_tree_root);
        inputs.extend([packet.checkpoint, profile.roots()[0], r0, r1]);
        inputs.extend(paths[0].clone());
    }
    anyhow::ensure!(inputs.len() == if profile.is_wide() { 151 } else { 82 }, "claim encoding mismatch");
    Ok(inputs)
}
fn single_public_credit(profile: w::Profile, current: u128, sent: u64, claimed: u64) -> Result<u128> {
    anyhow::ensure!(!profile.is_wide() && sent < w::P && claimed < w::P, "invalid single-Felt public credit");
    let credit = sent.checked_sub(claimed).context("public credit counters regressed")? as u128;
    anyhow::ensure!(
        credit > 0 && current <= profile.maximum() && credit <= profile.maximum() - current,
        "public claim has no credit or would overflow the contract balance format"
    );
    Ok(credit)
}
async fn pin(p: &RpcProvider, a: &w::Asset) -> Result<()> {
    let c = p.get_contract_leaf_data(a.contract_id).await?;
    let (fields, slots) = a.profile.fields_slots();
    anyhow::ensure!(
        c.code_root.to_string() == a.code_root
            && c.state_layout_root.to_string() == a.layout_root
            && c.state_tree_height.to_canonical_u64() == 32
            && c.state_layout_field_count.to_canonical_u64() == fields
            && c.state_layout_slot_count.to_canonical_u64() == slots,
        "private FT chain profile differs from owner-pinned code/layout"
    );
    // Authenticate the fetched method schema against the pinned code root.
    // A width-looking state layout alone is not evidence of a supported ABI.
    let code = p.get_contract_code_definition(a.contract_id).await?;
    anyhow::ensure!(code.state_tree_height == 32, "private FT code tree height mismatch");
    let defs = code
        .functions
        .iter()
        .map(psy_vm::dpn::contract::cfc_code_definition_to_dapen_fc)
        .collect::<Result<Vec<_>>>()?;
    for (f, d) in code.functions.iter().zip(&defs) {
        anyhow::ensure!(
            f.vm_type == 1
                && f.method_id == d.method_id
                && f.num_inputs as usize == d.circuit_inputs.len()
                && f.num_outputs as usize == d.circuit_outputs.len(),
            "private FT method descriptor differs from authenticated code"
        );
    }
    let hashes = defs.iter().map(psy_vm::dpn::contract::hash_dpn_function::<F>).collect::<Vec<_>>();
    let root = psy_client_data::qblock::cmds::deploy_contract::get_code_root_by_code_hashes::<
        F,
        <C as plonky2::plonk::config::GenericConfig<D>>::Hasher,
    >(&hashes, psy_config::network_constants::CONTRACT_FUNCTION_TREE_HEIGHT - 1);
    anyhow::ensure!(root == c.code_root, "private FT method code does not authenticate to pinned code root");
    for (name, size) in [
        ("private_transfer", if a.profile.is_wide() { 14 } else { 9 }),
        ("private_claim", if a.profile.is_wide() { 151 } else { 82 }),
        (a.profile.public_claim_method(), 1),
    ] {
        let matches = defs.iter().filter(|d| d.name == name).collect::<Vec<_>>();
        anyhow::ensure!(
            matches.len() == 1 && matches[0].circuit_inputs.len() == size && matches[0].circuit_outputs.is_empty(),
            "private FT profile method signature mismatch: {name}"
        );
    }
    Ok(())
}
fn circuit() -> Result<PrivateNoteInclusionCircuit<C, D>> {
    let c = PrivateNoteInclusionCircuit::<C, D>::new(32, 24, 32, 20);
    anyhow::ensure!(w::words(c.get_fingerprint()) == w::FP, "native note verifier changed");
    Ok(c)
}
fn packet_proofs(profile: w::Profile, packet: &w::Packet) -> Result<Vec<(usize, ProofWithPublicInputs<F, C, D>)>> {
    anyhow::ensure!(
        packet.kind == profile.kind() && packet.contract_id < (1<<24) && ((profile==w::Profile::SingleFeltNativeV1)==matches!(packet.contract_id,0|4)) && packet.checkpoint > 0 && packet.checkpoint < w::P,
        "invalid private packet"
    );
    w::canonical(&packet.owner)?;
    w::canonical(&packet.user_tree_root)?;
    let amount = profile.decode(packet.amount)?;
    anyhow::ensure!(amount > 0, "zero private packet");
    let c = circuit()?;
    let mut out = vec![];
    for i in 0..2 {
        w::canonical(&packet.nullifiers[i])?;
        if packet.amount[i] == 0 {
            anyhow::ensure!(
                packet.nullifiers[i] == [0; 4] && packet.proofs[i].is_none(),
                "zero denomination has proof/nullifier"
            );
            continue;
        }
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            packet.proofs[i].as_deref().context("missing denomination proof")?,
        )?;
        anyhow::ensure!(bytes.len() <= 1024 * 1024, "note proof too large");
        use bincode::Options;
        let proof: ProofWithPublicInputs<F, C, D> = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(1024 * 1024)
            .reject_trailing_bytes()
            .deserialize(&bytes)?;
        let mut inputs = packet.owner.to_vec();
        inputs.push(packet.amount[i]);
        inputs.extend(packet.user_tree_root);
        inputs.extend([packet.checkpoint, profile.roots()[i], packet.contract_id]);
        inputs.extend(packet.nullifiers[i]);
        anyhow::ensure!(
            proof.public_inputs == w::hash(&inputs).0.elements,
            "private proof amount/slot/contract/checkpoint binding mismatch"
        );
        plonky2::plonk::circuit_data::VerifierCircuitData {
            verifier_only: c.get_verifier_config_ref().clone(),
            common: c.get_common_circuit_data_ref().clone(),
        }
        .verify(proof.clone())?;
        out.push((i, proof));
    }
    anyhow::ensure!(
        packet.amount.contains(&0) || packet.nullifiers[0] != packet.nullifiers[1],
        "duplicate denomination nullifier"
    );
    Ok(out)
}
/// Journal the exact signed identity BEFORE a single broadcast. Never retry a
/// submit.
async fn sign_submit(
    state: &mut NetworkWallet,
    user: &LoadedUser,
    path: &Path,
    broadcast: &AtomicBool,
    mut stamp: impl FnMut(&str, u64, u64) -> Result<()>,
) -> Result<(String, u64)> {
    let mgr = state.session.user_session_mgrs.get(&user.pk_hash).context("private FT session")?;
    let burn = &mgr.require_lps()?.last_transaction_record().call_data.call_data;
    anyhow::ensure!(
        burn.contract_id == F::ZERO
            && burn.method_id == F::from_canonical_u64(2923993647)
            && burn.inputs.len() == 1
            && burn.inputs[0].to_canonical_u64() <= 1_001_000_000,
        "unexpected private FT fee shape/cap"
    );
    drop(mgr);
    let (ec, proof) = state.session.sign(user.pk_hash, DPNSoftwareDefinedCallData::default()).await?;
    let verifier = PsyUPSStepCircuitManager::<C, D>::new_with_config(psy_config::PSY_NETWORK_MAGIC);
    verifier.ups_end_cap.verify_proof(proof.clone())?;
    let hash = ec.core.state_transition.end_user_leaf_hash.to_string();
    let nonce = ec.core.new_user_leaf.nonce.to_canonical_u64();
    let p = state.session.st_provider.with_user_id_owned(user.user_id);
    let cp = p.get_latest_block_state().await?.checkpoint_id;
    let latest = p.get_user_leaf_data(cp, user.user_id).await?;
    anyhow::ensure!(
        ec.core.state_transition.start_user_leaf_hash == QHashOut::ZERO
            || latest.qfhash::<PsyHasher>() == ec.core.state_transition.start_user_leaf_hash,
        "stale private FT signing anchor"
    );
    anyhow::ensure!(
        matches!(p.get_tx_status(user.user_id, nonce).await?, psy_provider::session::TxStatus::Submittable),
        "private FT nonce not submittable"
    );
    let checkpoint_before = state
        .session
        .user_session_mgrs
        .get(&user.pk_hash)
        .context("signing session")?
        .require_lps()?
        .get_current_start_checkpoint_id_u64();
    stamp(&hash, nonce, checkpoint_before)?;
    let _ = path;
    broadcast.store(true, Ordering::SeqCst);
    p.submit_end_cap_proof::<F>(QSubmitEndCapRPCRequest {
        user_ec_input: ec,
        proof: bincode::serialize(&proof)?,
    })
    .await?;
    let confirmed = confirm(&p, user.user_id, &hash, checkpoint_before).await?;
    Ok((hash, confirmed))
}
async fn confirm(p: &RpcProvider, user: u64, hash: &str, checkpoint_before: u64) -> Result<u64> {
    anyhow::ensure!(checkpoint_before > 0, "missing pre-submit checkpoint: do not retry submission");
    p.wait_for_endcap_inclusion(user, hash.parse()?, checkpoint_before, Some(360), 3).await
}
// Status can promote an intent after awaiting a remote checkpoint. Hold the
// SAME cross-process wallet lock as send/recover across read, await and save;
// otherwise a stale snapshot can overwrite newly generated delivery secrets.
async fn status_record<F, Fut>(directory: &Path, id: &str, prefix: &str, user: u64, confirm: F) -> Result<serde_json::Value>
where F: FnOnce(String, u64) -> Fut, Fut: std::future::Future<Output = Result<u64>> {
    let _guard = w::operation_lock_in(directory, user)?;
    let path = directory.join(format!("{prefix}-{id}.json"));
    let mut value: serde_json::Value = w::read(&path)?;
    let owner = if prefix == "out" { value["sender"].as_u64() } else { value["user_id"].as_u64() };
    anyhow::ensure!(owner == Some(user), "record belongs to another wallet");
    if value["status"] == "broadcast_intent" {
        let hash = value["end_leaf"].as_str().context("pending hash")?.to_owned();
        let before = value["checkpoint_before"].as_u64().context("pending pre-submit checkpoint")?;
        let cp = confirm(hash, before).await?;
        value["status"] = serde_json::json!("included");
        value["checkpoint"] = serde_json::json!(cp);
        w::save(&path, &value, false)?;
    }
    Ok(serde_json::json!({"recordId":id,"status":value["status"],"endUserLeafHash":value["end_leaf"],"checkpointId":value["checkpoint"],"resubmitted":false}))
}

impl WalletManager {
    pub async fn wide_status(&self, network: &NetworkId, id: &str, direction: &str) -> Result<serde_json::Value> {
        w::validate_id(id)?;
        let prefix = match direction {
            "outgoing" => "out", "incoming" => "in", "public" => "public",
            _ => anyhow::bail!("invalid record direction"),
        };
        let state = self.state(network).await?;
        let user = state.require_user()?.user_id;
        let p = state.session.st_provider.with_user_id_owned(user);
        status_record(&w::directory(network.as_str())?, id, prefix, user, |hash, before| async move {
            confirm(&p, user, &hash, before).await
        }).await
    }
    pub async fn wide_balance(&self, network: &NetworkId, a: &w::Asset) -> Result<String> {
        let state = self.state(network).await?;
        let u = state.require_user()?;
        let p = state.session.st_provider.with_user_id_owned(u.user_id);
        pin(&p, a).await?;
        let cp = p.get_latest_block_state().await?.checkpoint_id;
        Ok(balance(&p, cp, u.user_id, a).await?.to_string())
    }
    pub async fn wide_send(
        &self,
        network: &NetworkId,
        expected: u64,
        a: &w::Asset,
        contact: &w::Contact,
        n: u128,
        id: &str,
        broadcast: &AtomicBool,
    ) -> Result<serde_json::Value> {
        let guard = w::operation_lock(network.as_str(), expected)?;
        let mut state = self.state(network).await?;
        let u = state.require_user_id(expected)?;
        anyhow::ensure!(u.sign_type != "sd-key", "wide FT entry requires an ordinary held-key wallet");
        let p = state.session.st_provider.with_user_id_owned(u.user_id);
        pin(&p, a).await?;
        let cp = p.get_latest_block_state().await?.checkpoint_id;
        let baseline_leaf = p.get_user_leaf_data(cp, u.user_id).await?;
        let current_balance = balance(&p, cp, u.user_id, a).await?;
        anyhow::ensure!(n <= current_balance, "insufficient private FT spendable balance");
        if a.contract_id == 0 {
            anyhow::ensure!(n + 1_001_000_000 < current_balance, "insufficient Native PSY principal plus fee headroom");
        }
        anyhow::ensure!(
            slot(&p, cp, u.user_id, 0, 0).await? > 1_001_000_000,
            "insufficient Native PSY fee headroom"
        );
        let value = a.profile.encode(n)?;
        let owner = parse_shield_elements_hex_pub(&contact.shielded_address)?;
        w::canonical(&owner)?;
        let indices = [
            slot(&p, cp, u.user_id, a.contract_id, a.profile.counts()[0]).await?,
            if a.profile.is_wide() {
                slot(&p, cp, u.user_id, a.contract_id, a.profile.counts()[1]).await?
            } else {
                0
            },
        ];
        for i in 0..2 {
            anyhow::ensure!(value[i] == 0 || indices[i] < (1 << 20), "denomination note tree full")
        }
        let mut rec = w::Recovery {
            sender: u.user_id,
            recipient: contact.user_id,
            contract_id: a.contract_id,
            profile: a.profile,
            amount: value,
            owner,
            secrets: [[0; 4]; 2],
            nullifier_secrets: [[0; 4]; 2],
            indices,
            status: "prepared".into(),
            end_leaf: None,
            nonce: None,
            checkpoint_before: None,
            checkpoint: None,
            delivery: None,
        };
        let mut note_hashes = [[0; 4]; 2];
        for i in 0..2 {
            if value[i] == 0 {
                continue;
            }
            rec.secrets[i] = std::array::from_fn(|_| w::sample());
            rec.nullifier_secrets[i] = std::array::from_fn(|_| w::sample());
            note_hashes[i] = w::words(w::hash(&rec.nullifier_secrets[i].into_iter().chain(rec.secrets[i]).collect::<Vec<_>>()));
        }
        let inputs = transfer_inputs(a.profile, owner, value, note_hashes)?;
        let path = w::directory(network.as_str())?.join(format!("out-{id}.json"));
        w::save(&path, &rec, true)?;
        state.session.start_session(u.pk_hash).await?;
        state
            .session
            .prove_contract_call(
                u.pk_hash,
                vec![ContractCallArgs {
                    contract_id: a.contract_id,
                    method_name: "private_transfer".into(),
                    inputs,
                }],
            )
            .await?;
        let before_sign = p.get_user_leaf_data(p.get_latest_block_state().await?.checkpoint_id, u.user_id).await?;
        anyhow::ensure!(
            before_sign == baseline_leaf,
            "wallet changed while preparing private FT note indices; no broadcast"
        );
        let (hash, confirmed) = sign_submit(&mut state, &u, &path, broadcast, |hash, nonce, checkpoint_before| {
            rec.status = "broadcast_intent".into();
            rec.end_leaf = Some(hash.into());
            rec.nonce = Some(nonce);
            rec.checkpoint_before = Some(checkpoint_before);
            w::save(&path, &rec, false)
        })
        .await?;
        rec.status = "included".into();
        rec.checkpoint = Some(confirmed);
        w::save(&path, &rec, false)?;
        drop(state);
        drop(guard);
        self.wide_recover(network, expected, a, contact, id).await.map(|mut v| {
            v["endUserLeafHash"] = serde_json::Value::String(hash);
            v
        })
    }
    pub async fn wide_recover(&self, network: &NetworkId, expected: u64, a: &w::Asset, contact: &w::Contact, id: &str) -> Result<serde_json::Value> {
        let _recovery_lock = w::operation_lock(network.as_str(), expected)?;
        w::validate_id(id)?;
        let mut state = self.state(network).await?;
        let u = state.require_user_id(expected)?;
        let path = w::directory(network.as_str())?.join(format!("out-{id}.json"));
        let mut r: w::Recovery = w::read(&path)?;
        anyhow::ensure!(
            r.sender == u.user_id
                && r.recipient == contact.user_id
                && r.contract_id == a.contract_id
                && r.profile == a.profile
                && r.owner == parse_shield_elements_hex_pub(&contact.shielded_address)?,
            "recovery identity/profile mismatch"
        );
        let p = state.session.st_provider.with_user_id_owned(u.user_id);
        pin(&p, a).await?;
        let hash = r
            .end_leaf
            .as_deref()
            .context("prepared record was never broadcast; no recovery submission is allowed")?;
        let cp = match r.checkpoint {
            Some(cp) => cp,
            None => confirm(&p, u.user_id, hash, r.checkpoint_before.context("missing pre-submit checkpoint")?).await?,
        };
        r.checkpoint = Some(cp);
        r.status = "included".into();
        w::save(&path, &r, false)?;
        if let Some(delivery) = r.delivery.clone() {
            let value = serde_json::json!({"submitted":true,"confirmed":true,"fullUpsVerified":true,"recoveryId":id,"endUserLeafHash":hash,"checkpointId":cp,"delivery":delivery,"amount":a.profile.decode(r.amount)?.to_string()});
            drop(state);
            return self.wide_publish(network, id, contact, &delivery, value).await;
        }
        let user_leaf = p.get_user_leaf_data(cp, u.user_id).await?;
        let contract = p.get_user_contract_tree_merkle_proof(cp, u.user_id, a.contract_id as u32).await?;
        let user = p.get_user_tree_merkle_proof(cp, u.user_id).await?;
        anyhow::ensure!(
            contract.root == user_leaf.user_state_tree_root && user.value == user_leaf.qfhash::<PsyHasher>(),
            "incoherent inclusion checkpoint"
        );
        let c = circuit()?;
        let mut packet = w::Packet {
            kind: a.profile.kind().into(),
            contract_id: a.contract_id,
            owner: r.owner,
            amount: r.amount,
            checkpoint: cp,
            user_tree_root: w::words(user.root),
            nullifiers: [[0; 4]; 2],
            proofs: [None, None],
        };
        for i in 0..2 {
            if r.amount[i] == 0 {
                continue;
            }
            anyhow::ensure!(
                slot(&p, cp, u.user_id, a.contract_id, a.profile.counts()[i]).await? == r.indices[i] + 1,
                "confirmed checkpoint does not contain this denomination append as its last note"
            );
            let nh = w::hash(&r.nullifier_secrets[i].into_iter().chain(r.secrets[i]).collect::<Vec<_>>());
            let commit = w::hh(
                w::hh(
                    QHashOut::from_values(r.owner[0], r.owner[1], r.owner[2], r.owner[3]),
                    QHashOut::from_values(r.amount[i], 0, 0, 0),
                ),
                nh,
            );
            let mut siblings = vec![];
            let mut zero = w::zero();
            for level in 0..20 {
                let sibling = if (r.indices[i] >> level) & 1 == 0 {
                    zero
                } else {
                    let mut words = [0; 4];
                    for j in 0..4 {
                        words[j] = slot(&p, cp, u.user_id, a.contract_id, a.profile.paths()[i] + level * 4 + j as u64).await?;
                    }
                    QHashOut::from_values(words[0], words[1], words[2], words[3])
                };
                siblings.push(sibling);
                zero = w::hh(zero, zero);
            }
            let membership = MerkleProofCore::new_from_params::<PoseidonHasher>(r.indices[i], commit, siblings);
            let root_slot = p
                .get_user_contract_state_tree_merkle_proof(cp, u.user_id, a.contract_id as u32, 32, a.profile.roots()[i])
                .await?;
            anyhow::ensure!(
                membership.root == root_slot.value && root_slot.root == contract.value,
                "denomination membership/state mismatch"
            );
            let input = PrivateNoteInclusionInput {
                nullifier_secret: QHashOut::from_values(
                    r.nullifier_secrets[i][0],
                    r.nullifier_secrets[i][1],
                    r.nullifier_secrets[i][2],
                    r.nullifier_secrets[i][3],
                ),
                sender_user_id: u.user_id,
                contract_id: a.contract_id,
                note_root_slot: a.profile.roots()[i],
                user_leaf: user_leaf.clone(),
                owner: QHashOut::from_values(r.owner[0], r.owner[1], r.owner[2], r.owner[3]),
                amount: F::from_canonical_u64(r.amount[i]),
                note_secret: QHashOut::from_values(r.secrets[i][0], r.secrets[i][1], r.secrets[i][2], r.secrets[i][3]),
                note_membership_proof: membership,
                note_root_slot_proof: root_slot,
                contract_proof: contract.clone(),
                user_tree_proof: user.clone(),
                checkpoint_id: F::from_canonical_u64(cp),
            };
            let proof = c.prove(&input)?;
            plonky2::plonk::circuit_data::VerifierCircuitData {
                verifier_only: c.get_verifier_config_ref().clone(),
                common: c.get_common_circuit_data_ref().clone(),
            }
            .verify(proof.clone())?;
            packet.nullifiers[i] = w::words(w::hash(&r.nullifier_secrets[i]));
            packet.proofs[i] = Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                bincode::serialize(&proof)?,
            ));
        }
        packet_proofs(a.profile, &packet)?;
        let delivery = w::encrypt(contact, &packet)?;
        r.delivery = Some(delivery.clone());
        r.status = "ready".into();
        w::save(&path, &r, false)?;
        let value = serde_json::json!({"submitted":true,"confirmed":true,"fullUpsVerified":true,"recoveryId":id,"endUserLeafHash":r.end_leaf,"checkpointId":cp,"delivery":delivery,"amount":a.profile.decode(r.amount)?.to_string(),"nativeProofsVerified":packet.proofs.iter().filter(|x|x.is_some()).count()});
        drop(state);
        self.wide_publish(network, id, contact, &delivery, value).await
    }
    async fn wide_publish(&self, network: &NetworkId, id: &str, contact: &w::Contact, delivery: &w::Delivery, mut value: serde_json::Value) -> Result<serde_json::Value> {
        value["transport"] = match self.nostr_relay(network) {
            Some(relay) => match crate::private_ft_delivery::publish(network.as_str(), id, &contact.npub, delivery, &relay).await {
                Ok(receipt) => receipt,
                Err(_) => serde_json::json!({"relayDelivered":false,"retry":"private_ft_recover","retryTransferAllowed":false}),
            },
            None => serde_json::json!({"relayDelivered":false,"reason":"network has no configured Nostr relay","retry":"private_ft_recover","retryTransferAllowed":false}),
        };
        Ok(value)
    }
    pub async fn wide_sync(&self, network: &NetworkId, expected: u64, config: &w::Config) -> Result<serde_json::Value> {
        let state = self.state(network).await?;
        let u = state.require_user_id(expected)?;
        anyhow::ensure!(u.sign_type != "sd-key", "ordinary held-key wallet required");
        let (r0, r1, nsec) = derive_receive_secrets(&u.private_key.to_string(), 0)?;
        let expected_owner=w::words(derive_shield_address(u.user_id,r0,r1));
        let keys = nostr::Keys::new(nostr::SecretKey::from_slice(&nsec)?);
        let recipient = keys.public_key().to_hex();
        drop(state);
        let relay = self.nostr_relay(network).context("network has no configured Nostr relay")?;
        let services = self.api_services_url(network);
        let received = crate::private_ft_delivery::receive(network.as_str(), &recipient, &relay, services.as_deref()).await?;
        let mut notes = vec![];
        let mut rejected = 0;
        for (group, delivery) in received.deliveries {
            // Cryptographically invalid candidates are terminal. Missing asset
            // config or transient chain failures remain retryable in the cache.
            let packet=match w::decrypt(&keys.secret_key().to_secret_hex(), &delivery) {
                Ok(packet)=>packet,Err(_)=>{crate::private_ft_delivery::accepted(network.as_str(),&recipient,&group)?;rejected+=1;continue;}
            };
            let profile=if packet.kind==w::Profile::U124PrivateV1.kind(){w::Profile::U124PrivateV1}
                else if matches!(packet.contract_id,0|4){w::Profile::SingleFeltNativeV1}else{w::Profile::SingleFeltPsy20V1};
            if packet.owner!=expected_owner || packet_proofs(profile,&packet).is_err() {
                crate::private_ft_delivery::accepted(network.as_str(),&recipient,&group)?;rejected+=1;continue;
            }
            let result=async {
                let asset=config.asset(network.as_str(),packet.contract_id)?;
                self.wide_accept(network,expected,&asset,&delivery).await
            }.await;
            match result {
                Ok(note)=>{crate::private_ft_delivery::accepted(network.as_str(),&recipient,&group)?;notes.push(note)},
                Err(error)=>{
                    if error.to_string().contains("invalid-native-ft-checkpoint:") {
                        crate::private_ft_delivery::accepted(network.as_str(),&recipient,&group)?;rejected+=1;continue;
                    }
                    // Stable Services storage makes temporary failures retryable
                    // without letting them monopolize the bounded hot cache.
                    if let Some(base)=services.as_deref() {crate::private_ft_delivery::deferred(network.as_str(),&recipient,&group,&delivery,base).await?;}
                    rejected+=1
                }
            }
        }
        Ok(serde_json::json!({"submitted":false,"notes":notes,"rejectedCandidates":rejected,"source":received.source,"historyComplete":received.history_complete,"cacheFull":received.cache_full,"limit":16}))
    }
    pub async fn wide_accept(&self, network: &NetworkId, expected: u64, a: &w::Asset, delivery: &w::Delivery) -> Result<serde_json::Value> {
        let state = self.state(network).await?;
        let u = state.require_user_id(expected)?;
        anyhow::ensure!(u.sign_type != "sd-key", "ordinary held-key wallet required");
        let (r0, r1, nsec) = derive_receive_secrets(&u.private_key.to_string(), 0)?;
        let key = nostr::SecretKey::from_slice(&nsec)?.to_secret_hex();
        let packet = w::decrypt(&key, delivery)?;
        anyhow::ensure!(
            packet.contract_id == a.contract_id && packet.owner == w::words(derive_shield_address(u.user_id, r0, r1)),
            "private packet recipient/asset mismatch"
        );
        pin(&state.session.st_provider, a).await?;
        packet_proofs(a.profile, &packet)?;
        checkpoint_root(&state.session.st_provider,packet.checkpoint,packet.user_tree_root).await?;
        let note_id = hex::encode(Sha256::digest(serde_json::to_vec(&packet)?));
        let path = w::directory(network.as_str())?.join(format!("in-{note_id}.json"));
        let record = w::Inbox {
            user_id: u.user_id,
            contract_id: a.contract_id,
            delivery: delivery.clone(),
            status: "ready".into(),
            end_leaf: None,
            nonce: None,
            checkpoint_before: None,
            checkpoint: None,
        };
        if path.exists() {
            let old: w::Inbox = w::read(&path)?;
            anyhow::ensure!(old.user_id == u.user_id && old.contract_id == a.contract_id, "inbox identity mismatch");
            return Ok(serde_json::json!({"noteId":note_id,"alreadySaved":true,"claimed":old.status=="included"}));
        }
        w::save(&path, &record, true)?;
        Ok(
            serde_json::json!({"noteId":note_id,"amount":a.profile.decode(packet.amount)?.to_string(),"checkpointId":packet.checkpoint,"verified":true,"submitted":false}),
        )
    }
    pub async fn wide_claim(&self, network: &NetworkId, expected: u64, a: &w::Asset, id: &str, broadcast: &AtomicBool) -> Result<serde_json::Value> {
        let _guard = w::operation_lock(network.as_str(), expected)?;
        w::validate_id(id)?;
        let mut state = self.state(network).await?;
        let u = state.require_user_id(expected)?;
        anyhow::ensure!(u.sign_type != "sd-key", "ordinary held-key wallet required");
        let path = w::directory(network.as_str())?.join(format!("in-{id}.json"));
        let mut record: w::Inbox = w::read(&path)?;
        anyhow::ensure!(
            record.user_id == u.user_id && record.contract_id == a.contract_id,
            "inbox recipient/asset mismatch"
        );
        anyhow::ensure!(
            record.status == "ready",
            "note is already claimed or pending: reconcile its transaction identity"
        );
        let p = state.session.st_provider.with_user_id_owned(u.user_id);
        pin(&p, a).await?;
        let (r0, r1, nsec) = derive_receive_secrets(&u.private_key.to_string(), 0)?;
        let packet = w::decrypt(&nostr::SecretKey::from_slice(&nsec)?.to_secret_hex(), &record.delivery)?;
        anyhow::ensure!(
            packet.contract_id == a.contract_id && packet.owner == w::words(derive_shield_address(u.user_id, r0, r1)),
            "claim packet recipient/asset mismatch"
        );
        let proofs = packet_proofs(a.profile, &packet)?;
        checkpoint_root(&p,packet.checkpoint,packet.user_tree_root).await?;
        let cp = p.get_latest_block_state().await?.checkpoint_id;
        let baseline_leaf = p.get_user_leaf_data(cp, u.user_id).await?;
        let current_balance = balance(&p, cp, u.user_id, a).await?;
        anyhow::ensure!(
            a.profile.decode(packet.amount)? <= a.profile.maximum() - current_balance,
            "private claim would overflow the contract balance format"
        );
        state.session.start_session(u.pk_hash).await?;
        let c = circuit()?;
        let mut refs = vec![];
        for (i, proof) in proofs {
            let index = state
                .session
                .add_external_proof(u.pk_hash, c.get_fingerprint(), proof, c.get_verifier_config_ref().clone())
                .await?;
            refs.push((i, index));
        }
        let mut paths = [vec![0; 65], vec![0; 65]];
        for (i, index) in refs {
            let mgr = state.session.user_session_mgrs.get(&u.pk_hash).context("private claim session manager")?;
            let proof = mgr.proof_tree_state.get_leaf_merkle_proof(index).await;
            anyhow::ensure!(
                index < 65536 && proof.siblings.len() == 16 && proof.root == mgr.proof_tree_state.get_proof_tree_root().await,
                "stale session proof path"
            );
            let mut path = vec![];
            for s in proof.siblings {
                path.extend(w::words(s));
            }
            path.push(index);
            paths[i] = path;
        }
        let inputs = claim_inputs(a.profile, &packet, r0, r1, &paths)?;
        state
            .session
            .prove_contract_call(
                u.pk_hash,
                vec![ContractCallArgs {
                    contract_id: a.contract_id,
                    method_name: "private_claim".into(),
                    inputs,
                }],
            )
            .await?;
        anyhow::ensure!(
            p.get_user_leaf_data(p.get_latest_block_state().await?.checkpoint_id, u.user_id).await? == baseline_leaf,
            "wallet changed while validating private claim balance; no broadcast"
        );
        let (hash, cp) = sign_submit(&mut state, &u, &path, broadcast, |hash, nonce, checkpoint_before| {
            record.status = "broadcast_intent".into();
            record.end_leaf = Some(hash.into());
            record.nonce = Some(nonce);
            record.checkpoint_before = Some(checkpoint_before);
            w::save(&path, &record, false)
        })
        .await?;
        record.status = "included".into();
        record.checkpoint = Some(cp);
        w::save(&path, &record, false)?;
        Ok(
            serde_json::json!({"submitted":true,"confirmed":true,"fullUpsVerified":true,"noteId":id,"endUserLeafHash":hash,"checkpointId":cp,"amount":a.profile.decode(packet.amount)?.to_string()}),
        )
    }
    pub async fn wide_public_claim(
        &self,
        network: &NetworkId,
        expected: u64,
        a: &w::Asset,
        sender: u64,
        id: &str,
        broadcast: &AtomicBool,
    ) -> Result<serde_json::Value> {
        let _guard = w::operation_lock(network.as_str(), expected)?;
        anyhow::ensure!(sender > 0 && sender < 16777216, "invalid public claim sender");
        let mut state = self.state(network).await?;
        let u = state.require_user_id(expected)?;
        pin(&state.session.st_provider, a).await?;
        anyhow::ensure!(u.sign_type != "sd-key", "ordinary held-key wallet required");
        let p = state.session.st_provider.with_user_id_owned(u.user_id);
        let single_anchor = if !a.profile.is_wide() {
            let cp = p.get_latest_block_state().await?.checkpoint_id;
            let caller_leaf = p.get_user_leaf_data(cp, u.user_id).await?;
            let sender_leaf = p.get_user_leaf_data(cp, sender).await?;
            single_public_credit(
                a.profile,
                balance(&p, cp, u.user_id, a).await?,
                slot(&p, cp, sender, a.contract_id, 3 + u.user_id * 2).await?,
                slot(&p, cp, u.user_id, a.contract_id, 3 + sender * 2 + 1).await?,
            )?;
            Some((caller_leaf, sender_leaf))
        } else {
            None
        };
        let path = w::directory(network.as_str())?.join(format!("public-{id}.json"));
        let mut record = w::Inbox {
            user_id: u.user_id,
            contract_id: a.contract_id,
            delivery: w::Delivery {
                kind: "public_claim".into(),
                ephemeral_pubkey: String::new(),
                ciphertexts: vec![],
            },
            status: "prepared".into(),
            end_leaf: None,
            nonce: None,
            checkpoint_before: None,
            checkpoint: None,
        };
        w::save(&path, &record, true)?;
        state.session.start_session(u.pk_hash).await?;
        state
            .session
            .prove_contract_call(
                u.pk_hash,
                vec![ContractCallArgs {
                    contract_id: a.contract_id,
                    method_name: a.profile.public_claim_method().into(),
                    inputs: vec![sender],
                }],
            )
            .await?;
        if let Some((caller_leaf, sender_leaf)) = single_anchor {
            let cp = p.get_latest_block_state().await?.checkpoint_id;
            anyhow::ensure!(
                p.get_user_leaf_data(cp, u.user_id).await? == caller_leaf && p.get_user_leaf_data(cp, sender).await? == sender_leaf,
                "caller or sender changed while validating public credit; no broadcast"
            );
        }
        let (hash, cp) = sign_submit(&mut state, &u, &path, broadcast, |hash, nonce, checkpoint_before| {
            record.status = "broadcast_intent".into();
            record.end_leaf = Some(hash.into());
            record.nonce = Some(nonce);
            record.checkpoint_before = Some(checkpoint_before);
            w::save(&path, &record, false)
        })
        .await?;
        record.status = "included".into();
        record.checkpoint = Some(cp);
        w::save(&path, &record, false)?;
        Ok(serde_json::json!({"submitted":true,"confirmed":true,"fullUpsVerified":true,"endUserLeafHash":hash,"checkpointId":cp}))
    }
}
