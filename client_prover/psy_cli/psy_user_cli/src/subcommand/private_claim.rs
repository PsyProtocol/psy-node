use std::{str::FromStr, time::Duration};

use base64::Engine;
use nostr_sdk::prelude::*;
use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use psy_client_common::{
    args::{ContractCallArgs, DPNSoftwareDefinedCallData},
    data::qhashout::QHashOut,
    ups::circuits::LocalCircuitType,
};
use psy_client_data::{
    config::store_config::{C, D, F},
    traits::qdatastore::qmetadata::QMetaDataStoreReaderSync,
};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_dpn_circuit::circuits::privacy::private_note_inclusion::PrivateNoteInclusionCircuit;
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use tokio::time::sleep;

use crate::subcommand::{
    args::PrivateClaimArgs,
    note_proof_common::{build_private_claim_inputs, NoteProofOutput},
};

const NOTE_TREE_HEIGHT: usize = 20;

async fn wait_checkpoint_with_nonce_change(provider: &RpcProvider, user_id: u64, checkpoint_before: u64, baseline_nonce: u64) -> anyhow::Result<u64> {
    let mut max_seen_latest = checkpoint_before;
    for _ in 0..180 {
        let coordinator_latest = provider.get_coordinator_latest_block_state().await.ok().map(|s| s.checkpoint_id);
        let realm_latest = provider.get_realm_latest_block_state().await.ok().map(|s| s.checkpoint_id);
        let latest = match (coordinator_latest, realm_latest) {
            (Some(c), Some(r)) => c.min(r),
            (Some(c), None) => c,
            (None, Some(r)) => r,
            (None, None) => {
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if latest > max_seen_latest {
            max_seen_latest = latest;
        }
        for checkpoint_to_check in checkpoint_before.saturating_add(1)..=latest {
            match provider.get_user_leaf_data(checkpoint_to_check, user_id).await {
                Ok(leaf) => {
                    let nonce = leaf.nonce.to_canonical_u64();
                    if nonce > baseline_nonce {
                        tracing::info!(
                            "private_claim nonce changed at checkpoint={} baseline_nonce={} new_nonce={}",
                            checkpoint_to_check,
                            baseline_nonce,
                            nonce
                        );
                        return Ok(checkpoint_to_check);
                    }
                }
                Err(_) => break,
            }
        }
        sleep(Duration::from_secs(1)).await;
    }

    anyhow::bail!(
        "timeout waiting private_claim nonce change after checkpoint {} (baseline_nonce={}, latest_seen={})",
        checkpoint_before,
        baseline_nonce,
        max_seen_latest
    );
}

async fn nostr_receive_private_msg(receiver_nsec: &str, relay_url: &str, timeout_secs: u64) -> anyhow::Result<String> {
    let receiver_keys = Keys::parse(receiver_nsec)?;
    let client = Client::new(receiver_keys);
    client.add_relay(relay_url).await?;
    client.connect().await;

    let receiver_pk = client.signer().await?.get_public_key().await?;
    let filter = Filter::new().kind(Kind::GiftWrap).pubkey(receiver_pk).limit(0);
    client.subscribe(filter, None).await?;

    let client_inner = client.clone();
    let content_cell = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let content_cell_inner = content_cell.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        client.handle_notifications(move |notification| {
            let c = client_inner.clone();
            let content_ref = content_cell_inner.clone();
            async move {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::GiftWrap {
                        if let Ok(UnwrappedGift { rumor, .. }) = c.unwrap_gift_wrap(&event).await {
                            if rumor.kind == Kind::PrivateDirectMessage {
                                if let Ok(mut guard) = content_ref.lock() {
                                    *guard = Some(rumor.content);
                                }
                                return Ok(true);
                            }
                        }
                    }
                }
                Ok(false)
            }
        }),
    )
    .await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(anyhow::anyhow!("nostr notification error: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("timeout waiting for Nostr message")),
    }

    client.disconnect().await;
    let content = content_cell
        .lock()
        .map_err(|_| anyhow::anyhow!("nostr message lock poisoned"))?
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no private message received"))?;
    Ok(content)
}

pub async fn run(args: PrivateClaimArgs) -> anyhow::Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    // Read note proof JSON from file or Nostr.
    let note_data: NoteProofOutput = if let Some(note_proof_file) = &args.note_proof {
        let json = std::fs::read_to_string(note_proof_file).map_err(|e| anyhow::anyhow!("Failed to read {}: {}", note_proof_file, e))?;
        serde_json::from_str(&json)?
    } else {
        let nsec = args
            .nostr_secret_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("either --note-proof or --nostr-secret-key must be provided"))?;
        let payload = nostr_receive_private_msg(nsec, &args.nostr_relay, args.nostr_timeout_secs).await?;
        serde_json::from_str(&payload).map_err(|e| anyhow::anyhow!("invalid note proof payload from nostr: {}", e))?
    };

    // Deserialize proof from bincode(base64).
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(note_data.note_proof_bincode_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid proof base64: {}", e))?;
    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof_bytes).map_err(|e| anyhow::anyhow!("invalid bincode proof: {}", e))?;
    let fingerprint = QHashOut::<F>::from_values(
        note_data.note_proof_fingerprint[0],
        note_data.note_proof_fingerprint[1],
        note_data.note_proof_fingerprint[2],
        note_data.note_proof_fingerprint[3],
    );
    let receiver_sk = QHashOut::<F>::from_str(&args.private_key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let verifier_data = if let Ok(info) = wallet_session.circuit_info.get_circuit_info_by_fingerprint(fingerprint) {
        info.verifier_data.to_verifier_data::<C, D>()
    } else {
        tracing::warn!(
            "external proof fingerprint {} not registered in session info; rebuilding PrivateNoteInclusion verifier data locally",
            fingerprint
        );
        let local = PrivateNoteInclusionCircuit::<C, D>::new(
            psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize,
            psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
            psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
            NOTE_TREE_HEIGHT,
        );
        let local_fingerprint = local.get_fingerprint();
        if local_fingerprint != fingerprint {
            anyhow::bail!(
                "local PrivateNoteInclusion fingerprint mismatch: payload={}, local={}",
                fingerprint,
                local_fingerprint
            );
        }
        local.get_verifier_config_ref().clone()
    };
    let zk_sig_fingerprint = wallet_session
        .circuit_info
        .get_circuit_info_by_id(LocalCircuitType::SimpleZKSignature.into())?
        .fingerprint;
    let receiver_pk = wallet_session.add_user(receiver_sk, zk_sig_fingerprint).await?;
    let receiver_user_id = provider
        .get_user_ids_for_public_key(receiver_pk)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for receiver public key"))?;

    // Important: start session first, then inject external proof into the active
    // session tree.
    wallet_session.start_session(receiver_pk).await?;
    let leaf_index = wallet_session.add_external_proof(receiver_pk, fingerprint, proof, verifier_data).await?;
    let leaf_proof = wallet_session
        .user_session_mgrs
        .get(&receiver_pk)
        .ok_or_else(|| anyhow::anyhow!("User session manager not found for {}", receiver_pk))?
        .proof_tree_state
        .get_leaf_merkle_proof(leaf_index)
        .await;

    let inputs = build_private_claim_inputs(&note_data, &leaf_proof, leaf_index, args.random0, args.random1);
    wallet_session
        .prove_contract_call(
            receiver_pk,
            vec![ContractCallArgs {
                contract_id: args.contract_id,
                method_name: "private_claim".to_string(),
                inputs,
            }],
        )
        .await?;

    tracing::info!("Submitting private_claim with proof_index={}", leaf_index);
    let checkpoint_before = provider.get_latest_block_state().await?.checkpoint_id;
    let baseline_nonce = provider
        .get_user_leaf_data(checkpoint_before, receiver_user_id)
        .await?
        .nonce
        .to_canonical_u64();
    let tx_hash = wallet_session.sign_and_submit(receiver_pk, DPNSoftwareDefinedCallData::default()).await?;
    tracing::info!("tx submitted! hash: {}", tx_hash);
    let checkpoint_after = wait_checkpoint_with_nonce_change(&provider, receiver_user_id, checkpoint_before, baseline_nonce).await?;
    tracing::info!(
        "private_claim confirmed by nonce change at checkpoint={} (start_checkpoint={}, baseline_nonce={})",
        checkpoint_after,
        checkpoint_before,
        baseline_nonce
    );

    Ok(())
}
