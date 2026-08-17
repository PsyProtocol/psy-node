use std::str::FromStr;

use anyhow::Context;
use base64::Engine;
#[cfg(not(target_arch = "wasm32"))]
use futures_util::{SinkExt, StreamExt};
use nostr_sdk::{prelude::*, UnsignedEvent};
use plonky2::field::types::{Field, Field64, PrimeField64};
use psy_client_common::{
    args::{WalletSessionArgs, WalletSourceArgs},
    data::qhashout::QHashOut,
    ups::circuits::LocalCircuitType,
};
use psy_client_data::{
    config::store_config::{C, D, F},
    privacy::private_note_inclusion::PrivateNoteInclusionInput,
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_crypto::{
    hash::{
        merkle::core::MerkleProofCore,
        traits::hasher::{FieldQHasher, PoseidonHasher},
    },
    shield_address::{derive_note_commitment, shield_address_to_bytes32},
    signature::zk::wallet::SimplePsyPrivateKey,
};
use psy_dpn_circuit::circuits::privacy::private_note_inclusion::PrivateNoteInclusionCircuit;
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use rand::RngCore;
use tokio::time::{sleep, Duration};
#[cfg(not(target_arch = "wasm32"))]
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::result::{CommandResult, TransactionResult, TransactionStatus};
use crate::subcommand::{
    args::PrivateTransferArgs,
    note_proof_common::{qhash_to_u64x4, NoteProofOutput},
    submit_end_cap_proof,
};
const NOTE_TREE_HEIGHT: usize = 20; // 2^20 = 1048576 notes

async fn get_contract_state_tree_height(provider: &RpcProvider, contract_id: u64) -> anyhow::Result<u8> {
    let height = provider
        .get_contract_leaf_data(contract_id)
        .await?
        .state_tree_height
        .to_canonical_u64();
    u8::try_from(height).with_context(|| format!("invalid state tree height {} for contract {}", height, contract_id))
}

#[derive(Clone)]
struct GenerateNoteProofInput {
    rpc_config: String,
    private_key: String,
    contract_id: u64,
    note_root_slot: u64,
    amount: u64,
    owner: String,
    note_secret: Vec<u64>,
    nullifier_secret: Vec<u64>,
    checkpoint_id: u64,
    output: String,
}

fn tag_limbs(values: &[u64; 4]) -> [String; 4] {
    [values[0].to_string(), values[1].to_string(), values[2].to_string(), values[3].to_string()]
}

fn sample_canonical_secret_limb(mut next_u64: impl FnMut() -> u64) -> u64 {
    loop {
        let candidate = next_u64();
        if candidate < F::ORDER {
            return candidate;
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn publish_event_to_relay(relay_url: &str, event: &Event) -> anyhow::Result<String> {
    let payload = serde_json::json!(["EVENT", serde_json::from_str::<serde_json::Value>(&event.as_json())?]);
    let (mut ws, _) = connect_async(relay_url).await?;
    ws.send(Message::Text(payload.to_string())).await?;

    let expected_id = event.id.to_string();
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(msg) = ws.next().await {
            let msg = msg?;
            let text = match msg {
                Message::Text(t) => t,
                Message::Binary(b) => String::from_utf8(b.to_vec())?,
                _ => continue,
            };
            let value: serde_json::Value = serde_json::from_str(&text)?;
            let Some(items) = value.as_array() else { continue };
            if items.first().and_then(|v| v.as_str()) != Some("OK") {
                continue;
            }
            if items.get(1).and_then(|v| v.as_str()) != Some(expected_id.as_str()) {
                continue;
            }
            let accepted = items.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
            if !accepted {
                let reason = items.get(3).and_then(|v| v.as_str()).unwrap_or("relay rejected event");
                anyhow::bail!(reason.to_string());
            }
            return Ok::<(), anyhow::Error>(());
        }
        anyhow::bail!("relay closed before acknowledging event")
    })
    .await;
    match result {
        Ok(inner) => inner?,
        Err(_) => anyhow::bail!("publish timeout"),
    }
    tracing::info!("Nostr sent event_id={}", expected_id);
    let _ = ws.close(None).await;
    Ok(expected_id)
}

/// Publish a v2 two-event private transfer backup (proof + secrets) mirroring
/// deposit.rs `publish_deposit_backup`. Event 1 is a plaintext GiftWrap with
/// the PrivateNoteInclusionCircuit proof; Event 2 is a NIP-59 encrypted
/// gift-wrap containing nullifier_secret + note_secret. Both share
/// `backup_id = note_commitment` (64 lowercase hex).
#[cfg(not(target_arch = "wasm32"))]
async fn publish_private_transfer_backup(
    note_data: &NoteProofOutput,
    note_commitment_q: QHashOut<F>,
    note_secret: [u64; 4],
    nullifier_secret: [u64; 4],
    recipient_npub: &str,
    relay_url: &str,
) -> anyhow::Result<(String, String)> {
    let recipient_pk = PublicKey::parse(recipient_npub)?;
    let sender_keys = Keys::generate();
    let backup_id = hex::encode(shield_address_to_bytes32(note_commitment_q));

    let note_proof_raw = serde_json::json!({
        "note_proof_bincode_b64": base64::engine::general_purpose::STANDARD.encode(&note_data.note_proof),
        "note_proof_fingerprint": note_data.note_proof_fingerprint,
        "owner": note_data.owner,
        "amount": note_data.amount,
        "user_tree_root": note_data.user_tree_root,
        "checkpoint_id": note_data.checkpoint_id,
        "note_root_slot": note_data.note_root_slot,
        "token_contract_id": note_data.token_contract_id.as_str(),
        "nullifier": note_data.nullifier,
    })
    .to_string();

    let proof_content = serde_json::json!({
        "type": "psy_private_transfer_proof",
        "version": 2,
        "backup_id": backup_id,
        "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis(),
        "note_proof_raw": note_proof_raw,
        "metadata": {
            "note_commitment": backup_id,
            "shield_address": tag_limbs(&note_data.owner).join(":"),
            "nullifier": tag_limbs(&note_data.nullifier).join(":"),
            "amount": note_data.amount,
            "checkpoint_id": note_data.checkpoint_id,
            "note_root_slot": note_data.note_root_slot,
            "token_contract_id": note_data.token_contract_id.as_str(),
        }
    })
    .to_string();

    let created_at = Timestamp::from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs());
    let unsigned_proof = UnsignedEvent::new(
        sender_keys.public_key(),
        created_at,
        Kind::GiftWrap,
        vec![
            Tag::custom(TagKind::p(), [recipient_pk.to_hex()]),
            Tag::custom(TagKind::t(), ["psy_private_transfer_proof".to_string()]),
            Tag::custom(TagKind::custom("backup_id"), [backup_id.clone()]),
            Tag::custom(TagKind::custom("shield_address"), tag_limbs(&note_data.owner)),
            Tag::custom(TagKind::custom("nullifier"), tag_limbs(&note_data.nullifier)),
            Tag::custom(TagKind::custom("token_contract_id"), [note_data.token_contract_id.clone()]),
        ],
        proof_content,
    );
    let proof_event = unsigned_proof.sign_with_keys(&sender_keys)?;

    let secrets_content = serde_json::json!({
        "type": "psy_private_transfer_secrets",
        "version": 2,
        "backup_id": backup_id,
        "nullifier_secret": tag_limbs(&nullifier_secret),
        "note_secret": tag_limbs(&note_secret),
    })
    .to_string();
    let rumor = EventBuilder::text_note(secrets_content).build(sender_keys.public_key());
    let secrets_event = EventBuilder::gift_wrap(
        &sender_keys,
        &recipient_pk,
        rumor,
        [
            Tag::custom(TagKind::t(), ["psy_private_transfer_secrets".to_string()]),
            Tag::custom(TagKind::custom("backup_id"), [backup_id]),
        ],
    )
    .await?;

    let proof_event_id = publish_event_to_relay(relay_url, &proof_event).await?;
    let secrets_event_id = publish_event_to_relay(relay_url, &secrets_event).await?;

    Ok((proof_event_id, secrets_event_id))
}

#[cfg(target_arch = "wasm32")]
async fn publish_private_transfer_backup(
    _note_data: &NoteProofOutput,
    _note_commitment_q: QHashOut<F>,
    _note_secret: [u64; 4],
    _nullifier_secret: [u64; 4],
    _recipient_npub: &str,
    _relay_url: &str,
) -> anyhow::Result<(String, String)> {
    anyhow::bail!("nostr send is not supported in wasm build")
}

async fn wait_next_checkpoint(provider: &RpcProvider, previous_checkpoint_id: u64) -> anyhow::Result<u64> {
    for _ in 0..60 {
        let latest = provider.get_latest_block_state().await?.checkpoint_id;
        if latest > previous_checkpoint_id {
            return Ok(latest);
        }
        sleep(Duration::from_secs(1)).await;
    }
    anyhow::bail!("timeout waiting for next checkpoint after {}", previous_checkpoint_id);
}

async fn wait_checkpoint_with_note_root(
    provider: &RpcProvider,
    sender_user_id: u64,
    contract_id: u64,
    note_root_slot: u64,
    min_checkpoint_id: u64,
    expected_note_root: QHashOut<F>,
) -> anyhow::Result<u64> {
    let user_provider = provider.with_user_id_owned(sender_user_id);
    let contract_state_tree_height = get_contract_state_tree_height(provider, contract_id).await?;
    let mut next_checkpoint_to_check = min_checkpoint_id;

    for _ in 0..120 {
        let latest = provider.get_latest_block_state().await?.checkpoint_id;
        tracing::debug!(
            "wait_checkpoint_with_note_root scanning checkpoints [{}..={}] expected_note_root={}",
            next_checkpoint_to_check,
            latest,
            expected_note_root
        );
        while next_checkpoint_to_check <= latest {
            let proof = user_provider
                .get_user_contract_state_tree_merkle_proof(
                    next_checkpoint_to_check,
                    sender_user_id,
                    contract_id as u32,
                    contract_state_tree_height,
                    note_root_slot,
                )
                .await
                .with_context(|| format!("note_root slot merkle proof failed at checkpoint {}", next_checkpoint_to_check))?;

            tracing::debug!(
                "wait_checkpoint_with_note_root checkpoint={} note_root_slot={} value={} root={}",
                next_checkpoint_to_check,
                note_root_slot,
                proof.value,
                proof.root
            );

            if proof.value == expected_note_root {
                tracing::info!(
                    "matched expected note_root at checkpoint={} slot={} value={}",
                    next_checkpoint_to_check,
                    note_root_slot,
                    proof.value
                );
                return Ok(next_checkpoint_to_check);
            }
            next_checkpoint_to_check = next_checkpoint_to_check.saturating_add(1);
        }
        sleep(Duration::from_secs(1)).await;
    }

    anyhow::bail!(
        "timeout waiting for checkpoint with expected note_root at slot {} starting from checkpoint {}",
        note_root_slot,
        min_checkpoint_id
    );
}

async fn wait_checkpoint_with_note_slots_change(
    provider: &RpcProvider,
    sender_user_id: u64,
    contract_id: u64,
    note_count_slot: u64,
    note_root_slot: u64,
    checkpoint_before: u64,
) -> anyhow::Result<u64> {
    let user_provider = provider.with_user_id_owned(sender_user_id);
    let contract_state_tree_height = get_contract_state_tree_height(provider, contract_id).await?;
    let baseline_count = user_provider
        .get_user_contract_state_tree_merkle_proof(
            checkpoint_before,
            sender_user_id,
            contract_id as u32,
            contract_state_tree_height,
            note_count_slot,
        )
        .await?
        .value;
    let baseline_root = user_provider
        .get_user_contract_state_tree_merkle_proof(
            checkpoint_before,
            sender_user_id,
            contract_id as u32,
            contract_state_tree_height,
            note_root_slot,
        )
        .await?
        .value;

    let mut max_seen_latest = checkpoint_before;
    let mut max_seen_coordinator = checkpoint_before;
    let mut max_seen_realm = checkpoint_before;
    let mut unchanged_polls = 0u32;
    let mut last_error = String::new();
    for _ in 0..180 {
        let coordinator_latest = provider.get_coordinator_latest_block_state().await.ok().map(|s| s.checkpoint_id);
        let realm_latest = provider.get_realm_latest_block_state().await.ok().map(|s| s.checkpoint_id);
        if let Some(c) = coordinator_latest {
            max_seen_coordinator = max_seen_coordinator.max(c);
        }
        if let Some(r) = realm_latest {
            max_seen_realm = max_seen_realm.max(r);
        }
        let latest_observable = match (coordinator_latest, realm_latest) {
            (Some(c), Some(r)) => c.min(r),
            (Some(c), None) => c,
            (None, Some(r)) => r,
            (None, None) => {
                tracing::warn!("wait_checkpoint_with_note_slots_change latest checkpoint rpc failed on both coordinator and realm");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if latest_observable > max_seen_latest {
            max_seen_latest = latest_observable;
            unchanged_polls = 0;
        } else {
            unchanged_polls = unchanged_polls.saturating_add(1);
        }
        if unchanged_polls >= 30 {
            tracing::warn!(
                "coordinator checkpoint appears stalled while waiting note slots change (continuing): coordinator_latest={}, realm_latest={:?}, start_checkpoint={}, count_slot={}, root_slot={}",
                coordinator_latest.unwrap_or(latest_observable),
                realm_latest,
                checkpoint_before,
                note_count_slot,
                note_root_slot
            );
            unchanged_polls = 0;
        }
        if latest_observable <= checkpoint_before {
            sleep(Duration::from_secs(1)).await;
            continue;
        }

        let count_proof = match user_provider
            .get_user_contract_state_tree_merkle_proof(
                latest_observable,
                sender_user_id,
                contract_id as u32,
                contract_state_tree_height,
                note_count_slot,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                last_error = format!("count proof rpc failed at checkpoint {}: {}", latest_observable, e);
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let root_proof = match user_provider
            .get_user_contract_state_tree_merkle_proof(
                latest_observable,
                sender_user_id,
                contract_id as u32,
                contract_state_tree_height,
                note_root_slot,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                last_error = format!("root proof rpc failed at checkpoint {}: {}", latest_observable, e);
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        if count_proof.value != baseline_count || root_proof.value != baseline_root {
            tracing::info!(
                "note slots changed at checkpoint={} count(slot {}): {} -> {}, root(slot {}): {} -> {}",
                latest_observable,
                note_count_slot,
                baseline_count,
                count_proof.value,
                note_root_slot,
                baseline_root,
                root_proof.value
            );
            return Ok(latest_observable);
        }
        last_error = format!(
            "slots unchanged at checkpoint {}: count={} root={}",
            latest_observable, count_proof.value, root_proof.value
        );
        sleep(Duration::from_secs(1)).await;
    }

    if max_seen_latest <= checkpoint_before {
        anyhow::bail!(
            "timeout waiting for note slots change after checkpoint {}: no new checkpoint produced (latest still {}). count slot={}, root slot={}",
            checkpoint_before,
            max_seen_latest,
            note_count_slot,
            note_root_slot
        );
    }
    anyhow::bail!(
        "timeout waiting for note slots change after checkpoint {} (latestObservable={}, latestCoordinator={}, latestRealm={}, lastError={}, count slot {}, root slot {})",
        checkpoint_before,
        max_seen_latest,
        max_seen_coordinator,
        max_seen_realm,
        last_error,
        note_count_slot,
        note_root_slot
    );
}

async fn wait_checkpoint_with_nonce_change(
    provider: &RpcProvider,
    sender_user_id: u64,
    checkpoint_before: u64,
    baseline_nonce: u64,
) -> anyhow::Result<u64> {
    let mut max_seen_latest = checkpoint_before;
    let mut unchanged_polls = 0u32;
    for _ in 0..180 {
        let coordinator_latest = provider.get_coordinator_latest_block_state().await.ok().map(|s| s.checkpoint_id);
        let realm_latest = provider.get_realm_latest_block_state().await.ok().map(|s| s.checkpoint_id);
        let latest = match (coordinator_latest, realm_latest) {
            (Some(c), Some(r)) => c.max(r),
            (Some(c), None) => c,
            (None, Some(r)) => r,
            (None, None) => {
                tracing::warn!("wait_checkpoint_with_nonce_change latest checkpoint rpc failed on both coordinator and realm");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if latest > max_seen_latest {
            max_seen_latest = latest;
            unchanged_polls = 0;
        } else {
            unchanged_polls = unchanged_polls.saturating_add(1);
        }
        if unchanged_polls >= 30 {
            tracing::warn!(
                "coordinator checkpoint appears stalled while waiting nonce change (continuing): coordinator_latest={}, realm_latest={:?}, start_checkpoint={}, baseline_nonce={}",
                coordinator_latest.unwrap_or(latest),
                realm_latest,
                checkpoint_before,
                baseline_nonce
            );
            unchanged_polls = 0;
        }

        for checkpoint_to_check in checkpoint_before.saturating_add(1)..=latest {
            match provider.get_user_leaf_data(checkpoint_to_check, sender_user_id).await {
                Ok(leaf) => {
                    let nonce = leaf.nonce.to_canonical_u64();
                    if nonce > baseline_nonce {
                        tracing::info!(
                            "user nonce changed at checkpoint={} baseline_nonce={} new_nonce={}",
                            checkpoint_to_check,
                            baseline_nonce,
                            nonce
                        );
                        return Ok(checkpoint_to_check);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "wait_checkpoint_with_nonce_change get_user_leaf_data failed at checkpoint {}: {}",
                        checkpoint_to_check,
                        e
                    );
                    break;
                }
            }
        }
        sleep(Duration::from_secs(1)).await;
    }

    if max_seen_latest <= checkpoint_before {
        anyhow::bail!(
            "timeout waiting for nonce change after checkpoint {} (baseline nonce {}): no new checkpoint produced (latest still {})",
            checkpoint_before,
            baseline_nonce,
            max_seen_latest
        );
    }
    anyhow::bail!(
        "timeout waiting for nonce change after checkpoint {} (baseline nonce {}, latest seen {})",
        checkpoint_before,
        baseline_nonce,
        max_seen_latest
    );
}

async fn build_membership_proof_from_previous_checkpoint(
    provider: &RpcProvider,
    sender_user_id: u64,
    contract_id: u64,
    note_root_slot: u64,
    amount: u64,
    owner: QHashOut<F>,
    note_commitment: QHashOut<F>,
    checkpoint_id: u64,
) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
    let user_provider = provider.with_user_id_owned(sender_user_id);
    let contract_state_tree_height = get_contract_state_tree_height(provider, contract_id).await?;

    let note_count_slot = note_root_slot.saturating_sub(1);
    let note_count_proof = user_provider
        .get_user_contract_state_tree_merkle_proof(
            checkpoint_id,
            sender_user_id,
            contract_id as u32,
            contract_state_tree_height,
            note_count_slot,
        )
        .await?;
    let note_index = note_count_proof.value.0.elements[3].to_canonical_u64();
    tracing::info!(
        "build_membership_proof checkpoint={} contract_id={} note_count_slot={} note_count_value={} parsed_note_index(elements[3])={}",
        checkpoint_id,
        contract_id,
        note_count_slot,
        note_count_proof.value,
        note_index
    );

    let mut last_path: Vec<QHashOut<F>> = Vec::with_capacity(20);
    for level in 0..20u64 {
        let slot = note_root_slot + 1 + level;
        let proof = user_provider
            .get_user_contract_state_tree_merkle_proof(
                checkpoint_id,
                sender_user_id,
                contract_id as u32,
                contract_state_tree_height,
                slot,
            )
            .await?;
        tracing::debug!(
            "build_membership_proof checkpoint={} level={} last_path_slot={} value={}",
            checkpoint_id,
            level,
            slot,
            proof.value
        );
        last_path.push(proof.value);
    }

    let value_hash = QHashOut::<F>::from_values(amount, 0, 0, 0);
    let inner = PoseidonHasher::q_two_to_one(owner, value_hash);
    let commitment = PoseidonHasher::q_two_to_one(inner, note_commitment);

    let mut siblings = Vec::with_capacity(20);
    let mut zero = QHashOut::<F>::from_values(0, 0, 0, 0);
    for level in 0..20usize {
        let bit = (note_index >> level) & 1;
        if bit == 0 {
            siblings.push(zero);
        } else {
            siblings.push(last_path[level]);
        }
        zero = PoseidonHasher::q_two_to_one(zero, zero);
    }

    let proof = MerkleProofCore::new_from_params::<PoseidonHasher>(note_index, commitment, siblings);
    tracing::info!(
        "build_membership_proof done checkpoint={} note_index={} commitment={} computed_note_root={}",
        checkpoint_id,
        note_index,
        commitment,
        proof.root
    );
    Ok(proof)
}

async fn run_note_proof_with_membership_proof(
    input: GenerateNoteProofInput,
    note_membership_proof: MerkleProofCore<QHashOut<F>>,
) -> anyhow::Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&input.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();

    let sender_sk = QHashOut::<F>::from_str(&input.private_key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    let provider = RpcProvider::new_with_config(&rpc_config)?;
    let contract_state_tree_height = get_contract_state_tree_height(&provider, input.contract_id).await?;
    let checkpoint_id = if input.checkpoint_id == u64::MAX {
        provider.get_latest_block_state().await?.checkpoint_id
    } else {
        input.checkpoint_id
    };

    let wallet_session = WalletSession::new(&rpc_config).await?;
    let zk_sig_fingerprint = wallet_session
        .circuit_info
        .get_circuit_info_by_id(LocalCircuitType::SimpleZKSignature.into())?
        .fingerprint;
    let sender_public_key = SimplePsyPrivateKey::new(sender_sk).get_public_key_for_fingerprint::<PoseidonHasher>(zk_sig_fingerprint);
    let sender_user_ids = provider
        .get_user_ids_for_public_key(sender_public_key)
        .await
        .map_err(|e| anyhow::anyhow!("get_user_ids_for_public_key failed: {}", e))?;
    let sender_user_id = *sender_user_ids
        .first()
        .ok_or_else(|| anyhow::anyhow!("No user id found for sender public key"))?;

    let user_provider = provider.with_user_id_owned(sender_user_id);
    let user_leaf = user_provider
        .get_user_leaf_data(checkpoint_id, sender_user_id)
        .await
        .map_err(|e| anyhow::anyhow!("get_user_leaf_data failed: {}", e))?;

    let note_root_slot_proof = user_provider
        .get_user_contract_state_tree_merkle_proof(
            checkpoint_id,
            sender_user_id,
            input.contract_id as u32,
            contract_state_tree_height,
            input.note_root_slot,
        )
        .await
        .map_err(|e| anyhow::anyhow!("note_root slot merkle proof failed: {}", e))?;
    tracing::info!(
        "run_note_proof note_root_slot_proof checkpoint={} slot={} value={} root={}",
        checkpoint_id,
        input.note_root_slot,
        note_root_slot_proof.value,
        note_root_slot_proof.root
    );
    tracing::info!(
        "run_note_proof membership checkpoint={} note_index={} commitment={} membership_root={}",
        checkpoint_id,
        note_membership_proof.index,
        note_membership_proof.value,
        note_membership_proof.root
    );
    if note_membership_proof.root != note_root_slot_proof.value {
        anyhow::bail!(
            "run_note_proof root mismatch: membership_root={} != slot_value={} (checkpoint={}, slot={}); checkpoint does not contain this note root",
            note_membership_proof.root,
            note_root_slot_proof.value,
            checkpoint_id,
            input.note_root_slot
        );
    }

    let contract_proof = user_provider
        .get_user_contract_tree_merkle_proof(checkpoint_id, sender_user_id, input.contract_id as u32)
        .await
        .map_err(|e| anyhow::anyhow!("UCT merkle proof failed: {}", e))?;

    let user_tree_proof = user_provider
        .get_user_tree_merkle_proof(checkpoint_id, sender_user_id)
        .await
        .map_err(|e| anyhow::anyhow!("user tree merkle proof failed: {}", e))?;
    let global_user_tree_root = user_tree_proof.root;

    let note_secret = QHashOut::<F>::from_values(input.note_secret[0], input.note_secret[1], input.note_secret[2], input.note_secret[3]);
    let nullifier_secret = QHashOut::<F>::from_values(
        input.nullifier_secret[0],
        input.nullifier_secret[1],
        input.nullifier_secret[2],
        input.nullifier_secret[3],
    );
    let amount = F::from_canonical_u64(input.amount);
    let owner = QHashOut::<F>::from_str(&input.owner).map_err(|e| anyhow::anyhow!("Invalid owner: {}", e))?;

    let circuit_input = PrivateNoteInclusionInput {
        nullifier_secret,
        sender_user_id,
        contract_id: input.contract_id,
        note_root_slot: input.note_root_slot,
        user_leaf,
        owner,
        amount,
        note_secret,
        note_membership_proof,
        note_root_slot_proof,
        contract_proof,
        user_tree_proof,
        checkpoint_id: F::from_canonical_u64(checkpoint_id),
    };

    let circuit = PrivateNoteInclusionCircuit::<C, D>::new(
        psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize,
        psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
        psy_config::network_constants::TOKEN_CONTRACT_STATE_TREE_HEIGHT as usize,
        NOTE_TREE_HEIGHT,
    );
    let fingerprint = circuit.get_fingerprint();
    let proof = circuit.prove(&circuit_input)?;
    let fingerprint_after_prove = circuit.get_fingerprint();
    tracing::info!(
        fingerprint_before_prove = %fingerprint,
        fingerprint_after_prove = %fingerprint_after_prove,
        "PrivateNoteInclusion fingerprint"
    );
    let proof_bytes = bincode::serialize(&proof)?;

    let nullifier = PoseidonHasher::q_hash_many(&nullifier_secret.0.elements);

    let output = NoteProofOutput {
        nullifier: qhash_to_u64x4(nullifier),
        owner: qhash_to_u64x4(owner),
        amount: input.amount,
        user_tree_root: qhash_to_u64x4(global_user_tree_root),
        checkpoint_id,
        note_root_slot: input.note_root_slot,
        token_contract_id: input.contract_id.to_string(),
        note_proof_fingerprint: qhash_to_u64x4(fingerprint),
        note_proof: proof_bytes,
    };

    let json = serde_json::to_string_pretty(&output)?;
    std::fs::write(&input.output, &json)?;
    Ok(())
}

pub async fn run(args: PrivateTransferArgs) -> anyhow::Result<CommandResult> {
    let mut rng = rand::thread_rng();
    let note_secret = std::array::from_fn(|_| sample_canonical_secret_limb(|| rng.next_u64()));
    let nullifier_secret = std::array::from_fn(|_| sample_canonical_secret_limb(|| rng.next_u64()));

    let receiver_hex = args
        .receiver
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--receiver (or --owner alias) is required; receiver should provide shielded address out-of-band"))?;
    let owner_hash = QHashOut::<F>::from_str(&receiver_hex).map_err(|e| anyhow::anyhow!("Invalid receiver: {}", e))?;
    let sender_sk = QHashOut::<F>::from_str(&args.private_key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
    let note_commitment_q = derive_note_commitment(nullifier_secret, note_secret);
    let note_commitment = qhash_to_u64x4(note_commitment_q);

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    let wallet_session = WalletSession::new(&rpc_config).await?;
    let zk_sig_fingerprint = wallet_session
        .circuit_info
        .get_circuit_info_by_id(LocalCircuitType::SimpleZKSignature.into())?
        .fingerprint;
    let sender_pk = SimplePsyPrivateKey::new(sender_sk).get_public_key_for_fingerprint::<PoseidonHasher>(zk_sig_fingerprint);
    let sender_user_id = provider
        .get_user_ids_for_public_key(sender_pk)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for sender public key"))?;

    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let baseline_user_leaf = provider.get_user_leaf_data(checkpoint_before, sender_user_id).await?;
    let baseline_nonce = baseline_user_leaf.nonce.to_canonical_u64();
    tracing::info!(
        "private_transfer start checkpoint_before={} sender_user_id={} contract_id={} note_root_slot={} amount={} baseline_nonce={}",
        checkpoint_before,
        sender_user_id,
        args.contract_id,
        args.note_root_slot,
        args.amount,
        baseline_nonce
    );

    let owner_u64 = qhash_to_u64x4(owner_hash);
    let mut inputs = Vec::<u64>::new();
    inputs.extend_from_slice(&owner_u64);
    inputs.push(args.amount);
    inputs.extend_from_slice(&note_commitment);

    // 1) Execute private_transfer contract call.
    let (tx_hash, end_user_leaf_hash) = submit_end_cap_proof::run_with_end_user_leaf_hash(WalletSessionArgs {
        rpc_config: args.rpc_config.clone(),
        wallet: WalletSourceArgs {
            sign_type: args.sign_type.clone(),
            private_key: Some(args.private_key.clone()),
            keystore_path: None,
            wallet_password: None,
            fingerprint: None,
            sd_key_allowed_contract_id: vec![],
            sd_key_allowed_method_id: vec![],
            sd_key_expected_tx_count: 2,
            sd_key_definition: None,
        },
        contract_id: vec![args.contract_id],
        method_name: vec!["private_transfer".to_string()],
        inputs: vec![serde_json::to_string(&inputs)?],
        sign_inputs: vec![],
        contract_calls_file: None,
        external_proof_file: vec![],
        wait_until_confirmation: true,
    })
    .await?;
    tracing::info!(
        "private_transfer endcap submitted! tx_hash={} end_user_leaf_hash={}",
        tx_hash,
        end_user_leaf_hash
    );

    // Build membership proof from the checkpoint just before private_transfer.
    let note_membership_proof = build_membership_proof_from_previous_checkpoint(
        &provider,
        sender_user_id,
        args.contract_id,
        args.note_root_slot,
        args.amount,
        owner_hash,
        note_commitment_q,
        checkpoint_before,
    )
    .await?;
    tracing::info!(
        "private_transfer membership note_index={} commitment={} computed_root={} (local)",
        note_membership_proof.index,
        note_membership_proof.value,
        note_membership_proof.root
    );
    let note_count_slot = args.note_root_slot.saturating_sub(1);
    let checkpoint_after = match wait_checkpoint_with_note_slots_change(
        &provider,
        sender_user_id,
        args.contract_id,
        note_count_slot,
        args.note_root_slot,
        checkpoint_before,
    )
    .await
    {
        Ok(cp) => cp,
        Err(primary_err) => {
            tracing::warn!(
                "note slots change not observed in primary window after tx baseline checkpoint {}: {}. falling back to expected note_root matching",
                checkpoint_before,
                primary_err
            );
            let fallback_min_checkpoint = wait_next_checkpoint(&provider, checkpoint_before).await.unwrap_or(checkpoint_before);
            wait_checkpoint_with_note_root(
                &provider,
                sender_user_id,
                args.contract_id,
                args.note_root_slot,
                fallback_min_checkpoint,
                note_membership_proof.root,
            )
            .await
            .with_context(|| {
                format!(
                    "note root was not observable after tx baseline checkpoint {} (primary wait and fallback both failed)",
                    checkpoint_before
                )
            })?
        }
    };

    // 2) Generate note proof JSON from next checkpoint state.
    run_note_proof_with_membership_proof(
        GenerateNoteProofInput {
            rpc_config: args.rpc_config.clone(),
            private_key: args.private_key.clone(),
            contract_id: args.contract_id,
            note_root_slot: args.note_root_slot,
            amount: args.amount,
            owner: receiver_hex.clone(),
            note_secret: note_secret.to_vec(),
            nullifier_secret: nullifier_secret.to_vec(),
            checkpoint_id: checkpoint_after,
            output: args.output.clone(),
        },
        note_membership_proof,
    )
    .await?;

    // 3) Optionally send generated note proof over Nostr.
    let note_payload = std::fs::read_to_string(&args.output).with_context(|| format!("failed to read generated note proof {}", args.output))?;
    let note_data: NoteProofOutput = serde_json::from_str(&note_payload).context("generated note proof is not valid json")?;
    if let Some(npub) = &args.nostr_recipient_pubkey {
        let (proof_id, secrets_id) = publish_private_transfer_backup(
            &note_data,
            note_commitment_q,
            note_secret,
            nullifier_secret,
            npub,
            &args.nostr_relay,
        )
        .await?;
        println!(
            "private transfer backup sent via Nostr: proof={}, secrets={}",
            proof_id, secrets_id
        );
    } else {
        println!("Note proof saved to {} (file mode)", args.output);
    }

    println!("private_transfer note_commitment: {:?}", note_commitment);
    Ok(CommandResult::Transaction(TransactionResult {
        transaction_hash: tx_hash,
        user_id: Some(sender_user_id),
        status: TransactionStatus::Confirmed,
        confirmed_checkpoint: Some(checkpoint_after),
        network: psy_config.current_network_name().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_limb_sampling_rejects_noncanonical_values() {
        let mut candidates = [F::ORDER, u64::MAX, F::ORDER - 1].into_iter();

        let sampled = sample_canonical_secret_limb(|| candidates.next().expect("candidate sequence exhausted"));

        assert_eq!(sampled, F::ORDER - 1);
    }
}
