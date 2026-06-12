use std::str::FromStr;

use anyhow::Context;
use base64::Engine;
use nostr_sdk::prelude::*;
use plonky2::field::types::{Field, PrimeField64};
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
        traits::{
            hasher::{FieldQHasher, PoseidonHasher},
            qhashable::QFieldHashable,
        },
    },
    signature::zk::wallet::SimplePsyPrivateKey,
};
use psy_dpn_circuit::circuits::privacy::private_note_inclusion::PrivateNoteInclusionCircuit;
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use rand::RngCore;
use tokio::time::{sleep, Duration};

use crate::subcommand::{
    args::PrivateTransferArgs,
    note_proof_common::{qhash_to_u64x4, NoteProofOutput},
    submit_end_cap_proof,
};

const NOTE_TREE_HEIGHT: usize = 20; // 2^20 = 1048576 notes

#[derive(Clone)]
struct GenerateNoteProofInput {
    rpc_config: String,
    private_key: String,
    contract_id: u64,
    note_root_slot: u64,
    amount: u64,
    owner: String,
    note_secret_hash: Vec<u64>,
    nullifier_secret: Vec<u64>,
    checkpoint_id: u64,
    output: String,
}

async fn nostr_send_private_msg(sender_nsec: &str, recipient_npub: &str, relay_url: &str, content: &str) -> anyhow::Result<()> {
    let sender_keys = Keys::parse(sender_nsec)?;
    let recipient_pk = PublicKey::parse(recipient_npub)?;
    let client = Client::new(sender_keys);
    client.add_relay(relay_url).await?;
    client.connect().await;
    let output = client.send_private_msg(recipient_pk, content, []).await?;
    tracing::info!("Nostr sent: success={}, failed={}", output.success.len(), output.failed.len());
    client.disconnect().await;
    Ok(())
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
                    psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
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
    let baseline_count = user_provider
        .get_user_contract_state_tree_merkle_proof(
            checkpoint_before,
            sender_user_id,
            contract_id as u32,
            psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
            note_count_slot,
        )
        .await?
        .value;
    let baseline_root = user_provider
        .get_user_contract_state_tree_merkle_proof(
            checkpoint_before,
            sender_user_id,
            contract_id as u32,
            psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
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
                psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
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
                psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
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
    note_secret_hash: QHashOut<F>,
    checkpoint_id: u64,
) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
    let user_provider = provider.with_user_id_owned(sender_user_id);

    let note_count_slot = note_root_slot.saturating_sub(1);
    let note_count_proof = user_provider
        .get_user_contract_state_tree_merkle_proof(
            checkpoint_id,
            sender_user_id,
            contract_id as u32,
            psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
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
                psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
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
    let commitment = PoseidonHasher::q_two_to_one(inner, note_secret_hash);

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
    let sender_pk_param = SimplePsyPrivateKey::new(sender_sk).get_public_key_param::<PoseidonHasher>();

    let provider = RpcProvider::new_with_config(&rpc_config)?;
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
            psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as u8,
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
        tracing::error!(
            "run_note_proof root mismatch: membership_root={} != slot_value={} (checkpoint={}, slot={})",
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

    let note_secret_hash = QHashOut::<F>::from_values(
        input.note_secret_hash[0],
        input.note_secret_hash[1],
        input.note_secret_hash[2],
        input.note_secret_hash[3],
    );
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
        randomness: note_secret_hash,
        note_membership_proof,
        note_root_slot_proof,
        contract_proof,
        user_tree_proof,
        checkpoint_id: F::from_canonical_u64(checkpoint_id),
    };

    let circuit = PrivateNoteInclusionCircuit::<C, D>::new(
        psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize,
        psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
        psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
        NOTE_TREE_HEIGHT,
    );
    let proof = circuit.prove(&circuit_input)?;
    let fingerprint = circuit.get_fingerprint();
    let proof_bytes = bincode::serialize(&proof)?;
    let proof_b64 = base64::engine::general_purpose::STANDARD.encode(proof_bytes);

    let nullifier = PoseidonHasher::q_hash_many(&nullifier_secret.0.elements);

    let output = NoteProofOutput {
        nullifier: qhash_to_u64x4(nullifier),
        owner: qhash_to_u64x4(owner),
        amount: input.amount,
        user_tree_root: qhash_to_u64x4(global_user_tree_root),
        checkpoint_id,
        note_root_slot: input.note_root_slot,
        note_proof_fingerprint: qhash_to_u64x4(fingerprint),
        note_proof_bincode_b64: proof_b64,
    };

    let json = serde_json::to_string_pretty(&output)?;
    std::fs::write(&input.output, &json)?;
    Ok(())
}

pub async fn run(args: PrivateTransferArgs) -> anyhow::Result<()> {
    let mut rng = rand::thread_rng();
    let note_secret_hash = vec![rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()];
    let nullifier_secret = vec![rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()];

    let receiver_hex = args
        .receiver
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--receiver (or --owner alias) is required; receiver should provide shielded address out-of-band"))?;
    let owner_hash = QHashOut::<F>::from_str(&receiver_hex).map_err(|e| anyhow::anyhow!("Invalid receiver: {}", e))?;
    let sender_sk = QHashOut::<F>::from_str(&args.private_key).map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;
    let note_secret_hash_q = QHashOut::<F>::from_values(note_secret_hash[0], note_secret_hash[1], note_secret_hash[2], note_secret_hash[3]);

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
    inputs.extend_from_slice(&note_secret_hash);

    // 1) Execute private_transfer contract call.
    let end_user_leaf_hash = submit_end_cap_proof::run_with_end_user_leaf_hash(WalletSessionArgs {
        rpc_config: args.rpc_config.clone(),
        wallet: WalletSourceArgs {
            sign_type: args.sign_type.clone(),
            private_key: Some(args.private_key.clone()),
            keystore_path: None,
            wallet_password: None,
            fingerprint: None,
            sdk_key_allowed_contract_id: vec![],
            sdk_key_allowed_method_id: vec![],
            sdk_key_expected_tx_count: 2,
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
    tracing::info!("private_transfer endcap submitted! end_user_leaf_hash={}", end_user_leaf_hash);

    // Build membership proof from the checkpoint just before private_transfer.
    let note_membership_proof = build_membership_proof_from_previous_checkpoint(
        &provider,
        sender_user_id,
        args.contract_id,
        args.note_root_slot,
        args.amount,
        owner_hash,
        note_secret_hash_q,
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
    tracing::info!(
        "private_transfer selected checkpoint_after={} (baseline checkpoint={}, note_count slot {} changed)",
        checkpoint_after,
        checkpoint_before,
        note_count_slot
    );

    // 2) Generate note proof JSON from next checkpoint state.
    run_note_proof_with_membership_proof(
        GenerateNoteProofInput {
            rpc_config: args.rpc_config.clone(),
            private_key: args.private_key.clone(),
            contract_id: args.contract_id,
            note_root_slot: args.note_root_slot,
            amount: args.amount,
            owner: receiver_hex.clone(),
            note_secret_hash: note_secret_hash.clone(),
            nullifier_secret: nullifier_secret.clone(),
            checkpoint_id: checkpoint_after,
            output: args.output.clone(),
        },
        note_membership_proof,
    )
    .await?;

    // 3) Optionally send generated note proof over Nostr.
    let note_payload = std::fs::read_to_string(&args.output).with_context(|| format!("failed to read generated note proof {}", args.output))?;
    match (&args.nostr_secret_key, &args.nostr_recipient_pubkey) {
        (Some(nsec), Some(npub)) => {
            nostr_send_private_msg(nsec, npub, &args.nostr_relay, &note_payload).await?;
            println!("Note proof sent via Nostr relay {}", args.nostr_relay);
        }
        (None, None) => {
            println!("Note proof saved to {} (file mode)", args.output);
        }
        _ => {
            anyhow::bail!("--nostr-secret-key and --nostr-recipient-pubkey must be provided together");
        }
    }

    println!("private_transfer note_secret_hash: {:?}", note_secret_hash);
    Ok(())
}
