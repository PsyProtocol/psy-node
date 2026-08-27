//! Nostr note delivery for private transfers — NIP-59 gift wrap + NIP-44 v2.
//!
//! Reproduces the EXACT format the shipped web wallet publishes
//! (mode-a-web-wallet-bridge/src/unified/nostr-giftwrap.ts) so that recipient
//! wallets can drain and claim the note. The earlier CLI path tagged its note
//! `psy_private_transfer` while recipient wallets drain `psy_private_transfer_proof`
//! — that mismatch would strand funds; this module uses the drain's tags.
//!
//! Wrap construction (both layers use fresh EPHEMERAL keys → sender anonymity):
//!   1. NIP-44 v2 encrypt the payload to the recipient's pubkey → kind-13 SEAL,
//!      signed by an ephemeral sender key.
//!   2. NIP-44 v2 encrypt the JSON-serialized seal → kind-1059 WRAP, signed by a
//!      second ephemeral key, tagged `p=<recipient>`, `t=psy_private_transfer_proof`,
//!      `shield_address=<4 limbs>`, `nullifier=<4 limbs>`.
//!   3. Publish the wrap to the relay and await the relay's OK.
//!
//! Delivery is the recipient's ONLY way to learn of the note; a settlement whose
//! note is not delivered (or delivered in the wrong format) is unclaimable.

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use nostr::nips::nip44::{self, Version};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, TagKind};
use std::borrow::Cow;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

/// The tag the recipient wallets' Nostr drain filters private-transfer notes on.
const TRANSFER_PROOF_TAG: &str = "psy_private_transfer_proof";
const TRANSFER_SECRETS_TAG: &str = "psy_private_transfer_secrets";

fn limb_tag(name: &'static str, limbs: &[u64; 4]) -> Tag {
    Tag::custom(
        TagKind::Custom(Cow::Borrowed(name)),
        limbs.iter().map(|v| v.to_string()),
    )
}

fn value_tag(name: &'static str, values: impl IntoIterator<Item = String>) -> Tag {
    Tag::custom(TagKind::Custom(Cow::Borrowed(name)), values)
}

fn private_transfer_tags(
    receiver_pk: PublicKey,
    event_type: &'static str,
    backup_id: &str,
    shield_limbs: &[u64; 4],
    nullifier_limbs: &[u64; 4],
    contract_id: u64,
) -> Vec<Tag> {
    let nullifier_hex = format!(
        "0x{}",
        nullifier_limbs.iter().map(|word| format!("{word:016x}")).collect::<String>()
    );
    let contract_id = contract_id.to_string();
    vec![
        Tag::public_key(receiver_pk),
        value_tag("t", [event_type.to_string()]),
        value_tag("backup_id", [backup_id.to_string()]),
        limb_tag("shield_address", shield_limbs),
        limb_tag("nullifier", nullifier_limbs),
        value_tag("nullifier_hex", [nullifier_hex]),
        value_tag("token_contract_id", [contract_id.clone()]),
        value_tag("contract_id", [contract_id]),
    ]
}

fn stringify_json_numbers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Number(number) => *value = serde_json::Value::String(number.to_string()),
        serde_json::Value::Array(values) => values.iter_mut().for_each(stringify_json_numbers),
        serde_json::Value::Object(values) => values.values_mut().for_each(stringify_json_numbers),
        _ => {}
    }
}

fn build_encrypted_wrap(recipient_pk: PublicKey, payload: &str, tags: Vec<Tag>) -> Result<String> {
    let sender = Keys::generate();
    let sealed = nip44::encrypt(sender.secret_key(), &recipient_pk, payload, Version::V2)
        .context("seal nip44 encrypt failed")?;
    let seal = EventBuilder::new(Kind::Seal, sealed)
        .sign_with_keys(&sender)
        .context("seal sign failed")?;

    let wrapper = Keys::generate();
    let wrapped = nip44::encrypt(wrapper.secret_key(), &recipient_pk, &seal.as_json(), Version::V2)
        .context("wrap nip44 encrypt failed")?;
    Ok(EventBuilder::new(Kind::GiftWrap, wrapped)
        .tags(tags)
        .sign_with_keys(&wrapper)
        .context("wrap sign failed")?
        .as_json())
}

/// Build the kind-1059 gift-wrap event JSON for a private-transfer note.
/// Pure (no I/O) so it can be unit-tested and inspected before publishing.
pub fn build_gift_wrap(
    recipient_npub: &str,
    payload: &str,
    shield_limbs: &[u64; 4],
    nullifier_limbs: &[u64; 4],
) -> Result<String> {
    let receiver_pk =
        PublicKey::parse(recipient_npub).context("invalid recipient npub / hex pubkey")?;

    let tags = vec![
        Tag::public_key(receiver_pk),
        Tag::custom(
            TagKind::Custom(Cow::Borrowed("t")),
            [TRANSFER_PROOF_TAG.to_string()],
        ),
        limb_tag("shield_address", shield_limbs),
        limb_tag("nullifier", nullifier_limbs),
    ];
    build_encrypted_wrap(receiver_pk, payload, tags)
}

/// Build the exact proof/secrets event pair consumed by psy-services and the
/// current wallet. The proof is public-but-signed metadata; only the raw note
/// secrets are NIP-59/NIP-44 encrypted to the recipient.
pub fn build_private_transfer_events(
    recipient_npub: &str,
    amount: u64,
    contract_id: u64,
    tx_hash: &str,
    note_commitment: &[u64; 4],
    note_proof_raw: &str,
    nullifier_secret: &[u64; 4],
    note_secret: &[u64; 4],
    shield_limbs: &[u64; 4],
    nullifier_limbs: &[u64; 4],
) -> Result<Vec<String>> {
    let receiver_pk = PublicKey::parse(recipient_npub).context("invalid recipient npub / hex pubkey")?;
    let backup_id = note_commitment.iter().map(|word| format!("{word:016x}")).collect::<String>();
    let contract = contract_id.to_string();
    let amount = amount.to_string();
    let shield = shield_limbs.iter().map(u64::to_string).collect::<Vec<_>>();
    let nullifier = nullifier_limbs.iter().map(u64::to_string).collect::<Vec<_>>();
    let mut note_proof: serde_json::Value = serde_json::from_str(note_proof_raw).context("note proof JSON is invalid")?;
    // Match the wallet's parseJsonPreservingIntegers: proof limbs exceed
    // JavaScript's safe integer range, so the published envelope must encode
    // every integer as a decimal string.
    stringify_json_numbers(&mut note_proof);
    let proof_object = note_proof.as_object_mut().ok_or_else(|| anyhow!("note proof JSON must be an object"))?;
    proof_object.insert("token_contract_id".into(), serde_json::Value::String(contract.clone()));
    let augmented_note_proof_raw = serde_json::to_string(&note_proof)?;

    let proof_content = serde_json::json!({
        "type": TRANSFER_PROOF_TAG,
        "backup_id": backup_id,
        "amount": amount,
        "token_contract_id": contract,
        "contract_id": contract,
        "tx_hash": tx_hash,
        "note_commitment": backup_id,
        "shield_address": shield,
        "nullifier": nullifier,
        "note_proof": note_proof,
        "note_proof_raw": augmented_note_proof_raw,
    })
    .to_string();
    let proof_signer = Keys::generate();
    let proof_event = EventBuilder::new(Kind::GiftWrap, proof_content)
        .tags(private_transfer_tags(
            receiver_pk,
            TRANSFER_PROOF_TAG,
            &backup_id,
            shield_limbs,
            nullifier_limbs,
            contract_id,
        ))
        .sign_with_keys(&proof_signer)
        .context("proof event sign failed")?
        .as_json();

    let secrets_content = serde_json::json!({
        "type": TRANSFER_SECRETS_TAG,
        "backup_id": backup_id,
        "note_commitment": backup_id,
        "shield_address": shield,
        "amount": amount,
        "token_contract_id": contract,
        "contract_id": contract,
        "tx_hash": tx_hash,
        "nullifier_secret": nullifier_secret.iter().map(u64::to_string).collect::<Vec<_>>(),
        "note_secret": note_secret.iter().map(u64::to_string).collect::<Vec<_>>(),
    })
    .to_string();
    let secrets_event = build_encrypted_wrap(
        receiver_pk,
        &secrets_content,
        private_transfer_tags(receiver_pk, TRANSFER_SECRETS_TAG, &backup_id, shield_limbs, nullifier_limbs, contract_id),
    )?;
    Ok(vec![proof_event, secrets_event])
}

pub fn build_deposit_backup_events(recipient_npub: &str, note: &crate::wallet::DepositNote, deposit_proof_raw: &str) -> Result<Vec<String>> {
    let receiver_pk = PublicKey::parse(recipient_npub).context("invalid recipient npub / hex pubkey")?;
    let note_commitment = psy_crypto::shield_address::derive_note_commitment(note.nullifier_secret, note.note_secret);
    let commitment_limbs = crate::wallet::qhash_to_u64x4_pub(note_commitment);
    let backup_id = commitment_limbs.iter().map(|word| format!("{word:016x}")).collect::<String>();
    let nullifier_hash = psy_crypto::shield_address::derive_nullifier_hash(note.nullifier_secret);
    let nullifier_limbs = crate::wallet::qhash_to_u64x4_pub(nullifier_hash);
    let shield_limbs = crate::wallet::parse_shield_elements_hex_pub(&note.shield_address_hex)?;
    let mut deposit_proof: serde_json::Value = serde_json::from_str(deposit_proof_raw).context("deposit proof JSON is invalid")?;
    stringify_json_numbers(&mut deposit_proof);
    let local_index = deposit_proof
        .get("deposit_index")
        .and_then(|value| value.as_str())
        .unwrap_or("0")
        .to_string();
    let proof_content = serde_json::json!({
        "type": "psy_deposit_proof",
        "version": 2,
        "backup_id": backup_id,
        "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis().to_string(),
        "deposit_proof": deposit_proof,
        "metadata": {
            "note_commitment": backup_id,
            "shield_address": shield_limbs.iter().map(u64::to_string).collect::<Vec<_>>().join(":"),
            "token_address": note.l1_token_address,
            "amount": note.amount_base_units.to_string(),
            "source_chain_index": note.source_chain_index.to_string(),
            "tx_hash": note.l1_tx_hash,
            "global_deposit_index": note.expected_deposit_index.to_string(),
            "chain_local_deposit_index": local_index,
            "deposit_index": local_index,
            "contract_id": note.l2_token_contract_id.to_string(),
            "token_contract_id": note.l2_token_contract_id.to_string(),
        }
    })
    .to_string();
    let proof_tags = vec![
        Tag::public_key(receiver_pk),
        value_tag("t", ["psy_deposit_proof".to_string()]),
        value_tag("backup_id", [backup_id.clone()]),
        limb_tag("shield_address", &shield_limbs),
        limb_tag("nullifier", &nullifier_limbs),
        value_tag("deposit_index", [note.expected_deposit_index.to_string()]),
        value_tag("global_deposit_index", [note.expected_deposit_index.to_string()]),
        value_tag("chain_local_deposit_index", [local_index]),
        value_tag("token_contract_id", [note.l2_token_contract_id.to_string()]),
    ];
    let proof_event = EventBuilder::new(Kind::GiftWrap, proof_content)
        .tags(proof_tags)
        .sign_with_keys(&Keys::generate())
        .context("deposit proof event sign failed")?
        .as_json();
    let secrets_content = serde_json::json!({
        "type": "psy_deposit_secrets",
        "version": 2,
        "backup_id": backup_id,
        "nullifier_secret": note.nullifier_secret.iter().map(u64::to_string).collect::<Vec<_>>(),
        "note_secret": note.note_secret.iter().map(u64::to_string).collect::<Vec<_>>(),
    })
    .to_string();
    let secrets_event = build_encrypted_wrap(
            receiver_pk,
        &secrets_content,
        vec![
            Tag::public_key(receiver_pk),
            value_tag("t", ["psy_deposit_secrets".to_string()]),
            value_tag("backup_id", [backup_id]),
        ],
    )?;
    Ok(vec![proof_event, secrets_event])
}

/// Publish an already-built gift-wrap event JSON to a relay and await its OK.
#[allow(dead_code)]
pub async fn publish_event(relay_url: &str, event_json: &str) -> Result<String> {
    let event: serde_json::Value =
        serde_json::from_str(event_json).context("event json parse failed")?;
    let event_id = event
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("event has no id"))?
        .to_string();

    let (mut ws, _) = connect_async(relay_url)
        .await
        .with_context(|| format!("connect to relay {relay_url} failed"))?;
    let msg = serde_json::json!(["EVENT", event]).to_string();
    ws.send(Message::Text(msg))
        .await
        .context("relay send failed")?;

    // Await the relay's ["OK", <id>, <accepted>, <reason>].
    let deadline = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while let Some(msg) = ws.next().await {
            let text = match msg? {
                Message::Text(t) => t,
                Message::Binary(b) => String::from_utf8(b)?,
                _ => continue,
            };
            let value: serde_json::Value = serde_json::from_str(&text)?;
            let Some(items) = value.as_array() else { continue };
            if items.first().and_then(|v| v.as_str()) != Some("OK") {
                continue;
            }
            if items.get(1).and_then(|v| v.as_str()) != Some(event_id.as_str()) {
                continue;
            }
            let accepted = items.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
            if !accepted {
                let reason = items.get(3).and_then(|v| v.as_str()).unwrap_or("relay rejected event");
                anyhow::bail!("{reason}");
            }
            return Ok::<(), anyhow::Error>(());
        }
        anyhow::bail!("relay closed before acknowledging the event")
    })
    .await;

    let _ = ws.close(None).await;
    match deadline {
        Ok(inner) => inner.map(|_| event_id),
        Err(_) => Err(anyhow!("publish timed out after 15s")),
    }
}


/// NIP-44 v2 caps a single plaintext at 65,535 bytes, and the OUTER encrypt's
/// input is the whole serialized seal (inner ciphertext is base64, ~+33%, plus
/// the seal envelope). 32,000 keeps the outer input comfortably inside the cap
/// — the same figure the shipped web wallet uses, and note proofs (~90 KB of
/// base64) routinely need it. A payload that fits is sent unchunked.
const MAX_NIP44_PLAIN_BYTES: usize = 32_000;

/// Split a payload for NIP-44, chunking on BYTE boundaries of the JSON string.
/// The payload is ASCII (JSON with base64 inside), so slicing is safe.
fn split_for_nip44(plaintext: &str) -> Vec<&str> {
    if plaintext.len() <= MAX_NIP44_PLAIN_BYTES {
        return vec![plaintext];
    }
    // Split on char boundaries. The payload embeds caller-supplied strings
    // (token symbol), so "it is ASCII" is an assumption, not an invariant —
    // and a panic here would fire AFTER the on-chain settle, turning a
    // delivery hiccup into debited-and-undelivered funds.
    let mut chunks = Vec::new();
    let mut rest = plaintext;
    while rest.len() > MAX_NIP44_PLAIN_BYTES {
        let mut cut = MAX_NIP44_PLAIN_BYTES;
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        let (head, tail) = rest.split_at(cut);
        chunks.push(head);
        rest = tail;
    }
    chunks.push(rest);
    chunks
}

/// Build the gift-wrap events for a payload of any size.
///
/// A multi-chunk payload becomes N independent wraps whose bodies are
/// `{"type":"psy_private_payment_chunk","gid","index","total","body"}` — the
/// exact envelope recipient wallets reassemble. The gid keeps two concurrent
/// payments to the same shield address from colliding by (total, index): without
/// it their chunks overwrite each other and neither ever reassembles.
pub fn build_note_events(
    recipient_npub: &str,
    payload: &str,
    shield_limbs: &[u64; 4],
    nullifier_limbs: &[u64; 4],
) -> Result<Vec<String>> {
    let parts = split_for_nip44(payload);
    if parts.len() == 1 {
        return Ok(vec![build_gift_wrap(recipient_npub, payload, shield_limbs, nullifier_limbs)?]);
    }
    let gid: String = {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64())
    };
    let total = parts.len();
    parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            let body = serde_json::json!({
                "type": "psy_private_payment_chunk",
                "gid": gid,
                "index": index,
                "total": total,
                "body": part,
            })
            .to_string();
            build_gift_wrap(recipient_npub, &body, shield_limbs, nullifier_limbs)
        })
        .collect()
}

/// Publish a batch of events over ONE relay connection, awaiting each OK.
/// One connection per event trips relay rate limits ("too many concurrent
/// connects"); a delivery is only complete when EVERY chunk is accepted.
pub async fn publish_events(relay_url: &str, events: &[String]) -> Result<Vec<String>> {
    let (mut ws, _) = connect_async(relay_url)
        .await
        .with_context(|| format!("connect to relay {relay_url} failed"))?;
    let mut ids = Vec::with_capacity(events.len());
    for event_json in events {
        let event: serde_json::Value =
            serde_json::from_str(event_json).context("event json parse failed")?;
        let event_id = event
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("event has no id"))?
            .to_string();
        ws.send(Message::Text(serde_json::json!(["EVENT", event]).to_string()))
            .await
            .context("relay send failed")?;
        let ack = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while let Some(msg) = ws.next().await {
                let text = match msg? {
                    Message::Text(t) => t,
                    Message::Binary(b) => String::from_utf8(b)?,
                    _ => continue,
                };
                let value: serde_json::Value = serde_json::from_str(&text)?;
                let Some(items) = value.as_array() else { continue };
                if items.first().and_then(|v| v.as_str()) != Some("OK")
                    || items.get(1).and_then(|v| v.as_str()) != Some(event_id.as_str())
                {
                    continue;
                }
                if !items.get(2).and_then(|v| v.as_bool()).unwrap_or(false) {
                    let reason =
                        items.get(3).and_then(|v| v.as_str()).unwrap_or("relay rejected event");
                    anyhow::bail!("{reason}");
                }
                return Ok::<(), anyhow::Error>(());
            }
            anyhow::bail!("relay closed before acknowledging the event")
        })
        .await
        .map_err(|_| anyhow!("publish timed out after 20s"))
        .and_then(|inner| inner);
        if let Err(e) = ack {
            let _ = ws.close(None).await;
            return Err(e.context(format!("chunk {}/{} was not accepted", ids.len() + 1, events.len())));
        }
        ids.push(event_id);
    }
    let _ = ws.close(None).await;
    Ok(ids)
}

/// Reassemble decrypted note payloads: singles pass through; chunk envelopes
/// are grouped by gid and joined in index order. Incomplete groups are held
/// back (more chunks may still be draining) rather than surfaced as garbage.
pub fn reassemble_payloads(decrypted: Vec<String>) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut singles = Vec::new();
    let mut groups: BTreeMap<String, (usize, BTreeMap<usize, String>)> = BTreeMap::new();
    for text in decrypted {
        let parsed: Option<serde_json::Value> = serde_json::from_str(&text).ok();
        let is_chunk = parsed
            .as_ref()
            .and_then(|v| v.get("type"))
            .and_then(|t| t.as_str())
            == Some("psy_private_payment_chunk");
        if !is_chunk {
            singles.push(text);
            continue;
        }
        let v = parsed.unwrap();
        let (Some(gid), Some(index), Some(total), Some(body)) = (
            v.get("gid").and_then(|x| x.as_str()),
            v.get("index").and_then(|x| x.as_u64()),
            v.get("total").and_then(|x| x.as_u64()),
            v.get("body").and_then(|x| x.as_str()),
        ) else {
            continue; // malformed chunk: skip it, never invent a payload
        };
        let entry = groups.entry(gid.to_string()).or_insert((total as usize, BTreeMap::new()));
        entry.1.insert(index as usize, body.to_string());
    }
    for (_gid, (total, parts)) in groups {
        if parts.len() == total {
            singles.push(parts.into_values().collect::<String>());
        }
    }
    singles
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Event;

    #[test]
    fn private_transfer_pair_matches_wallet_contract_and_carries_secrets() {
        let recipient = Keys::generate();
        let commitment = [0x11, 0x22, 0x33, 0x44];
        let shield = [1, 2, 3, 4];
        let nullifier = [5, 6, 7, 8];
        let nullifier_secret = [9, 10, 11, 12];
        let note_secret = [13, 14, 15, 16];
        let proof_raw = serde_json::json!({
            "nullifier": nullifier.map(|word| word.to_string()),
            "note_proof_bincode_b64": "proof"
        })
        .to_string();
        let events = build_private_transfer_events(
            &recipient.public_key().to_hex(),
            4_000_000_000,
            0,
            "tx-hash",
            &commitment,
            &proof_raw,
            &nullifier_secret,
            &note_secret,
            &shield,
            &nullifier,
        )
        .unwrap();
        assert_eq!(events.len(), 2, "wallet contract is one proof plus one secrets event");

        let proof = Event::from_json(&events[0]).unwrap();
        let proof_content: serde_json::Value = serde_json::from_str(&proof.content).unwrap();
        let backup_id = "0000000000000011000000000000002200000000000000330000000000000044";
        assert_eq!(proof_content["type"], TRANSFER_PROOF_TAG);
        assert_eq!(proof_content["backup_id"], backup_id);
        assert_eq!(proof_content["note_proof_raw"].as_str().map(|raw| serde_json::from_str::<serde_json::Value>(raw).unwrap()["token_contract_id"].clone()), Some(serde_json::json!("0")));

        let secrets = Event::from_json(&events[1]).unwrap();
        let opened = open_note(recipient.secret_key(), &secrets.as_json()).unwrap();
        let secrets_content: serde_json::Value = serde_json::from_str(&opened).unwrap();
        assert_eq!(secrets_content["type"], TRANSFER_SECRETS_TAG);
        assert_eq!(secrets_content["backup_id"], backup_id);
        assert_eq!(secrets_content["nullifier_secret"], serde_json::json!(["9", "10", "11", "12"]));
        assert_eq!(secrets_content["note_secret"], serde_json::json!(["13", "14", "15", "16"]));
        for required in ["backup_id", "shield_address", "nullifier", "nullifier_hex", "token_contract_id", "contract_id"] {
            assert!(secrets.tags.iter().any(|tag| tag.as_slice().first().map(String::as_str) == Some(required)), "missing {required} tag");
        }
    }

    #[test]
    fn deposit_pair_matches_wallet_contract_and_carries_secrets() {
        let recipient = Keys::generate();
        let note = crate::wallet::DepositNote {
            network: Some("localhost".into()),
            note_secret: [13, 14, 15, 16],
            nullifier_secret: [9, 10, 11, 12],
            shield_address_hex: "0000000000000001:0000000000000002:0000000000000003:0000000000000004".into(),
            l1_token_address: "0x0000000000000000000000000000000000000001".into(),
            l2_token_contract_id: 4,
            amount_base_units: 4_000_000,
            source_chain_index: 0,
            expected_deposit_index: 7,
            l1_tx_hash: Some("0xdeposit".into()),
            claimed: false,
            delivered: false,
            deposit_proof_json: None,
            nostr_event_ids: Vec::new(),
        };
        let proof_raw =
            serde_json::json!({"type": "psy_shield_deposit_proof", "version": 1, "deposit_index": "7", "deposit_proof_bincode_b64": "AQID"})
                .to_string();
        let events = build_deposit_backup_events(&recipient.public_key().to_hex(), &note, &proof_raw).unwrap();
        assert_eq!(events.len(), 2);
        let proof = Event::from_json(&events[0]).unwrap();
        assert_eq!(proof.kind, Kind::GiftWrap);
        let proof_content: serde_json::Value = serde_json::from_str(&proof.content).unwrap();
        assert_eq!(proof_content["type"], "psy_deposit_proof");
        assert_eq!(proof_content["version"], 2);
        assert_eq!(proof_content["deposit_proof"]["deposit_index"], "7");
        let backup_id = proof_content["backup_id"].as_str().unwrap();
        assert_eq!(backup_id.len(), 64);
        let secrets = Event::from_json(&events[1]).unwrap();
        let opened = open_note(recipient.secret_key(), &secrets.as_json()).unwrap();
        let secrets_content: serde_json::Value = serde_json::from_str(&opened).unwrap();
        assert_eq!(secrets_content["type"], "psy_deposit_secrets");
        assert_eq!(secrets_content["backup_id"], backup_id);
        assert_eq!(secrets_content["nullifier_secret"], serde_json::json!(["9", "10", "11", "12"]));
        assert_eq!(secrets_content["note_secret"], serde_json::json!(["13", "14", "15", "16"]));
    }

    /// A payload past NIP-44's cap must survive chunk → wrap → open → reassemble
    /// byte-for-byte, or large notes (every real note proof) strand funds.
    #[test]
    fn oversized_payload_round_trips_through_chunks() {
        let recipient = Keys::generate();
        let npub_hex = recipient.public_key().to_hex();
        // ~90 KB, like a real note-proof envelope; ASCII by construction.
        let payload = format!(
            "{{\"type\":\"psy_private_payment\",\"noteProofRaw\":\"{}\"}}",
            "A".repeat(90_000)
        );
        let events = build_note_events(&npub_hex, &payload, &[1, 2, 3, 4], &[5, 6, 7, 8]).unwrap();
        assert!(events.len() >= 3, "90 KB at 32 KB/chunk must be at least 3 chunks");

        let secret = recipient.secret_key();
        let mut decrypted = Vec::new();
        for e in &events {
            decrypted.push(open_note(secret, e).unwrap());
        }
        let out = reassemble_payloads(decrypted);
        assert_eq!(out.len(), 1, "one payment must reassemble to one payload");
        assert_eq!(out[0], payload, "reassembly must be byte-exact");
    }

    /// Chunks from two concurrent payments must not cross-contaminate.
    #[test]
    fn two_chunked_payments_reassemble_independently() {
        let a = format!("{{\"p\":\"{}\"}}", "x".repeat(40_000));
        let b = format!("{{\"p\":\"{}\"}}", "y".repeat(40_000));
        let recipient = Keys::generate();
        let npub = recipient.public_key().to_hex();
        let mut decrypted = Vec::new();
        for payload in [&a, &b] {
            for e in build_note_events(&npub, payload, &[0; 4], &[0; 4]).unwrap() {
                decrypted.push(open_note(recipient.secret_key(), &e).unwrap());
            }
        }
        let mut out = reassemble_payloads(decrypted);
        out.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(out, want);
    }

    /// The recipient must be able to open both NIP-59 layers and recover the
    /// exact payload — otherwise the note (and the funds) are unclaimable. This
    /// proves format correctness without any network.
    #[test]
    fn recipient_can_decrypt_the_gift_wrap() {
        let recipient = Keys::generate();
        let npub_hex = recipient.public_key().to_hex();
        let payload = r#"{"type":"psy_private_payment","amount":"1000","shieldAddress":"a:b:c:d"}"#;
        let shield = [1u64, 2, 3, 4];
        let nullifier = [5u64, 6, 7, 8];

        let wrap_json = build_gift_wrap(&npub_hex, payload, &shield, &nullifier).unwrap();
        let wrap: Event = Event::from_json(&wrap_json).unwrap();

        assert_eq!(wrap.kind, Kind::GiftWrap, "outer must be kind 1059");
        let has_tag = |name: &str, val: &str| {
            wrap.tags.iter().any(|t| {
                let s = t.as_slice();
                s.first().map(String::as_str) == Some(name) && s.get(1).map(String::as_str) == Some(val)
            })
        };
        assert!(has_tag("t", TRANSFER_PROOF_TAG), "must carry the drain tag");
        assert!(has_tag("p", &recipient.public_key().to_hex()), "must p-tag the recipient");
        assert!(wrap.tags.iter().any(|t| t.as_slice().first().map(String::as_str) == Some("shield_address")));
        assert!(wrap.tags.iter().any(|t| t.as_slice().first().map(String::as_str) == Some("nullifier")));

        // Layer 1: decrypt the wrap → the seal.
        let seal_json =
            nip44::decrypt(recipient.secret_key(), &wrap.pubkey, &wrap.content).expect("wrap decrypt");
        let seal: Event = Event::from_json(&seal_json).unwrap();
        assert_eq!(seal.kind, Kind::Seal, "inner must be kind 13");

        // Layer 2: decrypt the seal → the original payload.
        let recovered =
            nip44::decrypt(recipient.secret_key(), &seal.pubkey, &seal.content).expect("seal decrypt");
        assert_eq!(recovered, payload, "recovered payload must equal the original");
    }

    /// Live: publish the wallet-compatible proof/secrets pair to the relay
    /// configured for the selected network and confirm both are accepted.
    /// Ignored by default (needs the mesh); run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_relay_accepts_the_wrap() {
        let config_path = std::env::var("PSY_CONFIG").unwrap_or_else(|_| {
            format!("{}/../../psy-genesis/config.json", env!("CARGO_MANIFEST_DIR"))
        });
        let config: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read PSY_CONFIG")).expect("parse PSY_CONFIG");
        let network = std::env::var("PSY_MCP_NETWORK")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| config.get("defaultNetwork").and_then(|value| value.as_str()).map(str::to_string))
            .expect("PSY_CONFIG must select a network");
        let relay = config["networks"][&network]["nostr_relay_url"]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .expect("selected network must configure nostr_relay_url");
        let recipient = Keys::generate();
        let events = build_private_transfer_events(
            &recipient.public_key().to_hex(),
            1_000,
            0,
            "live-test-tx",
            &[11, 12, 13, 14],
            &serde_json::json!({ "nullifier": ["5", "6", "7", "8"], "note_proof_bincode_b64": "live-test" }).to_string(),
            &[9, 10, 11, 12],
            &[13, 14, 15, 16],
            &[1, 2, 3, 4],
            &[5, 6, 7, 8],
        )
        .expect("build proof/secrets pair");
        let ids = publish_events(relay, &events).await.expect("relay should accept both events");
        assert_eq!(ids.len(), 2, "relay must accept proof and secrets");
        assert!(ids.iter().all(|id| id.len() == 64), "event ids should be 32-byte hex");
    }
}

/// Build + publish in one step.
#[allow(dead_code)]
pub async fn deliver_private_note(
    relay_url: &str,
    recipient_npub: &str,
    payload: &str,
    shield_limbs: &[u64; 4],
    nullifier_limbs: &[u64; 4],
) -> Result<String> {
    let event_json = build_gift_wrap(recipient_npub, payload, shield_limbs, nullifier_limbs)?;
    publish_event(relay_url, &event_json).await
}

/// Open a kind-1059 gift wrap addressed to us and return the inner payload.
///
/// Mirror of the send path: unwrap (NIP-44 → kind-13 seal), then unseal
/// (NIP-44 → payload). Both layers were encrypted TO our pubkey by ephemeral
/// senders, so our secret key plus each event's author pubkey opens them.
///
/// Notes are not always wrapped: psy-wallet's main path stores the payload as
/// plaintext JSON to dodge NIP-44's 64 KiB limit (see psy-services'
/// `nostr_note` handler). Plaintext is therefore returned as-is rather than
/// treated as an error.
pub fn open_note(secret: &nostr::SecretKey, wrapped: &str) -> Result<String> {
    let trimmed = wrapped.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("empty note"));
    }
    // Already the payload (plaintext form)?
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if v.get("type").and_then(|t| t.as_str()) == Some("psy_private_payment")
            || v.get("note_proof_bincode_b64").is_some()
        {
            return Ok(trimmed.to_string());
        }
    }
    let wrap = nostr::Event::from_json(trimmed).context("note is not a Nostr event")?;
    let seal_json = nip44::decrypt(secret, &wrap.pubkey, &wrap.content)
        .context("could not open the gift wrap — is this note addressed to us?")?;
    // A seal is itself an event; a non-event here means the sender wrapped the
    // payload directly, which older senders did.
    match nostr::Event::from_json(&seal_json) {
        Ok(seal) => nip44::decrypt(secret, &seal.pubkey, &seal.content)
            .context("could not open the seal"),
        Err(_) => Ok(seal_json),
    }
}

/// One note as psy-services returns it.
#[derive(Debug, Clone)]
pub struct ServiceNote {
    pub event_id: String,
    pub wrapped_note: String,
    #[allow(dead_code)]
    pub nullifier_hex: Option<String>,
}

/// Fetch notes addressed to `npub` from psy-services.
///
/// The service already runs the relay subscriber and mirrors `kind:1059` events
/// into its store, so a client never needs its own relay connection — it asks
/// for its notes and filters on the service's own claim status.
pub async fn fetch_notes(services_url: &str, npub: &str, unclaimed_only: bool) -> Result<Vec<ServiceNote>> {
    let base = services_url.trim_end_matches('/');
    let claimed = if unclaimed_only { "&claimed=false" } else { "" };
    let url = format!("{base}/api/v1/get/user/notes?nostr_pubkey={npub}{claimed}&limit=100");
    let body: serde_json::Value = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .with_context(|| format!("psy-services unreachable at {base}"))?
        .json()
        .await
        .context("psy-services returned a non-JSON response")?;
    if body.get("success").and_then(|s| s.as_bool()) != Some(true) {
        return Err(anyhow!("psy-services rejected the note query: {body}"));
    }
    let items = body
        .get("data")
        .and_then(|d| d.get("items"))
        .and_then(|i| i.as_array())
        .ok_or_else(|| anyhow!("unexpected notes response shape: {body}"))?;
    // `wrapped_note` is the full Nostr event as a JSON OBJECT (the service
    // stores it structurally); older rows may hold it as a string. Accepting
    // only one shape silently dropped every note of the other — and a drain
    // that silently sees nothing is indistinguishable from an empty inbox.
    Ok(items
        .iter()
        .filter_map(|it| {
            let wrapped = match it.get("wrapped_note") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(obj @ serde_json::Value::Object(_)) => obj.to_string(),
                _ => return None,
            };
            Some(ServiceNote {
                event_id: it.get("event_id")?.as_str()?.to_string(),
                wrapped_note: wrapped,
                nullifier_hex: it.get("nullifier_hex").and_then(|n| n.as_str()).map(String::from),
            })
        })
        .collect())
}
