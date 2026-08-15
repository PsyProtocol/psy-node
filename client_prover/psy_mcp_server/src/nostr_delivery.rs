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

fn limb_tag(name: &'static str, limbs: &[u64; 4]) -> Tag {
    Tag::custom(
        TagKind::Custom(Cow::Borrowed(name)),
        limbs.iter().map(|v| v.to_string()),
    )
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

    // 1. Seal (kind 13): NIP-44 encrypt the payload to the recipient, sign with
    //    an ephemeral sender key. No tags on the seal (matches the web wallet).
    let sender = Keys::generate();
    let sealed = nip44::encrypt(sender.secret_key(), &receiver_pk, payload, Version::V2)
        .context("seal nip44 encrypt failed")?;
    let seal = EventBuilder::new(Kind::Seal, sealed)
        .sign_with_keys(&sender)
        .context("seal sign failed")?;

    // 2. Wrap (kind 1059): NIP-44 encrypt the serialized seal to the recipient,
    //    sign with a second ephemeral key, carry the drain tags.
    let wrapper = Keys::generate();
    let seal_json = seal.as_json();
    let wrapped = nip44::encrypt(wrapper.secret_key(), &receiver_pk, &seal_json, Version::V2)
        .context("wrap nip44 encrypt failed")?;
    let tags = vec![
        Tag::public_key(receiver_pk),
        Tag::custom(
            TagKind::Custom(Cow::Borrowed("t")),
            [TRANSFER_PROOF_TAG.to_string()],
        ),
        limb_tag("shield_address", shield_limbs),
        limb_tag("nullifier", nullifier_limbs),
    ];
    let wrap = EventBuilder::new(Kind::GiftWrap, wrapped)
        .tags(tags)
        .sign_with_keys(&wrapper)
        .context("wrap sign failed")?;

    Ok(wrap.as_json())
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

    /// Live: publish to the local relay and confirm it accepts the event.
    /// Ignored by default (needs the mesh); run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_relay_accepts_the_wrap() {
        let recipient = Keys::generate();
        let id = deliver_private_note(
            "wss://nostr-local.psy-protocol.xyz",
            &recipient.public_key().to_hex(),
            r#"{"type":"psy_private_payment","amount":"1000"}"#,
            &[1, 2, 3, 4],
            &[5, 6, 7, 8],
        )
        .await
        .expect("relay should accept the wrap");
        assert_eq!(id.len(), 64, "returned event id should be a 32-byte hex");
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
