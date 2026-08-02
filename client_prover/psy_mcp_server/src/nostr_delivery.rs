//! Nostr note delivery for private transfers — NIP-59 gift wrap + NIP-44 v2.
//!
//! Reproduces the EXACT format the shipped web wallet publishes
//! (mode-a-web-wallet-bridge/src/unified/nostr-giftwrap.ts) so that recipient
//! wallets can drain and claim the note. The earlier CLI path tagged its note
//! `psy_private_transfer` while recipient wallets drain
//! `psy_private_transfer_proof` — that mismatch would strand funds; this module
//! uses the drain's tags.
//!
//! Wrap construction (both layers use fresh EPHEMERAL keys → sender anonymity):
//!   1. NIP-44 v2 encrypt the payload to the recipient's pubkey → kind-13 SEAL,
//!      signed by an ephemeral sender key.
//!   2. NIP-44 v2 encrypt the JSON-serialized seal → kind-1059 WRAP, signed by
//!      a second ephemeral key, tagged `p=<recipient>`,
//!      `t=psy_private_transfer_proof`, `shield_address=<4 limbs>`,
//!      `nullifier=<4 limbs>`.
//!   3. Publish the wrap to the relay and await the relay's OK.
//!
//! Delivery is the recipient's ONLY way to learn of the note; a settlement
//! whose note is not delivered (or delivered in the wrong format) is
//! unclaimable.

use std::borrow::Cow;

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use nostr::{
    nips::nip44::{self, Version},
    EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, TagKind,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// The tag the recipient wallets' Nostr drain filters private-transfer notes
/// on.
const TRANSFER_PROOF_TAG: &str = "psy_private_transfer_proof";

fn limb_tag(name: &'static str, limbs: &[u64; 4]) -> Tag {
    Tag::custom(TagKind::Custom(Cow::Borrowed(name)), limbs.iter().map(|v| v.to_string()))
}

/// Build the kind-1059 gift-wrap event JSON for a private-transfer note.
/// Pure (no I/O) so it can be unit-tested and inspected before publishing.
pub fn build_gift_wrap(recipient_npub: &str, payload: &str, shield_limbs: &[u64; 4], nullifier_limbs: &[u64; 4]) -> Result<String> {
    let receiver_pk = PublicKey::parse(recipient_npub).context("invalid recipient npub / hex pubkey")?;

    // 1. Seal (kind 13): NIP-44 encrypt the payload to the recipient, sign with an
    //    ephemeral sender key. No tags on the seal (matches the web wallet).
    let sender = Keys::generate();
    let sealed = nip44::encrypt(sender.secret_key(), &receiver_pk, payload, Version::V2).context("seal nip44 encrypt failed")?;
    let seal = EventBuilder::new(Kind::Seal, sealed)
        .sign_with_keys(&sender)
        .context("seal sign failed")?;

    // 2. Wrap (kind 1059): NIP-44 encrypt the serialized seal to the recipient,
    //    sign with a second ephemeral key, carry the drain tags.
    let wrapper = Keys::generate();
    let seal_json = seal.as_json();
    let wrapped = nip44::encrypt(wrapper.secret_key(), &receiver_pk, &seal_json, Version::V2).context("wrap nip44 encrypt failed")?;
    let tags = vec![
        Tag::public_key(receiver_pk),
        Tag::custom(TagKind::Custom(Cow::Borrowed("t")), [TRANSFER_PROOF_TAG.to_string()]),
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
pub async fn publish_event(relay_url: &str, event_json: &str) -> Result<String> {
    let event: serde_json::Value = serde_json::from_str(event_json).context("event json parse failed")?;
    let event_id = event
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("event has no id"))?
        .to_string();

    let (mut ws, _) = connect_async(relay_url)
        .await
        .with_context(|| format!("connect to relay {relay_url} failed"))?;
    let msg = serde_json::json!(["EVENT", event]).to_string();
    ws.send(Message::Text(msg)).await.context("relay send failed")?;

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

#[cfg(test)]
mod tests {
    use nostr::Event;

    use super::*;

    /// The recipient must be able to open both NIP-59 layers and recover the
    /// exact payload — otherwise the note (and the funds) are unclaimable. This
    /// proves format correctness without any network.
    #[test]
    fn recipient_can_decrypt_the_gift_wrap() {
        let recipient = Keys::generate();
        let npub_hex = recipient.public_key().to_hex();
        let payload = r#"{"type":"psy_private_payment","amountNano":"1000","shieldAddress":"a:b:c:d"}"#;
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
        assert!(wrap
            .tags
            .iter()
            .any(|t| t.as_slice().first().map(String::as_str) == Some("shield_address")));
        assert!(wrap.tags.iter().any(|t| t.as_slice().first().map(String::as_str) == Some("nullifier")));

        // Layer 1: decrypt the wrap → the seal.
        let seal_json = nip44::decrypt(recipient.secret_key(), &wrap.pubkey, &wrap.content).expect("wrap decrypt");
        let seal: Event = Event::from_json(&seal_json).unwrap();
        assert_eq!(seal.kind, Kind::Seal, "inner must be kind 13");

        // Layer 2: decrypt the seal → the original payload.
        let recovered = nip44::decrypt(recipient.secret_key(), &seal.pubkey, &seal.content).expect("seal decrypt");
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
            r#"{"type":"psy_private_payment","amountNano":"1000"}"#,
            &[1, 2, 3, 4],
            &[5, 6, 7, 8],
        )
        .await
        .expect("relay should accept the wrap");
        assert_eq!(id.len(), 64, "returned event id should be a 32-byte hex");
    }
}

/// Build + publish in one step.
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
