//! Blind, signed transport for encrypted single-Felt and U124 FT packets.
//! Relay acknowledgements are delivery receipts, never settlement receipts.
use std::{collections::BTreeMap, time::Duration};

use anyhow::{ensure, Context, Result};
use futures_util::{SinkExt, StreamExt};
use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::wide_private::{self as w, Delivery};
pub const MARKER: &str = "psy_private_ft_delivery_v1";
pub const MAX_EVENTS: usize = 256;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Part {
    pub version: u8,
    pub delivery_id: String,
    pub kind: String,
    pub ephemeral_pubkey: String,
    pub index: usize,
    pub total: usize,
    pub ciphertext: String,
}
pub fn delivery_id(d: &Delivery) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(d)?)))
}
pub fn validate_part(p: &Part) -> Result<()> {
    w::validate_id(&p.delivery_id)?;
    ensure!(
        p.version == 1 && (1..=132).contains(&p.total) && p.index < p.total,
        "invalid FT delivery part"
    );
    ensure!(
        matches!(p.kind.as_str(), "psy_private_ft_single_v1" | "psy_private_ft_u124_v1"),
        "unsupported FT format"
    );
    ensure!(
        p.ephemeral_pubkey.len() == 64 && PublicKey::parse(&p.ephemeral_pubkey)?.to_hex() == p.ephemeral_pubkey,
        "invalid encryption pubkey"
    );
    ensure!((1..=90000).contains(&p.ciphertext.len()), "invalid ciphertext length");
    // Only NIP44-v2 base64 payloads belong in the blind mailbox.
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(&p.ciphertext)?;
    ensure!(bytes.first() == Some(&2) && bytes.len() >= 99, "invalid NIP44-v2 payload");
    Ok(())
}
pub fn events(recipient: &str, delivery: &Delivery) -> Result<Vec<String>> {
    let recipient = PublicKey::parse(recipient)?;
    let id = delivery_id(delivery)?;
    let signer = Keys::generate();
    delivery
        .ciphertexts
        .iter()
        .enumerate()
        .map(|(index, ciphertext)| {
            let part = Part {
                version: 1,
                delivery_id: id.clone(),
                kind: delivery.kind.clone(),
                ephemeral_pubkey: delivery.ephemeral_pubkey.clone(),
                index,
                total: delivery.ciphertexts.len(),
                ciphertext: ciphertext.clone(),
            };
            validate_part(&part)?;
            Ok(EventBuilder::new(Kind::GiftWrap, serde_json::to_string(&part)?)
                .tags([Tag::public_key(recipient), Tag::parse(["t", MARKER])?])
                .sign_with_keys(&signer)?
                .as_json())
        })
        .collect()
}
pub fn event_part(raw: &str, recipient: &str) -> Result<Part> {
    ensure!(raw.len() <= 100000, "FT event too large");
    let event = Event::from_json(raw)?;
    event.verify()?;
    ensure!(event.kind == Kind::GiftWrap && event.tags.len() == 2, "invalid FT event routing");
    let expected = PublicKey::parse(recipient)?.to_hex();
    let tags: Vec<_> = event.tags.iter().map(|t| t.as_slice()).collect();
    ensure!(
        tags.iter().any(|t| *t == ["t", MARKER]) && tags.iter().any(|t| *t == ["p", expected.as_str()]),
        "FT recipient/marker mismatch"
    );
    let part: Part = serde_json::from_str(&event.content)?;
    validate_part(&part)?;
    Ok(part)
}
pub fn assemble(parts: &[Part]) -> Result<Delivery> {
    let first = parts.first().context("empty FT delivery")?;
    ensure!(parts.len() <= MAX_EVENTS, "too many FT delivery parts");
    let mut chunks = BTreeMap::new();
    for part in parts {
        validate_part(part)?;
        ensure!(
            part.delivery_id == first.delivery_id
                && part.kind == first.kind
                && part.ephemeral_pubkey == first.ephemeral_pubkey
                && part.total == first.total,
            "mixed FT delivery"
        );
        if let Some(prior) = chunks.insert(part.index, part.ciphertext.clone()) {
            ensure!(prior == part.ciphertext, "conflicting FT part");
        }
    }
    ensure!(chunks.len() == first.total, "incomplete FT delivery");
    let d = Delivery {
        kind: first.kind.clone(),
        ephemeral_pubkey: first.ephemeral_pubkey.clone(),
        ciphertexts: chunks.into_values().collect(),
    };
    ensure!(
        d.ciphertexts.iter().map(String::len).sum::<usize>() <= 8 * 1024 * 1024 && delivery_id(&d)? == first.delivery_id,
        "FT delivery checksum mismatch"
    );
    Ok(d)
}

/// Persist the exact signed batch before publishing. A retry reuses the batch;
/// it cannot create another payment or expose any decrypted material.
pub async fn publish(network: &str, id: &str, recipient: &str, d: &Delivery, relay: &str) -> Result<serde_json::Value> {
    w::validate_id(id)?;
    let _lock = w::operation_lock(network, 0)?;
    let path = w::directory(network)?.join(format!("relay-out-{id}.json"));
    let batch: Vec<String> = if path.exists() {
        w::read(&path)?
    } else {
        let batch = events(recipient, d)?;
        w::save(&path, &batch, true)?;
        batch
    };
    let expected = delivery_id(d)?;
    let parts = batch.iter().map(|e| event_part(e, recipient)).collect::<Result<Vec<_>>>()?;
    ensure!(delivery_id(&assemble(&parts)?)? == expected, "saved delivery identity mismatch");
    let mut acked = 0;
    for event in &batch {
        // Bound connection, send, and acknowledgement as one operation.
        match tokio::time::timeout(Duration::from_secs(20), crate::nostr_delivery::publish_event(relay, event)).await {
            Ok(Ok(_)) => acked += 1,
            _ => {
                return Ok(
                    serde_json::json!({"relayDelivered":false,"deliveryId":expected,"acknowledgedParts":acked,"totalParts":batch.len(),"retry":"private_ft_recover","retryTransferAllowed":false}),
                )
            }
        }
    }
    Ok(serde_json::json!({"relayDelivered":true,"deliveryId":expected,"acknowledgedParts":acked,"totalParts":batch.len()}))
}

#[derive(Serialize, Deserialize, Default)]
struct ReceiveState {
    services_cursor: Option<String>,
    group_cursor: String,
    #[serde(default)]
    discarded_groups: std::collections::BTreeSet<String>,
    #[serde(default)]
    retry_cursor: String,
    #[serde(default)]
    eviction_cursor: String,
    #[serde(default)]
    backed_parts: std::collections::BTreeSet<String>,
    #[serde(default)]
    replay: Option<ReplayState>,
}
/// Once overflow occurs, fixed-bound full-history sweeps remain enabled.
/// The next sweep always covers newer evictions too; no unbounded ticket list.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct ReplayState {
    after: Option<String>,
    through: Option<String>,
    round: u64,
    next_group: usize,
    covered_through: Option<String>,
    generation: u64,
    sweep_generation: u64,
}
fn dirty_replay(state: &mut ReceiveState) {
    let replay = state.replay.get_or_insert_with(ReplayState::default);
    replay.generation = replay.generation.wrapping_add(1);
    replay.covered_through = None;
}
/// Encrypted recovery candidates are durable before advancing a replay cursor.
fn pending_candidates(directory: &std::path::Path) -> Result<Vec<(String, Delivery)>> {
    let dir = directory.join("replay-pending");
    std::fs::create_dir_all(&dir)?;
    let mut result = vec![];
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            let value: (String, Delivery) = w::read(&path)?;
            result.push(value);
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}
fn journal_candidate(directory: &std::path::Path, group: &str, delivery: &Delivery) -> Result<bool> {
    let dir = directory.join("replay-pending");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", delivery_id(delivery)?));
    if path.exists() {
        return Ok(true);
    }
    let mut count = 0;
    let mut bytes = 0;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|e| e == "json") {
            count += 1;
            bytes += entry.metadata()?.len();
        }
    }
    let value = (group, delivery);
    if count >= 16 || bytes + serde_json::to_vec(&value)?.len() as u64 > 32 * 1024 * 1024 {
        return Ok(false);
    }
    w::save(&path, &value, true)?;
    Ok(true)
}
fn clear_pending(directory: &std::path::Path, id: &str) -> Result<()> {
    for ext in ["json", "lock"] {
        let path = directory.join("replay-pending").join(format!("{id}.{ext}"));
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}
pub struct Received {
    pub deliveries: Vec<(String, Delivery)>,
    pub source: &'static str,
    pub history_complete: bool,
    pub cache_full: bool,
}
async fn snapshot(recipient: &str, relay: &str) -> Result<Vec<String>> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (mut ws, _) = connect_async(relay).await?;
        let sub = w::new_id();
        let filter = serde_json::json!({"kinds":[1059],"#p":[recipient],"#t":[MARKER],"limit":MAX_EVENTS});
        ws.send(Message::Text(serde_json::json!(["REQ", sub, filter]).to_string())).await?;
        let mut result = vec![];
        let mut complete = false;
        while let Some(msg) = ws.next().await {
            let Message::Text(raw) = msg? else { continue };
            ensure!(raw.len() <= 101000, "oversized FT relay message");
            let v: serde_json::Value = serde_json::from_str(&raw)?;
            if v[1].as_str() != Some(sub.as_str()) {
                continue;
            }
            if v[0] == "EOSE" {
                complete = true;
                break;
            }
            if v[0] == "CLOSED" {
                anyhow::bail!("FT relay subscription rejected")
            }
            if v[0] == "EVENT" {
                result.push(serde_json::to_string(&v[2])?);
                if result.len() >= MAX_EVENTS {
                    complete = true;
                    break;
                }
            }
        }
        let _ = ws.close(None).await;
        ensure!(complete, "FT relay closed before snapshot completion");
        Ok::<_, anyhow::Error>(result)
    })
    .await
    .context("FT relay snapshot timed out")?
}
#[derive(Deserialize)]
struct MailboxPage {
    events: Vec<serde_json::Value>,
    next_cursor: Option<String>,
    has_more: bool,
    #[serde(default)]
    replay_supported: bool,
}
async fn mailbox_page(base: &str, recipient: &str, cursor: Option<&str>, group: Option<&str>) -> Result<MailboxPage> {
    mailbox_range(base, recipient, cursor, group, None).await
}
async fn mailbox_range(base: &str, recipient: &str, cursor: Option<&str>, group: Option<&str>, through: Option<&str>) -> Result<MailboxPage> {
    let mut url = reqwest::Url::parse(&format!("{}/api/v1/user/private-ft-deliveries", base.trim_end_matches('/')))?;
    ensure!(matches!(url.scheme(), "https" | "http"), "invalid FT mailbox scheme");
    url.query_pairs_mut()
        .append_pair("nostr_pubkey", recipient)
        .append_pair("limit", &MAX_EVENTS.to_string());
    if let Some(group) = group {
        ensure!(group.len() == 129 && group.as_bytes()[64] == b'-', "invalid recovery group");
        w::validate_id(&group[..64])?;
        w::validate_id(&group[65..])?;
        url.query_pairs_mut()
            .append_pair("author", &group[..64])
            .append_pair("delivery_id", &group[65..]);
    } else if let Some(cursor) = cursor {
        url.query_pairs_mut().append_pair("after", cursor);
    }
    if let Some(end) = through {
        url.query_pairs_mut().append_pair("through", end);
    }
    let mut response = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?
        .get(url)
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = vec![];
    while let Some(chunk) = response.chunk().await? {
        ensure!(bytes.len() + chunk.len() <= 32 * 1024 * 1024, "FT mailbox response too large");
        bytes.extend_from_slice(&chunk);
    }
    let mut body: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(body["success"] == true, "FT mailbox API failed");
    let page: MailboxPage = serde_json::from_value(body["data"].take())?;
    ensure!(
        page.events.len() <= MAX_EVENTS && page.next_cursor.as_ref().is_none_or(|s| s.len() <= 128),
        "invalid FT mailbox page"
    );
    ensure!(
        group.is_some() || page.events.is_empty() || (page.next_cursor.is_some() && page.next_cursor.as_deref() != cursor),
        "FT mailbox cursor did not advance"
    );
    ensure!(through.is_none() || page.replay_supported, "FT service lacks bounded replay support");
    Ok(page)
}
fn group_parts(events: &[serde_json::Value], recipient: &str, group: &str) -> Vec<Part> {
    events
        .iter()
        .filter_map(|raw| {
            let text = serde_json::to_string(raw).ok()?;
            let event = Event::from_json(&text).ok()?;
            let part = event_part(&text, recipient).ok()?;
            (format!("{}-{}", event.pubkey.to_hex(), part.delivery_id) == group).then_some(part)
        })
        .collect()
}
/// Services supplies stable keyset pagination. A legacy service falls back to
/// a standard NIP-01 latest-window snapshot, explicitly marked incomplete;
/// no unsupported event-ID-prefix extension is assumed.
pub async fn receive(network: &str, recipient: &str, relay: &str, services: Option<&str>) -> Result<Received> {
    receive_with_limits(network, recipient, relay, services, 4096, 32 * 1024 * 1024).await
}
async fn receive_with_limits(
    network: &str,
    recipient: &str,
    relay: &str,
    services: Option<&str>,
    max_files: usize,
    max_bytes: u64,
) -> Result<Received> {
    let recipient = PublicKey::parse(recipient)?.to_hex();
    let _lock = w::operation_lock(network, 0)?;
    let directory = w::directory(network)?.join(format!("relay-in-{recipient}"));
    let done_dir = directory.join("done");
    std::fs::create_dir_all(&done_dir)?;
    let state_path = directory.join("cursor.json");
    let mut state: ReceiveState = if state_path.exists() {
        w::read(&state_path)?
    } else {
        ReceiveState::default()
    };
    let mut files = BTreeMap::new();
    let mut total_bytes = 0u64;
    let mut cached: BTreeMap<String, Vec<(std::path::PathBuf, Part, bool)>> = BTreeMap::new();
    for entry in std::fs::read_dir(&directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") || path == state_path {
            continue;
        }
        let meta = entry.metadata()?;
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some((group, _)) = name.rsplit_once('-') else { continue };
        let part: Part = w::read(&path)?;
        if done_dir.join(format!("{}.json", part.delivery_id)).exists() {
            state.backed_parts.remove(name);
            std::fs::remove_file(&path)?;
            let _ = std::fs::remove_file(path.with_extension("lock"));
            continue;
        }
        cached.entry(group.to_owned()).or_default().push((
            path.clone(),
            part,
            meta.modified()?.elapsed().unwrap_or_default() > Duration::from_secs(7 * 86400),
        ));
        total_bytes += meta.len();
        files.insert(path, meta.len());
    }
    // Never expire a complete pending delivery. Evicted partial groups keep a
    // bounded durable recovery ticket; directed lookup does not rewind the scan.
    let mut expiry_order = cached.iter().collect::<Vec<_>>();
    let pivot = expiry_order.partition_point(|(group, _)| *group <= &state.eviction_cursor);
    expiry_order.rotate_left(pivot);
    let mut probed = false;
    for (group, entries) in expiry_order {
        let parts = entries.iter().map(|(_, p, _)| p.clone()).collect::<Vec<_>>();
        if services.is_some() && entries.iter().all(|(_, _, old)| *old) && assemble(&parts).is_err() {
            // A configured URL can still be an old service returning 404.
            // Verify this exact group's cached bytes are durably retrievable.
            if probed {
                break;
            }
            probed = true;
            state.eviction_cursor = group.clone();
            let Some(base) = services else { continue };
            let Ok(page) = mailbox_page(base, &recipient, None, Some(group)).await else {
                break;
            };
            let remote = page
                .events
                .iter()
                .filter_map(|raw| {
                    let text = serde_json::to_string(raw).ok()?;
                    let e = Event::from_json(&text).ok()?;
                    let p = event_part(&text, &recipient).ok()?;
                    (format!("{}-{}", e.pubkey.to_hex(), p.delivery_id) == *group).then_some(p)
                })
                .collect::<Vec<_>>();
            if !parts.iter().all(|part| {
                remote.iter().any(|r| {
                    r.index == part.index
                        && r.ciphertext == part.ciphertext
                        && r.total == part.total
                        && r.kind == part.kind
                        && r.ephemeral_pubkey == part.ephemeral_pubkey
                })
            }) {
                continue;
            }
            if state.discarded_groups.len() < 4096 {
                state.discarded_groups.insert(group.clone());
            } else if page.replay_supported {
                dirty_replay(&mut state);
            } else {
                continue;
            }
            // Persist the recovery ticket before deleting any ciphertext bytes.
            w::save(&state_path, &state, false)?;
            for (path, _, _) in entries {
                if let Some(len) = files.remove(path) {
                    total_bytes -= len;
                }
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    state.backed_parts.remove(name);
                }
                std::fs::remove_file(path)?;
                let _ = std::fs::remove_file(path.with_extension("lock"));
            }
        }
    }
    let mut recovered = pending_candidates(&directory)?;
    for (_, d) in &recovered {
        let id = delivery_id(d)?;
        if done_dir.join(format!("{id}.json")).exists() {
            clear_pending(&directory, &id)?;
        }
    }
    recovered.retain(|(_, d)| delivery_id(d).is_ok_and(|id| !done_dir.join(format!("{id}.json")).exists()));
    if let Some(base) = services {
        let ticket = state
            .discarded_groups
            .range((std::ops::Bound::Excluded(state.retry_cursor.clone()), std::ops::Bound::Unbounded))
            .next()
            .or_else(|| state.discarded_groups.iter().next())
            .cloned();
        if let Some(group) = ticket {
            state.retry_cursor = group.clone();
            if !done_dir.join(format!("{}.json", &group[65..])).exists() {
                if let Ok(page) = mailbox_page(base, &recipient, None, Some(&group)).await {
                    let parts = page
                        .events
                        .iter()
                        .filter_map(|raw| {
                            let text = serde_json::to_string(raw).ok()?;
                            let event = Event::from_json(&text).ok()?;
                            let part = event_part(&text, &recipient).ok()?;
                            (format!("{}-{}", event.pubkey.to_hex(), part.delivery_id) == group).then_some(part)
                        })
                        .collect::<Vec<_>>();
                    if let Ok(delivery) = assemble(&parts) {
                        if journal_candidate(&directory, &group, &delivery)? {
                            recovered.push((group.clone(), delivery));
                        }
                    }
                }
            } else {
                state.discarded_groups.remove(&group);
            }
        }
    }
    let mut source = "cache";
    let mut complete = false;
    let mut cache_full = false;
    let page = if let Some(base) = services {
        mailbox_page(base, &recipient, state.services_cursor.as_deref(), None).await.ok()
    } else {
        None
    };
    let replay_supported = page.as_ref().is_some_and(|p| p.replay_supported);
    let (raw, next_cursor) = if let Some(page) = page {
        source = "services";
        complete = !page.has_more;
        (
            page.events
                .iter()
                .map(serde_json::to_string)
                .collect::<std::result::Result<Vec<_>, _>>()?,
            page.next_cursor,
        )
    } else {
        match snapshot(&recipient, relay).await {
            Ok(raw) => {
                source = "relay_latest_window";
                (raw, None)
            }
            Err(_) => (vec![], None),
        }
    };
    for event_raw in raw {
        let Ok(part) = event_part(&event_raw, &recipient) else { continue };
        if done_dir.join(format!("{}.json", part.delivery_id)).exists() {
            continue;
        }
        let event = Event::from_json(&event_raw)?;
        let group = format!("{}-{}", event.pubkey.to_hex(), part.delivery_id);
        if state.discarded_groups.contains(&group) {
            continue;
        }
        let path = directory.join(format!("{group}-{}.json", part.index));
        if files.contains_key(&path) {
            if source == "services" && w::read::<Part>(&path)? == part {
                state.backed_parts.insert(path.file_name().unwrap().to_str().unwrap().to_owned());
            }
            continue;
        }
        let bytes = serde_json::to_vec(&part)?.len() as u64;
        while files.len() >= max_files || total_bytes + bytes > max_bytes {
            let victim = if replay_supported {
                cached
                    .iter()
                    .find(|(id, entries)| {
                        **id != group
                            && entries.iter().any(|(p, _, _)| files.contains_key(p))
                            && assemble(
                                &entries
                                    .iter()
                                    .filter(|(p, _, _)| files.contains_key(p))
                                    .map(|(_, p, _)| p.clone())
                                    .collect::<Vec<_>>(),
                            )
                            .is_err()
                            && entries
                                .iter()
                                .filter(|(p, _, _)| files.contains_key(p))
                                .all(|(p, _, _)| p.file_name().and_then(|s| s.to_str()).is_some_and(|n| state.backed_parts.contains(n)))
                    })
                    .map(|(id, _)| id.clone())
            } else {
                None
            };
            let Some(victim) = victim else { break };
            // Journal replay coverage before any ciphertext is deleted.
            dirty_replay(&mut state);
            w::save(&state_path, &state, false)?;
            if let Some(entries) = cached.remove(&victim) {
                for (path, _, _) in entries {
                    if let Some(len) = files.remove(&path) {
                        total_bytes -= len;
                        std::fs::remove_file(&path)?;
                        let _ = std::fs::remove_file(path.with_extension("lock"));
                        if let Some(n) = path.file_name().and_then(|s| s.to_str()) {
                            state.backed_parts.remove(n);
                        }
                    }
                }
            }
        }
        if files.len() >= max_files || total_bytes + bytes > max_bytes {
            cache_full = true;
            complete = false;
            if replay_supported {
                dirty_replay(&mut state);
                w::save(&state_path, &state, false)?;
                continue;
            }
            break;
        }
        w::save(&path, &part, true)?;
        if source == "services" {
            state.backed_parts.insert(path.file_name().unwrap().to_str().unwrap().to_owned());
        }
        files.insert(path.clone(), bytes);
        total_bytes += bytes;
        cached.entry(group).or_default().push((path, part, false));
    }
    if source == "services" && (!cache_full || replay_supported) {
        if next_cursor.is_some() {
            state.services_cursor = next_cursor;
        }
    }
    if replay_supported && state.replay.is_some() && !state.discarded_groups.is_empty() {
        dirty_replay(&mut state);
        state.discarded_groups.clear();
    }
    // Fixed snapshots and stable page offsets ensure every historical group gets
    // a turn. A dirty generation schedules another sweep without restarting this
    // one.
    if replay_supported {
        if let (Some(base), Some(mut replay)) = (services, state.replay.clone()) {
            if replay.covered_through != state.services_cursor || replay.covered_through.is_none() {
                if replay.through.is_none() {
                    replay.through = state.services_cursor.clone();
                    replay.sweep_generation = replay.generation;
                }
                if let Some(end) = replay.through.clone() {
                    if let Ok(page) = mailbox_range(base, &recipient, replay.after.as_deref(), None, Some(&end)).await {
                        let mut order = vec![];
                        let mut seen = std::collections::BTreeSet::new();
                        for raw in &page.events {
                            if let Ok(text) = serde_json::to_string(raw) {
                                if let Ok(part) = event_part(&text, &recipient) {
                                    let e = Event::from_json(&text)?;
                                    let group = format!("{}-{}", e.pubkey.to_hex(), part.delivery_id);
                                    if seen.insert(group.clone()) {
                                        order.push(group);
                                    }
                                }
                            }
                        }
                        let mut advanced = true;
                        if let Some(group) = order.get(replay.next_group) {
                            if !done_dir.join(format!("{}.json", &group[65..])).exists() {
                                match mailbox_page(base, &recipient, None, Some(group)).await {
                                    Ok(full) => {
                                        if let Ok(delivery) = assemble(&group_parts(&full.events, &recipient, group)) {
                                            advanced = journal_candidate(&directory, group, &delivery)?;
                                            if advanced {
                                                recovered.push((group.clone(), delivery));
                                            }
                                        }
                                    }
                                    Err(_) => advanced = false,
                                }
                            }
                            if advanced {
                                replay.next_group += 1;
                            }
                        }
                        if advanced && replay.next_group >= order.len() {
                            replay.next_group = 0;
                            if page.has_more {
                                replay.after = page.next_cursor;
                            } else {
                                // Returned pending candidates are not covered until acknowledged.
                                if replay.generation == replay.sweep_generation && pending_candidates(&directory)?.is_empty() {
                                    replay.covered_through = Some(end);
                                }
                                replay.after = None;
                                replay.through = None;
                                replay.round = replay.round.wrapping_add(1);
                            }
                        }
                    }
                }
            }
            state.replay = Some(replay);
        }
    }
    let mut groups: BTreeMap<String, Vec<Part>> = BTreeMap::new();
    for path in files.keys() {
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some((group, _)) = name.rsplit_once('-') else { continue };
        let part: Part = w::read(path)?;
        if done_dir.join(format!("{}.json", part.delivery_id)).exists() {
            continue;
        }
        groups.entry(group.to_owned()).or_default().push(part);
    }
    let mut ready = groups
        .into_iter()
        .filter_map(|(id, p)| assemble(&p).ok().map(|d| (id, d)))
        .collect::<Vec<_>>();
    let pivot = ready.partition_point(|(id, _)| id <= &state.group_cursor);
    ready.rotate_left(pivot);
    recovered.sort_by(|a, b| a.0.cmp(&b.0));
    recovered.dedup_by(|a, b| a.0 == b.0);
    recovered.truncate(16);
    ready.truncate(16usize.saturating_sub(recovered.len()));
    if let Some((last, _)) = ready.last() {
        state.group_cursor = last.clone();
    }
    ready.append(&mut recovered);
    let mut unique = std::collections::BTreeSet::new();
    ready.retain(|(_, delivery)| delivery_id(delivery).is_ok_and(|id| unique.insert(id)));
    complete &= state.discarded_groups.is_empty()
        && state
            .replay
            .as_ref()
            .is_none_or(|r| r.covered_through.is_some() && r.covered_through == state.services_cursor);
    w::save(&state_path, &state, false)?;
    Ok(Received {
        deliveries: ready,
        source,
        history_complete: complete,
        cache_full,
    })
}
/// Release a retryable complete candidate only after its recovery ticket is
/// durable.
pub async fn deferred(network: &str, recipient: &str, group: &str, delivery: &Delivery, services: &str) -> Result<bool> {
    ensure!(group.len() == 129 && group.as_bytes()[64] == b'-', "invalid FT group");
    w::validate_id(&group[..64])?;
    w::validate_id(&group[65..])?;
    let recipient = PublicKey::parse(recipient)?.to_hex();
    let Ok(page) = mailbox_page(services, &recipient, None, Some(group)).await else {
        return Ok(false);
    };
    let remote = page
        .events
        .iter()
        .filter_map(|raw| {
            let text = serde_json::to_string(raw).ok()?;
            let e = Event::from_json(&text).ok()?;
            let p = event_part(&text, &recipient).ok()?;
            (format!("{}-{}", e.pubkey.to_hex(), p.delivery_id) == group).then_some(p)
        })
        .collect::<Vec<_>>();
    let Ok(restored) = assemble(&remote) else { return Ok(false) };
    ensure!(delivery_id(&restored)? == delivery_id(delivery)?, "FT group recovery identity mismatch");
    let _lock = w::operation_lock(network, 0)?;
    let dir = w::directory(network)?.join(format!("relay-in-{recipient}"));
    let state_path = dir.join("cursor.json");
    let mut state: ReceiveState = w::read(&state_path)?;
    if state.discarded_groups.len() < 4096 {
        state.discarded_groups.insert(group.to_owned());
    } else if page.replay_supported {
        dirty_replay(&mut state);
    } else {
        return Ok(false);
    }
    if state.replay.is_some() {
        dirty_replay(&mut state);
    }
    state.backed_parts.retain(|name| !name.starts_with(&format!("{group}-")));
    w::save(&state_path, &state, false)?;
    clear_pending(&dir, &group[65..])?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_name().to_str().is_some_and(|n| n.starts_with(&format!("{group}-"))) {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(true)
}
/// Write one small completion record per stable ciphertext identity, not per
/// signature. Re-signing the same delivery cannot grow a monolithic index.
pub fn accepted(network: &str, recipient: &str, group: &str) -> Result<()> {
    ensure!(group.len() == 129 && group.as_bytes()[64] == b'-', "invalid FT group");
    w::validate_id(&group[..64])?;
    w::validate_id(&group[65..])?;
    let recipient = PublicKey::parse(recipient)?.to_hex();
    let _lock = w::operation_lock(network, 0)?;
    let dir = w::directory(network)?.join(format!("relay-in-{recipient}"));
    let done = dir.join("done");
    std::fs::create_dir_all(&done)?;
    w::save(&done.join(format!("{}.json", &group[65..])), &serde_json::json!({"accepted":true}), false)?;
    let state_path = dir.join("cursor.json");
    if state_path.exists() {
        let mut state: ReceiveState = w::read(&state_path)?;
        state.discarded_groups.retain(|g| !g.ends_with(&group[64..]));
        state
            .backed_parts
            .retain(|name| !name.get(64..).is_some_and(|suffix| suffix.starts_with(&format!("{}-", &group[64..]))));
        w::save(&state_path, &state, false)?;
    }
    clear_pending(&dir, &group[65..])?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .and_then(|n| n.get(64..))
            .is_some_and(|suffix| suffix.starts_with(&format!("{}-", &group[64..])))
        {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn services_pagination_rotation_and_signer_isolation() -> Result<()> {
        let _env_lock = crate::keystore::TEST_KEYSTORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use std::sync::Arc;

        use tokio::net::TcpListener;
        let keys = Keys::generate();
        let contact = w::Contact {
            network: "fixture".into(),
            user_id: 1,
            shielded_address: "".into(),
            npub: keys.public_key().to_hex(),
        };
        let mut all = vec![];
        for i in 0..40 {
            let packet = w::Packet {
                kind: "psy_private_ft_u124_v1".into(),
                contract_id: 2457,
                owner: [1; 4],
                amount: [7, 1],
                checkpoint: i + 1,
                user_tree_root: [2; 4],
                nullifiers: [[3; 4]; 2],
                proofs: [Some("x".repeat(220000)), Some("y".repeat(220000))],
            };
            all.extend(events(&contact.npub, &w::encrypt(&contact, &packet)?)?);
        }
        assert!(all.len() > 512);
        let mut forged = Event::from_json(&all[0])?;
        let mut part: Part = serde_json::from_str(&forged.content)?;
        part.ciphertext = serde_json::from_str::<Part>(&Event::from_json(&all[1])?.content)?.ciphertext;
        forged = EventBuilder::new(Kind::GiftWrap, serde_json::to_string(&part)?)
            .tags(forged.tags)
            .sign_with_keys(&Keys::generate())?;
        all.insert(0, forged.as_json());
        let initial = Event::from_json(&all[1])?;
        let initial_part = event_part(&all[1], &contact.npub)?;
        let recovery_group = format!("{}-{}", initial.pubkey.to_hex(), initial_part.delivery_id);
        let initial_raw = all[1].clone();
        let all = Arc::new(all);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let services = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut stream, _)) = listener.accept().await {
                let all = all.clone();
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let n = stream.read(&mut buffer).await.unwrap();
                    let request = String::from_utf8_lossy(&buffer[..n]);
                    let target = request.split_whitespace().nth(1).unwrap();
                    let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
                    let group_id = url.query_pairs().find(|(k, _)| k == "delivery_id").map(|(_, v)| v.to_string());
                    let author = url.query_pairs().find(|(k, _)| k == "author").map(|(_, v)| v.to_string());
                    if let (Some(id), Some(author)) = (group_id, author) {
                        let events = all
                            .iter()
                            .filter_map(|raw| {
                                let e = Event::from_json(raw).ok()?;
                                let p: Part = serde_json::from_str(&e.content).ok()?;
                                (e.pubkey.to_hex() == author && p.delivery_id == id).then(|| serde_json::from_str::<serde_json::Value>(raw).unwrap())
                            })
                            .collect::<Vec<_>>();
                        let body = serde_json::json!({"success":true,"data":{"events":events,"next_cursor":null,"has_more":false}}).to_string();
                        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        stream.write_all(header.as_bytes()).await.unwrap();
                        stream.write_all(body.as_bytes()).await.unwrap();
                        return;
                    }
                    let offset = url
                        .query_pairs()
                        .find(|(k, _)| k == "after")
                        .map(|(_, v)| v.parse::<usize>().unwrap())
                        .unwrap_or(0);
                    let page = all
                        .iter()
                        .skip(offset)
                        .take(MAX_EVENTS)
                        .map(|s| serde_json::from_str::<serde_json::Value>(s).unwrap())
                        .collect::<Vec<_>>();
                    let next = offset + page.len();
                    let body=serde_json::json!({"success":true,"data":{"events":page,"next_cursor":if next>offset{Some(next.to_string())}else{None},"has_more":next<all.len()}}).to_string();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(header.as_bytes()).await.unwrap();
                    stream.write_all(body.as_bytes()).await.unwrap();
                });
            }
        });
        let network = format!("private-ft-integration-test-{}", w::new_id());
        let dir = w::directory(&network)?.join(format!("relay-in-{}", contact.npub));
        std::fs::create_dir_all(&dir)?;
        let partial = event_part(&initial_raw, &contact.npub)?;
        let partial_path = dir.join(format!("{recovery_group}-0.json"));
        w::save(&partial_path, &partial, true)?;
        let old = std::time::SystemTime::now() - Duration::from_secs(8 * 86400);
        std::fs::File::open(&partial_path)?.set_times(std::fs::FileTimes::new().set_modified(old))?;
        // Skip the first genuine group's rows in the normal forward scan.
        w::save(
            &dir.join("cursor.json"),
            &ReceiveState {
                services_cursor: Some((initial_part.total + 1).to_string()),
                ..Default::default()
            },
            true,
        )?;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..40 {
            for (group, d) in receive(&network, &contact.npub, "ws://127.0.0.1:1", Some(&services)).await?.deliveries {
                let packet = w::decrypt(&keys.secret_key().to_secret_hex(), &d)?;
                seen.insert(packet.checkpoint);
                accepted(&network, &contact.npub, &group)?;
            }
            if seen.len() == 40 {
                break;
            }
        }
        task.abort();
        assert_eq!(
            seen.len(),
            40,
            "all complete deliveries, including those outside the first relay window, must be discoverable"
        );
        std::fs::remove_dir_all(w::directory(&network)?)?;
        Ok(())
    }
    #[tokio::test]
    async fn a_full_cache_still_returns_complete_local_deliveries() -> Result<()> {
        let _env_lock = crate::keystore::TEST_KEYSTORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let keys = Keys::generate();
        let network = format!("private-ft-full-cache-test-{}", w::new_id());
        let contact = w::Contact {
            network: network.clone(),
            user_id: 1,
            shielded_address: "".into(),
            npub: keys.public_key().to_hex(),
        };
        let packet = w::Packet {
            kind: "psy_private_ft_single_v1".into(),
            contract_id: 0,
            owner: [1; 4],
            amount: [7, 0],
            checkpoint: 1,
            user_tree_root: [2; 4],
            nullifiers: [[3; 4], [0; 4]],
            proofs: [Some("fixture".into()), None],
        };
        let d = w::encrypt(&contact, &packet)?;
        let event = Event::from_json(&events(&contact.npub, &d)?[0])?;
        let part = event_part(&event.as_json(), &contact.npub)?;
        let dir = w::directory(&network)?.join(format!("relay-in-{}", contact.npub));
        std::fs::create_dir_all(&dir)?;
        let group = format!("{}-{}", event.pubkey.to_hex(), part.delivery_id);
        w::save(&dir.join(format!("{group}-0.json")), &part, true)?;
        // Complete pending groups survive outages longer than the partial TTL.
        let old = std::time::SystemTime::now() - Duration::from_secs(8 * 86400);
        std::fs::File::open(dir.join(format!("{group}-0.json")))?.set_times(std::fs::FileTimes::new().set_modified(old))?;
        let other = w::encrypt(&contact, &packet)?;
        let incoming = events(&contact.npub, &other)?;
        let incoming: Vec<serde_json::Value> = incoming.iter().map(|v| serde_json::from_str(v)).collect::<std::result::Result<_, _>>()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut b = [0; 4096];
            let _ = stream.read(&mut b).await;
            let body = serde_json::json!({"success":true,"data":{"events":incoming,"next_cursor":"next","has_more":false}}).to_string();
            let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(body.as_bytes()).await.unwrap();
        });
        let result = receive_with_limits(&network, &contact.npub, "ws://127.0.0.1:1", Some(&base), 1, 32 * 1024 * 1024).await?;
        task.await?;
        assert!(result.cache_full);
        assert!(!result.history_complete);
        assert_eq!(result.deliveries.len(), 1);
        assert_eq!(delivery_id(&result.deliveries[0].1)?, delivery_id(&d)?);
        accepted(&network, &contact.npub, &group)?;
        let state: ReceiveState = w::read(&dir.join("cursor.json"))?;
        assert!(state.services_cursor.is_none());
        assert!(dir.join("done").join(format!("{}.json", part.delivery_id)).exists());
        std::fs::remove_dir_all(w::directory(&network)?)?;
        Ok(())
    }
    #[tokio::test]
    async fn expired_blocking_prefix_cannot_replay_forever() -> Result<()> {
        let _env_lock = crate::keystore::TEST_KEYSTORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let keys = Keys::generate();
        let network = format!("private-ft-expiry-test-{}", w::new_id());
        let contact = w::Contact {
            network: network.clone(),
            user_id: 1,
            shielded_address: "".into(),
            npub: keys.public_key().to_hex(),
        };
        let mut packet = w::Packet {
            kind: "psy_private_ft_single_v1".into(),
            contract_id: 0,
            owner: [1; 4],
            amount: [7, 0],
            checkpoint: 1,
            user_tree_root: [2; 4],
            nullifiers: [[3; 4], [0; 4]],
            proofs: [Some("x".repeat(33000)), None],
        };
        let mut raw = vec![];
        for _ in 0..2 {
            raw.push(events(&contact.npub, &w::encrypt(&contact, &packet)?)?[0].clone());
        }
        packet.proofs[0] = Some("fixture".into());
        let good = w::encrypt(&contact, &packet)?;
        raw.extend(events(&contact.npub, &good)?);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut b = [0; 4096];
                let _ = stream.read(&mut b).await;
                let events = raw
                    .iter()
                    .map(|e| serde_json::from_str::<serde_json::Value>(e).unwrap())
                    .collect::<Vec<_>>();
                let body = serde_json::json!({"success":true,"data":{"events":events,"next_cursor":"next","has_more":false}}).to_string();
                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                stream.write_all(header.as_bytes()).await.unwrap();
                stream.write_all(body.as_bytes()).await.unwrap();
            }
        });
        let first = receive_with_limits(&network, &contact.npub, "ws://127.0.0.1:1", Some(&base), 2, 32 * 1024 * 1024).await?;
        assert!(first.cache_full);
        assert!(first.deliveries.is_empty());
        let dir = w::directory(&network)?.join(format!("relay-in-{}", contact.npub));
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|s| s == "json") && path.file_name().and_then(|s| s.to_str()) != Some("cursor.json") {
                let old = std::time::SystemTime::now() - Duration::from_secs(8 * 86400);
                std::fs::File::open(path)?.set_times(std::fs::FileTimes::new().set_modified(old))?;
            }
        }
        let second = receive_with_limits(&network, &contact.npub, "ws://127.0.0.1:1", Some(&base), 2, 32 * 1024 * 1024).await?;
        assert!(!second.cache_full);
        assert_eq!(second.deliveries.len(), 1);
        assert_eq!(delivery_id(&second.deliveries[0].1)?, delivery_id(&good)?);
        let state: ReceiveState = w::read(&dir.join("cursor.json"))?;
        assert_eq!(state.services_cursor.as_deref(), Some("next"));
        assert_eq!(state.discarded_groups.len(), 1);
        task.await?;
        std::fs::remove_dir_all(w::directory(&network)?)?;
        Ok(())
    }
    #[tokio::test]
    async fn old_services_cannot_expire_unbacked_relay_fragments() -> Result<()> {
        let _env_lock = crate::keystore::TEST_KEYSTORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let keys = Keys::generate();
        let network = format!("private-ft-old-services-{}", w::new_id());
        let contact = w::Contact {
            network: network.clone(),
            user_id: 1,
            shielded_address: String::new(),
            npub: keys.public_key().to_hex(),
        };
        let packet = w::Packet {
            kind: "psy_private_ft_u124_v1".into(),
            contract_id: 2457,
            owner: [1; 4],
            amount: [7, 1],
            checkpoint: 1,
            user_tree_root: [2; 4],
            nullifiers: [[3; 4], [4; 4]],
            proofs: [Some("x".repeat(33000)), Some("y".repeat(33000))],
        };
        let raw = events(&contact.npub, &w::encrypt(&contact, &packet)?)?;
        let event = Event::from_json(&raw[0])?;
        let part = event_part(&raw[0], &contact.npub)?;
        let dir = w::directory(&network)?.join(format!("relay-in-{}", contact.npub));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}-{}-0.json", event.pubkey.to_hex(), part.delivery_id));
        w::save(&path, &part, true)?;
        std::fs::File::open(&path)?
            .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now() - Duration::from_secs(8 * 86400)))?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut b = [0; 4096];
                let _ = stream.read(&mut b).await;
                stream
                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let result = receive(&network, &contact.npub, "ws://127.0.0.1:1", Some(&base)).await?;
        assert!(path.exists());
        assert!(result.deliveries.is_empty());
        let state: ReceiveState = w::read(&dir.join("cursor.json"))?;
        assert!(state.discarded_groups.is_empty());
        task.await?;
        std::fs::remove_dir_all(w::directory(&network)?)?;
        Ok(())
    }
    #[tokio::test]
    async fn full_ticket_queue_cannot_block_new_deliveries_and_replay_survives_restart() -> Result<()> {
        let _env_lock = crate::keystore::TEST_KEYSTORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use std::sync::Arc;

        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let keys = Keys::generate();
        let network = format!("ft-overflow-{}", w::new_id());
        let contact = w::Contact {
            network: network.clone(),
            user_id: 1,
            shielded_address: String::new(),
            npub: keys.public_key().to_hex(),
        };
        let mut packet = w::Packet {
            kind: "psy_private_ft_u124_v1".into(),
            contract_id: 2457,
            owner: [1; 4],
            amount: [7, 1],
            checkpoint: 1,
            user_tree_root: [2; 4],
            nullifiers: [[3; 4], [4; 4]],
            proofs: [Some("x".repeat(33000)), Some("y".repeat(33000))],
        };
        let signer = Keys::generate();
        let mut all = vec![];
        for i in 0..8 {
            let raw = events(&contact.npub, &w::encrypt(&contact, &packet)?)?;
            let mut part = event_part(&raw[0], &contact.npub)?;
            part.delivery_id = format!("{i:064x}");
            all.push(
                EventBuilder::new(Kind::GiftWrap, serde_json::to_string(&part)?)
                    .tags([Tag::public_key(keys.public_key()), Tag::parse(["t", MARKER])?])
                    .sign_with_keys(&signer)?
                    .as_json(),
            );
        }
        packet.proofs = [Some("fixture".into()), Some("fixture".into())];
        let good = w::encrypt(&contact, &packet)?;
        all.extend(events(&contact.npub, &good)?);
        let all = Arc::new(all);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let all = all.clone();
                tokio::spawn(async move {
                    let mut buffer = [0; 4096];
                    let n = stream.read(&mut buffer).await.unwrap();
                    let request = String::from_utf8_lossy(&buffer[..n]);
                    let target = request.split_whitespace().nth(1).unwrap();
                    let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
                    let q = url.query_pairs().into_owned().collect::<BTreeMap<_, _>>();
                    let start = q.get("after").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                    let end = q.get("through").and_then(|s| s.parse::<usize>().ok()).unwrap_or(all.len());
                    let group = q.get("delivery_id");
                    let raw: Vec<_> = if let Some(id) = group {
                        all.iter()
                            .filter(|raw| {
                                let e = Event::from_json(*raw).unwrap();
                                let p: Part = serde_json::from_str(&e.content).unwrap();
                                p.delivery_id == *id && Some(e.pubkey.to_hex()).as_ref() == q.get("author")
                            })
                            .cloned()
                            .collect()
                    } else {
                        all.iter().skip(start).take(end.saturating_sub(start).min(MAX_EVENTS)).cloned().collect()
                    };
                    let next = start + raw.len();
                    let events = raw
                        .iter()
                        .map(|s| serde_json::from_str::<serde_json::Value>(s).unwrap())
                        .collect::<Vec<_>>();
                    let body=serde_json::json!({"success":true,"data":{"events":events,"next_cursor":if group.is_none()&&next>start{Some(next.to_string())}else{None},"has_more":group.is_none()&&next<end,"replay_supported":true}}).to_string();
                    let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    stream.write_all(header.as_bytes()).await.unwrap();
                    stream.write_all(body.as_bytes()).await.unwrap();
                });
            }
        });
        let dir = w::directory(&network)?.join(format!("relay-in-{}", contact.npub));
        std::fs::create_dir_all(&dir)?;
        let tickets = (0..4096).map(|i| format!("{}-{i:064x}", keys.public_key().to_hex())).collect();
        w::save(
            &dir.join("cursor.json"),
            &ReceiveState {
                discarded_groups: tickets,
                ..Default::default()
            },
            true,
        )?;
        let first = receive_with_limits(&network, &contact.npub, "ws://127.0.0.1:1", Some(&base), 2, 32 * 1024 * 1024).await?;
        assert!(first
            .deliveries
            .iter()
            .any(|(_, d)| delivery_id(d).unwrap() == delivery_id(&good).unwrap()));
        assert!(
            std::fs::read_dir(&dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file() && !e.file_name().to_string_lossy().starts_with("cursor."))
                .count()
                <= 4,
            "hot JSON and lock files must both remain bounded"
        );
        let state: ReceiveState = w::read(&dir.join("cursor.json"))?;
        assert!(state.replay.is_some());
        assert!(state.discarded_groups.is_empty());
        assert!(state.services_cursor.is_some());
        // Restart with the persisted cursor/range; a valid pending delivery is
        // still reachable even though both cache and ticket quota were full.
        let second = receive_with_limits(&network, &contact.npub, "ws://127.0.0.1:1", Some(&base), 2, 32 * 1024 * 1024).await?;
        assert!(second
            .deliveries
            .iter()
            .any(|(_, d)| delivery_id(d).unwrap() == delivery_id(&good).unwrap()));
        for (group, delivery) in second.deliveries {
            if delivery_id(&delivery)? == delivery_id(&good)? {
                accepted(&network, &contact.npub, &group)?;
            }
        }
        let mut completed = false;
        for _ in 0..12 {
            let next = receive_with_limits(&network, &contact.npub, "ws://127.0.0.1:1", Some(&base), 2, 32 * 1024 * 1024).await?;
            if next.history_complete {
                completed = true;
                break;
            }
        }
        assert!(completed, "a drained overflow must return to complete");
        task.abort();
        std::fs::remove_dir_all(w::directory(&network)?)?;
        Ok(())
    }
    #[tokio::test]
    async fn replay_journal_survives_restart_and_acknowledgement_cleans_all_signers() -> Result<()> {
        let _env_lock = crate::keystore::TEST_KEYSTORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let network = format!("ft-journal-{}", w::new_id());
        let recipient = Keys::generate().public_key().to_hex();
        let contact = w::Contact {
            network: network.clone(),
            user_id: 1,
            shielded_address: String::new(),
            npub: recipient.clone(),
        };
        let packet = w::Packet {
            kind: "psy_private_ft_u124_v1".into(),
            contract_id: 2457,
            owner: [1; 4],
            amount: [1, 1],
            checkpoint: 1,
            user_tree_root: [2; 4],
            nullifiers: [[3; 4], [4; 4]],
            proofs: [Some("fixture".into()), Some("fixture".into())],
        };
        let delivery = w::encrypt(&contact, &packet)?;
        let id = delivery_id(&delivery)?;
        let dir = w::directory(&network)?.join(format!("relay-in-{recipient}"));
        std::fs::create_dir_all(&dir)?;
        let raw = events(&recipient, &delivery)?;
        let part = event_part(&raw[0], &recipient)?;
        let a = format!("{}-{id}", Keys::generate().public_key().to_hex());
        let b = format!("{}-{id}", Keys::generate().public_key().to_hex());
        for group in [&a, &b] {
            w::save(&dir.join(format!("{group}-0.json")), &part, true)?;
        }
        assert!(journal_candidate(&dir, &a, &delivery)?);
        // Only the journal survives a crash between cursor save and verification.
        for group in [&a, &b] {
            std::fs::remove_file(dir.join(format!("{group}-0.json")))?;
            let _ = std::fs::remove_file(dir.join(format!("{group}-0.lock")));
        }
        let restored = receive(&network, &recipient, "ws://127.0.0.1:1", None).await?;
        assert_eq!(restored.deliveries.len(), 1);
        assert_eq!(delivery_id(&restored.deliveries[0].1)?, id);
        for group in [&a, &b] {
            w::save(&dir.join(format!("{group}-0.json")), &part, true)?;
        }
        accepted(&network, &recipient, &a)?;
        accepted(&network, &recipient, &a)?;
        assert!(pending_candidates(&dir)?.is_empty());
        assert!(!dir.join(format!("{a}-0.json")).exists());
        assert!(!dir.join(format!("{b}-0.lock")).exists());
        // Compatibility: old done-marked alias files are cleaned on startup too.
        w::save(&dir.join(format!("{b}-0.json")), &part, true)?;
        assert!(receive(&network, &recipient, "ws://127.0.0.1:1", None).await?.deliveries.is_empty());
        assert!(!dir.join(format!("{b}-0.json")).exists());
        std::fs::remove_dir_all(w::directory(&network)?)?;
        Ok(())
    }
    #[test]
    fn pending_journal_capacity_never_overwrites_unacknowledged_candidates() -> Result<()> {
        let _env_lock = crate::keystore::TEST_KEYSTORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let network = format!("ft-journal-quota-{}", w::new_id());
        let directory = w::directory(&network)?;
        let mut delivery = Delivery {
            kind: "psy_private_ft_u124_v1".into(),
            ephemeral_pubkey: String::new(),
            ciphertexts: vec!["synthetic encrypted fixture".into()],
        };
        let group = format!("{}-{}", "a".repeat(64), "b".repeat(64));
        for _ in 0..16 {
            delivery.ephemeral_pubkey = Keys::generate().public_key().to_hex();
            assert!(journal_candidate(&directory, &group, &delivery)?);
        }
        delivery.ephemeral_pubkey = Keys::generate().public_key().to_hex();
        assert!(!journal_candidate(&directory, &group, &delivery)?);
        assert_eq!(pending_candidates(&directory)?.len(), 16);
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }
    #[test]
    fn dirty_generation_preserves_active_snapshot_and_offset() {
        let mut state = ReceiveState {
            replay: Some(ReplayState {
                after: Some("page1".into()),
                through: Some("end".into()),
                next_group: 2,
                covered_through: Some("end".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        dirty_replay(&mut state);
        let r = state.replay.unwrap();
        assert_eq!(r.after.as_deref(), Some("page1"));
        assert_eq!(r.next_group, 2);
        assert_eq!(r.generation, 1);
        assert!(r.covered_through.is_none());
    }
    #[test]
    fn export_synthetic_interop_fixture() -> Result<()> {
        let Some(path) = std::env::var_os("PSY_FT_INTEROP_FIXTURE") else {
            return Ok(());
        };
        // Synthetic public test key, unrelated to any wallet or funded account.
        let mut raw = [0u8; 32];
        raw[31] = 1;
        let keys = Keys::new(nostr::SecretKey::from_slice(&raw)?);
        let contact = w::Contact {
            network: "fixture".into(),
            user_id: 1,
            shielded_address: "".into(),
            npub: keys.public_key().to_hex(),
        };
        let packet = w::Packet {
            kind: "psy_private_ft_u124_v1".into(),
            contract_id: 2457,
            owner: [1; 4],
            amount: [1000000000000000017, 2],
            checkpoint: 123,
            user_tree_root: [2; 4],
            nullifiers: [[3; 4], [4; 4]],
            proofs: [Some("x".repeat(33000)), Some("y".repeat(33000))],
        };
        let delivery = w::encrypt(&contact, &packet)?;
        let events = events(&contact.npub, &delivery)?
            .iter()
            .map(|e| serde_json::from_str::<serde_json::Value>(e))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        std::fs::write(
            path,
            serde_json::to_vec(
                &serde_json::json!({"syntheticSecretHex":hex::encode(raw),"recipient":contact.npub,"packet":serde_json::to_string(&packet)?,"events":events}),
            )?,
        )?;
        Ok(())
    }
    #[test]
    fn signed_chunk_roundtrip_and_poison_rejection() -> Result<()> {
        let keys = Keys::generate();
        let other = Keys::generate();
        let contact = w::Contact {
            network: "n".into(),
            user_id: 1,
            shielded_address: "".into(),
            npub: keys.public_key().to_hex(),
        };
        for kind in ["psy_private_ft_single_v1", "psy_private_ft_u124_v1"] {
            let packet = w::Packet {
                kind: kind.into(),
                contract_id: 2457,
                owner: [1; 4],
                amount: [7, 1],
                checkpoint: 4,
                user_tree_root: [2; 4],
                nullifiers: [[3; 4]; 2],
                proofs: [Some("x".repeat(90000)), Some("y".repeat(90000))],
            };
            let delivery = w::encrypt(&contact, &packet)?;
            let signed = events(&contact.npub, &delivery)?;
            assert!(signed.len() > 2);
            let mut parts = signed.iter().map(|e| event_part(e, &contact.npub)).collect::<Result<Vec<_>>>()?;
            assert!(event_part(&signed[0], &other.public_key().to_hex()).is_err());
            parts.reverse();
            assert_eq!(delivery_id(&assemble(&parts)?)?, delivery_id(&delivery)?);
            assert!(assemble(&parts[1..]).is_err());
            let mut resigned = parts.clone();
            resigned.push(parts[0].clone());
            assert_eq!(delivery_id(&assemble(&resigned)?)?, delivery_id(&delivery)?);
            let mut poisoned = parts.clone();
            poisoned[0].ciphertext = poisoned[1].ciphertext.clone();
            assert!(assemble(&poisoned).is_err());
            let mut forged: serde_json::Value = serde_json::from_str(&signed[0])?;
            forged["content"] = serde_json::json!("plaintext");
            assert!(event_part(&forged.to_string(), &contact.npub).is_err());
            assert_eq!(w::decrypt(&keys.secret_key().to_secret_hex(), &assemble(&parts)?)?.amount, [7, 1]);
        }
        Ok(())
    }
}
