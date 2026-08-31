//! `init-realm-p2p-keys`: materialize Realm P2P identity/BLS key files and a
//! `roster.json` for local E2E.
//!
//! For each `(realm, sub)` pair this writes:
//!   - `realm_{id}_sub_{sub}_processor_identity.key` (libp2p Ed25519 protobuf)
//!   - `realm_{id}_sub_{sub}_edge_identity.key`     (libp2p Ed25519 protobuf)
//!   - `realm_{id}_sub_{sub}_bls.key`               (64 hex chars, no newline)
//!
//! plus a single `coordinator_identity.key` used as a dummy coordinator
//! multiaddr target, and a `roster.json` describing the generated material.
//!
//! Only the roster path is printed. BLS secrets and identity seeds never
//! reach stdout. Paths recorded in `roster.json` are repo-relative (the
//! `--out-dir` value as given); no absolute `<workspace>/...` paths are emitted.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

use psy_data::p2p::NodeId;
use psy_node_common::realm::network::{
    generate_bls_secret_file, generate_ed25519_identity_file,
};

#[derive(Clone, Serialize)]
struct SubEntry {
    processor_node_id_hex38: String,
    processor_peer_id: String,
    edge_node_id_hex38: String,
    edge_peer_id: String,
    bls_public_hex: String,
    processor_identity_path: String,
    edge_identity_path: String,
    bls_path: String,
}

#[derive(Clone, Serialize)]
struct CoordinatorEntry {
    peer_id: String,
    node_id_hex38: String,
    identity_path: String,
}

#[derive(Serialize)]
struct Roster {
    coordinator: CoordinatorEntry,
    realms: BTreeMap<String, BTreeMap<String, SubEntry>>,
}

/// Join `out_dir` (as given on the command line) with `file` using a single
/// forward slash, preserving the caller's repo-relative form.
fn join_path(out_dir: &str, file: &str) -> String {
    let trimmed = out_dir.trim_end_matches('/');
    format!("{trimmed}/{file}")
}

pub async fn run(out_dir: String, realm_ids: Vec<u64>, sub_ids: Vec<u16>) -> anyhow::Result<()> {
    if realm_ids.is_empty() {
        anyhow::bail!("--realm-ids must list at least one realm id");
    }
    if sub_ids.is_empty() {
        anyhow::bail!("--sub-ids must list at least one sub id");
    }

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| anyhow::anyhow!("failed to create out-dir {out_dir}: {e}"))?;

    let mut realms: BTreeMap<String, BTreeMap<String, SubEntry>> = BTreeMap::new();
    for realm_id in &realm_ids {
        let mut subs: BTreeMap<String, SubEntry> = BTreeMap::new();
        for sub_id in &sub_ids {
            let processor_file = format!("realm_{realm_id}_sub_{sub_id}_processor_identity.key");
            let edge_file = format!("realm_{realm_id}_sub_{sub_id}_edge_identity.key");
            let bls_file = format!("realm_{realm_id}_sub_{sub_id}_bls.key");

            let processor_path = join_path(&out_dir, &processor_file);
            let edge_path = join_path(&out_dir, &edge_file);
            let bls_path = join_path(&out_dir, &bls_file);

            let processor_node_id = generate_ed25519_identity_file(&processor_path)
                .map_err(|e| anyhow::anyhow!("failed to write {processor_path}: {e}"))?;
            let edge_node_id = generate_ed25519_identity_file(&edge_path)
                .map_err(|e| anyhow::anyhow!("failed to write {edge_path}: {e}"))?;
            let bls_public = generate_bls_secret_file(&bls_path)
                .map_err(|e| anyhow::anyhow!("failed to write {bls_path}: {e}"))?;

            subs.insert(
                sub_id.to_string(),
                SubEntry {
                    processor_node_id_hex38: hex::encode(processor_node_id.to_raw()),
                    processor_peer_id: processor_node_id.to_base58(),
                    edge_node_id_hex38: hex::encode(edge_node_id.to_raw()),
                    edge_peer_id: edge_node_id.to_base58(),
                    bls_public_hex: hex::encode(bls_public.to_bytes()),
                    processor_identity_path: processor_path,
                    edge_identity_path: edge_path,
                    bls_path,
                },
            );
        }
        realms.insert(realm_id.to_string(), subs);
    }

    let coordinator_file = "coordinator_identity.key";
    let coordinator_path = join_path(&out_dir, coordinator_file);
    let coordinator_node_id = generate_ed25519_identity_file(&coordinator_path)
        .map_err(|e| anyhow::anyhow!("failed to write {coordinator_path}: {e}"))?;
    let coordinator = CoordinatorEntry {
        peer_id: coordinator_node_id.to_base58(),
        node_id_hex38: hex::encode(coordinator_node_id.to_raw()),
        identity_path: coordinator_path,
    };

    let roster = Roster { coordinator, realms };
    let roster_path = join_path(&out_dir, "roster.json");
    let json = serde_json::to_string_pretty(&roster)
        .map_err(|e| anyhow::anyhow!("failed to serialize roster: {e}"))?;
    std::fs::write(Path::new(&roster_path), json)
        .map_err(|e| anyhow::anyhow!("failed to write {roster_path}: {e}"))?;

    // Print only the roster path. No secrets reach stdout.
    println!("{roster_path}");
    Ok(())
}