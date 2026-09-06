//! Generate local Realm P2P secrets and update a full network config.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use psy_data::p2p::{MAX_VALIDATORS_PER_REALM, MIN_VALIDATORS_PER_REALM};
use psy_node_common::realm::network::{generate_bls_secret_file, generate_ed25519_identity_file};
use serde_json::{json, Value};

fn join_path(out_dir: &str, file: &str) -> String {
    format!("{}/{}", out_dir.trim_end_matches('/'), file)
}
fn preflight_validator_count(validators_per_realm: u16) -> anyhow::Result<()> {
    anyhow::ensure!(
        (MIN_VALIDATORS_PER_REALM..=MAX_VALIDATORS_PER_REALM)
            .contains(&usize::from(validators_per_realm)),
        "--validators-per-realm must be in {MIN_VALIDATORS_PER_REALM}..={MAX_VALIDATORS_PER_REALM}"
    );
    Ok(())
}
fn preflight_public_ports(realm_ids: &[u64], validators_per_realm: u16, edges_per_validator: u16) -> anyhow::Result<()> {
    let realm_stride = u64::from(20_u16.max(validators_per_realm.checked_mul(edges_per_validator)
        .ok_or_else(|| anyhow::anyhow!("Realm P2P edge count overflows"))?));
    let mut owners = HashMap::<u64, String>::new();
    for &realm_id in realm_ids {
        for position in 1..=validators_per_realm {
            let processor_port = 41000_u64
                .checked_add(realm_id.checked_mul(20).ok_or_else(|| anyhow::anyhow!("Realm {realm_id} P2P port overflows"))?)
                .and_then(|port| port.checked_add(u64::from(position)))
                .ok_or_else(|| anyhow::anyhow!("Realm {realm_id} processor P2P port overflows"))?;
            anyhow::ensure!(processor_port <= u16::MAX.into(), "Realm {realm_id} processor P2P port exceeds {}", u16::MAX);
            let processor_owner = format!("processor Realm {realm_id} validator {position}");
            if let Some(previous) = owners.insert(processor_port, processor_owner.clone()) {
                anyhow::bail!("TCP port {processor_port} is assigned to both {previous} and {processor_owner}");
            }
            for edge_index in 0..edges_per_validator {
                let edge_port = 41100_u64
                    .checked_add(realm_id.checked_mul(realm_stride).ok_or_else(|| anyhow::anyhow!("Realm {realm_id} P2P port overflows"))?)
                    .and_then(|port| port.checked_add(u64::from(position - 1) * u64::from(edges_per_validator)))
                    .and_then(|port| port.checked_add(u64::from(edge_index) + 1))
                    .ok_or_else(|| anyhow::anyhow!("Realm {realm_id} edge P2P port overflows"))?;
                anyhow::ensure!(edge_port <= u16::MAX.into(), "Realm {realm_id} edge P2P port exceeds {}", u16::MAX);
                let edge_owner = format!("edge Realm {realm_id} validator {position} edge {edge_index}");
                if let Some(previous) = owners.insert(edge_port, edge_owner.clone()) {
                    anyhow::bail!("TCP port {edge_port} is assigned to both {previous} and {edge_owner}");
                }
            }
        }
    }
    Ok(())
}
fn clear_inactive_realms(realms: &mut [Value], active_realm_ids: &HashSet<u64>) {
    for realm in realms {
        let Some(realm_id) = realm.get("id").and_then(Value::as_u64) else {
            continue;
        };
        if !active_realm_ids.contains(&realm_id) {
            realm["validators"] = json!([]);
        }
    }
}




pub async fn run(out_dir: String, realm_ids: Vec<u64>, validators_per_realm: u16, edges_per_validator: u16, validator_user_ids: Vec<u64>) -> anyhow::Result<()> {
    anyhow::ensure!(!realm_ids.is_empty(), "--realm-ids must list at least one realm id");
    let active_realm_ids: HashSet<u64> = realm_ids.iter().copied().collect();
    anyhow::ensure!(active_realm_ids.len() == realm_ids.len(), "--realm-ids contains a duplicate Realm id");
    preflight_validator_count(validators_per_realm)?;
    anyhow::ensure!(validator_user_ids.len() == realm_ids.len() * usize::from(validators_per_realm), "--validator-user-ids must provide one user id per validator, in --realm-ids order");
    anyhow::ensure!(validator_user_ids.iter().copied().collect::<HashSet<_>>().len() == validator_user_ids.len(), "--validator-user-ids contains a duplicate user id");
    anyhow::ensure!((1..=u8::MAX as u16).contains(&edges_per_validator), "--edges-per-validator must be in 1..=255");
    preflight_public_ports(&realm_ids, validators_per_realm, edges_per_validator)?;

    let source_path = std::env::var("PSY_CONFIG_PATH").unwrap_or_else(|_| "psy-genesis/config.json".into());
    let mut root: Value = serde_json::from_str(&std::fs::read_to_string(&source_path)
        .map_err(|error| anyhow::anyhow!("failed to read network config {source_path}: {error}"))?)?;
    let default_network = root.get("defaultNetwork").and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("network config has no defaultNetwork"))?;
    let network_name = std::env::var("PSY_NETWORK").unwrap_or_else(|_| default_network.to_string());
    let public_host = std::env::var("PSY_REALM_P2P_PUBLIC_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let public_host_protocol = if public_host.parse::<std::net::Ipv4Addr>().is_ok() {
        "ip4"
    } else if public_host.parse::<std::net::Ipv6Addr>().is_ok() {
        "ip6"
    } else {
        "dns4"
    };
    root["defaultNetwork"] = Value::String(network_name.clone());
    let network = root.get_mut("networks").and_then(Value::as_object_mut)
        .and_then(|networks| networks.get_mut(&network_name))
        .ok_or_else(|| anyhow::anyhow!("network config has no network {network_name}"))?;
    let realm_user_tree_height = network.get("realm_user_tree_height").and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("network {network_name} has no realm_user_tree_height"))?;
    anyhow::ensure!(realm_user_tree_height < u64::BITS as u64, "network {network_name} realm_user_tree_height must be less than {}", u64::BITS);
    let users_per_realm = 1_u64.checked_shl(realm_user_tree_height as u32)
        .ok_or_else(|| anyhow::anyhow!("network {network_name} realm user range overflows u64"))?;
    anyhow::ensure!(u64::from(validators_per_realm) <= users_per_realm, "--validators-per-realm exceeds network {network_name} Realm user range");
    let realm_stride = u64::from(20_u16.max(validators_per_realm * edges_per_validator));
    let configured_realms = network.get("realm_configs").and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("network {network_name} has no realm_configs array"))?;
    for (realm_index, &realm_id) in realm_ids.iter().enumerate() {
        anyhow::ensure!(configured_realms.iter().any(|realm| realm.get("id").and_then(Value::as_u64) == Some(realm_id)), "network {network_name} has no Realm {realm_id}");
        let realm_start = realm_id.checked_mul(users_per_realm)
            .ok_or_else(|| anyhow::anyhow!("Realm {realm_id} user range overflows u64"))?;
        let realm_end = realm_start.checked_add(users_per_realm)
            .ok_or_else(|| anyhow::anyhow!("Realm {realm_id} user range overflows u64"))?;
        let offset = realm_index * usize::from(validators_per_realm);
        for &user_id in &validator_user_ids[offset..offset + usize::from(validators_per_realm)] {
            anyhow::ensure!((realm_start..realm_end).contains(&user_id), "validator user id {user_id} is outside Realm {realm_id} range [{realm_start}, {realm_end})");
        }
        for position in 1..=validators_per_realm {
            let processor_port = 41000_u64
                .checked_add(realm_id.checked_mul(20).ok_or_else(|| anyhow::anyhow!("Realm {realm_id} P2P port overflows"))?)
                .and_then(|port| port.checked_add(u64::from(position)))
                .ok_or_else(|| anyhow::anyhow!("Realm {realm_id} processor P2P port overflows"))?;
            anyhow::ensure!(processor_port <= u16::MAX.into(), "Realm {realm_id} processor P2P port exceeds {}", u16::MAX);
            for edge_index in 0..edges_per_validator {
                let edge_port = 41100_u64
                    .checked_add(realm_id.checked_mul(realm_stride).ok_or_else(|| anyhow::anyhow!("Realm {realm_id} P2P port overflows"))?)
                    .and_then(|port| port.checked_add(u64::from(position - 1) * u64::from(edges_per_validator)))
                    .and_then(|port| port.checked_add(u64::from(edge_index) + 1))
                    .ok_or_else(|| anyhow::anyhow!("Realm {realm_id} edge P2P port overflows"))?;
                anyhow::ensure!(edge_port <= u16::MAX.into(), "Realm {realm_id} edge P2P port exceeds {}", u16::MAX);
            }
        }
    }
    std::fs::create_dir_all(&out_dir)
        .map_err(|error| anyhow::anyhow!("failed to create out-dir {out_dir}: {error}"))?;
    network["p2p"] = json!({ "checkpoints_per_epoch": 10 });
    let realms = network.get_mut("realm_configs").and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("network {network_name} has no realm_configs array"))?;
    clear_inactive_realms(realms, &active_realm_ids);

    for (realm_index, realm_id) in realm_ids.into_iter().enumerate() {
        let realm = realms.iter_mut().find(|realm| realm.get("id").and_then(Value::as_u64) == Some(realm_id))
            .ok_or_else(|| anyhow::anyhow!("network {network_name} has no Realm {realm_id}"))?;
        let mut validators = Vec::with_capacity(validators_per_realm as usize);
        for index in 0..validators_per_realm {
            let position = index + 1;
            let processor_path = join_path(&out_dir, &format!("realm_{realm_id}_sub_{position}_processor_identity.key"));
            let bls_path = join_path(&out_dir, &format!("realm_{realm_id}_sub_{position}_bls.key"));
            let processor_node_id = generate_ed25519_identity_file(&processor_path)
                .map_err(|error| anyhow::anyhow!("failed to write {processor_path}: {error}"))?;
            let mut edge_nodes = Vec::with_capacity(edges_per_validator as usize);
            for edge_index in 0..edges_per_validator {
                let edge_suffix = if edge_index == 0 { "edge_identity.key".to_string() } else { format!("edge_{edge_index}_identity.key") };
                let edge_path = join_path(&out_dir, &format!("realm_{realm_id}_sub_{position}_{edge_suffix}"));
                let edge_node_id = generate_ed25519_identity_file(&edge_path)
                    .map_err(|error| anyhow::anyhow!("failed to write {edge_path}: {error}"))?;
                let edge_port = 41100_u64
                    .checked_add(realm_id.checked_mul(realm_stride).ok_or_else(|| anyhow::anyhow!("Realm {realm_id} P2P port overflows"))?)
                    .and_then(|port| port.checked_add(u64::from(position - 1) * u64::from(edges_per_validator)))
                    .and_then(|port| port.checked_add(u64::from(edge_index) + 1))
                    .ok_or_else(|| anyhow::anyhow!("Realm {realm_id} edge P2P port overflows"))?;
                anyhow::ensure!(edge_port <= u16::MAX.into(), "Realm {realm_id} edge P2P port exceeds {}", u16::MAX);
                edge_nodes.push(json!({
                    "node_id": hex::encode(edge_node_id.to_raw()),
                    "addresses": [format!("/{public_host_protocol}/{public_host}/tcp/{edge_port}/p2p/{}", edge_node_id.to_base58())]
                }));
            }
            let bls_public = generate_bls_secret_file(&bls_path)
                .map_err(|error| anyhow::anyhow!("failed to write {bls_path}: {error}"))?;
            let processor_port = 41000_u64
                .checked_add(realm_id.checked_mul(20).ok_or_else(|| anyhow::anyhow!("Realm {realm_id} P2P port overflows"))?)
                .and_then(|port| port.checked_add(u64::from(position)))
                .ok_or_else(|| anyhow::anyhow!("Realm {realm_id} processor P2P port overflows"))?;
            anyhow::ensure!(processor_port <= u16::MAX.into(), "Realm {realm_id} processor P2P port exceeds {}", u16::MAX);
            let validator_user_id = validator_user_ids[realm_index * usize::from(validators_per_realm) + usize::from(index)];
            validators.push(json!({
                "validator_user_id": validator_user_id,
                "processor_node_id": hex::encode(processor_node_id.to_raw()),
                "bls_public_key": hex::encode(bls_public.to_bytes()),
                "processor_addresses": [format!("/{public_host_protocol}/{public_host}/tcp/{processor_port}/p2p/{}", processor_node_id.to_base58())],
                "edge_nodes": edge_nodes
            }));
        }
        realm["validators"] = Value::Array(validators);
    }

    let config_path = join_path(&out_dir, "config.json");
    std::fs::write(Path::new(&config_path), serde_json::to_string_pretty(&root)?)
        .map_err(|error| anyhow::anyhow!("failed to write {config_path}: {error}"))?;
    println!("{config_path}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_count_preflight_rejects_65_before_mutation() {
        assert!(preflight_validator_count(65).is_err());
    }

    #[test]
    fn public_port_preflight_rejects_cross_family_collision() {
        let error = preflight_public_ports(&[0, 1, 2, 3, 4, 5], 2, 1).unwrap_err().to_string();
        assert!(error.contains("TCP port 41101"));
        assert!(error.contains("edge Realm 0"));
        assert!(error.contains("processor Realm 5"));
    }

    #[test]
    fn public_port_preflight_accepts_two_realms() {
        preflight_public_ports(&[0, 1], 2, 1).unwrap();
    }

    #[test]
    fn inactive_realms_are_cleared() {
        let mut realms = vec![
            json!({ "id": 0, "validators": [{ "validator_user_id": 1 }] }),
            json!({ "id": 1, "validators": [{ "validator_user_id": 1048577 }] }),
        ];
        clear_inactive_realms(&mut realms, &HashSet::from([0]));
        assert_eq!(realms[0]["validators"].as_array().unwrap().len(), 1);
        assert!(realms[1]["validators"].as_array().unwrap().is_empty());
    }
}
