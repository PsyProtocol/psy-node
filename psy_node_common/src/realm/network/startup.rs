//! Optional Realm P2P construction from start-config strings.
//!
//! Empty identity/listen means the caller keeps today's HTTP path. When P2P
//! is enabled, rotation must be fully specified (period > 0 and non-empty
//! validator sub-ids) so the scheduled-proposer check cannot silently disable.

use crate::realm::network::{
    load_bls_secret_key, NetworkError, RealmNetwork, RealmNetworkConfig, RealmNetworkHandle,
};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use parth_common::realm_rotation::RealmRotationConfig;
use psy_data::p2p::{BlsSecretKey, NodeId, NODE_ID_RAW_LEN};
use std::collections::HashMap;
use std::str::FromStr;

/// Parsed optional Realm network plus the rotation/BLS material the
/// processor or edge setter needs.
pub struct OptionalRealmNetwork {
    pub network: RealmNetwork,
    pub handle: RealmNetworkHandle,
    pub rotation: RealmRotationConfig,
    pub bls_secret: Option<BlsSecretKey>,
    pub local_node_id: NodeId,
}

/// Parse a bootnode multiaddr that must terminate in `/p2p/<peer>`.
pub fn parse_bootnode(value: &str) -> Result<(PeerId, Multiaddr), NetworkError> {
    let addr = Multiaddr::from_str(value).map_err(|error| {
        NetworkError::Configuration(format!("invalid bootnode multiaddr {value}: {error}"))
    })?;
    let peer = addr
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .ok_or_else(|| {
            NetworkError::Configuration(format!("bootnode multiaddr missing /p2p/: {value}"))
        })?;
    Ok((peer, addr))
}

/// Parse an edge proposer mapping `SUB:HEX38` into `(realm_sub_id, NodeId)`.
pub fn parse_proposer_node_id(value: &str) -> anyhow::Result<(u16, NodeId)> {
    let (sub, hex_id) = value.split_once(':').ok_or_else(|| {
        anyhow::anyhow!("p2p proposer node id must be SUB:HEX38, got {value}")
    })?;
    let sub_id: u16 = sub.parse().map_err(|error| {
        anyhow::anyhow!("invalid proposer sub_id in {value}: {error}")
    })?;
    let bytes = hex::decode(hex_id)
        .map_err(|error| anyhow::anyhow!("invalid NodeId hex in {value}: {error}"))?;
    if bytes.len() != NODE_ID_RAW_LEN {
        anyhow::bail!(
            "NodeId hex for sub {sub_id} must be {NODE_ID_RAW_LEN} bytes, got {}",
            bytes.len()
        );
    }
    let mut raw = [0u8; NODE_ID_RAW_LEN];
    raw.copy_from_slice(&bytes);
    Ok((sub_id, NodeId::from_raw(raw)?))
}

/// Parse a list of `SUB:HEX38` mappings into the edge forward table.
pub fn parse_proposer_node_ids(values: &[String]) -> anyhow::Result<HashMap<u16, NodeId>> {
    let mut map = HashMap::with_capacity(values.len());
    for value in values {
        let (sub_id, node_id) = parse_proposer_node_id(value)?;
        if map.insert(sub_id, node_id).is_some() {
            anyhow::bail!("duplicate p2p proposer NodeId for sub_id {sub_id}");
        }
    }
    Ok(map)
}

/// Build a Realm network when P2P identity + listen are configured.
///
/// Validators (`is_edge = false`) require a BLS key and a coordinator
/// multiaddr. Edges leave BLS unset. Rotation is fail-closed: empty validators
/// or zero period is a configuration error, not a silent disable.
pub fn build_optional_realm_network(
    chain_id: u32,
    realm_id: u32,
    is_edge: bool,
    identity_key_path: &str,
    bls_key_path: Option<&str>,
    listen: &str,
    bootnodes: &[String],
    coordinator: Option<&str>,
    validator_sub_ids: &[u16],
    checkpoints_per_epoch: u64,
) -> Result<OptionalRealmNetwork, NetworkError> {
    if validator_sub_ids.is_empty() || checkpoints_per_epoch == 0 {
        return Err(NetworkError::Configuration(
            "P2P enabled requires non-empty validator_sub_ids and checkpoints_per_epoch > 0"
                .into(),
        ));
    }
    let listen_addr = Multiaddr::from_str(listen).map_err(|error| {
        NetworkError::Configuration(format!("invalid p2p listen {listen}: {error}"))
    })?;
    let mut bootnode_addresses = Vec::with_capacity(bootnodes.len());
    for bootnode in bootnodes {
        bootnode_addresses.push(parse_bootnode(bootnode)?);
    }
    let mut coordinator_addresses = Vec::new();
    if let Some(coordinator_addr) = coordinator {
        let addr = Multiaddr::from_str(coordinator_addr).map_err(|error| {
            NetworkError::Configuration(format!(
                "invalid p2p coordinator {coordinator_addr}: {error}"
            ))
        })?;
        coordinator_addresses.push(addr);
    }
    if !is_edge && coordinator_addresses.is_empty() {
        return Err(NetworkError::Configuration(
            "validator requires p2p coordinator address".into(),
        ));
    }
    if !is_edge && bls_key_path.is_none() {
        return Err(NetworkError::Configuration(
            "validator requires p2p BLS key".into(),
        ));
    }
    let bls_secret = match bls_key_path {
        Some(path) => Some(load_bls_secret_key(path)?),
        None => None,
    };
    let config = RealmNetworkConfig {
        chain_id,
        realm_id,
        identity_key_path: identity_key_path.to_string(),
        bls_key_path: bls_key_path.map(str::to_string),
        listen_addresses: vec![listen_addr],
        external_addresses: vec![],
        bootnode_addresses,
        coordinator_addresses,
        serve_as_bootnode: false,
        is_edge,
        px_enabled: false,
        relay_server_enabled: false,
        bootnode_max_circuit_bytes: None,
        bootnode_max_circuit_duration_secs: None,
        bootnode_max_circuits: None,
        command_channel_capacity: 64,
        event_channel_capacity: 256,
        max_in_flight_proposals: 2,
        reassembly_chunk_bytes: 61_440,
        reassembly_expiry_secs: 1_800,
    };
    let (network, handle) = RealmNetwork::build(config, is_edge)?;
    let local_node_id = handle.local_node_id();
    Ok(OptionalRealmNetwork {
        network,
        handle,
        rotation: RealmRotationConfig {
            checkpoints_per_epoch,
            validator_sub_ids: validator_sub_ids.to_vec(),
        },
        bls_secret,
        local_node_id,
    })
}
