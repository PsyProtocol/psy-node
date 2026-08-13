//! Slim Realm network configuration.
//!
//! Holds the libp2p transport/role parameters needed to construct a
//! `RealmBehaviour` and drive a `RealmNetwork`. Authorization (validator-tree
//! role binding, EndCap route delegations) is intentionally NOT part of this
//! slim port: it belongs to the edge/processor wiring layer.

use crate::realm::network::NetworkError;
use libp2p::{identity, Multiaddr, PeerId};
use psy_data::p2p::BlsSecretKey;
use std::num::NonZeroU32;
use std::path::Path;
use std::time::Duration;

/// Minimum per-direction relay circuit byte budget a bootnode must offer.
pub const BOOTNODE_MIN_CIRCUIT_BYTES: u64 = 268_435_456;
/// Minimum per-direction relay circuit duration a bootnode must offer (seconds).
pub const BOOTNODE_MIN_CIRCUIT_DURATION_SECS: u64 = 1_800;
/// Minimum concurrent relay circuits a bootnode must support.
pub const BOOTNODE_MIN_CIRCUITS: u32 = 64;

/// Local Realm P2P configuration. All multiaddresses are pre-parsed typed
/// values; string parsing and NodeId/authorization validation live outside
/// this slim module.
#[derive(Clone, Debug)]
pub struct RealmNetworkConfig {
    pub chain_id: u32,
    pub realm_id: u32,
    pub identity_key_path: String,
    /// Optional BLS secret key file (validators only). Edge/bootnode runtimes
    /// must leave this `None`.
    pub bls_key_path: Option<String>,
    pub listen_addresses: Vec<Multiaddr>,
    pub external_addresses: Vec<Multiaddr>,
    pub bootnode_addresses: Vec<(PeerId, Multiaddr)>,
    /// Direct coordinator endpoints (validators submit finalize here).
    pub coordinator_addresses: Vec<Multiaddr>,
    /// Bootnode runtime: provides relay/Identify/AutoNAT only and never joins
    /// the Realm application protocols.
    pub serve_as_bootnode: bool,
    /// Edge runtime: advertises only the EndCap forward protocol.
    pub is_edge: bool,
    pub px_enabled: bool,
    pub relay_server_enabled: bool,
    /// Bootnode relay v2 circuit limits (required when `serve_as_bootnode`).
    pub bootnode_max_circuit_bytes: Option<u64>,
    pub bootnode_max_circuit_duration_secs: Option<u64>,
    pub bootnode_max_circuits: Option<u32>,
    pub command_channel_capacity: usize,
    pub event_channel_capacity: usize,
    /// Bound on simultaneous in-flight proposal reassemblies (default 2).
    pub max_in_flight_proposals: usize,
    /// Proposal body chunk size (default 61 440 bytes).
    pub reassembly_chunk_bytes: usize,
    /// Proposal reassembly expiry (default 1 800 seconds).
    pub reassembly_expiry_secs: u64,
}

impl RealmNetworkConfig {
    /// Build the relay v2 server configuration when this node is a bootnode.
    pub fn relay_server_config(&self) -> Result<Option<libp2p::relay::Config>, NetworkError> {
        if !self.serve_as_bootnode || !self.relay_server_enabled {
            return Ok(None);
        }
        let max_circuits_u32 = self.bootnode_max_circuits.ok_or_else(|| {
            NetworkError::Configuration("bootnode_max_circuits is required".into())
        })?;
        let max_circuits = max_circuits_u32 as usize;
        let circuit_source_burst = max_circuits_u32
            .checked_mul(4)
            .and_then(NonZeroU32::new)
            .ok_or_else(|| {
                NetworkError::Configuration("bootnode circuit source burst exceeds u32".into())
            })?;
        let mut config = libp2p::relay::Config::default();
        config.max_circuit_bytes = self.bootnode_max_circuit_bytes.ok_or_else(|| {
            NetworkError::Configuration("bootnode_max_circuit_bytes is required".into())
        })?;
        config.max_circuit_duration = Duration::from_secs(
            self.bootnode_max_circuit_duration_secs
                .ok_or_else(|| NetworkError::Configuration("bootnode_max_circuit_duration_secs is required".into()))?,
        );
        config.max_circuits = max_circuits;
        config.max_circuits_per_peer = max_circuits;
        config.circuit_src_rate_limiters.clear();
        config = config
            .circuit_src_per_peer(circuit_source_burst, Duration::from_secs(120))
            .circuit_src_per_ip(circuit_source_burst, Duration::from_secs(60));
        Ok(Some(config))
    }

    /// Minimal structural validation independent of consensus authorization.
    pub fn validate(&self) -> Result<(), NetworkError> {
        if self.command_channel_capacity == 0 || self.event_channel_capacity == 0 {
            return Err(NetworkError::Configuration(
                "network channel capacities must be non-zero".into(),
            ));
        }
        if self.listen_addresses.is_empty() {
            return Err(NetworkError::Configuration("listen_addresses must be non-empty".into()));
        }
        if self.max_in_flight_proposals == 0 {
            return Err(NetworkError::Configuration(
                "max_in_flight_proposals must be non-zero".into(),
            ));
        }
        if self.reassembly_chunk_bytes == 0 || self.reassembly_expiry_secs == 0 {
            return Err(NetworkError::Configuration(
                "reassembly chunk/expiry bounds must be non-zero".into(),
            ));
        }
        if !self.serve_as_bootnode && !self.is_edge && self.coordinator_addresses.is_empty() {
            return Err(NetworkError::Configuration(
                "validator requires at least one coordinator address".into(),
            ));
        }
        if self.serve_as_bootnode {
            let max_bytes = self.bootnode_max_circuit_bytes.ok_or_else(|| {
                NetworkError::Configuration("bootnode_max_circuit_bytes is required".into())
            })?;
            let max_duration = self.bootnode_max_circuit_duration_secs.ok_or_else(|| {
                NetworkError::Configuration(
                    "bootnode_max_circuit_duration_secs is required".into(),
                )
            })?;
            let max_circuits = self.bootnode_max_circuits.ok_or_else(|| {
                NetworkError::Configuration("bootnode_max_circuits is required".into())
            })?;
            if max_bytes < BOOTNODE_MIN_CIRCUIT_BYTES
                || max_duration < BOOTNODE_MIN_CIRCUIT_DURATION_SECS
                || max_circuits < BOOTNODE_MIN_CIRCUITS
            {
                return Err(NetworkError::Configuration(
                    "bootnode forwarding limits are below protocol minimums".into(),
                ));
            }
            if self.external_addresses.is_empty() {
                return Err(NetworkError::Configuration(
                    "bootnode requires an external address".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Load a libp2p Ed25519 identity keypair from its protobuf encoding on disk.
pub fn load_ed25519_identity_key(path: impl AsRef<Path>) -> Result<identity::Keypair, NetworkError> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(|source| NetworkError::KeyFile {
        path: path.display().to_string(),
        details: source.to_string(),
    })?;
    let keypair = identity::Keypair::from_protobuf_encoding(&bytes).map_err(|source| {
        NetworkError::KeyFile {
            path: path.display().to_string(),
            details: source.to_string(),
        }
    })?;
    if keypair.key_type() != identity::KeyType::Ed25519 {
        return Err(NetworkError::KeyFile {
            path: path.display().to_string(),
            details: "identity key is not Ed25519".into(),
        });
    }
    Ok(keypair)
}

/// Load a BLS12-381 secret key from 64 hex characters on disk.
pub fn load_bls_secret_key(path: impl AsRef<Path>) -> Result<BlsSecretKey, NetworkError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| NetworkError::KeyFile {
        path: path.display().to_string(),
        details: source.to_string(),
    })?;
    if text.len() != 64 || !text.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(NetworkError::KeyFile {
            path: path.display().to_string(),
            details: "BLS key must contain exactly 64 hexadecimal characters with no whitespace"
                .into(),
        });
    }
    let bytes = hex::decode(text).map_err(|source| NetworkError::KeyFile {
        path: path.display().to_string(),
        details: source.to_string(),
    })?;
    BlsSecretKey::from_bytes(&bytes).map_err(|source| NetworkError::KeyFile {
        path: path.display().to_string(),
        details: source.to_string(),
    })
}