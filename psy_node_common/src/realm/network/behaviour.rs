//! libp2p `NetworkBehaviour` composition for the slim Realm P2P stack.
//!
//! Protocols wired:
//! - Gossipsub: `/psy/realm/{id}/proposals` and `/psy/realm/{id}/votes`
//!   (validator-only subscriptions).
//! - request-response: direct proposal-body ranges, EndCap forward,
//!   Realm finalize-submit.
//! - Identify, relay v2 (client always; server toggle for bootnodes),
//!   DCUtR, AutoNAT.
//!
//! Kademlia and UPnP are intentionally absent: the enabled libp2p feature set
//! does not include `kad` or `upnp`, and the slim port does not require them.

use crate::realm::network::codec::{
    DirectBodyCodec, EndCapForwardCodec, RealmFinalizeSubmitCodec, DIRECT_BODY_PROTOCOL_ID,
    END_CAP_FORWARD_PROTOCOL_ID, REALM_FINALIZE_SUBMIT_PROTOCOL_ID,
};
use crate::realm::network::config::RealmNetworkConfig;
use libp2p::autonat;
use libp2p::dcutr;
use libp2p::gossipsub;
use libp2p::identify;
use libp2p::relay;
use libp2p::request_response;
use libp2p::swarm::{behaviour::toggle::Toggle, NetworkBehaviour, StreamProtocol};
use libp2p::{identity, PeerId};
use psy_data::p2p::{GOSSIPSUB_MAX_TRANSMIT_SIZE, MAX_CONCURRENT_DIRECT_EXCHANGES, MAX_CONCURRENT_REALM_FINALIZE_SUBMITS};
use std::time::Duration;

pub const IDENTIFY_PROTOCOL_ID: &str = "/psy/realm/1";

/// Gossipsub topic for Realm proposal parts.
pub fn proposal_topic(realm_id: u32) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(format!("/psy/realm/{realm_id}/proposals"))
}

/// Gossipsub topic for Realm votes.
pub fn vote_topic(realm_id: u32) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(format!("/psy/realm/{realm_id}/votes"))
}

#[derive(NetworkBehaviour)]
pub struct RealmBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub direct_body: request_response::Behaviour<DirectBodyCodec>,
    pub end_cap_forward: request_response::Behaviour<EndCapForwardCodec>,
    pub realm_finalize_submit: request_response::Behaviour<RealmFinalizeSubmitCodec>,
    pub relay_client: relay::client::Behaviour,
    pub relay_server: Toggle<relay::Behaviour>,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
}

impl RealmBehaviour {
    pub fn new(
        key: &identity::Keypair,
        relay_client: relay::client::Behaviour,
        config: &RealmNetworkConfig,
        is_edge: bool,
    ) -> Self {
        let local_peer_id = key.public().to_peer_id();
        let is_bootnode = config.serve_as_bootnode;

        let mut gossip_config_builder = gossipsub::ConfigBuilder::default();
        gossip_config_builder
            .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
            .validation_mode(gossipsub::ValidationMode::Strict);
        if config.px_enabled {
            gossip_config_builder.do_px();
        }
        let gossip_config = gossip_config_builder
            .build()
            .expect("Realm Gossipsub constants are valid");
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossip_config,
        )
        .expect("signed strict Gossipsub configuration is valid");

        // Bootnodes and Edges never subscribe to the validator-only Realm
        // proposal/vote topics.
        if !is_bootnode && !is_edge {
            gossipsub
                .subscribe(&proposal_topic(config.realm_id))
                .expect("fixed proposal topic is valid");
            gossipsub
                .subscribe(&vote_topic(config.realm_id))
                .expect("fixed vote topic is valid");
        }

        let identify = identify::Behaviour::new(
            identify::Config::new(IDENTIFY_PROTOCOL_ID.to_string(), key.public())
                .with_push_listen_addr_updates(true)
                .with_cache_size(256),
        );

        let direct_body_config = request_response::Config::default()
            .with_request_timeout(Duration::from_secs(psy_data::p2p::DIRECT_REQUEST_TIMEOUT_SECS))
            .with_max_concurrent_streams(MAX_CONCURRENT_DIRECT_EXCHANGES);
        let end_cap_config = request_response::Config::default()
            .with_request_timeout(Duration::from_secs(psy_data::p2p::END_CAP_FORWARD_TIMEOUT_SECS))
            .with_max_concurrent_streams(MAX_CONCURRENT_DIRECT_EXCHANGES);
        let realm_finalize_config = request_response::Config::default()
            .with_request_timeout(Duration::from_secs(
                psy_data::p2p::REALM_FINALIZE_SUBMIT_TIMEOUT_SECS,
            ))
            .with_max_concurrent_streams(MAX_CONCURRENT_REALM_FINALIZE_SUBMITS);

        // DirectBody is validator-only. EndCap forward is Edge-only: validators
        // and bootnodes neither advertise nor accept the forwarding protocol.
        let direct_body_protocols: &[(StreamProtocol, request_response::ProtocolSupport)] =
            if is_bootnode || is_edge {
                &[]
            } else {
                &[(
                    StreamProtocol::new(DIRECT_BODY_PROTOCOL_ID),
                    request_response::ProtocolSupport::Full,
                )]
            };
        let end_cap_protocols: &[(StreamProtocol, request_response::ProtocolSupport)] =
            if is_edge {
                &[(
                    StreamProtocol::new(END_CAP_FORWARD_PROTOCOL_ID),
                    request_response::ProtocolSupport::Full,
                )]
            } else {
                &[]
            };
        // Validators submit finalization outbound to the Coordinator only;
        // they never accept inbound submissions. Bootnodes/edges hold none.
        let realm_finalize_protocols: &[(StreamProtocol, request_response::ProtocolSupport)] =
            if is_bootnode || is_edge {
                &[]
            } else {
                &[(
                    StreamProtocol::new(REALM_FINALIZE_SUBMIT_PROTOCOL_ID),
                    request_response::ProtocolSupport::Outbound,
                )]
            };

        let direct_body =
            request_response::Behaviour::new(direct_body_protocols.iter().cloned(), direct_body_config);
        let end_cap_forward = request_response::Behaviour::new(
            end_cap_protocols.iter().cloned(),
            end_cap_config,
        );
        let realm_finalize_submit = request_response::Behaviour::new(
            realm_finalize_protocols.iter().cloned(),
            realm_finalize_config,
        );

        let relay_server = config
            .relay_server_config()
            .expect("validated relay configuration remains valid")
            .map(|relay_config| relay::Behaviour::new(local_peer_id, relay_config))
            .into();
        let dcutr = dcutr::Behaviour::new(local_peer_id);
        let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());

        Self {
            gossipsub,
            identify,
            direct_body,
            end_cap_forward,
            realm_finalize_submit,
            relay_client,
            relay_server,
            dcutr,
            autonat,
        }
    }
}

/// Register a known validator peer for mesh membership.
pub fn add_known_address(behaviour: &mut RealmBehaviour, peer_id: PeerId, _address: libp2p::Multiaddr) {
    behaviour.gossipsub.add_explicit_peer(&peer_id);
}

/// Register a bootnode address for AutoNAT reachability probing.
pub fn add_bootnode_address(
    behaviour: &mut RealmBehaviour,
    peer_id: PeerId,
    address: libp2p::Multiaddr,
) {
    behaviour.autonat.add_server(peer_id, Some(address));
}