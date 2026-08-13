//! Slim Realm P2P network module.
//!
//! This module owns the libp2p behaviour, codecs, configuration, and bounded
//! proposal reassembly for the Realm application protocols. It exposes a
//! `RealmNetwork` (the driven `Swarm` plus channels and reassembly book) and
//! a `RealmNetworkHandle` (the application-facing command/event API).
//!
//! Wiring of the edge handler and processor drive loops is intentionally out
//! of scope for this port: the driving code consumes `RealmNetwork` accessors
//! (`swarm_mut`, `command_rx`, `event_tx`, `reassembly_mut`) to pump the
//! `Swarm` and translate between libp2p events and the command/event enums
//! defined here.
//!
//! Dropped from the upstream reference design (and absent here): the durable
//! third-party intake store, generation ancestry hints, the bootnode reserve
//! protocol, the multi-status raw-ack response, body commitment digests, and
//! the certificate distribution plumbing. The EndCap forward protocol is a
//! request/response stream, never gossipsub.
mod behaviour;
mod codec;
mod config;
mod reassembly;

pub use behaviour::{
    add_bootnode_address, add_known_address, proposal_topic, vote_topic, RealmBehaviour,
    IDENTIFY_PROTOCOL_ID,
};
pub use codec::{
    DirectBodyCodec, EndCapForwardCodec, EndCapForwardRequest, RealmFinalizeSubmitCodec,
    DIRECT_BODY_PROTOCOL_ID, END_CAP_FORWARD_PROTOCOL_ID, REALM_FINALIZE_SUBMIT_PROTOCOL_ID,
};
pub use config::{
    load_bls_secret_key, load_ed25519_identity_key, RealmNetworkConfig,
    BOOTNODE_MIN_CIRCUIT_BYTES, BOOTNODE_MIN_CIRCUIT_DURATION_SECS, BOOTNODE_MIN_CIRCUITS,
};
pub use reassembly::{
    validate_start, CompleteProposalBody, InsertOutcome, ProposalReassembly, ReassemblyBook,
    StartOutcome, VerifiedProposalBody,
};

use libp2p::request_response;
use libp2p::{identity, noise, tcp, yamux, Swarm, SwarmBuilder};
use psy_data::p2p::{
    DirectBodyResponse, EndCapForwardHeader, EndCapForwardResponse, NodeId, Proposal,
    RealmFinalizeSubmitCode, RealmFinalizeSubmitRequest, RealmFinalizeSubmitResponse, Vote,
};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};


#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("invalid Realm network configuration: {0}")]
    Configuration(String),
    #[error("network key file {path}: {details}")]
    KeyFile { path: String, details: String },
    #[error("unauthorized NodeId {0}")]
    Unauthorized(NodeId),
    #[error("protocol error: {0}")]
    Protocol(#[from] psy_data::p2p::ProtocolError),
    #[error("libp2p behaviour error: {0}")]
    Behaviour(String),
    #[error("libp2p transport error: {0}")]
    Transport(String),
    #[error("proposal reassembly error: {0}")]
    Reassembly(String),
    #[error("Realm network command channel closed")]
    CommandChannelClosed,
    #[error("Realm network response channel closed")]
    ResponseChannelClosed,
    #[error("direct request failed: {0}")]
    DirectRequest(String),
    #[error("request was rejected: {0}")]
    Rejected(String),
    #[error("Realm finalize submission rejected: {0}")]
    RealmFinalizeRejected(RealmFinalizeSubmitCode),
}

/// Application → network commands. The network's driving loop fulfils each
/// command and replies on the embedded oneshot channel.
#[derive(Debug)]
pub enum RealmNetworkCommand {
    /// Forward an EndCap stream (56-byte header + input + proof) to the
    /// scheduled proposer for the header's checkpoint.
    ForwardEndCap {
        header: EndCapForwardHeader,
        input: Vec<u8>,
        proof: Vec<u8>,
        response: oneshot::Sender<Result<EndCapForwardResponse, NetworkError>>,
    },
    /// Publish a proposal: chunk the body and gossip the parts.
    PublishProposal {
        proposal: Proposal,
        body: Vec<u8>,
        response: oneshot::Sender<Result<(), NetworkError>>,
    },
    /// Publish a vote on the Realm vote gossipsub topic.
    PublishVote {
        vote: Vote,
        response: oneshot::Sender<Result<(), NetworkError>>,
    },
    /// Submit a finalize request to the Coordinator and await its response.
    SubmitFinalize {
        request: RealmFinalizeSubmitRequest,
        response: oneshot::Sender<Result<RealmFinalizeSubmitResponse, NetworkError>>,
    },
    /// Respond to an inbound direct-body range request.
    ServeBody {
        request_id: request_response::InboundRequestId,
        response_body: DirectBodyResponse,
        response: oneshot::Sender<Result<(), NetworkError>>,
    },
}

/// Network → application events. The driving loop emits these for the
/// edge/processor layer to validate and act on; inbound request/response
/// events carry a reply channel for the application's verdict.
#[derive(Debug)]
pub enum RealmNetworkEvent {
    /// An EndCap forward request was received. The application validates the
    /// header/payload and replies with `EndCapForwardResponse` on `reply`.
    EndCapReceived {
        request_id: request_response::InboundRequestId,
        source: NodeId,
        header: EndCapForwardHeader,
        input: Vec<u8>,
        proof: Vec<u8>,
        reply: oneshot::Sender<EndCapForwardResponse>,
    },
    /// A complete, hash-verified proposal body has been reassembled.
    ProposalReady {
        source: NodeId,
        proposal: Proposal,
        body: VerifiedProposalBody,
    },
    /// A vote was received on the Realm vote topic.
    VoteReceived {
        source: NodeId,
        vote: Vote,
    },
    /// A finalize-submit request was received by the Coordinator. The
    /// application validates and replies with the admission response.
    FinalizeResult {
        request_id: request_response::InboundRequestId,
        source: NodeId,
        request: RealmFinalizeSubmitRequest,
        reply: oneshot::Sender<RealmFinalizeSubmitResponse>,
    },
}

/// Application-facing handle. The event receiver is single-consumer, so the
/// handle is not `Clone`; move it to the driving loop.
pub struct RealmNetworkHandle {
    commands: mpsc::Sender<RealmNetworkCommand>,
    events: mpsc::Receiver<RealmNetworkEvent>,
    local_node_id: NodeId,
}

impl std::fmt::Debug for RealmNetworkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealmNetworkHandle")
            .field("local_node_id", &self.local_node_id)
            .finish_non_exhaustive()
    }
}

impl RealmNetworkHandle {
    pub fn local_node_id(&self) -> NodeId {
        self.local_node_id
    }

    pub fn commands(&self) -> &mpsc::Sender<RealmNetworkCommand> {
        &self.commands
    }

    pub fn events(&mut self) -> &mut mpsc::Receiver<RealmNetworkEvent> {
        &mut self.events
    }

    pub async fn forward_end_cap(
        &self,
        header: EndCapForwardHeader,
        input: Vec<u8>,
        proof: Vec<u8>,
    ) -> Result<EndCapForwardResponse, NetworkError> {
        self.request(|response| RealmNetworkCommand::ForwardEndCap {
            header,
            input,
            proof,
            response,
        })
        .await?
    }

    pub async fn publish_proposal(
        &self,
        proposal: Proposal,
        body: Vec<u8>,
    ) -> Result<(), NetworkError> {
        self.request(|response| RealmNetworkCommand::PublishProposal {
            proposal,
            body,
            response,
        })
        .await?
    }

    pub async fn publish_vote(&self, vote: Vote) -> Result<(), NetworkError> {
        self.request(|response| RealmNetworkCommand::PublishVote { vote, response })
            .await?
    }

    pub async fn submit_finalize(
        &self,
        request: RealmFinalizeSubmitRequest,
    ) -> Result<RealmFinalizeSubmitResponse, NetworkError> {
        self.request(|response| RealmNetworkCommand::SubmitFinalize { request, response })
            .await?
    }

    pub async fn serve_body(
        &self,
        request_id: request_response::InboundRequestId,
        response_body: DirectBodyResponse,
    ) -> Result<(), NetworkError> {
        self.request(|response| RealmNetworkCommand::ServeBody {
            request_id,
            response_body,
            response,
        })
        .await?
    }

    async fn request<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> RealmNetworkCommand,
    ) -> Result<T, NetworkError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(command(tx))
            .await
            .map_err(|_| NetworkError::CommandChannelClosed)?;
        rx.await.map_err(|_| NetworkError::ResponseChannelClosed)
    }
}

/// The driven Realm network. The application pumps `swarm_mut()`,
/// `command_rx()`, and `event_tx()` in its own select loop; this type does
/// not run an internal event loop.
pub struct RealmNetwork {
    swarm: Swarm<RealmBehaviour>,
    config: RealmNetworkConfig,
    realm_id: u32,
    local_node_id: NodeId,
    command_rx: mpsc::Receiver<RealmNetworkCommand>,
    event_tx: mpsc::Sender<RealmNetworkEvent>,
    reassembly: ReassemblyBook,
}

impl std::fmt::Debug for RealmNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealmNetwork")
            .field("realm_id", &self.realm_id)
            .field("local_node_id", &self.local_node_id)
            .field("active_reassemblies", &self.reassembly.active_count())
            .finish_non_exhaustive()
    }
}

impl RealmNetwork {
    /// Build a Realm network from an already-loaded Ed25519 identity keypair.
    pub fn build_with_keypair(
        key: identity::Keypair,
        config: RealmNetworkConfig,
        is_edge: bool,
    ) -> Result<(Self, RealmNetworkHandle), NetworkError> {
        config.validate()?;
        let local_node_id = NodeId::from_keypair(&key)?;
        let realm_id = config.realm_id;
        let mut swarm = build_swarm(&key, &config, is_edge)?;

        for address in &config.listen_addresses {
            swarm
                .listen_on(address.clone())
                .map_err(|error| NetworkError::Transport(format!("listen {address}: {error}")))?;
        }
        for address in &config.external_addresses {
            swarm.add_external_address(address.clone());
        }
        // Register bootnodes for AutoNAT reachability probing. Dialing the
        // relay reservation address is left to the driving loop.
        {
            let behaviour = swarm.behaviour_mut();
            for (peer_id, address) in &config.bootnode_addresses {
                add_bootnode_address(behaviour, *peer_id, address.clone());
            }
        }

        let (command_tx, command_rx) = mpsc::channel(config.command_channel_capacity);
        let (event_tx, event_rx) = mpsc::channel(config.event_channel_capacity);

        let reassembly = ReassemblyBook::new(
            config.max_in_flight_proposals,
            config.reassembly_chunk_bytes,
            Duration::from_secs(config.reassembly_expiry_secs),
        );

        let handle = RealmNetworkHandle {
            commands: command_tx,
            events: event_rx,
            local_node_id,
        };

        Ok((
            Self {
                swarm,
                config,
                realm_id,
                local_node_id,
                command_rx,
                event_tx,
                reassembly,
            },
            handle,
        ))
    }

    /// Build a Realm network, loading the Ed25519 identity key from
    /// `config.identity_key_path`.
    pub fn build(
        config: RealmNetworkConfig,
        is_edge: bool,
    ) -> Result<(Self, RealmNetworkHandle), NetworkError> {
        let key = load_ed25519_identity_key(&config.identity_key_path)?;
        Self::build_with_keypair(key, config, is_edge)
    }

    pub fn swarm(&self) -> &Swarm<RealmBehaviour> {
        &self.swarm
    }

    pub fn swarm_mut(&mut self) -> &mut Swarm<RealmBehaviour> {
        &mut self.swarm
    }

    pub fn config(&self) -> &RealmNetworkConfig {
        &self.config
    }

    pub fn realm_id(&self) -> u32 {
        self.realm_id
    }

    pub fn local_node_id(&self) -> NodeId {
        self.local_node_id
    }

    pub fn command_rx(&mut self) -> &mut mpsc::Receiver<RealmNetworkCommand> {
        &mut self.command_rx
    }

    pub fn event_tx(&self) -> &mpsc::Sender<RealmNetworkEvent> {
        &self.event_tx
    }

    pub fn reassembly(&self) -> &ReassemblyBook {
        &self.reassembly
    }

    pub fn reassembly_mut(&mut self) -> &mut ReassemblyBook {
        &mut self.reassembly
    }
}

fn build_swarm(
    key: &identity::Keypair,
    config: &RealmNetworkConfig,
    is_edge: bool,
) -> Result<Swarm<RealmBehaviour>, NetworkError> {
    let protocol_timeout = Duration::from_secs(
        psy_data::p2p::END_CAP_FORWARD_TIMEOUT_SECS.max(psy_data::p2p::DIRECT_REQUEST_TIMEOUT_SECS),
    );
    SwarmBuilder::with_existing_identity(key.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|error| NetworkError::Transport(error.to_string()))?
        .with_dns()
        .map_err(|error| NetworkError::Transport(error.to_string()))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|error| NetworkError::Transport(error.to_string()))?
        .with_behaviour(|identity, relay_client| {
            RealmBehaviour::new(identity, relay_client, config, is_edge)
        })
        .map_err(|error| NetworkError::Behaviour(error.to_string()))
        .map(|builder| {
            builder
                .with_swarm_config(|swarm| swarm.with_idle_connection_timeout(protocol_timeout))
                .build()
        })
}