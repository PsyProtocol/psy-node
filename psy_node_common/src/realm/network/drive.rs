//! Drive loop for [`RealmNetwork`]: commands, swarm events, vote waiters.
use crate::realm::network::behaviour::{proposal_topic, register_explicit_peer, vote_topic, RealmBehaviourEvent};
use crate::realm::network::codec::EndCapForwardRequest;
use crate::realm::network::{
    InsertOutcome, NetworkError, RealmNetwork, RealmNetworkCommand, RealmNetworkEvent,
    ReassemblyBook, StartOutcome,
};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use libp2p::gossipsub;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{
    self, OutboundRequestId, ResponseChannel,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use psy_data::p2p::{
    vote_message, BlsPublicKey, BodyChunkRequest, BodyChunkResponse, EndCapForwardResponse,
    EndCapRejectReason, NodeId, Proposal, ProposalLookupRequest, ProposalLookupResponse,
    ProposalPart, ProtocolEncode, ValidatorLeaf, Vote, BODY_CHUNK_MAX_BYTES,
    MAINTENANCE_TICK_SECS, MAX_CONCURRENT_DIRECT_EXCHANGES, MAX_IN_FLIGHT_PROPOSALS,
    MAX_PROPOSAL_CHUNK_BYTES, MAX_VALIDATORS_PER_REALM, MAX_VOTE_AUTH,
    RANGE_REQUEST_RETRY_INTERVAL_SECS, VOTE_AUTH_TTL_SECS,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

/// Bounded reconnect backoff for disconnected realm peers.
const REALM_PEER_REDIAL_BACKOFF_SECS: u64 = 15;

struct VoteWaiter {
    proposal_id: [u8; 32],
    threshold: usize,
    deadline: Instant,
    votes: Vec<Vote>,
    seen: HashSet<u16>,
    response: oneshot::Sender<Result<Vec<Vote>, NetworkError>>,
}

struct ProposalVoteAuth {
    vote_message: Vec<u8>,
    leaf_bls_keys: Vec<(u16, BlsPublicKey)>,
    inserted_at: Instant,
}

struct DriveState {
    proposal_source: HashMap<[u8; 32], PeerId>,
    end_cap_responses: HashMap<
        OutboundRequestId,
        oneshot::Sender<Result<EndCapForwardResponse, NetworkError>>,
    >,
    pending_lookup: HashMap<
        OutboundRequestId,
        oneshot::Sender<Result<ProposalLookupResponse, NetworkError>>,
    >,
    pending_body: HashMap<
        OutboundRequestId,
        oneshot::Sender<Result<BodyChunkResponse, NetworkError>>,
    >,
    pending_direct: HashMap<OutboundRequestId, [u8; 32]>,
    vote_auth: HashMap<[u8; 32], ProposalVoteAuth>,
    vote_backlog: HashMap<[u8; 32], Vec<Vote>>,
    vote_waiters: Vec<VoteWaiter>,
    validator_leaves: HashMap<NodeId, ValidatorLeaf>,
    end_cap_replies: FuturesUnordered<
        BoxFuture<'static, (ResponseChannel<EndCapForwardResponse>, Option<EndCapForwardResponse>)>,
    >,
    lookup_replies: FuturesUnordered<
        BoxFuture<'static, (ResponseChannel<ProposalLookupResponse>, Option<ProposalLookupResponse>)>,
    >,
    body_replies: FuturesUnordered<
        BoxFuture<'static, (ResponseChannel<BodyChunkResponse>, Option<BodyChunkResponse>)>,
    >,
    connected_peers: HashSet<PeerId>,
    explicit_peers: HashSet<PeerId>,
    dial_attempts: HashMap<PeerId, Instant>,
    learned_addresses: HashMap<PeerId, Multiaddr>,
}

impl DriveState {
    fn new() -> Self {
        Self {
            proposal_source: HashMap::new(),
            end_cap_responses: HashMap::new(),
            pending_lookup: HashMap::new(),
            pending_body: HashMap::new(),
            pending_direct: HashMap::new(),
            vote_auth: HashMap::new(),
            vote_backlog: HashMap::new(),
            vote_waiters: Vec::new(),
            validator_leaves: HashMap::new(),
            end_cap_replies: FuturesUnordered::new(),
            lookup_replies: FuturesUnordered::new(),
            body_replies: FuturesUnordered::new(),
            connected_peers: HashSet::new(),
            explicit_peers: HashSet::new(),
            dial_attempts: HashMap::new(),
            learned_addresses: HashMap::new(),
        }
    }
}


pub async fn run_realm_network(mut network: RealmNetwork) {
    network.run().await;
}

impl RealmNetwork {
    pub async fn run(&mut self) {
        let mut state = DriveState::new();
        state.validator_leaves.clone_from(&self.validator_leaves);
        self.register_realm_peers(&mut state);
        self.redial_realm_peers(&mut state);

        let mut tick = tokio::time::interval(Duration::from_secs(MAINTENANCE_TICK_SECS));
        loop {
            tokio::select! {
                command = self.command_rx.recv() => {
                    match command {
                        Some(command) => self.handle_command(command, &mut state),
                        None => break,
                    }
                }
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event, &mut state);
                }
                Some((channel, reply)) = state.end_cap_replies.next() => {
                    let response =
                        reply.unwrap_or_else(|| EndCapForwardResponse::rejected(EndCapRejectReason::Busy));
                    if self
                        .swarm
                        .behaviour_mut()
                        .end_cap_forward
                        .send_response(channel, response)
                        .is_err()
                    {
                        tracing::warn!(
                            realm_id = self.realm_id,
                            "failed to send EndCap forward response"
                        );
                    }
                }
                Some((channel, reply)) = state.lookup_replies.next() => {
                    if let Some(response) = reply {
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .proposal_lookup
                            .send_response(channel, response);
                    }
                }
                Some((channel, reply)) = state.body_replies.next() => {
                    if let Some(response) = reply {
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .body_chunk
                            .send_response(channel, response);
                    }
                }
                _ = tick.tick() => {
                    self.maintain(&mut state);
                }
            }
        }
    }

    fn handle_command(&mut self, command: RealmNetworkCommand, state: &mut DriveState) {
        match command {
            RealmNetworkCommand::ForwardEndCap {
                destination,
                header,
                input,
                proof,
                response,
            } => {
                let request = match EndCapForwardRequest::new(header, input, proof) {
                    Ok(request) => request,
                    Err(error) => {
                        let _ = response.send(Err(NetworkError::DirectRequest(error.to_string())));
                        return;
                    }
                };
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .end_cap_forward
                    .send_request(&destination.to_peer_id(), request);
                state.end_cap_responses.insert(request_id, response);
            }
            RealmNetworkCommand::PublishProposal {
                proposal,
                body,
                leaf_bls_keys,
                response,
            } => {
                register_proposal_vote_auth(state, &proposal, leaf_bls_keys, Instant::now());
                let result = publish_proposal_parts(
                    &mut self.swarm,
                    self.realm_id,
                    &proposal,
                    &body,
                );
                if result.is_err() {
                    state.vote_auth.remove(&proposal.proposal_id);
                    state.vote_backlog.remove(&proposal.proposal_id);
                }
                let _ = response.send(result);
            }
            RealmNetworkCommand::PublishVote { vote, response } => {
                let result = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(vote_topic(self.realm_id), vote.protocol_encode_to_vec())
                    .map(|_| ())
                    .map_err(|error| NetworkError::Behaviour(error.to_string()));
                if result.is_ok() {
                    tracing::info!(
                        "realm P2P vote published proposal={} signer_sub_id={} realm={}",
                        hex::encode(vote.proposal_id),
                        vote.signer_sub_id,
                        self.realm_id
                    );
                }
                let _ = response.send(result);
            }
            RealmNetworkCommand::LookupProposal {
                destination,
                request,
                response,
            } => {
                if !has_validator_leaf(state, &destination) {
                    let _ = response.send(Err(NetworkError::NotAValidator(destination)));
                    return;
                }
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .proposal_lookup
                    .send_request(&destination.to_peer_id(), request);
                state.pending_lookup.insert(request_id, response);
            }
            RealmNetworkCommand::RequestBody {
                destination,
                request,
                response,
            } => {
                if !has_validator_leaf(state, &destination) {
                    let _ = response.send(Err(NetworkError::NotAValidator(destination)));
                    return;
                }
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .body_chunk
                    .send_request(&destination.to_peer_id(), request);
                state.pending_body.insert(request_id, response);
            }
            RealmNetworkCommand::WaitVotes {
                proposal_id,
                threshold,
                timeout,
                response,
            } => {
                if let Err(error) = validate_wait_votes_threshold(threshold) {
                    let _ = response.send(Err(error));
                    return;
                }
                if !state.vote_auth.contains_key(&proposal_id) {
                    let _ = response.send(Err(NetworkError::Rejected(
                        "wait_votes has no registered vote verification context".into(),
                    )));
                    return;
                }
                let votes = state.vote_backlog.remove(&proposal_id).unwrap_or_default();
                if votes.len() >= threshold {
                    let _ = response.send(Ok(votes));
                    clear_vote_auth_if_idle(state, proposal_id);
                    return;
                }
                let seen = votes.iter().map(|vote| vote.signer_sub_id).collect();
                state.vote_waiters.push(VoteWaiter {
                    proposal_id,
                    threshold,
                    deadline: Instant::now() + timeout,
                    votes,
                    seen,
                    response,
                });
            }
            RealmNetworkCommand::SetValidatorLeaves { leaves, response } => {
                let result = replace_validator_leaves(state, leaves);
                if result.is_ok() {
                    self.validator_leaves.clone_from(&state.validator_leaves);
                    self.register_realm_peers(state);
                }
                let _ = response.send(result);
            }
        }
    }

    fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<RealmBehaviourEvent>,
        state: &mut DriveState,
    ) {
        match event {
            SwarmEvent::Behaviour(RealmBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                message,
                ..
            })) => {
                let Some(source_peer) = message.source else {
                    return;
                };
                let Ok(source) = NodeId::from_peer_id(&source_peer) else {
                    return;
                };
                let proposal_hash = proposal_topic(self.realm_id).hash();
                let vote_hash = vote_topic(self.realm_id).hash();
                if message.topic == proposal_hash {
                    self.handle_proposal_part(source, source_peer, &message.data, state);
                } else if message.topic == vote_hash {
                    match Vote::decode_exact(&message.data) {
                        Ok(vote) => {
                            if !feed_vote_waiters(state, &vote) {
                                tracing::debug!(
                                    realm_id = self.realm_id,
                                    proposal = %hex::encode(vote.proposal_id),
                                    signer_sub_id = vote.signer_sub_id,
                                    "dropped unauthenticated Realm vote"
                                );
                                return;
                            }
                            tracing::info!(
                                "realm P2P vote received proposal={} signer_sub_id={} realm={} source={:?}",
                                hex::encode(vote.proposal_id),
                                vote.signer_sub_id,
                                self.realm_id,
                                source
                            );
                            let _ = self.event_tx.try_send(RealmNetworkEvent::VoteReceived {
                                source,
                                vote,
                            });
                        }
                        Err(error) => {
                            tracing::debug!(
                                realm_id = self.realm_id,
                                %error,
                                "dropped malformed Realm vote"
                            );
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(RealmBehaviourEvent::EndCapForward(event)) => {
                self.handle_end_cap_event(event, state);
            }
            SwarmEvent::Behaviour(RealmBehaviourEvent::BodyChunk(event)) => {
                self.handle_body_chunk_event(event, state);
            }
            SwarmEvent::Behaviour(RealmBehaviourEvent::ProposalLookup(event)) => {
                self.handle_proposal_lookup_event(event, state);
            }
            SwarmEvent::Behaviour(RealmBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed {
                peer_id,
                topic,
            })) => {
                tracing::debug!(realm_id = self.realm_id, %peer_id, %topic, "Realm gossipsub peer subscribed");
            }
            SwarmEvent::Behaviour(RealmBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed {
                peer_id,
                topic,
            })) => {
                tracing::debug!(realm_id = self.realm_id, %peer_id, %topic, "Realm gossipsub peer unsubscribed");
            }
            SwarmEvent::Behaviour(_) => {}
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                ..
            } => {
                state.connected_peers.insert(peer_id);
                state.dial_attempts.remove(&peer_id);
                if self.is_realm_peer(state, &peer_id) {
                    register_explicit_peer(self.swarm.behaviour_mut(), peer_id);
                    if let libp2p::swarm::derive_prelude::ConnectedPoint::Dialer { address, .. } = endpoint {
                        state.learned_addresses.insert(peer_id, address.clone());
                    }
                }
                tracing::debug!(realm_id = self.realm_id, %peer_id, "Realm P2P connection established");
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                if num_established == 0 {
                    state.connected_peers.remove(&peer_id);
                }
                tracing::debug!(
                    realm_id = self.realm_id,
                    %peer_id,
                    remaining = num_established,
                    cause = ?cause,
                    "Realm P2P connection closed"
                );
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::debug!(realm_id = self.realm_id, ?peer_id, %error, "outgoing connection error");
            }
            _ => {}
        }
    }

    fn handle_proposal_part(
        &mut self,
        source: NodeId,
        source_peer: PeerId,
        data: &[u8],
        state: &mut DriveState,
    ) {
        let part = match ProposalPart::decode_exact(data) {
            Ok(part) => part,
            Err(error) => {
                tracing::debug!(realm_id = self.realm_id, %error, "dropped malformed ProposalPart");
                return;
            }
        };
        let now = Instant::now();
        match part {
            ProposalPart::Start {
                proposal,
                total_parts,
                body_len,
            } => {
                let proposal_id = proposal.proposal_id;
                match admit_proposal_start(
                    state,
                    &mut self.reassembly,
                    proposal,
                    total_parts,
                    body_len,
                    source_peer,
                    now,
                ) {
                    Ok(StartOutcome::Inserted) => {
                        tracing::info!(
                            realm_id = self.realm_id,
                            proposal = %hex::encode(proposal_id),
                            source = ?source,
                            total_parts,
                            body_len,
                            "Realm P2P proposal start accepted"
                        );
                    }
                    Ok(StartOutcome::Duplicate) => {}
                    Err(error) => {
                        tracing::debug!(realm_id = self.realm_id, %error, "rejected ProposalPart::Start");
                    }
                }
            }
            ProposalPart::Chunk {
                proposal_id,
                offset,
                data,
            } => {
                if state.proposal_source.get(&proposal_id) != Some(&source_peer) {
                    tracing::debug!(realm_id = self.realm_id, "dropped ProposalPart::Chunk from non-Start source");
                    return;
                }
                match self.reassembly.insert_chunk(&proposal_id, offset, &data, now) {
                    Ok(InsertOutcome::Complete) => {
                        match self.reassembly.finalize(&proposal_id) {
                            Ok(complete) => {
                                retain_active_proposal_sources(state, &self.reassembly);
                                tracing::info!(
                                    realm_id = self.realm_id,
                                    proposal = %hex::encode(proposal_id),
                                    source = ?source,
                                    body_len = complete.body.len(),
                                    "Realm P2P proposal body complete"
                                );
                                let _ = self.event_tx.try_send(RealmNetworkEvent::ProposalReady {
                                    source,
                                    proposal: complete.proposal,
                                    body: complete.body,
                                });
                            }
                            Err(error) => {
                                retain_active_proposal_sources(state, &self.reassembly);
                                tracing::debug!(
                                    realm_id = self.realm_id,
                                    %error,
                                    "proposal finalize failed"
                                );
                            }
                        }
                    }
                    Ok(outcome) => {
                        if let Some(reassembly) = self.reassembly.get(&proposal_id) {
                            tracing::debug!(
                                realm_id = self.realm_id,
                                proposal = %hex::encode(proposal_id),
                                contiguous = reassembly.contiguous(),
                                body_len = reassembly.body_len(),
                                ?outcome,
                                "Realm P2P proposal chunk"
                            );
                        }
                    }
                    Err(error) => {
                        tracing::debug!(realm_id = self.realm_id, %error, "rejected ProposalPart::Chunk");
                    }
                }
            }
        }
    }

    fn handle_end_cap_event(
        &mut self,
        event: request_response::Event<EndCapForwardRequest, EndCapForwardResponse>,
        state: &mut DriveState,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    let Ok(source) = NodeId::from_peer_id(&peer) else {
                        let _ = self.swarm.behaviour_mut().end_cap_forward.send_response(
                            channel,
                            EndCapForwardResponse::rejected(EndCapRejectReason::Invalid),
                        );
                        return;
                    };
                    let (reply_tx, reply_rx) = oneshot::channel();
                    let event = RealmNetworkEvent::EndCapReceived {
                        request_id,
                        source,
                        header: request.header,
                        input: request.input,
                        proof: request.proof,
                        reply: reply_tx,
                    };
                    if reply_queue_at_capacity(state.end_cap_replies.len())
                        || self.event_tx.try_send(event).is_err()
                    {
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .end_cap_forward
                            .send_response(
                                channel,
                                EndCapForwardResponse::rejected(EndCapRejectReason::Busy),
                            );
                        return;
                    }
                    state.end_cap_replies.push(async move {
                        (channel, reply_rx.await.ok())
                    }.boxed());
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some(tx) = state.end_cap_responses.remove(&request_id) {
                        let _ = tx.send(Ok(response));
                    }
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(tx) = state.end_cap_responses.remove(&request_id) {
                    let _ = tx.send(Err(NetworkError::DirectRequest(error.to_string())));
                }
            }
            _ => {}
        }
    }

    fn handle_body_chunk_event(
        &mut self,
        event: request_response::Event<BodyChunkRequest, BodyChunkResponse>,
        state: &mut DriveState,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request,
                    channel,
                    ..
                } => {
                    let Ok(source) = NodeId::from_peer_id(&peer) else {
                        return;
                    };
                    if !has_validator_leaf(state, &source) {
                        return;
                    }
                    let (reply_tx, reply_rx) = oneshot::channel();
                    if reply_queue_at_capacity(state.body_replies.len())
                        || self
                            .event_tx
                            .try_send(RealmNetworkEvent::DirectBodyReceived {
                                source,
                                request,
                                reply: reply_tx,
                            })
                            .is_err()
                    {
                        return;
                    }
                    state.body_replies.push(
                        async move { (channel, reply_rx.await.ok()) }.boxed(),
                    );
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some(tx) = state.pending_body.remove(&request_id) {
                        let _ = tx.send(Ok(response));
                        return;
                    }
                    let Some(proposal_id) = state.pending_direct.remove(&request_id) else {
                        return;
                    };
                    if let Some(reassembly) = self.reassembly.get_mut(&proposal_id) {
                        reassembly.set_direct_request_active(false, Instant::now());
                    }
                    if response.data.is_empty() {
                        return;
                    }
                    match self.reassembly.insert_chunk(
                        &proposal_id,
                        response.offset,
                        &response.data,
                        Instant::now(),
                    ) {
                        Ok(InsertOutcome::Complete) => {
                            if let Ok(complete) = self.reassembly.finalize(&proposal_id) {
                                let source = resolve_proposal_ready_source(
                                    state.proposal_source.get(&proposal_id),
                                );
                                retain_active_proposal_sources(state, &self.reassembly);
                                let Some(source) = source else {
                                    tracing::warn!(
                                        realm_id = self.realm_id,
                                        "dropped ProposalReady: missing or invalid source NodeId"
                                    );
                                    return;
                                };
                                let _ = self.event_tx.try_send(RealmNetworkEvent::ProposalReady {
                                    source,
                                    proposal: complete.proposal,
                                    body: complete.body,
                                });
                            } else {
                                retain_active_proposal_sources(state, &self.reassembly);
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::debug!(
                                realm_id = self.realm_id,
                                %error,
                                "direct-body chunk rejected"
                            );
                        }
                    }
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(tx) = state.pending_body.remove(&request_id) {
                    let _ = tx.send(Err(NetworkError::DirectRequest(error.to_string())));
                    return;
                }
                if let Some(proposal_id) = state.pending_direct.remove(&request_id) {
                    if let Some(reassembly) = self.reassembly.get_mut(&proposal_id) {
                        reassembly.set_direct_request_active(false, Instant::now());
                    }
                    tracing::debug!(
                        realm_id = self.realm_id,
                        %error,
                        "direct-body outbound failed"
                    );
                }
            }
            _ => {}
        }
    }

    fn handle_proposal_lookup_event(
        &mut self,
        event: request_response::Event<ProposalLookupRequest, ProposalLookupResponse>,
        state: &mut DriveState,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request,
                    channel,
                    ..
                } => {
                    let Ok(source) = NodeId::from_peer_id(&peer) else {
                        return;
                    };
                    if !has_validator_leaf(state, &source) {
                        return;
                    }
                    let (reply_tx, reply_rx) = oneshot::channel();
                    if reply_queue_at_capacity(state.lookup_replies.len())
                        || self
                            .event_tx
                            .try_send(RealmNetworkEvent::LookupReceived {
                                source,
                                request,
                                reply: reply_tx,
                            })
                            .is_err()
                    {
                        return;
                    }
                    state.lookup_replies.push(
                        async move { (channel, reply_rx.await.ok()) }.boxed(),
                    );
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some(tx) = state.pending_lookup.remove(&request_id) {
                        let _ = tx.send(Ok(response));
                    }
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(tx) = state.pending_lookup.remove(&request_id) {
                    let _ = tx.send(Err(NetworkError::DirectRequest(error.to_string())));
                }
            }
            _ => {}
        }
    }


    fn maintain(&mut self, state: &mut DriveState) {
        let now = Instant::now();
        self.redial_realm_peers(state);
        expire_reassembly(state, &mut self.reassembly, now);
        expire_idle_vote_auth(state, now);

        let mut expired = Vec::new();
        state.vote_waiters.retain_mut(|waiter| {
            if now >= waiter.deadline {
                expired.push((
                    waiter.proposal_id,
                    std::mem::replace(&mut waiter.response, oneshot::channel().0),
                ));
                false
            } else {
                true
            }
        });
        for (proposal_id, response) in expired {
            let _ = response.send(Err(NetworkError::Timeout("wait_votes".into())));
            clear_vote_auth_if_idle(state, proposal_id);
        }

        let retry = Duration::from_secs(RANGE_REQUEST_RETRY_INTERVAL_SECS);
        let proposal_ids: Vec<[u8; 32]> = self.reassembly.proposal_ids().collect();
        for proposal_id in proposal_ids {
            let Some(peer) = state.proposal_source.get(&proposal_id).copied() else {
                continue;
            };
            let Some(reassembly) = self.reassembly.get_mut(&proposal_id) else {
                continue;
            };
            if reassembly.direct_request_active() || reassembly.is_complete() {
                continue;
            }
            if let Some(last) = reassembly.last_request_at() {
                if now.duration_since(last) < retry {
                    continue;
                }
            }
            let remaining = reassembly.body_len().saturating_sub(reassembly.contiguous());
            if remaining == 0 {
                continue;
            }
            let max_bytes = remaining.min(BODY_CHUNK_MAX_BYTES as u64) as u32;
            let request = BodyChunkRequest {
                proposal_id,
                offset: reassembly.contiguous(),
                max_bytes,
            };
            reassembly.set_direct_request_active(true, now);
            let request_id = self
                .swarm
                .behaviour_mut()
                .body_chunk
                .send_request(&peer, request);
            state.pending_direct.insert(request_id, proposal_id);
        }
    }

    /// Validator and bootnode peers this node must stay connected to.
    fn realm_peer_targets(&self, state: &DriveState) -> HashSet<PeerId> {
        let mut targets: HashSet<PeerId> = state
            .validator_leaves
            .keys()
            .map(|node_id| node_id.to_peer_id())
            .collect();
        targets.extend(
            self.config
                .bootnode_addresses
                .iter()
                .map(|(peer_id, _)| *peer_id),
        );
        targets.remove(&self.swarm.local_peer_id());
        targets
    }

    fn register_realm_peers(&mut self, state: &mut DriveState) {
        let targets = self.realm_peer_targets(state);
        if targets == state.explicit_peers {
            return;
        }
        for peer_id in targets.difference(&state.explicit_peers) {
            register_explicit_peer(self.swarm.behaviour_mut(), *peer_id);
        }
        for peer_id in state.explicit_peers.difference(&targets) {
            self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(peer_id);
        }
        tracing::info!(
            realm_id = self.realm_id,
            peers = ?targets,
            "Realm gossipsub explicit peers registered"
        );
        state.explicit_peers = targets;
    }

    /// Reconnect disconnected realm peers with a bounded per-peer backoff.
    fn redial_realm_peers(&mut self, state: &mut DriveState) {
        let now = Instant::now();
        let backoff = Duration::from_secs(REALM_PEER_REDIAL_BACKOFF_SECS);
        for peer_id in self.realm_peer_targets(state) {
            if state.connected_peers.contains(&peer_id) {
                continue;
            }
            if state
                .dial_attempts
                .get(&peer_id)
                .is_some_and(|last| now.duration_since(*last) < backoff)
            {
                continue;
            }
            state.dial_attempts.insert(peer_id, now);
            let dial: libp2p::swarm::dial_opts::DialOpts =
                if let Some((_, address)) = self
                    .config
                    .bootnode_addresses
                    .iter()
                    .find(|(candidate, _)| *candidate == peer_id)
                {
                    peer_dial_address(peer_id, address).into()
                } else if let Some(address) = state.learned_addresses.get(&peer_id) {
                    peer_dial_address(peer_id, address).into()
                } else {
                    peer_id.into()
                };
            if let Err(error) = self.swarm.dial(dial) {
                tracing::debug!(realm_id = self.realm_id, %peer_id, %error, "Realm peer dial failed");
            }
        }
    }

    fn is_realm_peer(&self, state: &DriveState, peer_id: &PeerId) -> bool {
        state
            .validator_leaves
            .keys()
            .any(|node_id| node_id.to_peer_id() == *peer_id)
            || self
                .config
                .bootnode_addresses
                .iter()
                .any(|(candidate, _)| candidate == peer_id)
    }
}

fn peer_dial_address(peer_id: PeerId, address: &Multiaddr) -> Multiaddr {
    let mut dial = address.clone();
    if !dial.iter().any(|p| matches!(p, Protocol::P2p(_))) {
        dial.push(Protocol::P2p(peer_id));
    }
    dial
}

fn publish_proposal_parts(
    swarm: &mut libp2p::Swarm<crate::realm::network::RealmBehaviour>,
    realm_id: u32,
    proposal: &Proposal,
    body: &[u8],
) -> Result<(), NetworkError> {
    if body.is_empty() {
        return Err(NetworkError::Protocol(psy_data::p2p::ProtocolError::Message(
            "proposal body is empty",
        )));
    }
    let chunk_size = MAX_PROPOSAL_CHUNK_BYTES;
    let total_parts = body.len().div_ceil(chunk_size) as u32;
    let start = ProposalPart::Start {
        proposal: proposal.clone(),
        total_parts,
        body_len: body.len() as u64,
    };
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(proposal_topic(realm_id), start.protocol_encode_to_vec())
        .map_err(|error| NetworkError::Behaviour(error.to_string()))?;
    let mut offset = 0usize;
    while offset < body.len() {
        let end = (offset + chunk_size).min(body.len());
        let chunk = ProposalPart::Chunk {
            proposal_id: proposal.proposal_id,
            offset: offset as u64,
            data: body[offset..end].to_vec(),
        };
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(proposal_topic(realm_id), chunk.protocol_encode_to_vec())
            .map_err(|error| NetworkError::Behaviour(error.to_string()))?;
        offset = end;
    }
    Ok(())
}

fn register_proposal_vote_auth(
    state: &mut DriveState,
    proposal: &Proposal,
    leaf_bls_keys: Vec<(u16, BlsPublicKey)>,
    now: Instant,
) {
    let leaf_bls_keys = leaf_bls_keys
        .into_iter()
        .filter(|(sub_id, _)| *sub_id != proposal.proposer_sub_id)
        .collect();
    if !state.vote_auth.contains_key(&proposal.proposal_id) {
        evict_idle_vote_auth(state);
        if state.vote_auth.len() >= MAX_VOTE_AUTH {
            return;
        }
    }
    state.vote_auth.insert(
        proposal.proposal_id,
        ProposalVoteAuth {
            vote_message: vote_message(
                proposal.chain_id,
                proposal.realm_id,
                &proposal.validator_tree_root,
                &proposal.proposal_id,
            ),
            leaf_bls_keys,
            inserted_at: now,
        },
    );
}

fn evict_idle_vote_auth(state: &mut DriveState) {
    while state.vote_auth.len() >= MAX_VOTE_AUTH {
        let oldest_idle = state
            .vote_auth
            .iter()
            .filter(|(proposal_id, _)| {
                !state
                    .vote_waiters
                    .iter()
                    .any(|waiter| waiter.proposal_id == **proposal_id)
            })
            .min_by_key(|(_, auth)| auth.inserted_at)
            .map(|(proposal_id, _)| *proposal_id);
        let Some(proposal_id) = oldest_idle else {
            break;
        };
        state.vote_auth.remove(&proposal_id);
        state.vote_backlog.remove(&proposal_id);
    }
}

fn expire_idle_vote_auth(state: &mut DriveState, now: Instant) {
    let ttl = Duration::from_secs(VOTE_AUTH_TTL_SECS);
    let expired: Vec<[u8; 32]> = state
        .vote_auth
        .iter()
        .filter(|(proposal_id, auth)| {
            now.duration_since(auth.inserted_at) >= ttl
                && !state
                    .vote_waiters
                    .iter()
                    .any(|waiter| waiter.proposal_id == **proposal_id)
        })
        .map(|(proposal_id, _)| *proposal_id)
        .collect();
    for proposal_id in expired {
        state.vote_auth.remove(&proposal_id);
        state.vote_backlog.remove(&proposal_id);
    }
}

fn admit_proposal_start(
    state: &mut DriveState,
    book: &mut ReassemblyBook,
    proposal: Proposal,
    total_parts: u32,
    body_len: u64,
    source_peer: PeerId,
    now: Instant,
) -> Result<StartOutcome, NetworkError> {
    let proposal_id = proposal.proposal_id;
    let outcome = book.start(proposal, total_parts, body_len, now)?;
    state.proposal_source.insert(proposal_id, source_peer);
    retain_active_proposal_sources(state, book);
    Ok(outcome)
}

fn retain_active_proposal_sources(state: &mut DriveState, book: &ReassemblyBook) {
    let active: HashSet<[u8; 32]> = book.proposal_ids().collect();
    state.proposal_source.retain(|proposal_id, _| active.contains(proposal_id));
}

fn expire_reassembly(state: &mut DriveState, book: &mut ReassemblyBook, now: Instant) {
    let _ = book.expire(now);
    retain_active_proposal_sources(state, book);
}

fn reply_queue_at_capacity(len: usize) -> bool {
    len >= MAX_CONCURRENT_DIRECT_EXCHANGES
}

fn has_validator_leaf(state: &DriveState, node_id: &NodeId) -> bool {
    state.validator_leaves.contains_key(node_id)
}

fn replace_validator_leaves(
    state: &mut DriveState,
    leaves: Vec<ValidatorLeaf>,
) -> Result<(), NetworkError> {
    if leaves.len() > MAX_VALIDATORS_PER_REALM {
        return Err(NetworkError::Rejected(format!(
            "validator leaf count {} exceeds {MAX_VALIDATORS_PER_REALM}",
            leaves.len()
        )));
    }
    state.validator_leaves.clear();
    for leaf in leaves {
        state.validator_leaves.insert(leaf.node_id, leaf);
    }
    Ok(())
}

fn vote_is_authenticated(state: &DriveState, vote: &Vote) -> bool {
    let Some(auth) = state.vote_auth.get(&vote.proposal_id) else {
        return false;
    };
    let Some(public_key) = auth
        .leaf_bls_keys
        .iter()
        .find(|(sub_id, _)| *sub_id == vote.signer_sub_id)
        .map(|(_, key)| key)
    else {
        return false;
    };
    vote.signature.verify_vote(&auth.vote_message, public_key).is_ok()
}

fn clear_vote_auth_if_idle(state: &mut DriveState, proposal_id: [u8; 32]) {
    if state.vote_waiters.iter().any(|waiter| waiter.proposal_id == proposal_id) {
        return;
    }
    state.vote_auth.remove(&proposal_id);
    state.vote_backlog.remove(&proposal_id);
}

fn feed_vote_waiters(state: &mut DriveState, vote: &Vote) -> bool {
    if !vote_is_authenticated(state, vote) {
        return false;
    }
    let mut delivered = false;
    let mut completed = Vec::new();
    for (index, waiter) in state.vote_waiters.iter_mut().enumerate() {
        if waiter.proposal_id != vote.proposal_id || !waiter.seen.insert(vote.signer_sub_id) {
            continue;
        }
        delivered = true;
        waiter.votes.push(vote.clone());
        if waiter.votes.len() >= waiter.threshold {
            completed.push(index);
        }
    }
    if !delivered {
        let votes = state.vote_backlog.entry(vote.proposal_id).or_default();
        if !votes.iter().any(|existing| existing.signer_sub_id == vote.signer_sub_id) {
            votes.push(vote.clone());
        }
    }
    let mut completed_ids = Vec::new();
    for index in completed.into_iter().rev() {
        let waiter = state.vote_waiters.remove(index);
        completed_ids.push(waiter.proposal_id);
        let _ = waiter.response.send(Ok(waiter.votes));
    }
    for proposal_id in completed_ids {
        clear_vote_auth_if_idle(state, proposal_id);
    }
    true
}


/// Fail-closed `wait_votes` configuration check: a zero threshold would
/// complete immediately with whatever votes are already known, so it is
/// rejected.
fn validate_wait_votes_threshold(threshold: usize) -> Result<(), NetworkError> {
    if threshold == 0 {
        return Err(NetworkError::Configuration(
            "wait_votes threshold must be non-zero".into(),
        ));
    }
    Ok(())
}

/// Resolve the `ProposalReady` source `NodeId` from the recorded gossip
/// source peer for a proposal. Fails closed: a missing source or a peer that
/// is not an Ed25519 identity multihash yields `None` — it never falls back
/// to the local node id.
///
/// Wired from the direct-body completion path by the coordinator; kept as a
/// pure function so the fail-closed policy is unit-tested without a Swarm.
fn resolve_proposal_ready_source(source_peer: Option<&PeerId>) -> Option<NodeId> {
    source_peer.and_then(|peer| NodeId::from_peer_id(peer).ok())
}

/// Fail-closed answer for an inbound end-cap forward whose `EndCapReceived`
/// event could not be delivered: the requesting peer must be told the
/// end-cap was not accepted (`accepted = false`) instead of being left
/// hanging. A successful delivery is answered later over the reply channel,
/// so nothing is sent here.
#[allow(dead_code)]
fn end_cap_reject_response(delivered: Result<(), ()>) -> Option<EndCapForwardResponse> {
    delivered
        .err()
        .map(|()| EndCapForwardResponse::rejected(EndCapRejectReason::Busy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p_identity::Keypair;
    #[test]
    fn resolve_proposal_ready_source_returns_recorded_source() {
        let keypair = Keypair::generate_ed25519();
        let peer = keypair.public().to_peer_id();
        let node = NodeId::from_peer_id(&peer).expect("ed25519 peer yields NodeId");
        assert_eq!(resolve_proposal_ready_source(Some(&peer)), Some(node));
        assert_eq!(node.to_peer_id(), peer);
    }

    #[test]
    fn resolve_proposal_ready_source_missing_source_is_none() {
        // No recorded source must fail closed — never fall back to the local
        // node id.
        assert_eq!(resolve_proposal_ready_source(None), None);
    }

    #[test]
    fn resolve_proposal_ready_source_rejects_non_ed25519_peer() {
        // A SHA-2-256 multihash is a valid libp2p PeerId but not an Ed25519
        // identity multihash, so NodeId conversion fails and the source must
        // resolve to None.
        let mut bytes = Vec::new();
        bytes.push(0x12); // sha2-256 multihash code
        bytes.push(0x20); // 32-byte digest length
        bytes.extend_from_slice(&[0u8; 32]);
        let peer = PeerId::from_bytes(&bytes).expect("sha256 multihash is a valid PeerId");
        assert!(NodeId::from_peer_id(&peer).is_err());
        assert_eq!(resolve_proposal_ready_source(Some(&peer)), None);
    }

    #[test]
    fn end_cap_reject_response_fails_closed_on_delivery_error() {
        assert_eq!(end_cap_reject_response(Ok(())), None);
        let rejected = end_cap_reject_response(Err(())).expect("failure yields a response");
        assert!(!rejected.is_accepted());
        assert_eq!(rejected.reject_reason(), EndCapRejectReason::Busy);
    }

    #[test]
    fn validate_wait_votes_threshold_rejects_zero() {
        assert!(validate_wait_votes_threshold(0).is_err());
        assert!(validate_wait_votes_threshold(1).is_ok());
        assert!(validate_wait_votes_threshold(7).is_ok());
    }

    fn bls_secret(seed: u8) -> psy_data::p2p::BlsSecretKey {
        psy_data::p2p::BlsSecretKey::key_gen(&[seed; 32]).expect("bls ikm")
    }

    fn test_proposal(proposal_id: [u8; 32]) -> Proposal {
        Proposal {
            chain_id: 1,
            realm_id: 7,
            base_checkpoint_id: 10,
            proposer_sub_id: 1,
            validator_tree_root: [9u8; 32],
            proposal_id,
            public_output_hash: [0u8; 32],
            finalizer_proof_hash: [0u8; 32],
            backup_hash: [0u8; 32],
            body_hash: [0u8; 32],
        }
    }

    fn signed_vote(
        secret: &psy_data::p2p::BlsSecretKey,
        proposal: &Proposal,
        signer_sub_id: u16,
        message: &[u8],
    ) -> Vote {
        Vote {
            proposal_id: proposal.proposal_id,
            signer_sub_id,
            signature: secret.sign_vote(message),
        }
    }

    #[test]
    fn invalid_signature_with_real_sub_id_cannot_suppress_later_valid_vote() {
        let mut state = DriveState::new();
        let proposal = test_proposal([0x11; 32]);
        let secret = bls_secret(1);
        let remote_sub_id = 2;
        let leaf_bls_keys = vec![(remote_sub_id, secret.public_key())];
        let canonical = vote_message(
            proposal.chain_id,
            proposal.realm_id,
            &proposal.validator_tree_root,
            &proposal.proposal_id,
        );
        let garbage = signed_vote(&secret, &proposal, remote_sub_id, b"not-the-vote-message");
        let valid = signed_vote(&secret, &proposal, remote_sub_id, &canonical);

        assert!(!feed_vote_waiters(&mut state, &garbage));
        assert!(state.vote_backlog.is_empty());

        register_proposal_vote_auth(&mut state, &proposal, leaf_bls_keys, Instant::now());
        let (response, mut result) = oneshot::channel();
        state.vote_waiters.push(VoteWaiter {
            proposal_id: proposal.proposal_id,
            threshold: 1,
            deadline: Instant::now() + Duration::from_secs(60),
            votes: Vec::new(),
            seen: HashSet::new(),
            response,
        });
        assert!(!feed_vote_waiters(&mut state, &garbage));
        assert!(state.vote_waiters[0].seen.is_empty());
        assert!(state.vote_backlog.is_empty());
        assert!(feed_vote_waiters(&mut state, &valid));
        let votes = result.try_recv().expect("waiter completed").expect("votes");
        assert_eq!(votes, vec![valid]);
        assert!(state.vote_waiters.is_empty());
        assert!(state.vote_auth.get(&proposal.proposal_id).is_none());
    }

    #[test]
    fn proposer_or_unknown_sub_id_cannot_complete_waiter() {
        let mut state = DriveState::new();
        let proposal = test_proposal([0x22; 32]);
        let proposer = bls_secret(2);
        let remote = bls_secret(3);
        register_proposal_vote_auth(
            &mut state,
            &proposal,
            vec![
                (proposal.proposer_sub_id, proposer.public_key()),
                (2, remote.public_key()),
            ],
            Instant::now(),
        );
        let canonical = vote_message(
            proposal.chain_id,
            proposal.realm_id,
            &proposal.validator_tree_root,
            &proposal.proposal_id,
        );
        let (response, mut result) = oneshot::channel();
        state.vote_waiters.push(VoteWaiter {
            proposal_id: proposal.proposal_id,
            threshold: 1,
            deadline: Instant::now() + Duration::from_secs(60),
            votes: Vec::new(),
            seen: HashSet::new(),
            response,
        });
        assert!(!feed_vote_waiters(
            &mut state,
            &signed_vote(&proposer, &proposal, proposal.proposer_sub_id, &canonical)
        ));
        assert!(!feed_vote_waiters(
            &mut state,
            &signed_vote(&bls_secret(4), &proposal, 99, &canonical)
        ));
        assert!(state.vote_waiters[0].seen.is_empty());
        assert!(state.vote_backlog.is_empty());
        assert!(result.try_recv().is_err());
        assert!(state.vote_auth.contains_key(&proposal.proposal_id));
        let remote_vote = signed_vote(&remote, &proposal, 2, &canonical);
        assert!(feed_vote_waiters(&mut state, &remote_vote));
        let votes = result.try_recv().expect("waiter completed").expect("votes");
        assert_eq!(votes, vec![remote_vote]);
    }

    #[test]
    fn valid_vote_reaches_waiter_threshold() {
        let mut state = DriveState::new();
        let proposal = test_proposal([0x33; 32]);
        let secret = bls_secret(4);
        let remote_sub_id = 2;
        register_proposal_vote_auth(
            &mut state,
            &proposal,
            vec![(remote_sub_id, secret.public_key())],
            Instant::now(),
        );
        let canonical = vote_message(
            proposal.chain_id,
            proposal.realm_id,
            &proposal.validator_tree_root,
            &proposal.proposal_id,
        );
        let valid = signed_vote(&secret, &proposal, remote_sub_id, &canonical);
        let (response, mut result) = oneshot::channel();
        state.vote_waiters.push(VoteWaiter {
            proposal_id: proposal.proposal_id,
            threshold: 1,
            deadline: Instant::now() + Duration::from_secs(60),
            votes: Vec::new(),
            seen: HashSet::new(),
            response,
        });
        assert!(feed_vote_waiters(&mut state, &valid));
        let votes = result.try_recv().expect("waiter completed").expect("votes");
        assert_eq!(votes, vec![valid]);
        assert!(state.vote_waiters.is_empty());
        assert!(state.vote_auth.get(&proposal.proposal_id).is_none());
        assert!(state.vote_backlog.get(&proposal.proposal_id).is_none());
    }

    #[test]
    fn unfinished_proposals_keep_reassembly_and_source_maps_bounded() {
        let mut book = ReassemblyBook::new(
            MAX_IN_FLIGHT_PROPOSALS,
            MAX_PROPOSAL_CHUNK_BYTES,
            Duration::from_secs(1_800),
        );
        let mut state = DriveState::new();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let now = Instant::now();
        for index in 0..32u8 {
            let mut proposal_id = [0u8; 32];
            proposal_id[0] = index;
            admit_proposal_start(
                &mut state,
                &mut book,
                test_proposal(proposal_id),
                1,
                1,
                peer,
                now,
            )
            .expect("valid start");
        }
        assert_eq!(book.active_count(), MAX_IN_FLIGHT_PROPOSALS);
        assert_eq!(state.proposal_source.len(), book.active_count());
        assert!(state.proposal_source.len() <= MAX_IN_FLIGHT_PROPOSALS);

        expire_reassembly(&mut state, &mut book, now + Duration::from_secs(1_801));
        assert_eq!(book.active_count(), 0);
        assert_eq!(state.proposal_source.len(), 0);
    }

    #[test]
    fn vote_auth_without_waiter_is_capped_and_expires() {
        let mut state = DriveState::new();
        let now = Instant::now();
        for index in 0..16u8 {
            let mut proposal_id = [0u8; 32];
            proposal_id[0] = index;
            register_proposal_vote_auth(&mut state, &test_proposal(proposal_id), Vec::new(), now);
        }
        assert!(state.vote_auth.len() <= MAX_VOTE_AUTH);
        assert!(state.vote_backlog.len() <= MAX_VOTE_AUTH);
        expire_idle_vote_auth(&mut state, now + Duration::from_secs(VOTE_AUTH_TTL_SECS));
        assert!(state.vote_auth.is_empty());
        assert!(state.vote_backlog.is_empty());
    }

    #[test]
    fn reply_queue_capacity_matches_direct_exchange_limit() {
        assert!(!reply_queue_at_capacity(0));
        assert!(!reply_queue_at_capacity(MAX_CONCURRENT_DIRECT_EXCHANGES - 1));
        assert!(reply_queue_at_capacity(MAX_CONCURRENT_DIRECT_EXCHANGES));
        assert!(reply_queue_at_capacity(MAX_CONCURRENT_DIRECT_EXCHANGES + 1));
    }

    #[test]
    fn missing_validator_leaf_closes_as_not_a_validator() {
        let mut state = DriveState::new();
        let node = NodeId::from_keypair(&Keypair::generate_ed25519()).expect("ed25519");
        assert!(!has_validator_leaf(&state, &node));
        let leaf = ValidatorLeaf::new(1, node, bls_secret(1).public_key());
        replace_validator_leaves(&mut state, vec![leaf]).expect("leaf count fits");
        assert!(has_validator_leaf(&state, &node));
        let other = NodeId::from_keypair(&Keypair::generate_ed25519()).expect("ed25519");
        assert!(!has_validator_leaf(&state, &other));
    }
}
