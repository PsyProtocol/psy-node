//! Drive loop for [`RealmNetwork`]: commands, swarm events, vote waiters.
use crate::realm::network::behaviour::{proposal_topic, vote_topic, RealmBehaviourEvent};
use crate::realm::network::codec::EndCapForwardRequest;
use crate::realm::network::{
    InsertOutcome, NetworkError, RealmNetwork, RealmNetworkCommand, RealmNetworkEvent,
    StartOutcome,
};
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use libp2p::gossipsub;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{
    self, InboundRequestId, OutboundRequestId, ResponseChannel,
};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use psy_data::p2p::{
    DirectBodyRequest, DirectBodyResponse, EndCapForwardResponse, NodeId, Proposal, ProposalPart,
    ProtocolEncode, RealmFinalizeSubmitCode, RealmFinalizeSubmitResponse, Vote,
    DIRECT_REQUEST_MAX_BYTES, MAINTENANCE_TICK_SECS, MAX_PROPOSAL_CHUNK_BYTES,
    RANGE_REQUEST_RETRY_INTERVAL_SECS,
};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

struct VoteWaiter {
    proposal_id: [u8; 32],
    threshold: usize,
    deadline: Instant,
    votes: Vec<Vote>,
    seen: HashSet<u16>,
    response: oneshot::Sender<Result<Vec<Vote>, NetworkError>>,
}

struct DriveState {
    published_bodies: HashMap<[u8; 32], (Proposal, Vec<u8>)>,
    proposal_source: HashMap<[u8; 32], PeerId>,
    pending_end_cap: HashMap<
        OutboundRequestId,
        oneshot::Sender<Result<EndCapForwardResponse, NetworkError>>,
    >,
    pending_finalize: HashMap<
        OutboundRequestId,
        oneshot::Sender<Result<RealmFinalizeSubmitResponse, NetworkError>>,
    >,
    inbound_body: HashMap<InboundRequestId, ResponseChannel<DirectBodyResponse>>,
    pending_direct: HashMap<OutboundRequestId, [u8; 32]>,
    vote_backlog: HashMap<[u8; 32], Vec<Vote>>,
    vote_waiters: Vec<VoteWaiter>,
    end_cap_replies: FuturesUnordered<
        BoxFuture<'static, (ResponseChannel<EndCapForwardResponse>, Option<EndCapForwardResponse>)>,
    >,
}

impl DriveState {
    fn new() -> Self {
        Self {
            published_bodies: HashMap::new(),
            proposal_source: HashMap::new(),
            pending_end_cap: HashMap::new(),
            pending_finalize: HashMap::new(),
            inbound_body: HashMap::new(),
            pending_direct: HashMap::new(),
            vote_backlog: HashMap::new(),
            vote_waiters: Vec::new(),
            end_cap_replies: FuturesUnordered::new(),
        }
    }
}

pub async fn run_realm_network(mut network: RealmNetwork) {
    network.run().await;
}

impl RealmNetwork {
    pub async fn run(&mut self) {
        let mut state = DriveState::new();
        for (peer_id, address) in self.config.bootnode_addresses.clone() {
            let mut dial = address.clone();
            if !dial.iter().any(|p| matches!(p, Protocol::P2p(_))) {
                dial.push(Protocol::P2p(peer_id));
            }
            if let Err(error) = self.swarm.dial(dial) {
                tracing::warn!(
                    realm_id = self.realm_id,
                    %peer_id,
                    %error,
                    "failed to dial Realm bootnode"
                );
            }
        }

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
                    let response = reply.unwrap_or_else(|| EndCapForwardResponse::new(false));
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
                state.pending_end_cap.insert(request_id, response);
            }
            RealmNetworkCommand::PublishProposal {
                proposal,
                body,
                response,
            } => {
                let result = publish_proposal_parts(
                    &mut self.swarm,
                    self.realm_id,
                    &proposal,
                    &body,
                );
                if result.is_ok() {
                    state
                        .published_bodies
                        .insert(proposal.proposal_id, (proposal, body));
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
            RealmNetworkCommand::SubmitFinalize { request, response } => {
                match first_coordinator_peer(&self.config.coordinator_addresses) {
                    Ok(peer) => {
                        if let Some(address) = self.config.coordinator_addresses.first() {
                            let _ = self.swarm.dial(address.clone());
                        }
                        let request_id = self
                            .swarm
                            .behaviour_mut()
                            .realm_finalize_submit
                            .send_request(&peer, request);
                        state.pending_finalize.insert(request_id, response);
                    }
                    Err(error) => {
                        let _ = response.send(Err(error));
                    }
                }
            }
            RealmNetworkCommand::ServeBody {
                request_id,
                response_body,
                response,
            } => {
                let result = match state.inbound_body.remove(&request_id) {
                    Some(channel) => self
                        .swarm
                        .behaviour_mut()
                        .direct_body
                        .send_response(channel, response_body)
                        .map_err(|_| NetworkError::DirectRequest("direct-body response channel closed".into())),
                    None => Err(NetworkError::DirectRequest(
                        "unknown inbound direct-body request".into(),
                    )),
                };
                let _ = response.send(result);
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
                let votes = state.vote_backlog.remove(&proposal_id).unwrap_or_default();
                if votes.len() >= threshold {
                    let _ = response.send(Ok(votes));
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
                            tracing::info!(
                                "realm P2P vote received proposal={} signer_sub_id={} realm={} source={:?}",
                                hex::encode(vote.proposal_id),
                                vote.signer_sub_id,
                                self.realm_id,
                                source
                            );
                            feed_vote_waiters(state, &vote);
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
            SwarmEvent::Behaviour(RealmBehaviourEvent::DirectBody(event)) => {
                self.handle_direct_body_event(event, state);
            }
            SwarmEvent::Behaviour(RealmBehaviourEvent::RealmFinalizeSubmit(event)) => {
                self.handle_finalize_event(event, state);
            }
            SwarmEvent::Behaviour(_) => {}
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
                state
                    .proposal_source
                    .insert(proposal.proposal_id, source_peer);
                match self
                    .reassembly
                    .start(proposal, total_parts, body_len, now)
                {
                    Ok(StartOutcome::Inserted | StartOutcome::Duplicate) => {}
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
                                let _ = self.event_tx.try_send(RealmNetworkEvent::ProposalReady {
                                    source,
                                    proposal: complete.proposal,
                                    body: complete.body,
                                });
                            }
                            Err(error) => {
                                tracing::debug!(
                                    realm_id = self.realm_id,
                                    %error,
                                    "proposal finalize failed"
                                );
                            }
                        }
                    }
                    Ok(_) => {}
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
                            EndCapForwardResponse::new(false),
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
                    if self.event_tx.try_send(event).is_err() {
                        let _ = self
                            .swarm
                            .behaviour_mut()
                            .end_cap_forward
                            .send_response(channel, EndCapForwardResponse::new(false));
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
                    if let Some(tx) = state.pending_end_cap.remove(&request_id) {
                        let _ = tx.send(Ok(response));
                    }
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(tx) = state.pending_end_cap.remove(&request_id) {
                    let _ = tx.send(Err(NetworkError::DirectRequest(error.to_string())));
                }
            }
            _ => {}
        }
    }

    fn handle_direct_body_event(
        &mut self,
        event: request_response::Event<DirectBodyRequest, DirectBodyResponse>,
        state: &mut DriveState,
    ) {
        match event {
            request_response::Event::Message { message, .. } => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => match serve_published_body(&state.published_bodies, &request) {
                    Ok(response_body) => {
                        if self
                            .swarm
                            .behaviour_mut()
                            .direct_body
                            .send_response(channel, response_body)
                            .is_err()
                        {
                            tracing::debug!(
                                realm_id = self.realm_id,
                                "direct-body inbound response channel closed"
                            );
                        }
                    }
                    Err(error) => {
                        state.inbound_body.insert(request_id, channel);
                        tracing::debug!(
                            realm_id = self.realm_id,
                            %error,
                            "no published body for inbound DirectBodyRequest"
                        );
                    }
                },
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
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
                                let Some(source) = resolve_proposal_ready_source(
                                    state.proposal_source.get(&proposal_id),
                                ) else {
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

    fn handle_finalize_event(
        &mut self,
        event: request_response::Event<
            psy_data::p2p::RealmFinalizeSubmitRequest,
            RealmFinalizeSubmitResponse,
        >,
        state: &mut DriveState,
    ) {
        match event {
            request_response::Event::Message { message, .. } => match message {
                request_response::Message::Request { channel, .. } => {
                    let _ = self.swarm.behaviour_mut().realm_finalize_submit.send_response(
                        channel,
                        RealmFinalizeSubmitResponse::new(RealmFinalizeSubmitCode::Internal),
                    );
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some(tx) = state.pending_finalize.remove(&request_id) {
                        let _ = tx.send(Ok(response));
                    }
                }
            },
            request_response::Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(tx) = state.pending_finalize.remove(&request_id) {
                    let _ = tx.send(Err(NetworkError::DirectRequest(error.to_string())));
                }
            }
            _ => {}
        }
    }

    fn maintain(&mut self, state: &mut DriveState) {
        let now = Instant::now();
        let _ = self.reassembly.expire(now);

        let mut expired = Vec::new();
        state.vote_waiters.retain_mut(|waiter| {
            if now >= waiter.deadline {
                expired.push(std::mem::replace(
                    &mut waiter.response,
                    oneshot::channel().0,
                ));
                false
            } else {
                true
            }
        });
        for response in expired {
            let _ = response.send(Err(NetworkError::Timeout("wait_votes".into())));
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
            let max_bytes = remaining.min(DIRECT_REQUEST_MAX_BYTES as u64) as u32;
            let request = DirectBodyRequest {
                proposal_id,
                offset: reassembly.contiguous(),
                max_bytes,
            };
            reassembly.set_direct_request_active(true, now);
            let request_id = self
                .swarm
                .behaviour_mut()
                .direct_body
                .send_request(&peer, request);
            state.pending_direct.insert(request_id, proposal_id);
        }
    }
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

fn serve_published_body(
    published: &HashMap<[u8; 32], (Proposal, Vec<u8>)>,
    request: &DirectBodyRequest,
) -> Result<DirectBodyResponse, NetworkError> {
    let (_proposal, body) = published.get(&request.proposal_id).ok_or_else(|| {
        NetworkError::DirectRequest("unknown proposal body".into())
    })?;
    let start = request.offset as usize;
    if start > body.len() {
        return Err(NetworkError::DirectRequest(
            "direct-body offset past end".into(),
        ));
    }
    let take = (request.max_bytes as usize).min(body.len() - start);
    let data = body[start..start + take].to_vec();
    Ok(DirectBodyResponse {
        offset: request.offset,
        eof: start + take == body.len(),
        body_len: body.len() as u64,
        body_hash: sha_body_hash(body),
        data,
    })
}

fn sha_body_hash(body: &[u8]) -> [u8; 32] {
    psy_data::p2p::sha256(body)
}

fn feed_vote_waiters(state: &mut DriveState, vote: &Vote) {
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
    for index in completed.into_iter().rev() {
        let waiter = state.vote_waiters.remove(index);
        let _ = waiter.response.send(Ok(waiter.votes));
    }
}

fn first_coordinator_peer(addresses: &[Multiaddr]) -> Result<PeerId, NetworkError> {
    addresses
        .iter()
        .find_map(|address| {
            address.iter().find_map(|protocol| match protocol {
                Protocol::P2p(peer) => Some(peer),
                _ => None,
            })
        })
        .ok_or_else(|| {
            NetworkError::Configuration("coordinator address has no /p2p PeerId".into())
        })
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
    delivered.err().map(|()| EndCapForwardResponse::new(false))
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
    }

    #[test]
    fn validate_wait_votes_threshold_rejects_zero() {
        assert!(validate_wait_votes_threshold(0).is_err());
        assert!(validate_wait_votes_threshold(1).is_ok());
        assert!(validate_wait_votes_threshold(7).is_ok());
    }
}
