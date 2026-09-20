//! Catch-up window fetching: peer selection, staged windows, and body downloads.

use std::collections::HashMap;

use anyhow::Context;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::p2p::{
    sha256, BodyChunkRequest, BodyChunkResponse, NodeId, Proposal, ProposalLookupEntry,
    ProposalLookupRequest, ProposalLookupResponse, ProposalLookupStatus, RealmTransition,
    BODY_CHUNK_MAX_BYTES, MAX_PROPOSAL_BODY_BYTES, PROPOSAL_LOOKUP_CONCURRENCY,
    PROPOSAL_LOOKUP_ROUND_SECS, PROPOSAL_LOOKUP_TIMEOUT_SECS, PROPOSAL_LOOKUP_WINDOW_TRANSITIONS,
};

use crate::realm::network::RealmNetworkCommands;
use crate::realm::processor::proposal_backup::{ProposalBackup, StagedProposal};

pub const CATCHUP_TRANSITION_ATTEMPTS: usize = 3;

/// One window transition after the fetch stage: staged bytes awaiting verification.
pub enum TransitionFetchOutcome {
    Staged(RealmTransition, StagedProposal),
    Absent(RealmTransition),
    Failed(RealmTransition, anyhow::Error),
}

/// Last-modified events must be chronological. Equal roots are leaf rewrites, not bodies.
/// A→B→A keeps the A→B hop because that first value differs.
pub(crate) fn first_root_change(
    last_committed: u64,
    last_committed_root: [u8; 32],
    last_modifieds: &[(u64, [u8; 32])],
) -> Option<(RealmTransition, u64)> {
    let mut old_root = last_committed_root;
    for &(checkpoint_id, new_root) in last_modifieds {
        if checkpoint_id <= last_committed {
            continue;
        }
        if new_root != old_root {
            return Some((
                RealmTransition { old_root, new_root },
                checkpoint_id,
            ));
        }
        old_root = new_root;
    }
    None
}

/// Peer set chosen once per catch-up batch: one primary and at most one backup.
///
/// The lookup key is the proposal's (old_root, new_root) transition, so any peer that
/// stored the proposal can answer; peers are tried in ascending validator sub-id
/// order and never rescanned per item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatchupPeers {
    primary: NodeId,
    backup: Option<NodeId>,
}

impl CatchupPeers {
    pub fn select(members: &[(u16, NodeId)], local_sub_id: u16) -> anyhow::Result<Self> {
        let mut unique_members: Vec<(u16, NodeId)> = members
            .iter()
            .copied()
            .filter(|(sub_id, _)| *sub_id != local_sub_id)
            .collect();
        unique_members.sort_by_key(|(sub_id, _)| *sub_id);
        unique_members.dedup_by_key(|(sub_id, _)| *sub_id);
        let mut iter = unique_members.into_iter();
        let primary = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("no other validator peer at this checkpoint"))?
            .1;
        Ok(Self {
            primary,
            backup: iter.next().map(|(_, peer)| peer),
        })
    }

}
/// Stage one proposal per transition: the primary peer answers the whole window, the
/// backup answers only when the primary fails, and never more than one backup.
pub async fn stage_transition_blocks(
    client: &RealmNetworkCommands,
    proposal_backup: &ProposalBackup,
    peers: &CatchupPeers,
    chain_id: u64,
    realm_id: u32,
    needed: &[RealmTransition],
    rejected_proposal_ids: &[[u8; 32]],
) -> Vec<TransitionFetchOutcome> {
    let mut staged = Vec::with_capacity(needed.len());
    let mut windows = needed.chunks(PROPOSAL_LOOKUP_WINDOW_TRANSITIONS);
    let mut tasks = futures::stream::FuturesUnordered::new();
    while tasks.len() < PROPOSAL_LOOKUP_CONCURRENCY {
        let Some(window) = windows.next() else {
            break;
        };
        tasks.push(stage_transition_window(
            client,
            proposal_backup,
            peers,
            chain_id,
            realm_id,
            window,
            rejected_proposal_ids,
        ));
    }
    while let Some(window_staged) = futures::StreamExt::next(&mut tasks).await {
        staged.extend(window_staged);
        if let Some(window) = windows.next() {
            tasks.push(stage_transition_window(
                client,
                proposal_backup,
                peers,
                chain_id,
                realm_id,
                window,
                rejected_proposal_ids,
            ));
        }
    }
    staged
}

async fn stage_transition_window(
    client: &RealmNetworkCommands,
    proposal_backup: &ProposalBackup,
    peers: &CatchupPeers,
    chain_id: u64,
    realm_id: u32,
    window: &[RealmTransition],
    rejected_proposal_ids: &[[u8; 32]],
) -> Vec<TransitionFetchOutcome> {
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(PROPOSAL_LOOKUP_TIMEOUT_SECS);
    let (peer, response) = match lookup_pending_transitions(client, peers, chain_id, realm_id, window, deadline).await
    {
        Ok(answered) => answered,
        Err(error) => {
            let message = format!("{error:#}");
            return window
                .iter()
                .map(|transition| TransitionFetchOutcome::Failed(*transition, anyhow::anyhow!("{message}")))
                .collect();
        }
    };
    if response.status == ProposalLookupStatus::Truncated {
        if window.len() <= 1 {
            return window
                .iter()
                .map(|transition| {
                    TransitionFetchOutcome::Failed(
                        *transition,
                        anyhow::anyhow!("peer truncated a single-transition window"),
                    )
                })
                .collect();
        }
        let (head, tail) = window.split_at(window.len() / 2);
        let mut staged = Box::pin(stage_transition_window(
            client,
            proposal_backup,
            peers,
            chain_id,
            realm_id,
            head,
            rejected_proposal_ids,
        ))
        .await;
        staged.extend(
            Box::pin(stage_transition_window(
                client,
                proposal_backup,
                peers,
                chain_id,
                realm_id,
                tail,
                rejected_proposal_ids,
            ))
            .await,
        );
        return staged;
    }
    let mut answers: Vec<ProposalLookupEntry> = response.entries;
    let mut staged = Vec::with_capacity(window.len());
    for transition in window {
        let candidates = answers
            .iter()
            .position(|entry| entry.transition == *transition)
            .map(|index| answers.swap_remove(index).candidates)
            .unwrap_or_default();
        let Some(candidate) = candidates
            .into_iter()
            .find(|candidate| !rejected_proposal_ids.contains(&candidate.proposal_id))
        else {
            staged.push(TransitionFetchOutcome::Absent(*transition));
            continue;
        };
        match download_proposal_body(client, peer, &candidate, deadline).await {
            Ok(body) => match proposal_backup.create_staged(&candidate, &body).await {
                Ok(staged_proposal) => staged.push(TransitionFetchOutcome::Staged(*transition, staged_proposal)),
                Err(error) => staged.push(TransitionFetchOutcome::Failed(*transition, error)),
            },
            Err(error) => staged.push(TransitionFetchOutcome::Failed(*transition, error)),
        }
    }
    staged
}

async fn lookup_pending_transitions(
    client: &RealmNetworkCommands,
    peers: &CatchupPeers,
    chain_id: u64,
    realm_id: u32,
    window: &[RealmTransition],
    deadline: tokio::time::Instant,
) -> anyhow::Result<(NodeId, ProposalLookupResponse)> {
    let request = ProposalLookupRequest {
        chain_id,
        realm_id,
        transitions: window.to_vec(),
    };
    let mut last_error = None;
    for peer in [Some(peers.primary), peers.backup].into_iter().flatten() {
        match lookup_pending_transitions_from_peer(client, peer, &request, deadline).await {
            Ok(response) => return Ok((peer, response)),
            Err(error) => {
                tracing::warn!(
                    "catch-up window lookup peer={peer} transitions={} error={error:#}",
                    window.len()
                );
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no catch-up peer available")))
}

async fn lookup_pending_transitions_from_peer(
    client: &RealmNetworkCommands,
    peer: NodeId,
    request: &ProposalLookupRequest,
    deadline: tokio::time::Instant,
) -> anyhow::Result<ProposalLookupResponse> {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    anyhow::ensure!(!remaining.is_zero(), "catch-up lookup timeout");
    let round = remaining.min(std::time::Duration::from_secs(PROPOSAL_LOOKUP_ROUND_SECS));
    match tokio::time::timeout(round, client.lookup_proposal(peer, request.clone())).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) => anyhow::bail!("{error}"),
        Err(_) => anyhow::bail!("catch-up lookup timeout"),
    }
}

async fn download_proposal_body(
    client: &RealmNetworkCommands,
    peer: NodeId,
    proposal: &Proposal,
    deadline: tokio::time::Instant,
) -> anyhow::Result<Vec<u8>> {
    let mut offset = 0u64;
    let mut body = Vec::new();
    let mut expected_hash = None;
    let mut expected_len = None;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        anyhow::ensure!(!remaining.is_zero(), "direct range timeout");
        let request = BodyChunkRequest {
            proposal_id: proposal.proposal_id,
            offset,
            max_bytes: BODY_CHUNK_MAX_BYTES,
        };
        let round = remaining.min(std::time::Duration::from_secs(PROPOSAL_LOOKUP_ROUND_SECS));
        let response = match tokio::time::timeout(round, client.request_body(peer, request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => anyhow::bail!("{error}"),
            Err(_) => anyhow::bail!("direct range timeout"),
        };
        if let Some(body_hash) = expected_hash {
            anyhow::ensure!(response.body_hash == body_hash, "direct range body_hash changed");
        } else {
            expected_hash = Some(response.body_hash);
        }
        if let Some(body_len) = expected_len {
            anyhow::ensure!(response.body_len == body_len, "direct range body_len changed");
        } else {
            anyhow::ensure!(
                response.body_len <= MAX_PROPOSAL_BODY_BYTES as u64,
                "direct range body_len exceeds maximum"
            );
            expected_len = Some(response.body_len);
        }
        anyhow::ensure!(response.offset == offset, "direct range offset mismatch");
        anyhow::ensure!(
            !response.data.is_empty() || response.eof,
            "direct range empty non-final chunk"
        );
        let next = offset
            .checked_add(response.data.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("direct range offset overflow"))?;
        anyhow::ensure!(next <= response.body_len, "direct range past body_len");
        anyhow::ensure!(
            response.eof == (next == response.body_len),
            "direct range eof mismatch"
        );
        body.extend_from_slice(&response.data);
        offset = next;
        if response.eof {
            anyhow::ensure!(sha256(&body) == proposal.body_hash, "direct range body hash mismatch");
            anyhow::ensure!(
                response.body_hash == proposal.body_hash,
                "direct range declared hash mismatch"
            );
            return Ok(body);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::realm::processor::proposal_backup::ProposalBackup;
    use psy_config::CHECKPOINTS_PER_EPOCH;
    use psy_data::p2p::{
        NodeId, Proposal, ProposalLookupEntry, ProposalLookupRequest, ProposalLookupResponse,
        ProposalLookupStatus, RealmTransition, PROPOSAL_LOOKUP_CANDIDATES_PER_TRANSITION,
        PROPOSAL_LOOKUP_CONCURRENCY,
    };

    const ROOT_A: [u8; 32] = [0xA; 32];
    const ROOT_B: [u8; 32] = [0xB; 32];

    #[test]
    fn first_root_change_skips_identity_rewrite() {
        assert_eq!(first_root_change(15, ROOT_A, &[(16, ROOT_A)]), None);
    }

    #[test]
    fn first_root_change_keeps_cycle_first_hop() {
        assert_eq!(
            first_root_change(15, ROOT_A, &[(20, ROOT_B), (50, ROOT_A)]),
            Some((RealmTransition { old_root: ROOT_A, new_root: ROOT_B }, 20)),
        );
    }

    #[test]
    fn first_root_change_skips_identity_then_takes_real() {
        assert_eq!(
            first_root_change(15, ROOT_A, &[(16, ROOT_A), (50, ROOT_B)]),
            Some((RealmTransition { old_root: ROOT_A, new_root: ROOT_B }, 50)),
        );
    }

    #[test]
    fn first_root_change_empty_is_none() {
        assert_eq!(first_root_change(15, ROOT_A, &[]), None);
    }

    fn build_proposal_with_body(old_root: [u8; 32], new_root: [u8; 32], salt: u8) -> (psy_data::p2p::Proposal, Vec<u8>) {
        build_proposal_with_body_at_checkpoint(old_root, new_root, salt, 99, 1)
    }

    fn build_proposal_with_body_at_checkpoint(
        old_root: [u8; 32],
        new_root: [u8; 32],
        salt: u8,
        base_checkpoint_id: u64,
        proposer_sub_id: u16,
    ) -> (psy_data::p2p::Proposal, Vec<u8>) {
        let output = vec![salt; psy_data::p2p::MAX_FINALIZER_OUTPUT_BYTES];
        let proof = vec![0xABu8; 32];
        let mut state_updates = vec![0u8; 40 + 64 + 20];
        state_updates[40..72].copy_from_slice(&old_root);
        state_updates[72..104].copy_from_slice(&new_root);
        let worker_tag = [0x11u8; 32];
        let body = psy_data::p2p::encode_proposal_body(&output, &proof, &state_updates, &worker_tag).unwrap();
        let proposal = psy_data::p2p::proposal_from_parts(
            1,
            0,
            base_checkpoint_id,
            proposer_sub_id,
            [salt; 32],
            psy_data::p2p::sha256(&output),
            psy_data::p2p::sha256(&proof),
            psy_data::p2p::sha256(&state_updates),
            psy_data::p2p::sha256(&body),
        );
        (proposal, body)
    }

    fn test_node(seed: u8) -> NodeId {
        let mut raw = [0u8; 38];
        raw[..6].copy_from_slice(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
        raw[6..].fill(seed);
        NodeId::from_raw(raw).unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum PeerFault {
        Timeout,
        NotAValidator(NodeId),
        Closed,
    }

    impl PeerFault {
        fn to_error(self) -> crate::realm::network::NetworkError {
            use crate::realm::network::NetworkError;
            match self {
                PeerFault::Timeout => NetworkError::Timeout("test fault".to_string()),
                PeerFault::NotAValidator(node) => NetworkError::NotAValidator(node),
                PeerFault::Closed => NetworkError::CommandChannelClosed,
            }
        }
    }


    #[derive(Default)]
    struct PeerDoubleState {
        offers: std::collections::HashMap<NodeId, Vec<(RealmTransition, Proposal)>>,
        bodies: std::collections::HashMap<(NodeId, [u8; 32]), Result<Vec<u8>, PeerFault>>,
        faults: std::collections::HashMap<NodeId, PeerFault>,
        looked_up: tokio::sync::Mutex<std::collections::HashSet<([u8; 32], [u8; 32])>>,
        inflight: std::sync::atomic::AtomicUsize,
        max_inflight: std::sync::atomic::AtomicUsize,
    }

    impl PeerDoubleState {
        fn offer(mut self, peer: NodeId, lookup: RealmTransition, proposal: Proposal) -> Self {
            self.offers.entry(peer).or_default().push((lookup, proposal));
            self
        }

        fn body(mut self, peer: NodeId, proposal_id: [u8; 32], body: Result<Vec<u8>, PeerFault>) -> Self {
            self.bodies.insert((peer, proposal_id), body);
            self
        }

        fn failing(mut self, peer: NodeId, fault: PeerFault) -> Self {
            self.faults.insert(peer, fault);
            self
        }
    }

    /// A command channel answering lookups and body ranges from a fixed inventory.
    fn spawn_peer_double(state: std::sync::Arc<PeerDoubleState>) -> RealmNetworkCommands {
        use crate::realm::network::{NetworkError, RealmNetworkCommand};
        let (commands, mut rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    RealmNetworkCommand::LookupProposal {
                        destination,
                        request,
                        response,
                    } => {
                        let live = state
                            .inflight
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            + 1;
                        state
                            .max_inflight
                            .fetch_max(live, std::sync::atomic::Ordering::SeqCst);
                        let answered = match state.faults.get(&destination) {
                            Some(fault) => Err(fault.to_error()),
                            None => {
                                let mut looked = state.looked_up.lock().await;
                                let offers = state.offers.get(&destination);
                                let mut entries = Vec::with_capacity(request.transitions.len());
                                for transition in &request.transitions {
                                    looked.insert((transition.old_root, transition.new_root));
                                    let candidates = offers
                                        .map(|offers| {
                                            offers
                                                .iter()
                                                .filter(|(lookup, _)| *lookup == *transition)
                                                .map(|(_, proposal)| proposal.clone())
                                                .take(PROPOSAL_LOOKUP_CANDIDATES_PER_TRANSITION)
                                                .collect()
                                        })
                                        .unwrap_or_default();
                                    entries.push(ProposalLookupEntry {
                                        transition: *transition,
                                        candidates,
                                    });
                                }
                                Ok(ProposalLookupResponse::candidates(entries))
                            }
                        };
                        let _ = response.send(answered);
                        state
                            .inflight
                            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    RealmNetworkCommand::RequestBody {
                        destination,
                        request,
                        response,
                    } => {
                        let answered = match state.bodies.get(&(destination, request.proposal_id)) {
                            Some(Ok(body)) => {
                                let start = request.offset as usize;
                                let take = (request.max_bytes as usize)
                                    .min(body.len().saturating_sub(start));
                                Ok(BodyChunkResponse {
                                    offset: request.offset,
                                    data: body[start..start + take].to_vec(),
                                    eof: start + take == body.len(),
                                    body_len: body.len() as u64,
                                    body_hash: sha256(body),
                                })
                            }
                            Some(Err(fault)) => Err(fault.to_error()),
                            None => Err(NetworkError::CommandChannelClosed),
                        };
                        let _ = response.send(answered);
                    }
                    _ => {}
                }
            }
        });
        RealmNetworkCommands::from_channel(commands, test_node(200))
    }

    fn lookup_of(old_root: [u8; 32], new_root: [u8; 32]) -> RealmTransition {
        RealmTransition { old_root, new_root }
    }

    fn single_peer(seed: u8) -> (Vec<(u16, NodeId)>, NodeId) {
        let peer = test_node(seed);
        (vec![(1, peer)], peer)
    }

    async fn install_staged_proposals(proposal_backup: &ProposalBackup, outcomes: Vec<TransitionFetchOutcome>) -> usize {
        let mut installed_proposal_count = 0usize;
        for outcome in outcomes {
            if let TransitionFetchOutcome::Staged(_, staged) = outcome {
                proposal_backup.install(staged).await.unwrap();
                installed_proposal_count += 1;
            }
        }
        installed_proposal_count
    }


    #[tokio::test]
    async fn history_window_stages_each_offered_transition() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (first, first_body) = build_proposal_with_body([1u8; 32], [2u8; 32], 1);
        let (second, second_body) = build_proposal_with_body([2u8; 32], [3u8; 32], 2);
        let first_lookup = lookup_of([1u8; 32], [2u8; 32]);
        let second_lookup = lookup_of([2u8; 32], [3u8; 32]);
        let (members, peer) = single_peer(1);
        let client = spawn_peer_double(std::sync::Arc::new(
            PeerDoubleState::default()
                .offer(peer, first_lookup, first.clone())
                .offer(peer, second_lookup, second.clone())
                .body(peer, first.proposal_id, Ok(first_body))
                .body(peer, second.proposal_id, Ok(second_body)),
        ));
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(
            &client,
            &proposal_backup,
            &peers,
            1,
            0,
            &[first_lookup, second_lookup],
            &[],
        )
        .await;
        assert_eq!(outcomes.len(), 2);
        assert!(proposal_backup.lookup_transition(&[1u8; 32], &[2u8; 32]).await.unwrap().is_empty());
        assert_eq!(install_staged_proposals(&proposal_backup, outcomes).await, 2);
        assert_eq!(
            proposal_backup.lookup_transition(&[1u8; 32], &[2u8; 32]).await.unwrap()[0].proposal_id,
            first.proposal_id
        );
        assert_eq!(
            proposal_backup.lookup_transition(&[2u8; 32], &[3u8; 32]).await.unwrap()[0].proposal_id,
            second.proposal_id
        );
    }

    #[tokio::test]
    async fn history_window_transition_failure_does_not_poison_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (good, good_body) = build_proposal_with_body([4u8; 32], [5u8; 32], 5);
        let (bad, mut bad_body) = build_proposal_with_body([5u8; 32], [6u8; 32], 6);
        bad_body[0] ^= 0xFF;
        let good_lookup = lookup_of([4u8; 32], [5u8; 32]);
        let bad_lookup = lookup_of([5u8; 32], [6u8; 32]);
        let (members, peer) = single_peer(3);
        let client = spawn_peer_double(std::sync::Arc::new(
            PeerDoubleState::default()
                .offer(peer, good_lookup, good.clone())
                .offer(peer, bad_lookup, bad.clone())
                .body(peer, good.proposal_id, Ok(good_body))
                .body(peer, bad.proposal_id, Ok(bad_body)),
        ));
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(
            &client,
            &proposal_backup,
            &peers,
            1,
            0,
            &[good_lookup, bad_lookup],
            &[],
        )
        .await;
        assert!(matches!(outcomes[0], TransitionFetchOutcome::Staged(..)));
        assert!(matches!(outcomes[1], TransitionFetchOutcome::Failed(..)));
        assert_eq!(install_staged_proposals(&proposal_backup, outcomes).await, 1);
        assert_eq!(proposal_backup.lookup_transition(&[4u8; 32], &[5u8; 32]).await.unwrap().len(), 1);
        assert!(proposal_backup.lookup_transition(&[5u8; 32], &[6u8; 32]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn history_lookup_failure_switches_to_backup_peer() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (proposal, body) = build_proposal_with_body([7u8; 32], [8u8; 32], 7);
        let lookup = lookup_of([7u8; 32], [8u8; 32]);
        let primary = test_node(4);
        let backup = test_node(5);
        let members = vec![(1, primary), (2, backup)];
        let client = spawn_peer_double(std::sync::Arc::new(
            PeerDoubleState::default()
                .failing(primary, PeerFault::Timeout)
                .offer(backup, lookup, proposal.clone())
                .body(backup, proposal.proposal_id, Ok(body)),
        ));
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(&client, &proposal_backup, &peers, 1, 0, &[lookup], &[]).await;
        assert_eq!(install_staged_proposals(&proposal_backup, outcomes).await, 1);
        assert_eq!(
            proposal_backup.lookup_transition(&[7u8; 32], &[8u8; 32]).await.unwrap()[0].proposal_id,
            proposal.proposal_id
        );
    }

    #[tokio::test]
    async fn history_window_fetch_concurrency_and_coverage() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (members, peer) = single_peer(8);
        let mut state = PeerDoubleState::default();
        let mut needed = Vec::new();
        for i in 0..5u8 {
            let old = [i; 32];
            let new = [i + 1; 32];
            let (proposal, mut body) = build_proposal_with_body(old, new, 20 + i);
            if i == 2 {
                body[0] ^= 0xFF;
            }
            let lookup = lookup_of(old, new);
            state = state
                .offer(peer, lookup, proposal.clone())
                .body(peer, proposal.proposal_id, Ok(body));
            needed.push(lookup);
        }
        let state = std::sync::Arc::new(state);
        let client = spawn_peer_double(state.clone());
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(&client, &proposal_backup, &peers, 1, 0, &needed, &[]).await;
        assert_eq!(install_staged_proposals(&proposal_backup, outcomes).await, 4);
        assert!(
            state.max_inflight.load(std::sync::atomic::Ordering::SeqCst) <= PROPOSAL_LOOKUP_CONCURRENCY
        );
        let looked = state.looked_up.lock().await;
        for lookup in &needed {
            assert!(
                looked.contains(&(lookup.old_root, lookup.new_root)),
                "missing lookup transition=({},{})",
                hex::encode(lookup.old_root),
                hex::encode(lookup.new_root)
            );
        }
        drop(looked);
        assert_eq!(proposal_backup.lookup_transition(&[2u8; 32], &[3u8; 32]).await.unwrap().len(), 0);
        assert_eq!(proposal_backup.lookup_transition(&[0u8; 32], &[1u8; 32]).await.unwrap().len(), 1);
        assert_eq!(proposal_backup.lookup_transition(&[3u8; 32], &[4u8; 32]).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn history_window_across_epochs() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let epoch = CHECKPOINTS_PER_EPOCH;
        let first_proposal_count = epoch - 1;
        let second_proposal_count = epoch * 3 - 1;
        let (first, first_body) =
            build_proposal_with_body_at_checkpoint([1u8; 32], [2u8; 32], 30, first_proposal_count, 1);
        let (second, second_body) =
            build_proposal_with_body_at_checkpoint([2u8; 32], [3u8; 32], 31, second_proposal_count, 2);
        let first_lookup = lookup_of([1u8; 32], [2u8; 32]);
        let second_lookup = lookup_of([2u8; 32], [3u8; 32]);
        let supplier = test_node(9);
        let members = vec![(3, supplier)];
        let client = spawn_peer_double(std::sync::Arc::new(
            PeerDoubleState::default()
                .offer(supplier, first_lookup, first.clone())
                .offer(supplier, second_lookup, second.clone())
                .body(supplier, first.proposal_id, Ok(first_body))
                .body(supplier, second.proposal_id, Ok(second_body)),
        ));
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let outcomes = stage_transition_blocks(
            &client,
            &proposal_backup,
            &peers,
            1,
            0,
            &[first_lookup, second_lookup],
            &[],
        )
        .await;
        assert_eq!(install_staged_proposals(&proposal_backup, outcomes).await, 2);
        assert_eq!(first.proposer_sub_id, 1);
        assert_eq!(second.proposer_sub_id, 2);
        let first_found = proposal_backup.lookup_transition(&[1u8; 32], &[2u8; 32]).await.unwrap();
        let second_found = proposal_backup.lookup_transition(&[2u8; 32], &[3u8; 32]).await.unwrap();
        assert_eq!(first_found[0].proposal_id, first.proposal_id);
        assert_eq!(second_found[0].proposal_id, second.proposal_id);
        assert!(first.base_checkpoint_id < second.base_checkpoint_id);
    }

    #[tokio::test]
    async fn history_window_without_anchor_leaf_fails_closed() {
        let error = CatchupPeers::select(&[], 1).expect_err("empty occupied leaves must fail closed");
        assert!(
            error
                .to_string()
                .contains("no other validator peer at this checkpoint"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn history_empty_answer_marks_every_transition_absent() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (members, _peer) = single_peer(10);
        let state = std::sync::Arc::new(PeerDoubleState::default());
        let client = spawn_peer_double(state.clone());
        let peers = CatchupPeers::select(&members, 9).unwrap();
        let needed = vec![lookup_of([8u8; 32], [9u8; 32])];
        let outcomes = stage_transition_blocks(&client, &proposal_backup, &peers, 1, 0, &needed, &[]).await;
        assert!(matches!(outcomes[0], TransitionFetchOutcome::Absent(..)));
        assert!(state.looked_up.lock().await.contains(&([8u8; 32], [9u8; 32])));
    }

    #[tokio::test]
    async fn history_resend_revotes() {
        let dir = tempfile::tempdir().unwrap();
        let proposal_backup = ProposalBackup::open(dir.path()).await.unwrap();
        let (proposal, body) = build_proposal_with_body([3u8; 32], [4u8; 32], 3);
        proposal_backup.save_proposal(&proposal, &body).await.unwrap();
        proposal_backup.save_proposal(&proposal, &body).await.unwrap();
        let first = proposal_backup
            .read_body_chunk(&BodyChunkRequest {
                proposal_id: proposal.proposal_id,
                offset: 0,
                max_bytes: 64,
            })
            .await
            .unwrap();
        proposal_backup.save_proposal(&proposal, &body).await.unwrap();
        let second = proposal_backup
            .read_body_chunk(&BodyChunkRequest {
                proposal_id: proposal.proposal_id,
                offset: 0,
                max_bytes: 64,
            })
            .await
            .unwrap();
        assert_eq!(first.body_hash, proposal.body_hash);
        assert_eq!(second.body_hash, proposal.body_hash);
        assert_eq!(first.body_len, second.body_len);
    }
}
