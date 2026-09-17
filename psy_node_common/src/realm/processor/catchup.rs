//! Catch-up window fetching: peer selection, staged windows, and body downloads.

use std::collections::HashMap;

use anyhow::Context;
use parth_core::protocol::core_types::Q256BitHash;
use psy_data::p2p::{
    sha256, BodyChunkRequest, BodyChunkResponse, NodeId, Proposal, ProposalLookupEntry,
    ProposalLookupRequest, ProposalLookupResponse, ProposalLookupStatus, RealmTransition,
    BODY_CHUNK_MAX_BYTES, MAX_PROPOSAL_BODY_BYTES, PROPOSAL_LOOKUP_CANDIDATES_PER_PAIR, PROPOSAL_LOOKUP_CONCURRENCY,
    PROPOSAL_LOOKUP_ROUND_SECS, PROPOSAL_LOOKUP_TIMEOUT_SECS, PROPOSAL_LOOKUP_WINDOW_PAIRS,
};

use crate::realm::network::RealmNetworkCommands;
use crate::realm::processor::proposal_store::{ProposalStore, StagedProposal};

pub const CATCHUP_PAIR_ATTEMPTS: usize = 3;

/// One window transition after the fetch stage: staged bytes awaiting verification.
pub enum TransitionFetchOutcome {
    Staged(RealmTransition, StagedProposal),
    Absent(RealmTransition),
    Failed(RealmTransition, anyhow::Error),
}

/// Next coordinator-authenticated realm transition after `last_committed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnappliedTransition {
    None { accounted_checkpoint: u64 },
    Real { pair: RealmTransition, included_checkpoint: u64 },
}

/// Last-modified events must be chronological. Equal roots are leaf rewrites, not bodies.
/// A→B→A keeps the A→B hop because that first value differs.
pub(crate) fn first_unapplied_transition(
    last_committed: u64,
    last_committed_root: [u8; 32],
    last_modifieds: &[(u64, [u8; 32])],
) -> UnappliedTransition {
    let mut old_root = last_committed_root;
    let mut accounted_checkpoint = last_committed;
    for &(checkpoint_id, new_root) in last_modifieds {
        if checkpoint_id <= last_committed {
            continue;
        }
        if new_root != old_root {
            return UnappliedTransition::Real {
                pair: RealmTransition { old_root, new_root },
                included_checkpoint: checkpoint_id,
            };
        }
        accounted_checkpoint = checkpoint_id;
        old_root = new_root;
    }
    UnappliedTransition::None { accounted_checkpoint }
}

/// Peer set chosen once per catch-up batch: one primary and at most one backup.
///
/// The lookup key is the proposal's (old_root, new_root) pair, so any peer that
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
/// Stage one proposal per pair: the primary peer answers the whole window, the
/// backup answers only when the primary fails, and never more than one backup.
pub async fn stage_transition_blocks(
    client: &RealmNetworkCommands,
    store: &ProposalStore,
    peers: &CatchupPeers,
    chain_id: u64,
    realm_id: u32,
    needed: &[RealmTransition],
    rejected_proposal_ids: &[[u8; 32]],
) -> Vec<TransitionFetchOutcome> {
    let mut staged = Vec::with_capacity(needed.len());
    let mut windows = needed.chunks(PROPOSAL_LOOKUP_WINDOW_PAIRS);
    let mut tasks = futures::stream::FuturesUnordered::new();
    while tasks.len() < PROPOSAL_LOOKUP_CONCURRENCY {
        let Some(window) = windows.next() else {
            break;
        };
        tasks.push(stage_transition_window(
            client,
            store,
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
                store,
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
    store: &ProposalStore,
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
            store,
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
                store,
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
            Ok(body) => match store.create_staged(&candidate, &body).await {
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
        pairs: window.to_vec(),
    };
    let mut last_error = None;
    for peer in [Some(peers.primary), peers.backup].into_iter().flatten() {
        match lookup_pending_transitions_from_peer(client, peer, &request, deadline).await {
            Ok(response) => return Ok((peer, response)),
            Err(error) => {
                tracing::warn!(
                    "catch-up window lookup peer={peer} pairs={} error={error:#}",
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
    use super::{first_unapplied_transition, UnappliedTransition};
    use psy_data::p2p::RealmTransition;

    const ROOT_A: [u8; 32] = [0xA; 32];
    const ROOT_B: [u8; 32] = [0xB; 32];

    #[test]
    fn first_unapplied_transition_skips_identity_rewrite() {
        let outcome = first_unapplied_transition(15, ROOT_A, &[(16, ROOT_A)]);
        assert_eq!(
            outcome,
            UnappliedTransition::None {
                accounted_checkpoint: 16
            }
        );
    }

    #[test]
    fn first_unapplied_transition_keeps_cycle_first_hop() {
        let outcome = first_unapplied_transition(15, ROOT_A, &[(20, ROOT_B), (50, ROOT_A)]);
        assert_eq!(
            outcome,
            UnappliedTransition::Real {
                pair: RealmTransition {
                    old_root: ROOT_A,
                    new_root: ROOT_B,
                },
                included_checkpoint: 20,
            }
        );
    }

    #[test]
    fn first_unapplied_transition_skips_identity_then_takes_real() {
        let outcome = first_unapplied_transition(15, ROOT_A, &[(16, ROOT_A), (50, ROOT_B)]);
        assert_eq!(
            outcome,
            UnappliedTransition::Real {
                pair: RealmTransition {
                    old_root: ROOT_A,
                    new_root: ROOT_B,
                },
                included_checkpoint: 50,
            }
        );
    }

    #[test]
    fn first_unapplied_transition_empty_is_accounted_at_committed() {
        let outcome = first_unapplied_transition(15, ROOT_A, &[]);
        assert_eq!(
            outcome,
            UnappliedTransition::None {
                accounted_checkpoint: 15
            }
        );
    }
}
