//! The edge's half of the operator interface: write the request down, and
//! report what the chain is doing.
//!
//! ## The one thing an edge writes
//!
//! An edge is a read-only role -- its store is a `PsyCoordinatorEdgeAPIStoreReader`
//! -- and this is the single exception.  It is deliberately as narrow as an
//! exception can be: one method, writing one control table that is on no commit
//! path, holds no chain state, and is named by no G-W assertion.  `WRITABLE_TABLES`
//! below pins that, so any change that widens the edge's write surface has to
//! edit a constant whose whole purpose is to be noticed.
//!
//! ## Why this cannot also run the rollback
//!
//! Two reasons, either sufficient.  There may be several edges, and two of them
//! carrying out the same request would race over the same archive slots.  And
//! the rollback rewrites the database under whoever holds the head, so it must
//! happen where the head is held and where no block is in flight -- which is the
//! Coordinator processor, between two block attempts.

use std::sync::Arc;

use parth_core::protocol::core_types::Q256BitHash;
use psy_api_core::coordinator::rollback_admin_rpc::{
    RollbackPhaseName, RollbackRequestAccepted, RollbackRequestExpiry, RollbackStatusReport,
};
use psy_data::protocol::canonical_chain::{CanonicalChainRef, NetworkId};
use psy_node_core::store::canonical_head::CanonicalHeadReadState;
use psy_node_core::store::manifest_store::CoordinatorCommitRecording;
use psy_node_core::store::rollback_control::RollbackControlState;
use psy_node_core::store::rollback_request::{
    PickupDecision, RollbackRequestMailbox, StaleReason, decide_pickup,
};

/// What the operator interface can reach from an edge.
pub struct RollbackAdminSurface<Hash: Q256BitHash> {
    mailbox: Arc<dyn RollbackRequestMailbox>,
    recording: CoordinatorCommitRecording<Hash>,
    network: NetworkId,
}

impl<Hash: Q256BitHash> RollbackAdminSurface<Hash> {
    /// Every table this surface may write.
    ///
    /// One, and it is the mailbox.  See the module note.
    pub const WRITABLE_TABLES: [&'static str; 1] = ["coordinator_rollback_request"];

    pub fn new(
        mailbox: Arc<dyn RollbackRequestMailbox>,
        recording: CoordinatorCommitRecording<Hash>,
        network: NetworkId,
    ) -> Self {
        Self {
            mailbox,
            recording,
            network,
        }
    }

    /// Write a request down.  Returns as soon as it is durable.
    ///
    /// The head is not checked here.  A request naming a head the chain has
    /// already passed is refused at pickup, by `decide_pickup`, and refusing it
    /// twice in two places would put the rule in two places -- where the copies
    /// drift, and the quiet one wins.  What this does check is that the caller
    /// asked for something: a target at or above the head they saw discards
    /// nothing, and there is no reason to write that down.
    pub async fn request(
        &self,
        target: u64,
        expected_head: u64,
        requested_by: &str,
    ) -> anyhow::Result<RollbackRequestAccepted> {
        if target >= expected_head {
            anyhow::bail!(
                "a rollback to {target} from a head of {expected_head} would discard nothing"
            );
        }
        let requested_at_us = self
            .mailbox
            .submit(target, expected_head, requested_by)
            .await?;
        Ok(RollbackRequestAccepted {
            requested_at_us,
            target,
            expected_head,
        })
    }

    /// The mailbox and the control row, read together.
    ///
    /// The control row wins: while a rollback is running, what is in the mailbox
    /// is of no interest, because the processor only looks at it when idle.  It
    /// is only when nothing is running that the mailbox decides between "waiting
    /// to be taken up" and "nothing is going to happen, and here is why".
    pub async fn status(&self) -> anyhow::Result<RollbackStatusReport> {
        let (chain_epoch, head, control) =
            match self.recording.canonical_head().read_canonical_head(self.network).await? {
                CanonicalHeadReadState::Current(stored) => (
                    stored.canonical_ref().chain_epoch().get(),
                    Some(stored.canonical_ref().checkpoint().checkpoint_id().get()),
                    Some(*stored.rollback_control()),
                ),
                CanonicalHeadReadState::Uninitialized => (0, None, None),
            };

        let live = control.unwrap_or(RollbackControlState::Idle);
        if !matches!(live, RollbackControlState::Idle) {
            let phase = phase_name_of(&live);
            return Ok(RollbackStatusReport {
                phase,
                past_point_of_no_return: phase.past_point_of_no_return(),
                chain_epoch,
                head,
                target: live
                    .requested()
                    .map(|request| request.target().checkpoint_id().get()),
                last_request_expired: None,
                participants: None,
            });
        }

        let Some(entry) = self.mailbox.newest().await? else {
            return Ok(RollbackStatusReport::idle(chain_epoch, head));
        };
        // Without a head there is no chain, so there is nothing a request could
        // still be true about.
        let Some(live_head) = head else {
            return Ok(RollbackStatusReport::idle(chain_epoch, head));
        };
        match decide_pickup(&entry, live_head) {
            PickupDecision::Take { target } => Ok(RollbackStatusReport::pending_pickup(
                chain_epoch,
                live_head,
                target,
            )),
            PickupDecision::Stale { reason } => {
                let mut report = RollbackStatusReport::idle(chain_epoch, head);
                report.last_request_expired = Some(expiry_of(reason));
                Ok(report)
            }
        }
    }

    /// The chain reference the caller should quote as `expected_head`.
    pub async fn current_head(&self) -> anyhow::Result<Option<CanonicalChainRef<Hash>>> {
        Ok(
            match self.recording.canonical_head().read_canonical_head(self.network).await? {
                CanonicalHeadReadState::Current(stored) => Some(*stored.canonical_ref()),
                CanonicalHeadReadState::Uninitialized => None,
            },
        )
    }
}

/// The control state, named for the wire.
///
/// A `match` with no default arm on purpose.  A control state added later must
/// be named here or the build stops; a default arm would let it arrive at an
/// operator as whatever the fallback happened to be, and the one moment this is
/// read is the moment the chain is in a state nobody expected.
pub fn phase_name_of<Hash>(state: &RollbackControlState<Hash>) -> RollbackPhaseName {
    match state {
        RollbackControlState::Idle => RollbackPhaseName::Idle,
        RollbackControlState::Requested(_) => RollbackPhaseName::Requested,
        RollbackControlState::Frozen(_) => RollbackPhaseName::Frozen,
        RollbackControlState::Archiving(_) => RollbackPhaseName::Archiving,
        RollbackControlState::ArchiveBarrierReady(_) => RollbackPhaseName::ArchiveBarrierReady,
        RollbackControlState::Deleting(_) => RollbackPhaseName::Deleting,
        RollbackControlState::Restoring(_) => RollbackPhaseName::Restoring,
        RollbackControlState::Verifying(_) => RollbackPhaseName::Verifying,
        RollbackControlState::AllRealmsReady(_) => RollbackPhaseName::AllRealmsReady,
        RollbackControlState::Aborting(_) => RollbackPhaseName::Aborting,
    }
}

const fn expiry_of(reason: StaleReason) -> RollbackRequestExpiry {
    match reason {
        StaleReason::AlreadyConsumed => RollbackRequestExpiry::AlreadyConsumed,
        StaleReason::HeadBelowExpected => RollbackRequestExpiry::HeadBelowExpected,
        StaleReason::TargetNotBelowHead => RollbackRequestExpiry::TargetNotBelowHead,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::PHash;

    /// The edge's write surface is one table.
    ///
    /// This is the whole of the exception to "an edge does not write".  A change
    /// that widens it should have to come through here.
    #[test]
    fn the_edge_write_surface_is_one_table() {
        assert_eq!(
            RollbackAdminSurface::<PHash>::WRITABLE_TABLES,
            ["coordinator_rollback_request"]
        );
    }

    /// Every phase the control row can hold has a name on the wire, and no two
    /// share one.
    ///
    /// The compiler already forces the match to be exhaustive; this is about the
    /// other direction -- two states quietly mapped to the same name would make
    /// `deleting` and `restoring` indistinguishable to an operator watching a
    /// rollback go past the point of no return.
    #[test]
    fn no_two_control_states_share_a_wire_name() {
        let names = [
            RollbackPhaseName::Idle,
            RollbackPhaseName::Requested,
            RollbackPhaseName::Frozen,
            RollbackPhaseName::Archiving,
            RollbackPhaseName::ArchiveBarrierReady,
            RollbackPhaseName::Deleting,
            RollbackPhaseName::Restoring,
            RollbackPhaseName::Verifying,
            RollbackPhaseName::AllRealmsReady,
            RollbackPhaseName::Aborting,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for name in names {
            assert!(seen.insert(name.as_str()), "{name:?} reuses a wire name");
        }
        // `pending_pickup` is the only wire phase with no control state behind
        // it: nothing has started, so the control row still says Idle.
        assert!(!seen.contains(RollbackPhaseName::PendingPickup.as_str()));
    }

    #[test]
    fn an_idle_control_row_is_named_idle() {
        assert_eq!(
            phase_name_of::<PHash>(&RollbackControlState::Idle),
            RollbackPhaseName::Idle
        );
    }

    #[test]
    fn every_expiry_reason_survives_the_crossing_to_the_wire() {
        // Collapsing these into one would leave an operator unable to tell
        // "send it again against the current head" from "it already happened".
        let mut seen = std::collections::BTreeSet::new();
        for reason in [
            StaleReason::AlreadyConsumed,
            StaleReason::HeadBelowExpected,
            StaleReason::TargetNotBelowHead,
        ] {
            assert!(
                seen.insert(format!("{:?}", expiry_of(reason))),
                "{reason:?} shares a wire spelling with another reason"
            );
        }
        assert_eq!(seen.len(), 3);
    }
}
