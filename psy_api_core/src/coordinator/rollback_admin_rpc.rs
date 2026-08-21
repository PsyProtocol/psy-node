//! The `psy_rollback` operator interface (design-r1 §10).
//!
//! ## R1 does not authenticate this
//!
//! Anything that can reach this port can ask for a destructive rollback.  That
//! is a deliberate scope decision -- §10 puts authentication in a separate piece
//! of work before a production network -- and not an oversight.  It must be
//! closed before this is exposed anywhere but a test network.
//!
//! ## Asking is not doing
//!
//! `request` writes the request down and returns.  The rollback runs in the
//! Coordinator processor, at the boundary between two block attempts, because
//! that is the process that owns the head and the only moment at which it has no
//! block in flight.  An edge is a read-only role and there may be several of
//! them, so an edge that carried the rollback out would be both exceeding its
//! contract and racing its peers.
//!
//! The visible consequence is that a request is pending for up to one block
//! period before anything happens, which is why `status` has a phase for exactly
//! that.  Without it an operator who asked and then looked would be told `idle`
//! and conclude their request had been dropped.
//!
//! ## There is no abort
//!
//! A request names the head the operator saw.  Once the chain produces past it
//! the request can never be taken up, so withdrawing one is simply not sending
//! it again -- and after a rollback the head *is* the target, which is the same
//! rule preventing a completed request from being carried out twice.  Once the
//! processor has taken a request up, the rollback can only be finished: §4.1's
//! point of no return, with its operator-facing boundary at pickup rather than
//! at the archive barrier.

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};

/// Where the chain is, as far as a rollback is concerned.
///
/// Its own enum rather than the store's `RollbackControlState`, because this one
/// is a wire format: renaming a variant here breaks operators' scripts, and
/// renaming one there is an internal refactor.  The two are mapped in one place,
/// by a `match` with no default arm, so a new control state fails to compile
/// rather than arriving here as something unrecognised.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackPhaseName {
    /// No rollback, and nothing waiting to start one.
    Idle,
    /// A request stands and the processor has not reached the boundary at which
    /// it looks.  Not a phase of the rollback -- nothing has begun -- but the
    /// operator needs to be able to tell it apart from `idle`.
    PendingPickup,
    Requested,
    Frozen,
    Archiving,
    ArchiveBarrierReady,
    Deleting,
    Restoring,
    Verifying,
    AllRealmsReady,
    /// The control row can express an abort, so this can name one.
    ///
    /// R1 implements no abort and offers no way to ask for one, so a live chain
    /// never reports this.  It exists because `status` has to be able to say
    /// what the control row holds -- a report that could not name a state would
    /// have to lie or fail at exactly the moment something unexpected happened,
    /// which is the moment it is read.
    Aborting,
}

impl RollbackPhaseName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::PendingPickup => "pending_pickup",
            Self::Requested => "requested",
            Self::Frozen => "frozen",
            Self::Archiving => "archiving",
            Self::ArchiveBarrierReady => "archive_barrier_ready",
            Self::Deleting => "deleting",
            Self::Restoring => "restoring",
            Self::Verifying => "verifying",
            Self::AllRealmsReady => "all_realms_ready",
            Self::Aborting => "aborting",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "idle" => Some(Self::Idle),
            "pending_pickup" => Some(Self::PendingPickup),
            "requested" => Some(Self::Requested),
            "frozen" => Some(Self::Frozen),
            "archiving" => Some(Self::Archiving),
            "archive_barrier_ready" => Some(Self::ArchiveBarrierReady),
            "deleting" => Some(Self::Deleting),
            "restoring" => Some(Self::Restoring),
            "verifying" => Some(Self::Verifying),
            "all_realms_ready" => Some(Self::AllRealmsReady),
            "aborting" => Some(Self::Aborting),
            _ => None,
        }
    }

    /// Whether the rollback has crossed the global archive barrier.
    ///
    /// Reported rather than left to the reader, because it is the one thing an
    /// operator watching a rollback actually needs to know and deriving it from
    /// a phase name means every script re-derives it -- and one of them will get
    /// the boundary wrong in the direction that matters.
    pub const fn past_point_of_no_return(self) -> bool {
        match self {
            Self::Idle
            | Self::PendingPickup
            | Self::Requested
            | Self::Frozen
            | Self::Archiving
            // An abort is only reachable before the barrier, so it is by
            // definition on this side of it.
            | Self::Aborting => false,
            Self::ArchiveBarrierReady
            | Self::Deleting
            | Self::Restoring
            | Self::Verifying
            | Self::AllRealmsReady => true,
        }
    }
}

/// How far one participant has got, by what it has filed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollbackParticipantProgress {
    /// `"coordinator"`, or `"realm:{id}:{sub}"`.
    pub scope: String,
    pub froze: bool,
    pub archived: bool,
    pub verified: bool,
}

/// Why a request that was written down will never be taken up.
///
/// Named individually because the responses differ: an expired request should
/// be sent again against the current head, and a carried-out one should not.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackRequestExpiry {
    AlreadyConsumed,
    HeadBelowExpected,
    TargetNotBelowHead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollbackStatusReport {
    pub phase: RollbackPhaseName,
    pub past_point_of_no_return: bool,
    pub chain_epoch: u64,
    pub head: Option<u64>,
    pub target: Option<u64>,
    /// Set when the newest request in the mailbox can no longer be taken up, so
    /// an operator who sees `idle` after asking is told why rather than left to
    /// guess.
    pub last_request_expired: Option<RollbackRequestExpiry>,
    /// Per-participant progress, when the responder is able to read the
    /// receipts.
    ///
    /// `None` rather than an empty list when it is not, because those mean
    /// opposite things: "nobody has filed anything" would be alarming halfway
    /// through a rollback, while "this endpoint does not report progress" is
    /// merely a limit of the answer.
    pub participants: Option<Vec<RollbackParticipantProgress>>,
}

impl RollbackStatusReport {
    /// A chain with nothing happening and nothing waiting.
    pub fn idle(chain_epoch: u64, head: Option<u64>) -> Self {
        Self {
            phase: RollbackPhaseName::Idle,
            past_point_of_no_return: false,
            chain_epoch,
            head,
            target: None,
            last_request_expired: None,
            participants: None,
        }
    }

    /// A request that stands, waiting for the processor to reach the boundary.
    pub fn pending_pickup(chain_epoch: u64, head: u64, target: u64) -> Self {
        Self {
            phase: RollbackPhaseName::PendingPickup,
            past_point_of_no_return: false,
            chain_epoch,
            head: Some(head),
            target: Some(target),
            last_request_expired: None,
            participants: None,
        }
    }
}

/// The read-only go/no-go for a target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollbackPlanReport {
    pub feasible: bool,
    /// Required when `feasible` is false, and it must name the chain epoch:
    /// after one rollback, everything committed before it lives in another
    /// manifest partition, and "no committed manifest" reads like corruption
    /// unless the refusal says which epoch it looked in (§11.3).
    pub refusal: Option<String>,
    pub target: u64,
    pub head: u64,
    pub planned_rows: u64,
}

/// What `request` promises: that the request was written down, not that a
/// rollback has begun.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollbackRequestAccepted {
    /// The microsecond that identifies this request in the mailbox.
    pub requested_at_us: i64,
    pub target: u64,
    pub expected_head: u64,
}

#[rpc(server, client, namespace = "psy_rollback")]
pub trait CoordinatorRollbackAdminRpc {
    /// Read-only.  Whether a rollback to `target` could be planned right now.
    #[method(name = "plan")]
    async fn rollback_plan(&self, target: u64) -> RpcResult<RollbackPlanReport>;

    /// Write the request down and return.  The Coordinator processor takes it up
    /// at its next block boundary, usually within one block period.
    ///
    /// `expected_head` is the head the caller saw.  A chain that has grown since
    /// is still rolled back -- more of it is discarded, which is what was asked
    /// for -- but a chain that is *shorter* means someone already rolled it
    /// back, and the request is refused rather than reinterpreted.
    #[method(name = "request")]
    async fn rollback_request(
        &self,
        target: u64,
        expected_head: u64,
    ) -> RpcResult<RollbackRequestAccepted>;

    /// The mailbox and the control row, read together.
    #[method(name = "status")]
    async fn rollback_status(&self) -> RpcResult<RollbackStatusReport>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every phase has a name, and the name round-trips.
    ///
    /// Spelled out one by one on purpose: these strings are what operators'
    /// scripts match on, so a rename has to be a visible edit here rather than
    /// something that follows silently from renaming a variant.
    #[test]
    fn every_phase_has_a_stable_wire_name() {
        for (phase, text) in [
            (RollbackPhaseName::Idle, "idle"),
            (RollbackPhaseName::PendingPickup, "pending_pickup"),
            (RollbackPhaseName::Requested, "requested"),
            (RollbackPhaseName::Frozen, "frozen"),
            (RollbackPhaseName::Archiving, "archiving"),
            (RollbackPhaseName::ArchiveBarrierReady, "archive_barrier_ready"),
            (RollbackPhaseName::Deleting, "deleting"),
            (RollbackPhaseName::Restoring, "restoring"),
            (RollbackPhaseName::Verifying, "verifying"),
            (RollbackPhaseName::AllRealmsReady, "all_realms_ready"),
            (RollbackPhaseName::Aborting, "aborting"),
        ] {
            assert_eq!(phase.as_str(), text);
            assert_eq!(RollbackPhaseName::parse(text), Some(phase));
            // And the JSON spelling is the same one, so a script reading the
            // report and a script reading a log line agree.
            assert_eq!(
                serde_json::to_string(&phase).unwrap(),
                format!("\"{text}\"")
            );
        }
    }

    #[test]
    fn an_unknown_phase_name_does_not_parse_into_something_plausible() {
        for text in ["", "IDLE", "deleting ", "abort"] {
            assert_eq!(RollbackPhaseName::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn the_point_of_no_return_is_named_phase_by_phase() {
        for phase in [
            RollbackPhaseName::ArchiveBarrierReady,
            RollbackPhaseName::Deleting,
            RollbackPhaseName::Restoring,
            RollbackPhaseName::Verifying,
            RollbackPhaseName::AllRealmsReady,
        ] {
            assert!(phase.past_point_of_no_return(), "{phase:?}");
        }
        for phase in [
            RollbackPhaseName::Idle,
            RollbackPhaseName::PendingPickup,
            RollbackPhaseName::Requested,
            RollbackPhaseName::Frozen,
            RollbackPhaseName::Archiving,
            RollbackPhaseName::Aborting,
        ] {
            assert!(!phase.past_point_of_no_return(), "{phase:?}");
        }
    }

    /// A request that stands must not be reported as an idle chain.
    #[test]
    fn a_pending_request_is_not_reported_as_idle() {
        let report = RollbackStatusReport::pending_pickup(3, 100, 90);
        assert_eq!(report.phase, RollbackPhaseName::PendingPickup);
        assert!(!report.past_point_of_no_return);
        assert_eq!(report.target, Some(90));
        assert_ne!(report, RollbackStatusReport::idle(3, Some(100)));
    }

    #[test]
    fn a_status_report_round_trips_through_json() {
        let report = RollbackStatusReport {
            phase: RollbackPhaseName::Verifying,
            past_point_of_no_return: true,
            chain_epoch: 4,
            head: Some(120),
            target: Some(90),
            last_request_expired: Some(RollbackRequestExpiry::AlreadyConsumed),
            participants: Some(vec![RollbackParticipantProgress {
                scope: "realm:0:1".to_string(),
                froze: true,
                archived: true,
                verified: false,
            }]),
        };
        let text = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serde_json::from_str::<RollbackStatusReport>(&text).unwrap(),
            report
        );
    }
}
