//! One durable record per rollback, so the chain can be audited afterwards.
//!
//! Everything else a rollback leaves behind describes *data*: the archive holds
//! the discarded rows with the checkpoint that wrote each one, and the receipts
//! hold what each participant proved.  None of it records the *event* -- that a
//! rollback happened at all, from which head to which target, when, and who took
//! part.  Without that the archive is a heap of rows under an opaque plan id,
//! and the only trace of the rollback itself is that the epoch counter moved.
//!
//! ## Why the epoch is the identity
//!
//! `start_rollback` allocates the next chain epoch when the request is written,
//! before anything is archived or deleted, and design-r1 never reuses one.  So
//! an epoch names exactly one rollback attempt for the life of the chain --
//! including the attempts that were aborted or that crashed, which are the ones
//! an audit most wants to find.  A synthetic id would have to be made unique;
//! this one already is, and it is the same value the head carries, so a row here
//! and a head out there cannot disagree about which rollback they mean.
//!
//! ## Why it is written twice
//!
//! Once when the rollback is requested and once when it ends.  Writing only at
//! the end would lose every rollback that did not reach an end -- a crash
//! between the archive and the delete leaves the chain in the state hardest to
//! reason about and no record that anything was attempted.  The first write is
//! the one that makes the second one's absence meaningful.

use std::fmt;

use psy_data::protocol::chain_context::AUTHORITY_SCOPE_LEN;

use super::rollback_participants::RollbackParticipant;

/// How a rollback ended, or that it has not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackOutcome {
    /// Requested and under way.  A row left in this state is a rollback that
    /// never reported back: it crashed, or it is still running.
    Started,
    /// Reached the target and published the new epoch.
    Completed {
        archived_rows: u64,
        deleted_rows: u64,
    },
    /// Abandoned before the point of no return.
    Aborted,
}

impl RollbackOutcome {
    pub const fn code(self) -> i16 {
        match self {
            Self::Started => 1,
            Self::Completed { .. } => 2,
            Self::Aborted => 3,
        }
    }

    /// Rebuild from what a row stores.  An unknown code is an error rather than
    /// a default: an audit that silently reads a future outcome as one of
    /// today's would be worse than one that refuses to read it.
    pub fn from_code(
        code: i16,
        archived_rows: u64,
        deleted_rows: u64,
    ) -> Result<Self, RollbackEventError> {
        match code {
            1 => Ok(Self::Started),
            2 => Ok(Self::Completed {
                archived_rows,
                deleted_rows,
            }),
            3 => Ok(Self::Aborted),
            other => Err(RollbackEventError::UnknownOutcome(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackEventError {
    UnknownOutcome(i16),
    /// The epoch a rollback publishes is always above the one it leaves.
    EpochNotAdvanced { previous: u64, allocated: u64 },
    /// A rollback discards a suffix, so the target is below the head.
    TargetNotBelowHead { target: u64, head: u64 },
}

impl fmt::Display for RollbackEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOutcome(code) => {
                write!(f, "rollback outcome code {code} is not one this build knows")
            }
            Self::EpochNotAdvanced {
                previous,
                allocated,
            } => write!(
                f,
                "a rollback allocated epoch {allocated} while the chain was already at {previous}; \
                 epochs are never reused, so this record could name another rollback"
            ),
            Self::TargetNotBelowHead { target, head } => write!(
                f,
                "a rollback from head {head} to target {target} discards nothing; the target must \
                 be below the head"
            ),
        }
    }
}

impl std::error::Error for RollbackEventError {}

/// What happened, in the terms an auditor asks about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackEvent {
    chain_epoch: u64,
    previous_epoch: u64,
    head: u64,
    target: u64,
    /// Ties this event to the archive rows, which are partitioned by it.  Opaque
    /// here on purpose: the executor chooses it and this record only has to make
    /// it findable.
    plan_id: Vec<u8>,
    /// Who took part, as the canonical scope bytes and nothing else.
    ///
    /// Deliberately not decoded back into authorities on read, for the reason
    /// the barrier does not decode receipts: turning stored bytes into an
    /// identity can produce an authority that never existed, and an audit that
    /// invented a participant would be worse than one that shows bytes.  A
    /// reader that knows which authorities to expect matches against them.
    participant_scopes: Vec<[u8; AUTHORITY_SCOPE_LEN]>,
    outcome: RollbackOutcome,
    /// Wall clock microseconds, from the same allocator the commit timestamps
    /// come from, so an event and the rows it discarded can be put on one axis.
    requested_at_us: i64,
}

impl RollbackEvent {
    pub fn try_new(
        chain_epoch: u64,
        previous_epoch: u64,
        head: u64,
        target: u64,
        plan_id: Vec<u8>,
        participants: &[RollbackParticipant],
        requested_at_us: i64,
    ) -> Result<Self, RollbackEventError> {
        if chain_epoch <= previous_epoch {
            return Err(RollbackEventError::EpochNotAdvanced {
                previous: previous_epoch,
                allocated: chain_epoch,
            });
        }
        if target >= head {
            return Err(RollbackEventError::TargetNotBelowHead { target, head });
        }
        Ok(Self {
            chain_epoch,
            previous_epoch,
            head,
            target,
            plan_id,
            participant_scopes: participants
                .iter()
                .map(|p| p.scope().to_canonical_bytes())
                .collect(),
            outcome: RollbackOutcome::Started,
            requested_at_us,
        })
    }

    pub const fn chain_epoch(&self) -> u64 {
        self.chain_epoch
    }
    pub const fn previous_epoch(&self) -> u64 {
        self.previous_epoch
    }
    pub const fn head(&self) -> u64 {
        self.head
    }
    pub const fn target(&self) -> u64 {
        self.target
    }
    pub fn plan_id(&self) -> &[u8] {
        &self.plan_id
    }
    pub fn participant_scopes(&self) -> &[[u8; AUTHORITY_SCOPE_LEN]] {
        &self.participant_scopes
    }

    /// Whether a known authority is among the recorded participants.
    ///
    /// Matching rather than decoding: the caller brings the identity, storage
    /// only confirms or denies it.
    pub fn includes(&self, participant: RollbackParticipant) -> bool {
        let scope = participant.scope().to_canonical_bytes();
        self.participant_scopes.iter().any(|s| *s == scope)
    }

    /// Rebuild a stored event.  Scope bytes are carried through untouched.
    pub fn from_stored(
        chain_epoch: u64,
        previous_epoch: u64,
        head: u64,
        target: u64,
        plan_id: Vec<u8>,
        participant_scopes: Vec<[u8; AUTHORITY_SCOPE_LEN]>,
        outcome: RollbackOutcome,
        requested_at_us: i64,
    ) -> Result<Self, RollbackEventError> {
        if chain_epoch <= previous_epoch {
            return Err(RollbackEventError::EpochNotAdvanced {
                previous: previous_epoch,
                allocated: chain_epoch,
            });
        }
        if target >= head {
            return Err(RollbackEventError::TargetNotBelowHead { target, head });
        }
        Ok(Self {
            chain_epoch,
            previous_epoch,
            head,
            target,
            plan_id,
            participant_scopes,
            outcome,
            requested_at_us,
        })
    }
    pub const fn outcome(&self) -> RollbackOutcome {
        self.outcome
    }
    pub const fn requested_at_us(&self) -> i64 {
        self.requested_at_us
    }

    /// How many checkpoints this rollback discarded.
    pub const fn discarded_checkpoints(&self) -> u64 {
        self.head - self.target
    }

    #[must_use]
    pub fn finished(mut self, outcome: RollbackOutcome) -> Self {
        self.outcome = outcome;
        self
    }
}

/// Where rollback events are kept.
///
/// Separate from every store the chain uses while running: it is written twice
/// per rollback and never otherwise, which is what keeps auditability from
/// costing anything on the commit path.
#[async_trait::async_trait]
pub trait RollbackEventStore: Send + Sync {
    /// Record that a rollback has been requested.  Written before anything is
    /// archived, so a rollback that dies mid-way still has a row.
    async fn record_rollback_requested(&self, event: &RollbackEvent) -> anyhow::Result<()>;

    /// Record how it ended, against the epoch that names it.
    async fn record_rollback_outcome(
        &self,
        chain_epoch: u64,
        outcome: RollbackOutcome,
    ) -> anyhow::Result<()>;

    /// Every rollback this chain has performed, newest first.
    async fn read_rollback_events(&self, limit: i32) -> anyhow::Result<Vec<RollbackEvent>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::protocol::chain_context::AuthorityScope;

    fn coordinator() -> RollbackParticipant {
        RollbackParticipant::new(AuthorityScope::Coordinator)
    }

    #[test]
    fn an_event_names_the_range_it_discarded() {
        let event = RollbackEvent::try_new(4, 3, 75, 65, b"plan".to_vec(), &[coordinator()], 17)
            .expect("a well formed rollback");
        assert_eq!(event.discarded_checkpoints(), 10);
        assert_eq!(event.outcome(), RollbackOutcome::Started);
    }

    #[test]
    fn an_epoch_that_did_not_advance_is_refused() {
        // The epoch is this record's identity.  One that did not advance could
        // name a rollback that already happened, and the audit would then show
        // one rollback where there were two.
        assert_eq!(
            RollbackEvent::try_new(3, 3, 75, 65, vec![], &[coordinator()], 0),
            Err(RollbackEventError::EpochNotAdvanced {
                previous: 3,
                allocated: 3
            })
        );
    }

    #[test]
    fn a_rollback_that_discards_nothing_is_refused() {
        assert_eq!(
            RollbackEvent::try_new(4, 3, 65, 65, vec![], &[coordinator()], 0),
            Err(RollbackEventError::TargetNotBelowHead {
                target: 65,
                head: 65
            })
        );
    }

    #[test]
    fn an_outcome_this_build_does_not_know_is_not_guessed() {
        // A newer node may write an outcome this one has never heard of.
        // Reading it as Completed would report a rollback that finished when it
        // may not have.
        assert_eq!(
            RollbackOutcome::from_code(9, 0, 0),
            Err(RollbackEventError::UnknownOutcome(9))
        );
        assert_eq!(
            RollbackOutcome::from_code(2, 1296, 1296),
            Ok(RollbackOutcome::Completed {
                archived_rows: 1296,
                deleted_rows: 1296
            })
        );
    }

    #[test]
    fn a_started_event_stays_started_until_it_is_finished() {
        // The property the audit rests on: a row still saying Started is a
        // rollback that never reported back, not a default.
        let event = RollbackEvent::try_new(4, 3, 75, 65, vec![], &[coordinator()], 0).unwrap();
        assert_eq!(event.outcome(), RollbackOutcome::Started);
        let done = event.finished(RollbackOutcome::Completed {
            archived_rows: 1296,
            deleted_rows: 1296,
        });
        assert_eq!(
            done.outcome(),
            RollbackOutcome::Completed {
                archived_rows: 1296,
                deleted_rows: 1296
            }
        );
    }
}
