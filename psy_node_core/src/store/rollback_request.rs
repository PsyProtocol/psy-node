//! An operator's request to roll the chain back, and the one decision that
//! admits it.
//!
//! design-r1 §10 gives the operator `rollback.request(T, expected_head)`.  What
//! receives it cannot be what acts on it: the request arrives at an edge, which
//! is a read-only role and may be one of several, while the rollback has to run
//! in the process that owns the head.  So the request is written down and picked
//! up later, and this module is the part that decides whether picking it up is
//! still the right thing to do.
//!
//! ## The mailbox is not the state machine
//!
//! §4.1 puts mutual exclusion and crash recovery on the durable control row, and
//! that does not change.  A request is only ever a question -- "will you roll
//! back to T?" -- and the control row remains the sole answer to "is a rollback
//! happening?".  Nothing here starts, resumes, or refuses a rollback that has
//! already begun; the caller consults this only while the control row is Idle.
//!
//! ## Why entries are never deleted
//!
//! An entry expires on its own: it names the head the operator saw, and once the
//! chain produces past it, `live_head` no longer matches and the entry can never
//! be taken up.  That is what makes withdrawing a request equivalent to not
//! sending it again, and it is why R1 needs no abort for the interval before
//! pickup.  Since expiry costs nothing, the rows stay -- and become the record
//! of who asked, when, and how many times before the chain took it up.
//!
//! ## What this deliberately does not decide
//!
//! Whether the range can actually be planned.  A target below the rollback floor
//! or below the start of the current epoch is `NOT_FEASIBLE`, and that judgment
//! belongs to the planner (§2.2), which reads manifests.  Repeating any part of
//! it here would create a second opinion on feasibility, and the two would
//! diverge the first time either changed.  This answers only whether the request
//! still describes the chain standing in front of it.

/// One request, as it was written down.
///
/// `requested_at_us` is the identity: re-sending is the operator's ordinary
/// retry, so two attempts are two entries rather than one overwritten row, and
/// the newest is the one that counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackRequestEntry {
    pub requested_at_us: i64,
    pub target: u64,
    /// The head the operator saw when they asked.
    ///
    /// This is the anti-replay token as much as it is a precondition.  After a
    /// rollback the head *is* the target, so an entry that was already acted on
    /// names a head above the live one and can never be taken up a second time
    /// -- independently of whether anything remembered to mark it consumed.
    pub expected_head: u64,
    pub requested_by: String,
    /// The chain epoch the rollback opened, once one was started for this entry.
    pub consumed_epoch: Option<u64>,
}

/// What to do with the newest entry in the mailbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PickupDecision {
    Take { target: u64 },
    Stale { reason: StaleReason },
}

/// Why a request no longer stands.
///
/// Named individually because an operator who sees nothing happen needs to be
/// told which of these it was: "expired because the chain moved on" and "already
/// carried out" call for opposite responses, and a single `Stale` would leave
/// them guessing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleReason {
    /// A rollback was already started for this entry.
    AlreadyConsumed,
    /// The chain is shorter than it was when the request was written, so
    /// something has already rolled it back and this request describes a chain
    /// that no longer exists.
    HeadBelowExpected,
    /// The target is not below the head the operator saw, so the request asks
    /// for nothing to be discarded.
    TargetNotBelowHead,
}

/// Whether the newest request may be taken up against the chain as it stands.
///
/// A chain that grew since the request was written is still rolled back.  The
/// operator asked for everything above `target` to go; the chain having produced
/// more only means there is more of it to discard, and that is the safe
/// direction -- the same one `ScyllaRollbackExecutor` already asserts when it
/// refuses a plan that starts *below* the published head.  Requiring exact
/// equality instead would make pickup a race against block production and turn
/// re-sending from a fallback into the normal path.
pub fn decide_pickup(entry: &RollbackRequestEntry, live_head: u64) -> PickupDecision {
    if entry.consumed_epoch.is_some() {
        return PickupDecision::Stale {
            reason: StaleReason::AlreadyConsumed,
        };
    }
    if live_head < entry.expected_head {
        return PickupDecision::Stale {
            reason: StaleReason::HeadBelowExpected,
        };
    }
    if entry.target >= entry.expected_head {
        return PickupDecision::Stale {
            reason: StaleReason::TargetNotBelowHead,
        };
    }
    PickupDecision::Take {
        target: entry.target,
    }
}

/// The mailbox itself, as everything above the storage layer sees it.
///
/// A trait for the same reason the rest of this control plane is one: the edge
/// that writes a request and the processor that takes it up both live in
/// `psy_node_common`, which does not -- and must not -- know what database is
/// underneath.
#[async_trait::async_trait]
pub trait RollbackRequestMailbox: Send + Sync {
    /// Write a request down and return the microsecond identifying it.
    ///
    /// Nothing here judges it.  Whether it still stands when the processor
    /// arrives is `decide_pickup`'s answer and whether the range can be planned
    /// is the planner's; a mailbox that also refused requests would be a third
    /// opinion on the same question.
    async fn submit(
        &self,
        target: u64,
        expected_head: u64,
        requested_by: &str,
    ) -> anyhow::Result<i64>;

    /// The request that counts: the most recently written one.
    async fn newest(&self) -> anyhow::Result<Option<RollbackRequestEntry>>;

    /// Record that a rollback was started for this request, in this epoch.
    async fn mark_consumed(&self, requested_at_us: i64, chain_epoch: u64) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(target: u64, expected_head: u64) -> RollbackRequestEntry {
        RollbackRequestEntry {
            requested_at_us: 1_787_000_000_000_000,
            target,
            expected_head,
            requested_by: "operator".to_string(),
            consumed_epoch: None,
        }
    }

    #[test]
    fn a_request_against_the_head_it_named_is_taken_up() {
        assert_eq!(
            decide_pickup(&entry(90, 100), 100),
            PickupDecision::Take { target: 90 }
        );
    }

    #[test]
    fn a_chain_that_grew_since_the_request_is_still_rolled_back() {
        // The operator asked for everything above 90 to go.  Four more
        // checkpoints having been produced does not contradict that; it only
        // means four more to discard.
        assert_eq!(
            decide_pickup(&entry(90, 100), 104),
            PickupDecision::Take { target: 90 }
        );
    }

    #[test]
    fn a_request_whose_chain_no_longer_exists_is_refused() {
        // The head is below the one the request named, so something already
        // rolled the chain back.  This is also what stops a completed request
        // from being carried out twice: afterwards the head *is* the target.
        assert_eq!(
            decide_pickup(&entry(90, 100), 90),
            PickupDecision::Stale {
                reason: StaleReason::HeadBelowExpected
            }
        );
    }

    #[test]
    fn a_consumed_entry_is_never_taken_twice() {
        let mut consumed = entry(90, 100);
        consumed.consumed_epoch = Some(1);
        assert_eq!(
            decide_pickup(&consumed, 100),
            PickupDecision::Stale {
                reason: StaleReason::AlreadyConsumed
            }
        );
    }

    #[test]
    fn being_consumed_outranks_the_head_having_moved() {
        // Both are true after a completed rollback, and the operator asking why
        // nothing happened deserves the one that says it already did.
        let mut consumed = entry(90, 100);
        consumed.consumed_epoch = Some(1);
        assert_eq!(
            decide_pickup(&consumed, 90),
            PickupDecision::Stale {
                reason: StaleReason::AlreadyConsumed
            }
        );
    }

    #[test]
    fn a_target_at_or_above_the_head_that_was_seen_is_refused() {
        // Nothing lies above it, so the request asks for nothing -- and a
        // request that asks for nothing must not open an epoch.
        for target in [100, 101] {
            assert_eq!(
                decide_pickup(&entry(target, 100), 100),
                PickupDecision::Stale {
                    reason: StaleReason::TargetNotBelowHead
                },
                "target {target}"
            );
        }
    }

    #[test]
    fn feasibility_is_not_decided_here() {
        // A target of 0 on a chain at 100 is very likely NOT_FEASIBLE -- it is
        // almost certainly below the rollback floor, and on a chain that has
        // been rolled back before it is below the epoch start.  This still
        // returns Take: the planner refuses it, with a reason that names the
        // epoch.  Refusing it here as well would put two opinions on
        // feasibility in the codebase, and the quiet one would drift.
        assert_eq!(
            decide_pickup(&entry(0, 100), 100),
            PickupDecision::Take { target: 0 }
        );
    }
}
