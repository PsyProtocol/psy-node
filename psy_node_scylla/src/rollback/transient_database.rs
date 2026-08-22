//! Telling a database that is briefly away from a chain that is broken.
//!
//! A processor parks on a failed block, deliberately: a stack that restarts its
//! way through a crash loop hides the thing you most need to see.  That is the
//! right answer to a corrupted witness and the wrong one to Scylla missing a
//! beat, and the two arrived at the same handler.
//!
//! Observed: a single-node cluster with RF=1 answered one commit with
//! `Unavailable` -- "Not enough nodes responded to the query", which on one node
//! means it was busy, not that a node was missing -- and the Coordinator parked
//! for good.  The chain sat at 2707 for two hours with all three participants
//! in step at the same height and every keyspace intact, which is what made it
//! look healthy.  Nothing was wrong with it that waiting a second would not
//! have fixed.
//!
//! Narrow on purpose.  Classifying the wrong error as transient turns a real
//! corruption into a restart loop, which is worse than parking, so this names
//! only failures that are about reaching the database rather than about what it
//! said.

use scylla::errors::{DbError, ExecutionError, RequestAttemptError};

/// Whether an error is the database being briefly unreachable or busy.
///
/// Walks the chain rather than testing the outermost error, because by the time
/// a failed commit reaches the processor loop it has been wrapped in context
/// several times over and the typed cause is somewhere underneath.
pub fn is_database_briefly_unavailable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<ExecutionError>()
            .is_some_and(execution_error_is_transient)
    })
}

fn execution_error_is_transient(error: &ExecutionError) -> bool {
    match error {
        // No connection to hand out this instant, or the request outlived the
        // client's patience.  Both are about reaching the database.
        ExecutionError::ConnectionPoolError(_) | ExecutionError::RequestTimeout(_) => true,
        ExecutionError::LastAttemptError(attempt) => attempt_is_transient(attempt),
        // `EmptyPlan` is a load-balancing misconfiguration and `BadQuery` is a
        // bug in the caller; neither gets better on its own, and retrying them
        // is the loop this is meant to avoid.
        _ => false,
    }
}

fn attempt_is_transient(error: &RequestAttemptError) -> bool {
    match error {
        RequestAttemptError::BrokenConnectionError(_)
        | RequestAttemptError::UnableToAllocStreamId => true,
        RequestAttemptError::DbError(db, _) => matches!(
            db,
            // Not enough replicas answered, the node is loaded, it is still
            // coming up, or a read or write ran out of time.  Every one of these
            // is the cluster asking to be tried again.
            DbError::Unavailable { .. }
                | DbError::Overloaded
                | DbError::IsBootstrapping
                | DbError::ReadTimeout { .. }
                | DbError::WriteTimeout { .. }
        ),
        // `ServerError` is deliberately absent: it means something unexpected
        // happened inside the database, which is exactly the kind of thing an
        // operator should see rather than have retried past.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_the_database_being_busy() {
        let error = anyhow::Error::new(ExecutionError::LastAttemptError(
            RequestAttemptError::DbError(
                DbError::Unavailable {
                    consistency: scylla::frame::types::Consistency::One,
                    required: 1,
                    alive: 0,
                },
                "Not enough nodes responded to the query".to_string(),
            ),
        ))
        .context("committing coordinator state update");
        assert!(is_database_briefly_unavailable(&error));
    }

    #[test]
    fn a_bad_query_is_not() {
        // The distinction the whole module exists for: this one never gets
        // better, so retrying it would hide it behind a restart loop.
        let error = anyhow::Error::new(ExecutionError::EmptyPlan);
        assert!(!is_database_briefly_unavailable(&error));
    }

    #[test]
    fn something_that_is_not_a_database_error_at_all_is_not() {
        let error = anyhow::anyhow!("the witness did not verify");
        assert!(!is_database_briefly_unavailable(&error));
    }
}
