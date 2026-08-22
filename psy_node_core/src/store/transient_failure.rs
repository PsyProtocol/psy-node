//! Whether a failed block is the chain's fault or the database's.
//!
//! A processor parks on a failed block, deliberately: a stack that restarts its
//! way through a crash loop hides the thing you most need to see.  That is the
//! right answer to a witness that will not verify and the wrong one to the
//! database missing a beat, and both arrive at the same handler.
//!
//! Observed: one `Unavailable` from a single-node cluster that was merely busy
//! parked the Coordinator for good.  The chain sat at one height for two hours
//! with all three participants in step and every keyspace intact -- which is
//! what made it look healthy -- over something that waiting a second would have
//! fixed.
//!
//! Telling the two apart needs the storage driver's own error types, and this
//! crate has none: it is the layer both the Scylla store and the processors are
//! written against.  So the storage layer installs the answer and the
//! processors ask through here.
//!
//! Nothing installed answers "not transient", which parks -- the behaviour
//! before this existed, and the safe direction to be wrong in.

use std::sync::OnceLock;

type Classifier = fn(&anyhow::Error) -> bool;

static CLASSIFIER: OnceLock<Classifier> = OnceLock::new();

/// Teach this process what its storage driver's transient failures look like.
///
/// Called once, by whichever store a node is built on.  A second call is
/// ignored rather than refused: two stores in one process would both be right,
/// and a startup that fails over which one spoke first would be worse than
/// either answer.
pub fn install_transient_classifier(classifier: Classifier) {
    let _ = CLASSIFIER.set(classifier);
}

/// Whether this error is the database being briefly unreachable or busy.
pub fn is_database_briefly_unavailable(error: &anyhow::Error) -> bool {
    CLASSIFIER.get().is_some_and(|classify| classify(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_storage_layer_nothing_is_transient() {
        // Parking is what happened before any of this existed, so a node whose
        // store never introduced itself behaves exactly as it used to.
        assert!(!is_database_briefly_unavailable(&anyhow::anyhow!("anything at all")));
    }
}
