//! Typed pending/proc generation reservation.
//!
//! Reserving a generation advances the monotonic pending counter and chooses
//! its proc-checkpoint namespace, but deliberately does not publish either
//! direction of the legacy pending/proc mapping.  Branch-exact writers use
//! this split so the mapping can be committed later by one timestamp-bound
//! durable intent.

use super::typed::{
    ProcCheckpointUniqueId, UniquePendingId, UniquePendingIdOutOfRange,
};

#[must_use = "an unmapped pending generation must be persisted in a durable intent or deliberately abandoned"]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReservedPendingGeneration {
    pending_id: UniquePendingId,
    proc_checkpoint_id: ProcCheckpointUniqueId,
}

impl ReservedPendingGeneration {
    pub(crate) fn try_new(
        pending_id: u64,
        proc_checkpoint_id: u128,
    ) -> Result<Self, UniquePendingIdOutOfRange> {
        Ok(Self {
            pending_id: UniquePendingId::try_new(pending_id)?,
            proc_checkpoint_id: ProcCheckpointUniqueId::from_u128(
                proc_checkpoint_id,
            ),
        })
    }

    pub const fn pending_id(self) -> UniquePendingId {
        self.pending_id
    }

    pub const fn proc_checkpoint_id(self) -> ProcCheckpointUniqueId {
        self.proc_checkpoint_id
    }

    pub const fn into_legacy_parts(self) -> (u64, u128) {
        (
            self.pending_id.get(),
            self.proc_checkpoint_id.as_u128(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_preserves_semantic_id_domains() {
        let reservation = ReservedPendingGeneration::try_new(17, 29).unwrap();
        assert_eq!(reservation.pending_id().get(), 17);
        assert_eq!(reservation.proc_checkpoint_id().as_u128(), 29);
        assert_eq!(reservation.into_legacy_parts(), (17, 29));
        assert!(ReservedPendingGeneration::try_new(i64::MAX as u64 + 1, 29)
            .is_err());
    }
}
