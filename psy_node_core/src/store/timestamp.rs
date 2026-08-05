//! Driver-independent CQL write-timestamp and rollback-fence contracts.
//!
//! These types deliberately allocate no timestamps. They only validate values
//! supplied by the future durable allocator (D-04) and preserve the strict
//! ordering needed by Scylla last-write-wins reconciliation.

use std::{error::Error, fmt};

/// A supplied timestamp cannot be represented by CQL's signed microsecond
/// timestamp field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampOutOfCqlRange {
    pub attempted: i128,
}

impl fmt::Display for TimestampOutOfCqlRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "timestamp {} is outside the signed CQL BIGINT range", self.attempted)
    }
}

impl Error for TimestampOutOfCqlRange {}

/// Ordering validation for a delete fence or a new-branch write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampOrderingError {
    OutOfCqlRange(TimestampOutOfCqlRange),
    DeleteFenceNotStrictlyAfter { orphan_write_max: i64, attempted_fence: i64 },
    NewBranchNotStrictlyAfterFence { delete_fence: i64, attempted_write: i64 },
}

impl fmt::Display for TimestampOrderingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfCqlRange(error) => error.fmt(f),
            Self::DeleteFenceNotStrictlyAfter { orphan_write_max, attempted_fence } => write!(
                f,
                "delete fence {attempted_fence} must be strictly after orphan write maximum {orphan_write_max}"
            ),
            Self::NewBranchNotStrictlyAfterFence { delete_fence, attempted_write } => write!(
                f,
                "new-branch write {attempted_write} must be strictly after delete fence {delete_fence}"
            ),
        }
    }
}

impl Error for TimestampOrderingError {}

impl From<TimestampOutOfCqlRange> for TimestampOrderingError {
    fn from(value: TimestampOutOfCqlRange) -> Self {
        Self::OutOfCqlRange(value)
    }
}

/// The explicit microsecond timestamp sealed into one authority commit.
///
/// No `From<u64>`, `Default`, arithmetic, or clock-reading API is provided:
/// callers must make timestamp allocation an explicit operation.
///
/// ```compile_fail
/// use psy_node_core::store::{timestamp::CommitWriteTimestampUs, typed::CheckpointId};
/// let checkpoint = CheckpointId::try_new(7).unwrap();
/// let _timestamp: CommitWriteTimestampUs = checkpoint;
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::timestamp::CommitWriteTimestampUs;
/// let _timestamp: CommitWriteTimestampUs = 7_u64.into();
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::{timestamp::CommitWriteTimestampUs, typed::UniquePendingId};
/// let pending = UniquePendingId::try_new(7).unwrap();
/// let _timestamp: CommitWriteTimestampUs = pending;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitWriteTimestampUs(i64);

impl CommitWriteTimestampUs {
    pub const fn try_from_i128(value: i128) -> Result<Self, TimestampOutOfCqlRange> {
        if value < i64::MIN as i128 || value > i64::MAX as i128 {
            Err(TimestampOutOfCqlRange { attempted: value })
        } else {
            Ok(Self(value as i64))
        }
    }

    pub const fn as_i64(self) -> i64 {
        self.0
    }
}

/// A delete timestamp carrying proof that it dominates the maximum timestamp
/// permitted on the orphaned branch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DeleteFenceTimestampUs {
    value: i64,
    orphan_write_max: CommitWriteTimestampUs,
}

/// A delete fence is not interchangeable with a normal write timestamp.
///
/// ```compile_fail
/// use psy_node_core::store::timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs};
/// let old = CommitWriteTimestampUs::try_from_i128(1).unwrap();
/// let fence = DeleteFenceTimestampUs::try_after(old, 2).unwrap();
/// let _write: CommitWriteTimestampUs = fence;
/// ```

impl DeleteFenceTimestampUs {
    pub const fn try_after(
        orphan_write_max: CommitWriteTimestampUs,
        candidate: i128,
    ) -> Result<Self, TimestampOrderingError> {
        let candidate = match CommitWriteTimestampUs::try_from_i128(candidate) {
            Ok(value) => value,
            Err(error) => return Err(TimestampOrderingError::OutOfCqlRange(error)),
        };
        if candidate.as_i64() <= orphan_write_max.as_i64() {
            return Err(TimestampOrderingError::DeleteFenceNotStrictlyAfter {
                orphan_write_max: orphan_write_max.as_i64(),
                attempted_fence: candidate.as_i64(),
            });
        }
        Ok(Self { value: candidate.as_i64(), orphan_write_max })
    }

    pub const fn as_i64(self) -> i64 {
        self.value
    }

    pub const fn orphan_write_max(self) -> CommitWriteTimestampUs {
        self.orphan_write_max
    }
}

/// A post-rollback write timestamp carrying proof that it dominates the
/// rollback delete fence.
///
/// ```compile_fail
/// use psy_node_core::store::timestamp::{
///     CommitWriteTimestampUs, DeleteFenceTimestampUs, NewBranchWriteTimestampUs,
/// };
/// let old = CommitWriteTimestampUs::try_from_i128(1).unwrap();
/// let fence = DeleteFenceTimestampUs::try_after(old, 2).unwrap();
/// let new_branch = NewBranchWriteTimestampUs::try_after(fence, 3).unwrap();
/// let _ordinary_write: CommitWriteTimestampUs = new_branch;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NewBranchWriteTimestampUs {
    value: CommitWriteTimestampUs,
    delete_fence: DeleteFenceTimestampUs,
}

impl NewBranchWriteTimestampUs {
    pub const fn try_after(
        delete_fence: DeleteFenceTimestampUs,
        candidate: i128,
    ) -> Result<Self, TimestampOrderingError> {
        let candidate = match CommitWriteTimestampUs::try_from_i128(candidate) {
            Ok(value) => value,
            Err(error) => return Err(TimestampOrderingError::OutOfCqlRange(error)),
        };
        if candidate.as_i64() <= delete_fence.as_i64() {
            return Err(TimestampOrderingError::NewBranchNotStrictlyAfterFence {
                delete_fence: delete_fence.as_i64(),
                attempted_write: candidate.as_i64(),
            });
        }
        Ok(Self { value: candidate, delete_fence })
    }

    /// Converts a validated new-branch timestamp into the timestamp accepted by
    /// a normal PUT sealer. This conversion is intentionally explicit.
    pub const fn as_commit_timestamp(self) -> CommitWriteTimestampUs {
        self.value
    }

    pub const fn delete_fence(self) -> DeleteFenceTimestampUs {
        self.delete_fence
    }
}

/// A fully checked `orphan writes < delete fence < new branch writes` window.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimestampFenceWindow {
    delete_fence: DeleteFenceTimestampUs,
    new_branch_write: NewBranchWriteTimestampUs,
}

impl TimestampFenceWindow {
    pub const fn try_new(
        orphan_write_max: CommitWriteTimestampUs,
        delete_fence: i128,
        new_branch_write: i128,
    ) -> Result<Self, TimestampOrderingError> {
        let delete_fence = match DeleteFenceTimestampUs::try_after(orphan_write_max, delete_fence) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let new_branch_write = match NewBranchWriteTimestampUs::try_after(delete_fence, new_branch_write) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Ok(Self { delete_fence, new_branch_write })
    }

    pub const fn delete_fence(self) -> DeleteFenceTimestampUs {
        self.delete_fence
    }

    pub const fn new_branch_write(self) -> NewBranchWriteTimestampUs {
        self.new_branch_write
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_entire_signed_cql_range() {
        assert_eq!(CommitWriteTimestampUs::try_from_i128(i64::MIN as i128).unwrap().as_i64(), i64::MIN);
        assert_eq!(CommitWriteTimestampUs::try_from_i128(i64::MAX as i128).unwrap().as_i64(), i64::MAX);
        assert_eq!(
            CommitWriteTimestampUs::try_from_i128(i64::MIN as i128 - 1),
            Err(TimestampOutOfCqlRange { attempted: i64::MIN as i128 - 1 })
        );
        assert_eq!(
            CommitWriteTimestampUs::try_from_i128(i64::MAX as i128 + 1),
            Err(TimestampOutOfCqlRange { attempted: i64::MAX as i128 + 1 })
        );
    }

    #[test]
    fn enforces_strict_fence_and_new_branch_ordering() {
        let orphan = CommitWriteTimestampUs::try_from_i128(1_000).unwrap();
        assert!(matches!(
            DeleteFenceTimestampUs::try_after(orphan, 1_000),
            Err(TimestampOrderingError::DeleteFenceNotStrictlyAfter { .. })
        ));
        assert!(matches!(
            DeleteFenceTimestampUs::try_after(orphan, 999),
            Err(TimestampOrderingError::DeleteFenceNotStrictlyAfter { .. })
        ));

        let fence = DeleteFenceTimestampUs::try_after(orphan, 2_000).unwrap();
        assert!(matches!(
            NewBranchWriteTimestampUs::try_after(fence, 2_000),
            Err(TimestampOrderingError::NewBranchNotStrictlyAfterFence { .. })
        ));
        assert!(matches!(
            NewBranchWriteTimestampUs::try_after(fence, 1_999),
            Err(TimestampOrderingError::NewBranchNotStrictlyAfterFence { .. })
        ));

        let window = TimestampFenceWindow::try_new(orphan, 2_000, 3_000).unwrap();
        assert_eq!(window.delete_fence().as_i64(), 2_000);
        assert_eq!(window.new_branch_write().as_commit_timestamp().as_i64(), 3_000);
    }

    #[test]
    fn maximum_timestamp_has_no_silent_successor() {
        let maximum = CommitWriteTimestampUs::try_from_i128(i64::MAX as i128).unwrap();
        assert!(matches!(
            DeleteFenceTimestampUs::try_after(maximum, i64::MAX as i128 + 1),
            Err(TimestampOrderingError::OutOfCqlRange(_))
        ));

        let before_maximum = CommitWriteTimestampUs::try_from_i128(i64::MAX as i128 - 1).unwrap();
        let maximum_fence = DeleteFenceTimestampUs::try_after(before_maximum, i64::MAX as i128).unwrap();
        assert!(matches!(
            NewBranchWriteTimestampUs::try_after(maximum_fence, i64::MAX as i128 + 1),
            Err(TimestampOrderingError::OutOfCqlRange(_))
        ));
    }
}
