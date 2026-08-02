//! Shared response types for Psy node APIs.

use serde::{Deserialize, Serialize};

/// Aggregated worker job statistics for a committed checkpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointJobStats {
    /// Pending ID used internally while the checkpoint was being processed.
    pub unique_pending_id: u64,
    /// Number of proof jobs completed for the checkpoint.
    pub total_completed: u64,
    /// Sum of proof execution durations in milliseconds.
    pub total_duration_ms: u64,
    /// Minimum proof execution duration, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_duration_ms: Option<u64>,
    /// Maximum proof execution duration, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_ms: Option<u64>,
}

impl CheckpointJobStats {
    pub fn average_duration_ms(&self) -> Option<u64> {
        (self.total_completed > 0).then(|| self.total_duration_ms / self.total_completed)
    }
}

#[cfg(test)]
mod tests {
    use super::CheckpointJobStats;

    #[test]
    fn average_duration_requires_completed_jobs() {
        let mut stats = CheckpointJobStats::default();
        assert_eq!(stats.average_duration_ms(), None);

        stats.total_completed = 4;
        stats.total_duration_ms = 1_002;
        assert_eq!(stats.average_duration_ms(), Some(250));
    }
}
