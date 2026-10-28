use std::collections::VecDeque;

use jsonrpsee::types::ErrorObjectOwned;
use parking_lot::Mutex;
use tokio::sync::oneshot;

#[derive(Debug, Clone)]
pub(super) struct ClaimReceipt {
    pub(super) tx_hash: String,
    pub(super) operator_user_id: u64,
}

pub(super) type ClaimOutcome = Result<ClaimReceipt, ErrorObjectOwned>;

pub(super) struct QueuedClaim {
    pub(super) recipient_user_id: u64,
    pub(super) reply: oneshot::Sender<ClaimOutcome>,
}

// Claims wait here until the next departure puts up to a batch of them into
// one operator End Cap. Callers hold their recipient lock while queued, so a
// recipient appears at most once.
#[derive(Default)]
pub(super) struct ClaimQueue {
    claims: Mutex<VecDeque<QueuedClaim>>,
}

impl ClaimQueue {
    pub(super) fn push(&self, recipient_user_id: u64) -> oneshot::Receiver<ClaimOutcome> {
        let (reply, receiver) = oneshot::channel();
        self.claims.lock().push_back(QueuedClaim { recipient_user_id, reply });
        receiver
    }

    pub(super) fn take(&self, max_claims: usize) -> Vec<QueuedClaim> {
        let mut claims = self.claims.lock();
        let count = claims.len().min(max_claims);
        claims.drain(..count).collect()
    }

    pub(super) fn len(&self) -> usize {
        self.claims.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_returns_oldest_claims_up_to_the_limit() {
        let queue = ClaimQueue::default();
        let _receivers: Vec<_> = (1..=5).map(|id| queue.push(id)).collect();
        let first: Vec<u64> = queue.take(3).iter().map(|claim| claim.recipient_user_id).collect();
        assert_eq!(first, vec![1, 2, 3]);
        assert_eq!(queue.len(), 2);
        let rest: Vec<u64> = queue.take(10).iter().map(|claim| claim.recipient_user_id).collect();
        assert_eq!(rest, vec![4, 5]);
        assert!(queue.take(10).is_empty());
    }
}
