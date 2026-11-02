//! Admission lanes of the internal HTTP server: per-lane concurrency, a
//! bounded queue, a queue wait and a request deadline.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use psy_bridge_reader_api::wire::{ErrorCode, Lane};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, PartialEq)]
pub struct LaneBudget {
    pub concurrency: usize,
    pub max_queue: usize,
    pub queue_wait: Duration,
    pub deadline: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Budgets {
    pub bridge_progress: LaneBudget,
    pub claim_proof: LaneBudget,
    pub interactive: LaneBudget,
    pub background: LaneBudget,
}

const MAX_DEADLINE: Duration = Duration::from_secs(10);

impl LaneBudget {
    fn validate(&self, name: &str) -> Result<(), String> {
        if self.concurrency == 0 {
            return Err(format!("{name}: concurrency must be > 0"));
        }
        if self.max_queue == 0 {
            return Err(format!("{name}: max_queue must be > 0"));
        }
        if self.queue_wait.is_zero() {
            return Err(format!("{name}: queue_wait must be > 0"));
        }
        if self.deadline.is_zero() {
            return Err(format!("{name}: deadline must be > 0"));
        }
        if self.deadline <= self.queue_wait {
            return Err(format!("{name}: deadline must exceed queue_wait"));
        }
        if self.deadline >= MAX_DEADLINE {
            return Err(format!("{name}: deadline must be below 10 s"));
        }
        Ok(())
    }
}

impl Budgets {
    pub fn validate(&self) -> Result<(), String> {
        self.bridge_progress.validate("bridge_progress")?;
        self.claim_proof.validate("claim_proof")?;
        self.interactive.validate("interactive")?;
        self.background.validate("background")
    }
}

fn lane_budget(concurrency: usize, max_queue: usize, wait_ms: u64, deadline_ms: u64) -> LaneBudget {
    LaneBudget {
        concurrency,
        max_queue,
        queue_wait: Duration::from_millis(wait_ms),
        deadline: Duration::from_millis(deadline_ms),
    }
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            bridge_progress: lane_budget(8, 64, 1000, 2000),
            claim_proof: lane_budget(4, 64, 1000, 3000),
            interactive: lane_budget(16, 256, 500, 2000),
            background: lane_budget(2, 16, 2000, 5000),
        }
    }
}

struct LaneState {
    budget: LaneBudget,
    semaphore: Arc<Semaphore>,
    queued: AtomicUsize,
}

pub struct Admission {
    lanes: [LaneState; 4],
}

/// Holds one concurrency slot of a lane until dropped.
#[derive(Debug)]
pub struct Permit {
    _permit: OwnedSemaphorePermit,
}

/// Releases a queue slot when dropped, including when the `enter` future is
/// cancelled while waiting.
struct QueueSlot<'a>(&'a AtomicUsize);

impl Drop for QueueSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn index(lane: &Lane) -> usize {
    match lane {
        Lane::BridgeProgress => 0,
        Lane::ClaimProof => 1,
        Lane::Interactive => 2,
        Lane::Background => 3,
    }
}

impl Admission {
    pub fn new(budgets: &Budgets) -> Admission {
        let state = |b: &LaneBudget| LaneState {
            budget: b.clone(),
            semaphore: Arc::new(Semaphore::new(b.concurrency)),
            queued: AtomicUsize::new(0),
        };
        Admission {
            lanes: [
                state(&budgets.bridge_progress),
                state(&budgets.claim_proof),
                state(&budgets.interactive),
                state(&budgets.background),
            ],
        }
    }

    pub fn budget(&self, lane: Lane) -> &LaneBudget {
        &self.lanes[index(&lane)].budget
    }

    pub fn queue_len(&self, lane: Lane) -> usize {
        self.lanes[index(&lane)].queued.load(Ordering::Acquire)
    }

    pub fn in_flight(&self, lane: Lane) -> usize {
        let l = &self.lanes[index(&lane)];
        l.budget.concurrency - l.semaphore.available_permits()
    }

    /// Takes a concurrency slot of `lane`, queueing for at most the lane's
    /// `queue_wait` and at most `max_queue` waiters. A full queue or an
    /// expired wait is `Overloaded`.
    pub async fn enter(&self, lane: Lane) -> Result<Permit, ErrorCode> {
        let l = &self.lanes[index(&lane)];
        // Fast path: a free slot never counts as queued.
        if let Ok(permit) = l.semaphore.clone().try_acquire_owned() {
            return Ok(Permit { _permit: permit });
        }
        let prev = l.queued.fetch_add(1, Ordering::AcqRel);
        let _slot = QueueSlot(&l.queued);
        if prev >= l.budget.max_queue {
            return Err(ErrorCode::Overloaded);
        }
        match tokio::time::timeout(l.budget.queue_wait, l.semaphore.clone().acquire_owned()).await
        {
            Ok(Ok(permit)) => Ok(Permit { _permit: permit }),
            _ => Err(ErrorCode::Overloaded),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Budgets {
        let b = |c, q| lane_budget(c, q, 500, 2000);
        Budgets {
            bridge_progress: b(1, 1),
            claim_proof: b(1, 1),
            interactive: b(2, 2),
            background: b(1, 1),
        }
    }

    #[test]
    fn budgets_default_matches_the_table_and_validates() {
        let d = Budgets::default();
        assert_eq!(d.validate(), Ok(()));
        assert_eq!(d.bridge_progress, lane_budget(8, 64, 1000, 2000));
        assert_eq!(d.claim_proof, lane_budget(4, 64, 1000, 3000));
        assert_eq!(d.interactive, lane_budget(16, 256, 500, 2000));
        assert_eq!(d.background, lane_budget(2, 16, 2000, 5000));
    }

    #[test]
    fn invalid_budgets_are_refused() {
        let mut b = Budgets::default();
        b.claim_proof.concurrency = 0;
        assert!(b.validate().is_err());
        let mut b = Budgets::default();
        b.interactive.max_queue = 0;
        assert!(b.validate().is_err());
        let mut b = Budgets::default();
        b.background.deadline = b.background.queue_wait;
        assert!(b.validate().is_err());
        let mut b = Budgets::default();
        b.bridge_progress.deadline = Duration::from_secs(10);
        assert!(b.validate().is_err());
        let mut b = Budgets::default();
        b.bridge_progress.queue_wait = Duration::ZERO;
        assert!(b.validate().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_lane_sheds_with_overloaded_and_other_lanes_still_enter() {
        let a = Arc::new(Admission::new(&small()));
        let p1 = a.enter(Lane::Interactive).await.unwrap();
        let p2 = a.enter(Lane::Interactive).await.unwrap();
        let mut waiters = Vec::new();
        for _ in 0..2 {
            let a = a.clone();
            waiters.push(tokio::spawn(async move { a.enter(Lane::Interactive).await.is_ok() }));
        }
        tokio::task::yield_now().await;
        assert_eq!(a.queue_len(Lane::Interactive), 2);
        let start = tokio::time::Instant::now();
        assert_eq!(a.enter(Lane::Interactive).await.err(), Some(ErrorCode::Overloaded));
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(a.enter(Lane::BridgeProgress).await.is_ok());
        drop((p1, p2));
        for w in waiters {
            assert!(w.await.unwrap());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn queue_wait_expiry_is_overloaded() {
        let a = Admission::new(&small());
        let _p = a.enter(Lane::Background).await.unwrap();
        let start = tokio::time::Instant::now();
        assert_eq!(a.enter(Lane::Background).await.err(), Some(ErrorCode::Overloaded));
        assert_eq!(start.elapsed(), Duration::from_millis(500));
        assert_eq!(a.queue_len(Lane::Background), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_queued_request_releases_its_slot() {
        let a = Admission::new(&small());
        let _p = a.enter(Lane::Background).await.unwrap();
        {
            let mut fut = Box::pin(a.enter(Lane::Background));
            assert!(futures_poll_once(&mut fut).await);
            assert_eq!(a.queue_len(Lane::Background), 1);
        }
        assert_eq!(a.queue_len(Lane::Background), 0);
        // The single queue slot is usable again: a new waiter queues rather than shedding.
        let mut fut = Box::pin(a.enter(Lane::Background));
        assert!(futures_poll_once(&mut fut).await);
        assert_eq!(a.queue_len(Lane::Background), 1);
    }

    /// Polls once; true if still pending.
    async fn futures_poll_once<F: std::future::Future + Unpin>(f: &mut F) -> bool {
        std::future::poll_fn(|cx| std::task::Poll::Ready(std::pin::Pin::new(&mut *f).poll(cx).is_pending())).await
    }

    #[tokio::test]
    async fn dropping_a_permit_frees_concurrency() {
        let a = Admission::new(&small());
        let p = a.enter(Lane::ClaimProof).await.unwrap();
        assert_eq!(a.in_flight(Lane::ClaimProof), 1);
        drop(p);
        assert_eq!(a.in_flight(Lane::ClaimProof), 0);
        assert!(a.enter(Lane::ClaimProof).await.is_ok());
    }
}
