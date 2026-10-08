use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

// An operator's End Cap is accepted by the edge before it is included. Until
// it is included the chain still shows the operator's old leaf, so a claim that
// starts then proves from that leaf and is rejected as stale once the earlier
// End Cap lands. The pool therefore keeps an operator out of rotation from its
// submission until the settle loop sees the submitted leaf on chain, or until
// `settle_timeout` passes (the End Cap was dropped and the old leaf is current).
#[derive(Debug)]
pub(super) struct OperatorPool<H> {
    slots: Mutex<Vec<Slot<H>>>,
    settle_timeout: Duration,
}

#[derive(Debug)]
struct Slot<H> {
    busy: bool,
    pending: Option<Pending<H>>,
    last_used: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pending<H> {
    pub end_user_leaf_hash: H,
    pub submitted_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Unavailable {
    // Every operator is proving a claim right now.
    AllBusy,
    // At least one operator is idle but waiting for its End Cap to land.
    Settling,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Settle {
    Included,
    TimedOut,
}

impl<H: Copy + PartialEq> OperatorPool<H> {
    pub(super) fn new(operator_count: usize, settle_timeout: Duration) -> Self {
        let slots = (0..operator_count)
            .map(|_| Slot {
                busy: false,
                pending: None,
                last_used: None,
            })
            .collect();
        Self {
            slots: Mutex::new(slots),
            settle_timeout,
        }
    }

    // Takes the idle, settled operator that was used least recently, so load
    // spreads over the whole pool instead of following recipient ids.
    pub(super) fn try_acquire(&self, exclude: &[usize]) -> Result<Lease<'_, H>, Unavailable> {
        let mut slots = self.slots.lock().unwrap();
        let mut settling = false;
        let mut best: Option<usize> = None;
        for (index, slot) in slots.iter().enumerate() {
            if slot.busy || exclude.contains(&index) {
                continue;
            }
            if slot.pending.is_some() {
                settling = true;
                continue;
            }
            if best.map_or(true, |b| slot.last_used < slots[b].last_used) {
                best = Some(index);
            }
        }
        match best {
            Some(index) => {
                slots[index].busy = true;
                Ok(Lease {
                    pool: self,
                    index,
                    pending: None,
                })
            }
            None if settling => Err(Unavailable::Settling),
            None => Err(Unavailable::AllBusy),
        }
    }

    pub(super) fn pending(&self) -> Vec<(usize, Pending<H>)> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.pending.map(|pending| (index, pending)))
            .collect()
    }

    // `on_chain` is the operator's current leaf hash, if it could be read.
    // Returns None while the operator must stay out of rotation.
    pub(super) fn settle(&self, index: usize, expected: Pending<H>, on_chain: Option<H>, now: Instant) -> Option<Settle> {
        let mut slots = self.slots.lock().unwrap();
        let slot = &mut slots[index];
        // A newer submission replaced the one this check was made for.
        if slot.pending != Some(expected) {
            return None;
        }
        let outcome = if on_chain == Some(expected.end_user_leaf_hash) {
            Settle::Included
        } else if now.duration_since(expected.submitted_at) >= self.settle_timeout {
            Settle::TimedOut
        } else {
            return None;
        };
        slot.pending = None;
        Some(outcome)
    }

    fn release(&self, index: usize, pending: Option<H>) {
        let mut slots = self.slots.lock().unwrap();
        let slot = &mut slots[index];
        let now = Instant::now();
        slot.busy = false;
        slot.last_used = Some(now);
        if let Some(end_user_leaf_hash) = pending {
            slot.pending = Some(Pending {
                end_user_leaf_hash,
                submitted_at: now,
            });
        }
    }
}

// Releases the operator on drop, so cancellation and panics cannot leak it.
#[derive(Debug)]
pub(super) struct Lease<'a, H: Copy + PartialEq> {
    pool: &'a OperatorPool<H>,
    index: usize,
    pending: Option<H>,
}

impl<H: Copy + PartialEq> Lease<'_, H> {
    pub(super) fn index(&self) -> usize {
        self.index
    }

    // Call once an End Cap may have reached the edge: the operator then stays
    // out of rotation until that leaf is on chain or the settle timeout passes.
    pub(super) fn mark_submitted(&mut self, end_user_leaf_hash: H) {
        self.pending = Some(end_user_leaf_hash);
    }
}

impl<H: Copy + PartialEq> Drop for Lease<'_, H> {
    fn drop(&mut self) {
        self.pool.release(self.index, self.pending);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(60);

    #[test]
    fn busy_operators_are_skipped_and_released_on_drop() {
        let pool = OperatorPool::<u64>::new(2, TIMEOUT);
        let a = pool.try_acquire(&[]).unwrap();
        let b = pool.try_acquire(&[]).unwrap();
        assert_ne!(a.index(), b.index());
        assert_eq!(pool.try_acquire(&[]).unwrap_err(), Unavailable::AllBusy);
        drop(a);
        assert!(pool.try_acquire(&[]).is_ok());
    }

    #[test]
    fn least_recently_used_operator_is_chosen() {
        let pool = OperatorPool::<u64>::new(3, TIMEOUT);
        let first = pool.try_acquire(&[]).unwrap().index();
        let second = pool.try_acquire(&[]).unwrap().index();
        let third = pool.try_acquire(&[]).unwrap().index();
        assert_ne!(first, second);
        assert_ne!(second, third);
        assert_ne!(first, third);
        assert_eq!(pool.try_acquire(&[]).unwrap().index(), first);
    }

    #[test]
    fn submitted_operator_waits_until_its_leaf_is_on_chain() {
        let pool = OperatorPool::<u64>::new(1, TIMEOUT);
        let mut lease = pool.try_acquire(&[]).unwrap();
        lease.mark_submitted(42);
        drop(lease);
        assert_eq!(pool.try_acquire(&[]).unwrap_err(), Unavailable::Settling);

        let (index, pending) = pool.pending()[0];
        assert_eq!(pool.settle(index, pending, Some(7), Instant::now()), None);
        assert_eq!(pool.settle(index, pending, None, Instant::now()), None);
        assert_eq!(pool.try_acquire(&[]).unwrap_err(), Unavailable::Settling);

        assert_eq!(pool.settle(index, pending, Some(42), Instant::now()), Some(Settle::Included));
        assert!(pool.pending().is_empty());
        assert!(pool.try_acquire(&[]).is_ok());
    }

    #[test]
    fn dropped_end_cap_frees_operator_after_timeout() {
        let pool = OperatorPool::<u64>::new(1, TIMEOUT);
        let mut lease = pool.try_acquire(&[]).unwrap();
        lease.mark_submitted(42);
        drop(lease);
        let (index, pending) = pool.pending()[0];
        let later = pending.submitted_at + TIMEOUT;
        assert_eq!(pool.settle(index, pending, Some(7), later), Some(Settle::TimedOut));
        assert!(pool.try_acquire(&[]).is_ok());
    }

    #[test]
    fn stale_settle_check_does_not_clear_a_newer_submission() {
        let pool = OperatorPool::<u64>::new(1, TIMEOUT);
        let mut lease = pool.try_acquire(&[]).unwrap();
        lease.mark_submitted(1);
        drop(lease);
        let (index, old) = pool.pending()[0];
        let later = old.submitted_at + TIMEOUT;
        assert_eq!(pool.settle(index, old, None, later), Some(Settle::TimedOut));

        let mut lease = pool.try_acquire(&[]).unwrap();
        lease.mark_submitted(2);
        drop(lease);
        assert_eq!(pool.settle(index, old, Some(1), later), None);
        assert_eq!(pool.pending().len(), 1);
    }

    #[test]
    fn excluded_operators_are_not_retried() {
        let pool = OperatorPool::<u64>::new(2, TIMEOUT);
        let first = pool.try_acquire(&[]).unwrap();
        let index = first.index();
        drop(first);
        let other = pool.try_acquire(&[index]).unwrap();
        assert_ne!(other.index(), index);
        drop(other);
        assert_eq!(pool.try_acquire(&[0, 1]).unwrap_err(), Unavailable::AllBusy);
    }
}
