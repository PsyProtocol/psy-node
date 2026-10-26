//! Thread pools for proving several jobs at once.
//!
//! A proof parallelises itself with rayon. When several jobs share rayon's
//! one global pool, their tasks interleave on every thread and each proof
//! costs more CPU than it does alone. Here a job that starts while nothing
//! else is being proved still runs in the global pool, with every thread, so
//! a worker with little to do proves each job as fast as before; a job that
//! starts while others are running takes a narrow pool of its own, so a busy
//! worker settles into narrow pools side by side.
//!
//! A job keeps the pool it started in. One that started beside others stays
//! in its narrow pool after they finish, and the pools together have more
//! threads than the machine has CPUs. A narrow pool is therefore half of all
//! threads by default, not an equal share. Measured on a 24-thread box with
//! captured production jobs, bursts run back to back: a proof on 12 threads
//! took about 7% longer than on 24 and on 8 about 25% longer; with equal
//! shares a burst of two jobs at a batch size of four finished 22% later
//! than in one shared pool; with half, bursts of 2, 3, 6 and 14 jobs finished
//! as fast or up to 8% sooner, and a full queue gave 8 to 14% more proofs per
//! second, than the shared pool. Several busy worker processes on one host,
//! smaller hosts and bursts after an idle gap were not measured.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use rayon::{ThreadPool, ThreadPoolBuilder};

pub struct ProvingPools {
    narrow: Vec<ThreadPool>,
    narrow_threads: usize,
    free_narrow: Mutex<Vec<usize>>,
    active: AtomicUsize,
}

/// Threads rayon gives its global pool: `RAYON_NUM_THREADS` when set, otherwise one per CPU.
pub fn default_total_threads() -> usize {
    std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
}

impl ProvingPools {
    /// Pools for up to `jobs` concurrent proofs beside a global pool of
    /// `total_threads` threads. A narrow pool has `narrow_threads` threads,
    /// or half of `total_threads` when that is `None`.
    pub fn new(total_threads: usize, jobs: usize, narrow_threads: Option<usize>) -> anyhow::Result<Self> {
        let total_threads = total_threads.max(1);
        let jobs = jobs.max(1);
        let narrow_threads = narrow_threads.unwrap_or(total_threads / 2).clamp(1, total_threads);
        // With one job at a time, or narrow pools as wide as the global one, every job runs in the global pool.
        let narrow_count = if jobs == 1 || narrow_threads == total_threads { 0 } else { jobs };
        let narrow = (0..narrow_count)
            .map(|pool| Ok(ThreadPoolBuilder::new().num_threads(narrow_threads).thread_name(move |i| format!("prove-narrow{}-{}", pool, i)).build()?))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self { free_narrow: Mutex::new((0..narrow.len()).rev().collect()), narrow, narrow_threads, active: AtomicUsize::new(0) })
    }

    /// Threads of each narrow pool.
    pub fn narrow_threads(&self) -> usize {
        self.narrow_threads
    }

    /// Runs `job` and returns its result. Rayon work started by `job` runs in
    /// the global pool when no other job is running, otherwise in a narrow
    /// pool of its own; the calling thread waits either way.
    pub fn run<R: Send>(&self, job: impl FnOnce() -> R + Send) -> R {
        let active = Active::enter(&self.active);
        let narrow = if active.alone { None } else { NarrowLease::take(self) };
        match &narrow {
            Some(lease) => self.narrow[lease.index].install(job),
            // Alone, or more callers than narrow pools: the global pool.
            None => job(),
        }
    }
}

/// Counts a running job for as long as it lives, also when the job panics.
struct Active<'a> {
    counter: &'a AtomicUsize,
    alone: bool,
}

impl<'a> Active<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        let alone = counter.fetch_add(1, Ordering::SeqCst) == 0;
        Active { counter, alone }
    }
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A narrow pool held by one job and returned when it ends, also when the job panics.
struct NarrowLease<'a> {
    pools: &'a ProvingPools,
    index: usize,
}

impl<'a> NarrowLease<'a> {
    fn take(pools: &'a ProvingPools) -> Option<Self> {
        let index = pools.free_narrow.lock().unwrap_or_else(|e| e.into_inner()).pop()?;
        Some(NarrowLease { pools, index })
    }
}

impl Drop for NarrowLease<'_> {
    fn drop(&mut self) {
        self.pools.free_narrow.lock().unwrap_or_else(|e| e.into_inner()).push(self.index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;
    use std::sync::{mpsc, Arc, Barrier};

    /// The pool rayon work started from here runs in: its size and the name
    /// of one of its threads (the global pool's threads have no name).
    fn where_rayon_runs() -> (usize, String) {
        rayon::join(|| (rayon::current_num_threads(), std::thread::current().name().unwrap_or("").to_string()), || ()).0
    }

    /// Holds one job open in `pools` until the returned sender is dropped.
    fn hold_a_job(pools: &Arc<ProvingPools>) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let started = Arc::new(Barrier::new(2));
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = {
            let (pools, started) = (pools.clone(), started.clone());
            std::thread::spawn(move || {
                pools.run(move || {
                    started.wait();
                    let _ = release_rx.recv();
                })
            })
        };
        started.wait();
        (release_tx, holder)
    }

    #[test]
    fn a_job_alone_runs_in_the_global_pool() {
        let pools = ProvingPools::new(8, 4, None).unwrap();
        assert_eq!(pools.narrow_threads(), 4);
        for _ in 0..3 {
            let (threads, name) = pools.run(where_rayon_runs);
            assert_eq!(threads, rayon::current_num_threads());
            assert!(!name.starts_with("prove-"), "{}", name);
        }
    }

    #[test]
    fn jobs_that_start_while_others_run_take_narrow_pools() {
        let pools = Arc::new(ProvingPools::new(8, 3, None).unwrap());
        assert_eq!(pools.narrow_threads(), 4);
        // Five jobs overlap: the first is alone, three fill the narrow pools, one is left over.
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let mut handles = Vec::new();
        for _ in 0..5 {
            let (job_pools, entered_tx, release_rx) = (pools.clone(), entered_tx.clone(), release_rx.clone());
            handles.push(std::thread::spawn(move || {
                job_pools.run(move || {
                    let name = std::thread::current().name().unwrap_or("").to_string();
                    entered_tx.send(()).unwrap();
                    let _ = release_rx.lock().unwrap().recv();
                    name
                })
            }));
            // The next job starts only once this one is running in its pool.
            entered_rx.recv().unwrap();
        }
        assert_eq!(pools.active.load(Ordering::SeqCst), 5);
        drop(release_tx);
        let names: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // The first job and the one beyond the narrow pools stay out of them.
        let in_narrow = |name: &String| name.starts_with("prove-narrow");
        assert_eq!(names.iter().map(in_narrow).collect::<Vec<_>>(), vec![false, true, true, true, false], "{:?}", names);
        let mut narrow_pools: Vec<&str> = names.iter().filter(|n| in_narrow(n)).map(|n| n.rsplit_once('-').unwrap().0).collect();
        narrow_pools.sort();
        narrow_pools.dedup();
        assert_eq!(narrow_pools.len(), 3, "each job has a narrow pool to itself: {:?}", names);
        assert_eq!(pools.active.load(Ordering::SeqCst), 0);
        assert_eq!(pools.free_narrow.lock().unwrap().len(), 3);
        // Once the worker is idle again, the next job is alone.
        assert!(!pools.run(where_rayon_runs).1.starts_with("prove-"));
    }

    #[test]
    fn rayon_work_inside_a_job_stays_in_its_pool() {
        let pools = Arc::new(ProvingPools::new(6, 3, None).unwrap());
        let (release, holder) = hold_a_job(&pools);
        let names: Vec<String> = pools.run(|| (0..64).into_par_iter().map(|_| std::thread::current().name().unwrap_or("").to_string()).collect());
        let threads = pools.run(|| rayon::current_num_threads());
        drop(release);
        holder.join().unwrap();
        let pool_of = |name: &str| name.rsplit_once('-').map(|(pool, _)| pool.to_string()).unwrap_or_default();
        let first = pool_of(&names[0]);
        assert!(first.starts_with("prove-narrow"), "{}", first);
        assert!(names.iter().all(|n| pool_of(n) == first), "parallel work left its pool: {:?}", names);
        assert_eq!(threads, 3);
    }

    #[test]
    fn a_panicking_job_gives_its_pool_back() {
        let pools = Arc::new(ProvingPools::new(4, 2, None).unwrap());
        let (release, holder) = hold_a_job(&pools);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pools.run(|| panic!("a proof failed badly"))));
        assert!(panicked.is_err());
        assert_eq!(pools.active.load(Ordering::SeqCst), 1);
        assert_eq!(pools.free_narrow.lock().unwrap().len(), 2);
        drop(release);
        holder.join().unwrap();
        assert_eq!(pools.active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn one_job_at_a_time_needs_no_narrow_pools() {
        let pools = ProvingPools::new(8, 1, None).unwrap();
        assert!(pools.narrow.is_empty());
        assert!(!pools.run(where_rayon_runs).1.starts_with("prove-"));
        let explicit = ProvingPools::new(8, 4, Some(3)).unwrap();
        assert_eq!((explicit.narrow.len(), explicit.narrow_threads()), (4, 3));
        let clamped = ProvingPools::new(1, 8, None).unwrap();
        assert!(clamped.narrow.is_empty());
        assert_eq!(ProvingPools::new(3, 8, None).unwrap().narrow_threads(), 1);
        let as_wide = ProvingPools::new(8, 4, Some(8)).unwrap();
        assert!(as_wide.narrow.is_empty());
    }
}
