use std::future::Future;

use dashmap::DashSet;

// This guard owns the membership, never a DashMap shard lock across an await.
pub(super) struct ClaimGuard<'a> {
    locks: &'a DashSet<u64>,
    id: u64,
}

impl<'a> ClaimGuard<'a> {
    pub(super) fn acquire(locks: &'a DashSet<u64>, id: u64) -> Option<Self> {
        if locks.insert(id) {
            Some(Self { locks, id })
        } else {
            None
        }
    }
}

impl Drop for ClaimGuard<'_> {
    fn drop(&mut self) {
        self.locks.remove(&self.id);
    }
}

// Dropping the HTTP waiter detaches this task. It still awaits the blocking
// prover, records submission, and releases both guards. Do not abort or timeout
// this task: the underlying blocking prover could still submit a transaction.
pub(super) async fn complete_claim<F>(work: F) -> Result<F::Output, tokio::task::JoinError>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(work).await
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use tokio::{
        sync::oneshot,
        time::{timeout, Duration},
    };

    use super::*;

    #[test]
    fn guard_excludes_duplicates_and_releases_on_drop() {
        let locks = DashSet::new();
        let guard = ClaimGuard::acquire(&locks, 7).unwrap();
        assert!(ClaimGuard::acquire(&locks, 7).is_none());
        assert!(locks.contains(&7));
        drop(guard);
        assert!(!locks.contains(&7));
        assert!(ClaimGuard::acquire(&locks, 7).is_some());
    }

    #[tokio::test]
    async fn disconnected_caller_keeps_locks_until_submission_is_recorded() {
        let recipients = Arc::new(DashSet::new());
        let operators = Arc::new(DashSet::new());
        let recorded = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = oneshot::channel();
        let work_recipients = recipients.clone();
        let work_operators = operators.clone();
        let work_recorded = recorded.clone();
        let caller = tokio::spawn(complete_claim(async move {
            let recipient = ClaimGuard::acquire(&work_recipients, 1).unwrap();
            let operator = ClaimGuard::acquire(&work_operators, 2).unwrap();
            tokio::task::spawn_blocking(move || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            })
            .await
            .unwrap();
            work_recorded.store(true, Ordering::SeqCst);
            drop(operator);
            drop(recipient);
            finished_tx.send(()).unwrap();
        }));
        timeout(Duration::from_secs(5), started_rx).await.unwrap().unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(ClaimGuard::acquire(&recipients, 1).is_none());
        assert!(ClaimGuard::acquire(&operators, 2).is_none());
        assert!(!recorded.load(Ordering::SeqCst));
        release_tx.send(()).unwrap();
        timeout(Duration::from_secs(5), finished_rx).await.unwrap().unwrap();
        assert!(recorded.load(Ordering::SeqCst));
        assert!(recipients.is_empty());
        assert!(operators.is_empty());
    }

    #[tokio::test]
    async fn returned_error_releases_both_locks() {
        let locks = Arc::new(DashSet::new());
        let work_locks = locks.clone();
        let result = complete_claim(async move {
            let _recipient = ClaimGuard::acquire(&work_locks, 1).unwrap();
            let _operator = ClaimGuard::acquire(&work_locks, 2).unwrap();
            Err::<(), _>("submission failed")
        })
        .await
        .unwrap();
        assert_eq!(result, Err("submission failed"));
        assert!(locks.is_empty());
    }

    #[tokio::test]
    async fn task_panic_releases_both_locks() {
        let locks = Arc::new(DashSet::new());
        let work_locks = locks.clone();
        let result = complete_claim(async move {
            let _recipient = ClaimGuard::acquire(&work_locks, 1).unwrap();
            let _operator = ClaimGuard::acquire(&work_locks, 2).unwrap();
            panic!("injected task panic");
        })
        .await;
        assert!(result.unwrap_err().is_panic());
        assert!(locks.is_empty());
    }

    #[tokio::test]
    async fn blocking_prover_panic_releases_locks() {
        let locks = Arc::new(DashSet::new());
        let work_locks = locks.clone();
        let result = complete_claim(async move {
            let _recipient = ClaimGuard::acquire(&work_locks, 1).unwrap();
            let _operator = ClaimGuard::acquire(&work_locks, 2).unwrap();
            tokio::task::spawn_blocking(|| panic!("injected prover panic")).await
        })
        .await
        .unwrap();
        assert!(result.unwrap_err().is_panic());
        assert!(locks.is_empty());
    }

    #[tokio::test]
    async fn http_disconnects_do_not_exhaust_ten_operators() {
        use std::sync::atomic::AtomicUsize;

        use jsonrpsee::{server::ServerBuilder, types::ErrorObjectOwned, RpcModule};
        use tokio::{io::AsyncWriteExt, net::TcpStream, sync::Semaphore};

        struct State {
            operators: DashSet<u64>,
            submitted: DashSet<u64>,
            started: AtomicUsize,
            release: Semaphore,
        }
        let state = Arc::new(State {
            operators: DashSet::new(),
            submitted: DashSet::new(),
            started: AtomicUsize::new(0),
            release: Semaphore::new(0),
        });
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut rpc = RpcModule::new(state.clone());
        rpc.register_async_method("claim", |params, state, _| async move {
            let id: u64 = params.one()?;
            complete_claim(async move {
                let _guard = ClaimGuard::acquire(&state.operators, id).ok_or_else(|| ErrorObjectOwned::owned(1, "busy", None::<()>))?;
                state.started.fetch_add(1, Ordering::SeqCst);
                state.release.acquire().await.unwrap().forget();
                state.submitted.insert(id);
                Ok::<_, ErrorObjectOwned>("submitted")
            })
            .await
            .unwrap()
        })
        .unwrap();
        let handle = server.start(rpc);
        timeout(Duration::from_secs(5), async {
            for id in 0..10 {
                let mut stream = TcpStream::connect(address).await.unwrap();
                let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"claim","params":[{id}]}}"#);
                let request = format!(
                    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(request.as_bytes()).await.unwrap();
                while state.started.load(Ordering::SeqCst) != id + 1 {
                    tokio::task::yield_now().await;
                }
                drop(stream);
            }
            assert_eq!(state.operators.len(), 10);
            assert!(state.submitted.is_empty());
            state.release.add_permits(10);
            while !state.operators.is_empty() {
                tokio::task::yield_now().await;
            }
            assert_eq!(state.submitted.len(), 10);
        })
        .await
        .unwrap();
        handle.stop().unwrap();
        handle.stopped().await;
    }
}
