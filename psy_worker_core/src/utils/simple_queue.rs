use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::Notify;

#[async_trait]
pub trait SimpleAsyncBytesQueue {
    async fn enqueue_job(&self, job_id: [u8; 24], job: Vec<u8>) -> anyhow::Result<()>;
    async fn dequeue_job(&self) -> anyhow::Result<Option<([u8; 24], Vec<u8>)>>;
    async fn report_job_complete(&self, job_id: [u8; 24]) -> anyhow::Result<()>;
    async fn wait_until_empty_and_all_jobs_complete(&self) -> anyhow::Result<()>;
}

pub struct CompletionAsyncBytesQueue {
    // We group state to minimize lock contention and ensure consistency.
    state: Mutex<QueueState>,
    // Signals when `pending_count` reaches 0.
    completion_notify: Notify,
}

struct QueueState {
    queue: VecDeque<([u8; 24], Vec<u8>)>,
    // Counts (Jobs Enqueued - Jobs Reported Complete).
    // This represents items in the queue PLUS items currently being processed by workers.
    pending_count: usize,
}

impl CompletionAsyncBytesQueue {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(QueueState {
                queue: VecDeque::new(),
                pending_count: 0,
            }),
            completion_notify: Notify::new(),
        }
    }
}

impl Default for CompletionAsyncBytesQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SimpleAsyncBytesQueue for CompletionAsyncBytesQueue {
    async fn enqueue_job(&self, job_id: [u8; 24], job: Vec<u8>) -> anyhow::Result<()> {
        let mut guard = self.state.lock().map_err(|_| anyhow::anyhow!("Mutex poisoned"))?;
        
        guard.queue.push_back((job_id, job));
        guard.pending_count += 1;
        
        Ok(())
    }

    async fn dequeue_job(&self) -> anyhow::Result<Option<([u8; 24], Vec<u8>)>> {
        let mut guard = self.state.lock().map_err(|_| anyhow::anyhow!("Mutex poisoned"))?;
        
        // We pop the job, but we do NOT decrement pending_count yet.
        // The job is now considered "in-flight".
        let job = guard.queue.pop_front();
        
        Ok(job)
    }

    async fn report_job_complete(&self, _job_id: [u8; 24]) -> anyhow::Result<()> {
        let mut guard = self.state.lock().map_err(|_| anyhow::anyhow!("Mutex poisoned"))?;

        if guard.pending_count == 0 {
            return Err(anyhow::anyhow!("Job reported complete, but pending count is zero. Logic error in worker."));
        }

        guard.pending_count -= 1;

        // If this was the last active job, wake up the waiters.
        if guard.pending_count == 0 {
            // Optimizing: We don't need to check queue.is_empty(), because 
            // if pending_count is 0, the queue MUST be empty.
            self.completion_notify.notify_waiters();
        }

        Ok(())
    }

    async fn wait_until_empty_and_all_jobs_complete(&self) -> anyhow::Result<()> {
        loop {
            // CRITICAL: Register interest before checking state to avoid race conditions.
            let notified = self.completion_notify.notified();

            {
                let guard = self.state.lock().map_err(|_| anyhow::anyhow!("Mutex poisoned"))?;
                if guard.pending_count == 0 {
                    return Ok(());
                }
            }

            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    fn create_queue() -> Arc<CompletionAsyncBytesQueue> {
        Arc::new(CompletionAsyncBytesQueue::new())
    }

    fn mock_id(i: u8) -> [u8; 24] {
        let mut id = [0u8; 24];
        id[0] = i;
        id
    }

    #[tokio::test]
    async fn test_lifecycle_completion() -> anyhow::Result<()> {
        let queue = create_queue();
        let id = mock_id(1);

        // 1. Enqueue
        queue.enqueue_job(id, vec![1, 2, 3]).await?;

        // 2. Start a waiter in background
        let q_wait = queue.clone();
        let waiter_handle = tokio::spawn(async move {
            q_wait.wait_until_empty_and_all_jobs_complete().await.unwrap();
        });

        // 3. Dequeue
        let result = queue.dequeue_job().await?;
        assert!(result.is_some());
        let (out_id, _data) = result.unwrap();
        assert_eq!(out_id, id);

        // At this point, queue is empty (VecDeque size 0), 
        // but the job is "In Flight" (pending_count 1).
        // The waiter should still be blocked.
        
        // Small sleep to ensure waiter didn't accidentally finish
        sleep(Duration::from_millis(20)).await;
        assert!(!waiter_handle.is_finished());

        // 4. Report Complete
        queue.report_job_complete(id).await?;

        // 5. Waiter should now finish immediately
        timeout(Duration::from_millis(100), waiter_handle).await??;

        Ok(())
    }

    #[tokio::test]
    async fn test_batch_processing_concurrency() -> anyhow::Result<()> {
        let queue = create_queue();
        let worker_count = 5;
        let jobs_per_producer = 100;
        let producer_count = 2;

        // Spawn Consumers (Workers)
        let mut workers = vec![];
        for _ in 0..worker_count {
            let q = queue.clone();
            workers.push(tokio::spawn(async move {
                loop {
                    match q.dequeue_job().await {
                        Ok(Some((id, _data))) => {
                            // Simulate work
                            // tokio::task::yield_now().await; 
                            
                            // Report complete
                            q.report_job_complete(id).await.expect("Report failed");
                        }
                        Ok(None) => {
                            // Simple backoff for test purposes logic to wait for more work
                            // In a real app, you might use a signal to shutdown workers, 
                            // but here we just yield and check if test is done via timeout later
                            sleep(Duration::from_millis(10)).await;
                        }
                        Err(_) => break,
                    }
                }
            }));
        }

        // Spawn Producers
        for p in 0..producer_count {
            let q = queue.clone();
            tokio::spawn(async move {
                for i in 0..jobs_per_producer {
                    q.enqueue_job(mock_id((p * 10 + i) as u8), vec![0]).await.unwrap();
                }
            });
        }

        // Main thread waits for EVERYTHING to be done
        // We use a timeout to ensure the test fails if logic is wrong
        timeout(Duration::from_secs(5), queue.wait_until_empty_and_all_jobs_complete()).await??;

        // Validation: Internal state should be zero
        let state = queue.state.lock().unwrap();
        assert_eq!(state.pending_count, 0);
        assert!(state.queue.is_empty());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_wait_returns_immediately_if_nothing_queued() -> anyhow::Result<()> {
        let queue = create_queue();
        timeout(Duration::from_millis(50), queue.wait_until_empty_and_all_jobs_complete()).await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_report_error_on_underflow() -> anyhow::Result<()> {
        let queue = create_queue();
        // No jobs enqueued
        let result = queue.report_job_complete(mock_id(1)).await;
        assert!(result.is_err());
        Ok(())
    }
}