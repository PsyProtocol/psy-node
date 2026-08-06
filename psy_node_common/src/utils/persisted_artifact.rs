use std::{future::Future, time::Duration};

use tokio::time::{sleep, Instant};

pub async fn wait_for_persisted_artifact<T, Load, LoadFuture>(
    artifact_name: &str,
    timeout_ms: u64,
    poll_interval: Duration,
    mut load: Load,
) -> anyhow::Result<T>
where
    Load: FnMut() -> LoadFuture,
    LoadFuture: Future<Output = anyhow::Result<Option<T>>>,
{
    let started_at = Instant::now();
    let deadline = (timeout_ms != u64::MAX)
        .then(|| started_at + Duration::from_millis(timeout_ms));

    loop {
        if let Some(artifact) = load().await? {
            tracing::info!(
                artifact_name,
                proof_store_ready = true,
                elapsed_ms = started_at.elapsed().as_millis(),
                "Persisted worker artifact ready"
            );
            return Ok(artifact);
        }

        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            tracing::error!(
                artifact_name,
                proof_store_ready = false,
                elapsed_ms = started_at.elapsed().as_millis(),
                "Timed out waiting for persisted worker artifact; processor recovery required"
            );
            anyhow::bail!(
                "Timed out after {}ms waiting for persisted worker artifact {}",
                timeout_ms,
                artifact_name,
            );
        }

        sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };

    use super::wait_for_persisted_artifact;

    #[tokio::test]
    async fn delayed_artifact_is_waited_for() {
        let ready = Arc::new(AtomicBool::new(false));
        let writer_ready = Arc::clone(&ready);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            writer_ready.store(true, Ordering::Release);
        });

        let artifact = wait_for_persisted_artifact(
            "realm root proof",
            500,
            Duration::from_millis(5),
            || {
                let ready = Arc::clone(&ready);
                async move {
                    Ok(ready
                        .load(Ordering::Acquire)
                        .then(|| vec![1_u8, 2, 3]))
                }
            },
        )
        .await
        .expect("delayed proof should become visible before the deadline");

        assert_eq!(artifact, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn missing_artifact_times_out() {
        let error = wait_for_persisted_artifact::<Vec<u8>, _, _>(
            "realm root proof",
            25,
            Duration::from_millis(5),
            || async { Ok(None) },
        )
        .await
        .expect_err("a proof that is never persisted must time out");

        assert!(error.to_string().contains("realm root proof"));
    }
}
