use std::time::Duration;

use psy_client_common::data::qhashout::QHashOut;

use crate::session::WalletSession;

use super::faucet::{PsyFaucetOperator, F};

pub(super) const OPERATOR_ADD_PASSES: usize = 4;
pub(super) const OPERATOR_ADD_RETRY_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub(super) struct OperatorKey {
    pub(super) user_id: u64,
    pub(super) private_key: QHashOut<F>,
    pub(super) fingerprint: QHashOut<F>,
    pub(super) expected_public_key: QHashOut<F>,
}

pub(super) trait OperatorSession {
    async fn add_operator(&mut self, key: &OperatorKey) -> anyhow::Result<QHashOut<F>>;
}

impl OperatorSession for WalletSession {
    async fn add_operator(&mut self, key: &OperatorKey) -> anyhow::Result<QHashOut<F>> {
        self.add_user_with_user_id(key.private_key, key.fingerprint, key.user_id).await
    }
}

// Adding an operator reads its user tree proof at the Coordinator's latest
// checkpoint, which a Realm Edge may not serve yet. Failed operators are
// retried in later passes against a newer checkpoint; operators that never
// succeed are left out so one unreadable Realm cannot keep the faucet down.
pub(super) async fn add_operators(
    session: &mut impl OperatorSession,
    keys: Vec<OperatorKey>,
    passes: usize,
    retry_delay: Duration,
) -> anyhow::Result<Vec<PsyFaucetOperator>> {
    let mut added = Vec::with_capacity(keys.len());
    let mut pending: Vec<(usize, OperatorKey)> = keys.into_iter().enumerate().collect();
    let mut last_error = None;
    for pass in 1..=passes {
        if pass > 1 {
            tokio::time::sleep(retry_delay).await;
        }
        let mut failed = Vec::new();
        for (position, key) in pending {
            match session.add_operator(&key).await {
                Ok(public_key) => {
                    anyhow::ensure!(
                        public_key == key.expected_public_key,
                        "faucet operator {} public key mismatch: config {}, generated {}",
                        key.user_id,
                        key.expected_public_key,
                        public_key
                    );
                    added.push((position, PsyFaucetOperator { user_id: key.user_id, public_key }));
                }
                Err(error) => {
                    tracing::warn!(operator_user_id = key.user_id, pass, passes, error = format!("{error:#}"), "faucet operator add failed");
                    last_error = Some(error);
                    failed.push((position, key));
                }
            }
        }
        pending = failed;
        if pending.is_empty() {
            break;
        }
    }
    if !pending.is_empty() {
        let skipped_user_ids: Vec<u64> = pending.iter().map(|(_, key)| key.user_id).collect();
        tracing::warn!(?skipped_user_ids, "faucet starts without operators that could not be added; restart to retry them");
    }
    if added.is_empty() {
        let cause = last_error.map(|error| format!("{error:#}")).unwrap_or_default();
        anyhow::bail!("no faucet operator could be added after {passes} passes; last error: {cause}");
    }
    added.sort_by_key(|(position, _)| *position);
    Ok(added.into_iter().map(|(_, operator)| operator).collect())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct ScriptedSession {
        failures_left: HashMap<u64, usize>,
        calls: Vec<u64>,
        wrong_key_user_id: Option<u64>,
    }

    impl OperatorSession for ScriptedSession {
        async fn add_operator(&mut self, key: &OperatorKey) -> anyhow::Result<QHashOut<F>> {
            self.calls.push(key.user_id);
            let left = self.failures_left.entry(key.user_id).or_insert(0);
            if *left > 0 {
                *left -= 1;
                anyhow::bail!("User tree proof not found for checkpoint_id 51636");
            }
            if self.wrong_key_user_id == Some(key.user_id) {
                return Ok(public_key(999));
            }
            Ok(key.expected_public_key)
        }
    }

    fn public_key(seed: u64) -> QHashOut<F> {
        QHashOut::from_values(seed, seed + 1, seed + 2, seed + 3)
    }

    fn key(user_id: u64) -> OperatorKey {
        OperatorKey {
            user_id,
            private_key: public_key(user_id + 100),
            fingerprint: public_key(7),
            expected_public_key: public_key(user_id),
        }
    }

    fn session(failures: &[(u64, usize)]) -> ScriptedSession {
        ScriptedSession { failures_left: failures.iter().copied().collect(), calls: Vec::new(), wrong_key_user_id: None }
    }

    const RETRY_DELAY: Duration = Duration::from_millis(20);

    fn user_ids(added: &[PsyFaucetOperator]) -> Vec<u64> {
        added.iter().map(|operator| operator.user_id).collect()
    }

    #[tokio::test]
    async fn transient_failure_is_retried_in_a_later_pass_and_order_is_kept() {
        let mut session = session(&[(2, 2)]);
        let added = add_operators(&mut session, vec![key(1), key(2), key(3)], 4, RETRY_DELAY).await.unwrap();
        assert_eq!(user_ids(&added), vec![1, 2, 3]);
        assert_eq!(session.calls, vec![1, 2, 3, 2, 2]);
        assert_eq!(added[1].public_key, public_key(2));
    }

    #[tokio::test]
    async fn operator_failing_every_pass_is_skipped() {
        let mut session = session(&[(2, usize::MAX)]);
        let added = add_operators(&mut session, vec![key(1), key(2), key(3)], 4, RETRY_DELAY).await.unwrap();
        assert_eq!(user_ids(&added), vec![1, 3]);
        assert_eq!(session.calls.iter().filter(|user_id| **user_id == 2).count(), 4);
    }

    #[tokio::test]
    async fn startup_fails_when_no_operator_can_be_added() {
        let mut session = session(&[(1, usize::MAX), (2, usize::MAX)]);
        let error = add_operators(&mut session, vec![key(1), key(2)], 3, RETRY_DELAY).await.unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no faucet operator could be added after 3 passes"), "{message}");
        assert!(message.contains("User tree proof not found for checkpoint_id 51636"), "{message}");
        assert_eq!(session.calls.len(), 6);
    }

    #[tokio::test]
    async fn public_key_mismatch_fails_startup_without_retry() {
        let mut session = session(&[]);
        session.wrong_key_user_id = Some(2);
        let error = add_operators(&mut session, vec![key(1), key(2), key(3)], 4, RETRY_DELAY).await.unwrap_err();
        assert!(error.to_string().contains("faucet operator 2 public key mismatch"));
        assert_eq!(session.calls, vec![1, 2]);
    }

    #[tokio::test]
    async fn passes_wait_for_the_retry_delay() {
        let mut session = session(&[(1, 1)]);
        let started = std::time::Instant::now();
        add_operators(&mut session, vec![key(1)], 4, RETRY_DELAY).await.unwrap();
        assert!(started.elapsed() >= RETRY_DELAY);
        assert_eq!(session.calls, vec![1, 1]);
    }
}
