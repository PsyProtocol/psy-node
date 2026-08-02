use std::{collections::HashMap, fs, path::Path, time::Duration};

use alloy_primitives::Address;
use anyhow::Context;
use psy_provider::provider::RpcProvider;
use serde::Deserialize;

use crate::bridge::{
    claim_withdrawals,
    constants::{DEFAULT_DEPLOYMENTS_NETWORK, DEFAULT_L1_RPC_URL},
    daemon::{
        fetch_l1_last_finalized_checkpoint, resolve_bridge_address, resolve_prove_proxy_url,
        run_l2_bridge_round_with_l1_provider, submit_deposit_batch_appends_with_l1_rpc,
        BridgeProposeDaemonConfig, DaemonState, DaemonFinalizeConfig, L2RoundResult,
    },
    finalize_bridge::{self, FinalizeBridgeAggArgs},
    l1_provider::connect_l1_readonly,
    propose_withdrawals::{self, ProposeWithdrawalsArgs},
    prove_bridge::{self, BridgeProveResult},
};

#[derive(Debug, Deserialize)]
struct ProofMetadata {
    #[serde(default)]
    from_checkpoint: Option<u64>,
    to_checkpoint: u64,
    #[serde(default)]
    num_checkpoints_aggregated: Option<u64>,
    #[serde(default)]
    deposit_tree_root: String,
    withdrawal_tree_root: String,
}

const L1_RETRY_MAX_ATTEMPTS: usize = 10;
const L1_RETRY_BASE_DELAY_SECS: u64 = 1;
const L1_RETRY_MAX_DELAY_SECS: u64 = 60;

#[derive(Clone, Debug)]
pub struct L1Client {
    rpc_urls: Vec<String>,
}

impl L1Client {
    pub fn from_finalize_config(finalize: &DaemonFinalizeConfig) -> Self {
        let primary = finalize
            .l1_rpc_url
            .clone()
            .unwrap_or_else(|| DEFAULT_L1_RPC_URL.to_string());
        let mut rpc_urls = vec![primary];
        if let Some(fallback) = finalize.l1_rpc_fallback_url.as_deref() {
            let fallback = fallback.trim();
            if !fallback.is_empty() && !rpc_urls.iter().any(|url| url == fallback) {
                rpc_urls.push(fallback.to_string());
            }
        }
        Self { rpc_urls }
    }

    /// Retry an L1 operation across all configured RPC URLs.
    /// `f` is called once per URL; the first success is returned.
    pub async fn with_retry<T, F, Fut>(
        &self,
        label: &str,
        max_attempts: usize,
        f: F,
    ) -> anyhow::Result<T>
    where
        F: Fn(&str) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        if self.rpc_urls.is_empty() {
            anyhow::bail!("no L1 RPC URLs configured for {label}");
        }

        let mut last_err = None;
        for attempt in 1..=max_attempts.max(1) {
            for (index, l1_rpc_url) in self.rpc_urls.iter().enumerate() {
                match f(l1_rpc_url).await {
                    Ok(value) => {
                        if attempt > 1 || index > 0 {
                            tracing::warn!(
                                l1_rpc_url = %l1_rpc_url,
                                label = %label,
                                attempt,
                                "L1 RPC retry/fallback succeeded"
                            );
                        }
                        return Ok(value);
                    }
                    Err(err) => {
                        tracing::warn!(
                            l1_rpc_url = %l1_rpc_url,
                            label = %label,
                            attempt,
                            error = %err,
                            error_debug = ?err,
                            "L1 RPC failed"
                        );
                        last_err = Some(err);
                    }
                }
            }

            if attempt < max_attempts {
                let delay_secs = (L1_RETRY_BASE_DELAY_SECS << (attempt.saturating_sub(1).min(5)))
                    .min(L1_RETRY_MAX_DELAY_SECS);
                tracing::warn!(
                    label = %label,
                    attempt,
                    next_attempt = attempt + 1,
                    delay_secs,
                    "all L1 RPC attempts failed; backing off before retry"
                );
                tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            }
        }

        match last_err {
            Some(err) => anyhow::bail!(
                "L1 operation '{}' failed after {} attempts: {}",
                label,
                max_attempts,
                err
            ),
            None => anyhow::bail!("L1 operation '{}' failed after {} attempts", label, max_attempts),
        }
    }

    pub async fn last_finalized_checkpoint(&self, state_manager: Address) -> anyhow::Result<u64> {
        self.with_retry("last_finalized_checkpoint", L1_RETRY_MAX_ATTEMPTS, |url| {
            let owned = url.to_string();
            async move {
                let l1_provider = connect_l1_readonly(
                    owned.parse()
                        .with_context(|| format!("invalid L1 rpc url: {owned}"))?,
                )?;
                fetch_l1_last_finalized_checkpoint(&l1_provider, state_manager).await
            }
        })
        .await
    }

    pub async fn query_withdrawal_subtree_root(&self, state_manager: Address) -> anyhow::Result<String> {
        use crate::bridge::l1_provider::connect_l1_readonly;
        use alloy_primitives::Address;
        use alloy_rpc_types_eth::TransactionRequest;
        use alloy_provider::Provider;

        let selector = alloy_primitives::hex::decode("7cd34bf4").unwrap();
        let tx = TransactionRequest::default()
            .to(state_manager)
            .input(alloy_primitives::Bytes::from(selector).into());

        self.with_retry("withdrawal_subtree_root", L1_RETRY_MAX_ATTEMPTS, |url| {
            let owned = url.to_string();
            let tx = tx.clone();
            async move {
                let provider = connect_l1_readonly(
                    owned.parse()
                        .with_context(|| format!("invalid L1 rpc url: {owned}"))?,
                )?;
                let raw = provider.call(tx).await?;
                Ok(format!("0x{}", alloy_primitives::hex::encode(&raw[..32])))
            }
        })
        .await
    }

    /// Run one L2 bridge round through a writable L1 provider.
    ///
    /// The returned result carries the sticky catch-up authority for the round:
    /// it starts from the pre-round window flag and latches true if the fresh
    /// coordinator head crosses the catch-up threshold mid-loop. Callers must
    /// honor that latch for deposit append targets and durable pending-claim
    /// settlement.
    pub async fn run_l2_bridge_round(
        &self,
        config: &BridgeProposeDaemonConfig,
        provider: &RpcProvider,
        bridge: Address,
        from_checkpoint: u64,
        to_checkpoint: u64,
        confirmation_lag_checkpoints: u64,
        is_catchup_batch: bool,
        state: &DaemonState,
        propose_args: ProposeWithdrawalsArgs,
        max_checkpoint_batch: u64,
    ) -> anyhow::Result<L2RoundResult> {
        self.with_retry("run_l2_bridge_round", L1_RETRY_MAX_ATTEMPTS, |url| {
            let owned = url.to_string();
            let propose_args_clone = propose_args.clone();
            async move {
                let l1_provider = connect_l1_readonly(
                    owned.parse()
                        .with_context(|| format!("invalid L1 rpc url: {owned}"))?,
                )?;
                run_l2_bridge_round_with_l1_provider(
                    config,
                    provider,
                    &l1_provider,
                    bridge,
                    from_checkpoint,
                    to_checkpoint,
                    confirmation_lag_checkpoints,
                    is_catchup_batch,
                    state,
                    propose_args_clone,
                    max_checkpoint_batch,
                )
                .await
            }
        })
        .await
    }

    pub async fn submit_deposit_batch_appends(
        &self,
        config: &BridgeProposeDaemonConfig,
        target_deposit_count: u32,
    ) -> anyhow::Result<()> {
        let prove_proxy_url = resolve_prove_proxy_url(config);
        self.with_retry("deposit_batch_appends", L1_RETRY_MAX_ATTEMPTS, |url| {
            let owned = url.to_string();
            let proxy = prove_proxy_url.clone();
            async move {
                submit_deposit_batch_appends_with_l1_rpc(
                    config,
                    &owned,
                    target_deposit_count,
                    proxy.as_deref(),
                )
                .await
            }
        })
        .await
    }

    pub async fn claim_withdrawals(
        &self,
        withdrawals: &[propose_withdrawals::PendingWithdrawal],
        config: &BridgeProposeDaemonConfig,
        to_checkpoint: u64,
    ) -> anyhow::Result<claim_withdrawals::BatchWithdrawalsReport> {
        let bridge_addr = resolve_bridge_address(config)?;
        tracing::info!(
            count = withdrawals.len(),
            to_checkpoint,
            "claiming current batch withdrawals on L1"
        );
        let prove_proxy_url = resolve_prove_proxy_url(config);
        self.with_retry("claim_withdrawals", L1_RETRY_MAX_ATTEMPTS, |url| {
            let owned = url.to_string();
            let bridge_addr = bridge_addr.clone();
            let proxy = prove_proxy_url.clone();
            async move {
                let report = claim_withdrawal_chunks(
                    withdrawals,
                    config,
                    &owned,
                    &bridge_addr,
                    proxy.as_deref(),
                )
                .await?;
                tracing::info!(
                    to_checkpoint,
                    requested = report.requested,
                    submitted_count = report.submitted_count,
                    already_claimed_count = report.already_claimed_count,
                    resolved = report.resolved_leaf_hashes.len(),
                    failed = report.failure_reasons.len(),
                    "bridge daemon batch withdrawal step finished"
                );
                Ok(report)
            }
        })
        .await
    }

    pub async fn load_or_build_proof(
        &self,
        config: &BridgeProposeDaemonConfig,
        proof_path: &Path,
        from_checkpoint: u64,
        to_checkpoint: u64,
        prove_proxy_url: Option<&str>,
    ) -> anyhow::Result<BridgeProveResult> {
        if proof_path.exists() {
            let meta = load_proof_metadata(proof_path)?;
            if meta.to_checkpoint == to_checkpoint
                && meta.from_checkpoint.unwrap_or(from_checkpoint) == from_checkpoint
                && meta
                    .num_checkpoints_aggregated
                    .unwrap_or_else(|| to_checkpoint.saturating_sub(from_checkpoint) + 1)
                    == to_checkpoint.saturating_sub(from_checkpoint) + 1
            {
                // Validate deposit_tree_root is present and well-formed.
                // Old cached proofs without this field will be rejected
                // and re-proved.
                if !meta.deposit_tree_root.starts_with("0x") || meta.deposit_tree_root.len() != 66
                    || !meta.deposit_tree_root[2..].chars().all(|c| c.is_ascii_hexdigit())
                {
                    tracing::warn!(
                        deposit_tree_root = %meta.deposit_tree_root,
                        "cached proof has missing or invalid deposit_tree_root; re-proving"
                    );
                    fs::remove_file(proof_path)?;
                } else {
                    return Ok(BridgeProveResult {
                        from_checkpoint,
                        to_checkpoint,
                        num_checkpoints_aggregated: to_checkpoint - from_checkpoint + 1,
                        proof_path: proof_path.to_path_buf(),
                        deposit_tree_root: meta.deposit_tree_root.clone(),
                        withdrawal_tree_root: meta.withdrawal_tree_root.clone(),
                    });
                }
            }
            fs::remove_file(proof_path)
                .with_context(|| format!("failed to remove stale proof {}", proof_path.display()))?;
        }

        self.with_retry("bridge_proof_generation", L1_RETRY_MAX_ATTEMPTS, |url| {
            let owned = url.to_string();
            async move {
                match load_or_build_proof_impl(
                    &owned,
                    config,
                    proof_path,
                    from_checkpoint,
                    to_checkpoint,
                    prove_proxy_url,
                )
                .await
                {
                    Ok(result) => Ok(result),
                    Err(err) => {
                        let _ = fs::remove_file(proof_path);
                        Err(err)
                    }
                }
            }
        })
        .await
    }

    pub async fn finalize(&self, args: FinalizeBridgeAggArgs) -> anyhow::Result<()> {
        let label = format!("finalize/{}", args.to_checkpoint);
        let args_base = args.clone();
        self.with_retry(&label, L1_RETRY_MAX_ATTEMPTS, |url| {
            let owned = url.to_string();
            let mut cloned = args_base.clone();
            cloned.l1_rpc_url = owned;
            async move { finalize_bridge::run(cloned).await }
        })
        .await
    }
}

fn load_proof_metadata(path: &Path) -> anyhow::Result<ProofMetadata> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read proof {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse proof {}", path.display()))
}

async fn load_or_build_proof_impl(
    _l1_rpc_url: &str,
    config: &BridgeProposeDaemonConfig,
    proof_path: &Path,
    from_checkpoint: u64,
    to_checkpoint: u64,
    prove_proxy_url: Option<&str>,
) -> anyhow::Result<BridgeProveResult> {
    let deployments_network = config
        .finalize
        .deployments_network
        .clone()
        .unwrap_or_else(|| DEFAULT_DEPLOYMENTS_NETWORK.to_string());
    let prove_result = if let Some(proxy_url) = prove_proxy_url {
        prove_bridge::run_prove_bridge_agg_with_result_remote(
            from_checkpoint,
            to_checkpoint,
            config.rpc_config.clone(),
            proof_path.to_path_buf(),
            deployments_network,
            proxy_url,
        )
        .await
    } else {
        prove_bridge::run_prove_bridge_agg_with_result(
            from_checkpoint,
            to_checkpoint,
            config.rpc_config.clone(),
            proof_path.to_path_buf(),
            deployments_network,
        )
        .await
    }?;

    Ok(prove_result)
}

async fn claim_withdrawal_chunks(
    withdrawals: &[propose_withdrawals::PendingWithdrawal],
    config: &BridgeProposeDaemonConfig,
    l1_rpc: &str,
    bridge_addr: &str,
    prove_proxy_url: Option<&str>,
) -> anyhow::Result<claim_withdrawals::BatchWithdrawalsReport> {
    let mut total = claim_withdrawals::BatchWithdrawalsReport {
        requested: 0,
        submitted_count: 0,
        already_claimed_count: 0,
        resolved_leaf_hashes: Vec::new(),
        failure_reasons: HashMap::new(),
    };
    let deployments_network = config
        .finalize
        .deployments_network
        .as_deref()
        .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
    let multicall3 = claim_withdrawals::resolve_multicall3_address(None, deployments_network)?;
    let multicall3_addr = multicall3.map(|a| a.to_string());

    tracing::info!(
        withdrawal_count = withdrawals.len(),
        multicall3 = %multicall3_addr.as_deref().unwrap_or("none"),
        "claiming withdrawals"
    );
    let report = claim_withdrawals::submit_batch(
        withdrawals,
        &config.services_url,
        l1_rpc,
        bridge_addr,
        multicall3_addr.as_deref(),
        deployments_network,
        config.finalize.private_key.as_deref(),
        config.finalize.keystore_path.as_deref().map(Path::new),
        config.finalize.password_env.as_deref().unwrap_or("WALLET_PASSWORD"),
        prove_proxy_url,
    )
    .await?;
    total.requested += report.requested;
    total.submitted_count += report.submitted_count;
    total.already_claimed_count += report.already_claimed_count;
    total.resolved_leaf_hashes.extend(report.resolved_leaf_hashes);
    total.failure_reasons.extend(report.failure_reasons);

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("psy-relayer-l1-client-test-{name}-{}", std::process::id()));
        path
    }

    #[test]
    fn proof_metadata_deserializes_with_deposit_tree_root() {
        let json = r#"{
            "from_checkpoint": 10,
            "to_checkpoint": 20,
            "deposit_tree_root": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "withdrawal_tree_root": "0x2222222222222222222222222222222222222222222222222222222222222222"
        }"#;

        let meta: ProofMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.to_checkpoint, 20);
        assert_eq!(
            meta.deposit_tree_root,
            "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        assert_eq!(
            meta.withdrawal_tree_root,
            "0x2222222222222222222222222222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn proof_metadata_deserializes_without_deposit_tree_root_old_format() {
        // Old cached proof saved before deposit_tree_root was added.
        // The field is #[serde(default)], so it should be empty string.
        let json = r#"{
            "from_checkpoint": 5,
            "to_checkpoint": 8,
            "withdrawal_tree_root": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"#;

        let meta: ProofMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.to_checkpoint, 8);
        assert_eq!(meta.deposit_tree_root, ""); // #[serde(default)] → empty String
    }

    #[test]
    fn load_proof_metadata_file_not_found() {
        let path = temp_path("nonexistent");
        let result = load_proof_metadata(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to read"));
    }

    #[test]
    fn load_proof_metadata_valid_json() {
        let path = temp_path("valid");
        let json = r#"{
            "to_checkpoint": 42,
            "deposit_tree_root": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "withdrawal_tree_root": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }"#;
        std::fs::write(&path, json).unwrap();

        let meta = load_proof_metadata(&path).unwrap();
        assert_eq!(meta.to_checkpoint, 42);
        assert_eq!(
            meta.deposit_tree_root,
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn load_proof_metadata_garbage_deposit_tree_root_is_rejected() {
        // cached proof has 0x prefix and 66 chars but non-hex characters
        let path = temp_path("garbage-hex");
        let json = r#"{
            "to_checkpoint": 10,
            "deposit_tree_root": "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "withdrawal_tree_root": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }"#;
        std::fs::write(&path, json).unwrap();

        // load_proof_metadata itself will succeed (just parses JSON),
        // but the caller (load_or_build_proof) will reject it.
        let meta = load_proof_metadata(&path).unwrap();
        assert_eq!(meta.deposit_tree_root.len(), 66);
        assert!(meta.deposit_tree_root.starts_with("0x"));
        // Verify it has non-hex chars
        assert!(meta.deposit_tree_root[2..]
            .chars()
            .any(|c| !c.is_ascii_hexdigit()));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn load_proof_metadata_invalid_json() {
        let path = temp_path("invalid");
        std::fs::write(&path, "this is not json").unwrap();

        let result = load_proof_metadata(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to parse"));

        std::fs::remove_file(&path).unwrap();
    }
}

