use std::{collections::HashMap, fs, path::Path, time::Duration};

use alloy_primitives::Address;
use anyhow::Context;
use psy_provider::provider::RpcProvider;
use serde::Deserialize;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;

use crate::bridge::{
    claim_withdrawals,
    constants::DEFAULT_DEPLOYMENTS_NETWORK,
    daemon::{
        fetch_l1_last_finalized_checkpoint, resolve_bridge_address, resolve_system_prove_proxy_url,
        run_l2_bridge_round_with_l1_snapshot, submit_deposit_batch_appends_with_l1_rpc,
        resolve_state_manager_address, fetch_proved_deposit_count, fetch_pending_deposit_count,
        BridgeProposeDaemonConfig, DaemonState, DaemonFinalizeConfig, L2RoundResult,
    },
    finalize_bridge::{self, FinalizeBridgeAggArgs},
    l1_provider::connect_l1_readonly,
    l1_provider::{build_pool_client, with_l1_rpc_client},
    rpc_providers::finalize_rpc_providers,
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
    /// BridgeAgg public inputs: predecessor checkpoint-tree root, then end root.
    #[serde(default)]
    checkpoint_roots: Vec<String>,
}

/// L2 root read failed. Callers must keep the cached proof; deleting it would
/// turn an unread lineage into a blind rebuild.
#[derive(Debug)]
pub(crate) struct CachedProofLineageUnread;

impl std::fmt::Display for CachedProofLineageUnread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("L2 checkpoint lineage unread; cached proof retained")
    }
}

impl std::error::Error for CachedProofLineageUnread {}

#[derive(Clone)]
pub struct L1Client {
    /// Scope identity: the first configured provider URL, not a routing preference.
    primary: url::Url,
    rpc: alloy_rpc_client::RpcClient,
}

impl std::fmt::Debug for L1Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L1Client").finish_non_exhaustive()
    }
}

impl L1Client {
    pub fn from_finalize_config(finalize: &DaemonFinalizeConfig, label: &str) -> anyhow::Result<Self> {
        let providers = finalize_rpc_providers(label, finalize)?;
        let primary: url::Url = providers[0]
            .url
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid L1 RPC URL for provider {}", providers[0].name))?;
        Ok(Self { rpc: build_pool_client(label, &providers)?, primary })
    }

    /// Run business logic once. Individual RPC packets own failover internally.
    pub async fn with_rpc_failover<T, F, Fut>(
        &self,
        label: &str,
        f: F,
    ) -> anyhow::Result<T>
    where
        F: FnOnce(&str) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        with_l1_rpc_client(self.primary.clone(), self.rpc.clone(), async {
            f(self.primary.as_str()).await
        })
            .await.with_context(|| format!("L1 operation {label} failed"))
    }

    pub async fn last_finalized_checkpoint(&self, state_manager: Address) -> anyhow::Result<u64> {
        self.with_rpc_failover("last_finalized_checkpoint", |url| {
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

        self.with_rpc_failover("withdrawal_subtree_root", |url| {
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

    /// Read an L1 snapshot with failover, then execute the L2 round exactly once.
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
        guardian: &super::guardian_client::LoadedGuardianConfig,
        bridge: Address,
        from_checkpoint: u64,
        to_checkpoint: u64,
        confirmation_lag_checkpoints: u64,
        is_catchup_batch: bool,
        state: &DaemonState,
        propose_args: ProposeWithdrawalsArgs,
        max_checkpoint_batch: u64,
    ) -> anyhow::Result<L2RoundResult> {
        let deployments_network = config.finalize.deployments_network.as_deref()
            .unwrap_or(DEFAULT_DEPLOYMENTS_NETWORK);
        let state_manager = resolve_state_manager_address(config)?;
        let (source_chain_index, proved, pending) = self.with_rpc_failover("read_l1_round_snapshot", |url| {
            let owned = url.to_string();
            async move {
                let l1_provider = connect_l1_readonly(
                    owned.parse()
                        .with_context(|| format!("invalid L1 rpc url: {owned}"))?,
                )?;
                let chain_index = crate::bridge::api_client::resolve_l1_chain_index(
                    &l1_provider, deployments_network, state_manager,
                ).await?;
                Ok((u64::from(chain_index),
                    fetch_proved_deposit_count(&l1_provider, bridge).await?,
                    fetch_pending_deposit_count(&l1_provider, bridge).await?))
            }
        }).await?;
        run_l2_bridge_round_with_l1_snapshot(
            config, provider, guardian, source_chain_index, proved, pending, from_checkpoint,
            to_checkpoint, confirmation_lag_checkpoints, is_catchup_batch, state,
            propose_args, max_checkpoint_batch,
        ).await
    }

    pub async fn submit_deposit_batch_appends(
        &self,
        config: &BridgeProposeDaemonConfig,
        target_deposit_count: u32,
        network: &psy_config::NetworkConfigGoldilocks,
    ) -> anyhow::Result<()> {
        let prove_proxy_url = resolve_system_prove_proxy_url(network)?;
        self.with_rpc_failover("deposit_batch_appends", |url| {
            let owned = url.to_string();
            let proxy = prove_proxy_url.clone();
            async move {
                submit_deposit_batch_appends_with_l1_rpc(
                    config,
                    &owned,
                    target_deposit_count,
                    Some(proxy.as_str()),
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
        network: &psy_config::NetworkConfigGoldilocks,
    ) -> anyhow::Result<claim_withdrawals::BatchWithdrawalsReport> {
        let bridge_addr = resolve_bridge_address(config)?;
        tracing::info!(
            count = withdrawals.len(),
            to_checkpoint,
            "claiming current batch withdrawals on L1"
        );
        let prove_proxy_url = resolve_system_prove_proxy_url(network)?;
        self.with_rpc_failover("claim_withdrawals", |url| {
            let owned = url.to_string();
            let bridge_addr = bridge_addr.clone();
            let proxy = prove_proxy_url.clone();
            async move {
                let report = claim_withdrawal_chunks(
                    withdrawals,
                    config,
                    &owned,
                    &bridge_addr,
                    Some(proxy.as_str()),
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
            let same_range = meta.to_checkpoint == to_checkpoint
                && meta.from_checkpoint == Some(from_checkpoint)
                && meta.num_checkpoints_aggregated
                    == Some(to_checkpoint.saturating_sub(from_checkpoint) + 1);
            if same_range && bytes32_hex(&meta.deposit_tree_root) {
                // Same checkpoint ids can name a pre-rollback chain. Reuse only
                // when both cached roots still are the current L2 roots.
                match cached_lineage_matches(config, &meta, from_checkpoint, to_checkpoint).await {
                    Ok(true) => {
                        return Ok(BridgeProveResult {
                            from_checkpoint,
                            to_checkpoint,
                            num_checkpoints_aggregated: to_checkpoint - from_checkpoint + 1,
                            proof_path: proof_path.to_path_buf(),
                            deposit_tree_root: meta.deposit_tree_root.clone(),
                            withdrawal_tree_root: meta.withdrawal_tree_root.clone(),
                        });
                    }
                    Ok(false) => {
                        tracing::warn!(
                            from_checkpoint,
                            to_checkpoint,
                            "cached bridge proof does not match current L2 checkpoint roots; re-proving"
                        );
                    }
                    Err(error) => return Err(error),
                }
            } else if same_range {
                tracing::warn!(
                    deposit_tree_root = %meta.deposit_tree_root,
                    "cached proof has missing or invalid deposit_tree_root; re-proving"
                );
            }
            fs::remove_file(proof_path)
                .with_context(|| format!("failed to remove stale proof {}", proof_path.display()))?;
        }

        // Proof generation does not use an L1 endpoint and must not alter its health.
        let result = load_or_build_proof_impl(
            config, proof_path, from_checkpoint, to_checkpoint, prove_proxy_url,
        ).await;
        if result.is_err() {
            let _ = fs::remove_file(proof_path);
        }
        result
    }

    pub async fn finalize(&self, args: FinalizeBridgeAggArgs) -> anyhow::Result<()> {
        let label = format!("finalize/{}", args.to_checkpoint);
        let args_base = args.clone();
        self.with_rpc_failover(&label, |url| {
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

fn lineage_unread(from_checkpoint: u64, to_checkpoint: u64, err: impl std::fmt::Display) -> anyhow::Error {
    anyhow::Error::new(CachedProofLineageUnread).context(format!(
        "failed to read L2 checkpoint roots for {from_checkpoint}..={to_checkpoint}: {err}"
    ))
}

fn bytes32_hex(value: &str) -> bool {
    value.starts_with("0x") && value.len() == 66 && value[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn checkpoint_root_hex(root: &QHashOut<GoldilocksField>) -> String {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let value = root.0.elements[3 - i].to_canonical_u64();
        out[i * 8..(i + 1) * 8].copy_from_slice(&value.to_be_bytes());
    }
    format!("0x{}", hex::encode(out))
}

async fn cached_lineage_matches(
    config: &BridgeProposeDaemonConfig,
    meta: &ProofMetadata,
    from_checkpoint: u64,
    to_checkpoint: u64,
) -> anyhow::Result<bool> {
    let (Some(cached_predecessor), Some(cached_end)) = (meta.checkpoint_roots.first(), meta.checkpoint_roots.get(1)) else {
        return Ok(false);
    };
    if !bytes32_hex(cached_predecessor) || !bytes32_hex(cached_end) {
        return Ok(false);
    }
    let Some(predecessor_id) = from_checkpoint.checked_sub(1) else {
        return Err(lineage_unread(from_checkpoint, to_checkpoint, "range has no predecessor checkpoint"));
    };
    let provider = RpcProvider::new_with_config_path(&config.rpc_config)
        .map_err(|err| lineage_unread(from_checkpoint, to_checkpoint, err))?;
    let predecessor = provider
        .get_checkpoint_tree_root(predecessor_id)
        .await
        .map_err(|err| lineage_unread(from_checkpoint, to_checkpoint, err))?;
    let end = provider
        .get_checkpoint_tree_root(to_checkpoint)
        .await
        .map_err(|err| lineage_unread(from_checkpoint, to_checkpoint, err))?;
    Ok(cached_predecessor.eq_ignore_ascii_case(&checkpoint_root_hex(&predecessor))
        && cached_end.eq_ignore_ascii_case(&checkpoint_root_hex(&end)))
}

async fn load_or_build_proof_impl(
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
        deferrals: HashMap::new(),
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
        config.finalize.fee_policy.as_ref(),
    )
    .await?;
    total.requested += report.requested;
    total.submitted_count += report.submitted_count;
    total.already_claimed_count += report.already_claimed_count;
    total.resolved_leaf_hashes.extend(report.resolved_leaf_hashes);
    total.failure_reasons.extend(report.failure_reasons);
    total.deferrals.extend(report.deferrals);

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::rpc_providers::RpcProviderConfig;
    use std::path::PathBuf;

    #[tokio::test]
    async fn business_callback_runs_once_and_synchronous_setup_is_scoped() {
        let primary = "http://127.0.0.1:1".parse::<url::Url>().unwrap();
        let other = "http://127.0.0.1:2".parse::<url::Url>().unwrap();
        let providers = vec![
            RpcProviderConfig {
                name: "p0".into(), url: primary.to_string(), priority_weight: 10,
                operator: String::new(), quota_group: String::new(),
            },
            RpcProviderConfig {
                name: "p1".into(), url: other.to_string(), priority_weight: 10,
                operator: String::new(), quota_group: String::new(),
            },
        ];
        let client = L1Client { rpc: build_pool_client("test", &providers).unwrap(), primary };
        let mut calls = 0;
        let result: anyhow::Result<()> = client.with_rpc_failover("test", |_| {
            calls += 1;
            // The closure itself, not only its returned future, needs the scope.
            assert!(connect_l1_readonly(other).is_err());
            async { anyhow::bail!("proof failure must not replay the business callback") }
        }).await;
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("psy-relayer-l1-client-test-{name}-{}", std::process::id()));
        path
    }

    #[tokio::test]
    async fn cached_proof_reuse_requires_current_l2_lineage() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        // Distinct limbs catch root-order and bytes32 encoding mistakes.
        const PREDECESSOR: &str = "0000000000000004000000000000000300000000000000020000000000000001";
        const END: &str = "0000000000000008000000000000000700000000000000060000000000000005";
        const OTHER: &str = "000000000000000c000000000000000b000000000000000a0000000000000009";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server_mode = mode.clone();
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).await.unwrap();
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request["method"], "psy_get_checkpoint_tree_root");
                let id = request["params"]["checkpoint_id"].as_u64().unwrap();
                assert!(id == 9 || id == 20);
                server_requests.lock().unwrap().push(id);
                let mode = server_mode.load(Ordering::SeqCst);
                let response = if mode == 3 || (mode == 4 && id == 20) {
                    serde_json::json!({"jsonrpc": "2.0", "id": request["id"],
                        "error": {"code": -32000, "message": "checkpoint root unavailable"}})
                } else {
                    let root = match (mode, id) {
                        (1, 9) | (2, 20) => OTHER,
                        (_, 9) => PREDECESSOR,
                        _ => END,
                    };
                    serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": root})
                }.to_string();
                reader.get_mut().write_all(format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(), response,
                ).as_bytes()).await.unwrap();
            }
        });
        let dir = temp_path("cache-lineage");
        fs::create_dir_all(&dir).unwrap();
        let rpc_path = dir.join("rpc.json");
        // Use the canonical schema and compiled network identity, overriding
        // only RPC endpoints so every request stays on the local stub.
        let genesis: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/../../psy-genesis/config.json"
        ))).unwrap();
        let mut network = genesis["networks"][psy_config::CURRENT_NETWORK].clone();
        assert!(network.is_object());
        network["realm_configs"] = serde_json::json!([{"id": 0, "rpc_url": [&url]}]);
        network["coordinator_configs"] = serde_json::json!([{"id": 0, "rpc_url": [&url]}]);
        for key in ["prove_proxy_url", "system_prove_proxy_url", "faucet_rpc_url", "api_services_url"] {
            network[key] = serde_json::json!([&url]);
        }
        let rpc_config = serde_json::json!({
            "networks": {(psy_config::CURRENT_NETWORK): network},
            "defaultNetwork": psy_config::CURRENT_NETWORK,
        });
        fs::write(&rpc_path, rpc_config.to_string()).unwrap();
        let mut config: BridgeProposeDaemonConfig = toml::from_str(&format!(
            "rpc_config = {:?}\nguardian_root = \"guardians-root\"\nservices_url = \"http://127.0.0.1:1\"\nwithdraw_method_id = 0\n",
            rpc_path.display(),
        )).unwrap();
        // A rejected cache enters the real rebuild path, failing before proving
        // or writing because this deployment deliberately does not exist.
        config.finalize.deployments_network = Some(format!("cache-lineage-no-deployment-{}", std::process::id()));
        config.finalize.l1_rpc_url = Some(url.clone());
        let client = L1Client::from_finalize_config(&config.finalize, "cache-lineage").unwrap();
        let proof_path = dir.join("bridge_proof_20.json");
        let original = serde_json::json!({
            "from_checkpoint": 10, "to_checkpoint": 20, "num_checkpoints_aggregated": 11,
            "checkpoint_roots": [format!("0x{PREDECESSOR}"), format!("0x{END}")],
            "deposit_tree_root": format!("0x{}", "11".repeat(32)),
            "withdrawal_tree_root": format!("0x{}", "22".repeat(32)),
            "proof": "cached-proof-must-not-be-rewritten"
        }).to_string();
        for scenario in 0..5 {
            mode.store(scenario, Ordering::SeqCst);
            requests.lock().unwrap().clear();
            fs::write(&proof_path, &original).unwrap();
            let result = client.load_or_build_proof(&config, &proof_path, 10, 20, Some(&url)).await;
            if scenario == 0 {
                let reused = result.unwrap();
                assert_eq!((reused.from_checkpoint, reused.to_checkpoint, reused.num_checkpoints_aggregated), (10, 20, 11));
                assert_eq!(reused.proof_path, proof_path);
                assert_eq!(fs::read_to_string(&proof_path).unwrap(), original);
            } else if scenario <= 2 {
                let error = result.unwrap_err();
                assert!(error.downcast_ref::<CachedProofLineageUnread>().is_none());
                assert!(format!("{error:#}").contains("failed to load deployed-contracts.json"), "{error:#}");
                assert!(!proof_path.exists(), "stale proof must not survive failed rebuild");
            } else {
                let error = result.unwrap_err();
                assert!(error.downcast_ref::<CachedProofLineageUnread>().is_some(), "{error:#}");
                assert!(format!("{error:#}").contains("10..=20"));
                assert_eq!(fs::read_to_string(&proof_path).unwrap(), original);
            }
            let expected = if scenario == 3 { vec![9] } else { vec![9, 20] };
            assert_eq!(*requests.lock().unwrap(), expected);
        }
        server.abort();
        fs::remove_dir_all(dir).unwrap();
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
