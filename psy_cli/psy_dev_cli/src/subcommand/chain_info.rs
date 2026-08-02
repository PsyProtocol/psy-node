use clap::{Parser, ValueEnum};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_core::{
    crypto::hash::traits::QFieldHashable,
    pgoldilocks::{PoseidonHasher, QHashOut},
    protocol::core_types::Q256BitHash,
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use psy_api_core::{
    coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient,
    realm::standard_edge_rpc::RealmEdgeRpcClient,
};
use psy_config::PsyConfigGoldilocks;
use psy_core::job::job_id::QProvingJobDataID;
use serde::Serialize;
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Debug, ValueEnum)]
pub enum ChainInfoFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
pub struct ChainInfoArgs {
    /// Path to network config JSON (same format as client_prover/config.json)
    #[arg(long = "config", default_value = "client_prover/config.json")]
    pub config: String,

    /// Network name inside config.json (defaults to config current network)
    #[arg(long = "network")]
    pub network: Option<String>,

    /// Override coordinator URL (otherwise use config coordinator_configs[0].rpc_url[0])
    #[arg(long = "coordinator-url")]
    pub coordinator_url: Option<String>,

    /// Override realm URLs in order (otherwise use config realm_configs[*].rpc_url[0])
    #[arg(long = "realm-url")]
    pub realm_urls: Vec<String>,

    /// Number of recent checkpoints to query per service
    #[arg(long = "recent-checkpoints", default_value = "5")]
    pub recent_checkpoints: usize,

    /// Sample the first N user IDs per realm (using users_per_realm from config)
    #[arg(long = "sample-users", default_value = "2")]
    pub sample_users: usize,

    /// Number of low contract IDs to query heights for per realm
    #[arg(long = "contract-count", default_value = "5")]
    pub contract_count: usize,

    /// Request timeout in milliseconds for each RPC call
    #[arg(long = "connect-timeout-ms", default_value = "2000")]
    pub connect_timeout_ms: u64,

    /// Output format
    #[arg(long = "format", default_value = "text")]
    pub format: ChainInfoFormat,

    /// Keep polling forever
    #[arg(long = "watch")]
    pub watch: bool,

    /// Watch interval in seconds
    #[arg(long = "interval-secs", default_value = "5")]
    pub interval_secs: u64,
}

type F = parth_core::PF;
type Hash = QHashOut<F>;
type ZKProof = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

#[derive(Clone, Debug, Serialize)]
pub struct ChainInfoReport {
    pub network: String,
    pub users_per_realm: u64,
    pub coordinator_url: String,
    pub realm_urls: Vec<(u64, String)>,
    pub prove_proxy_urls: Vec<String>,
    pub api_services_urls: Vec<String>,
    pub coordinator: ServiceReport,
    pub realms: Vec<ServiceReport>,
    pub sync_analysis: SyncAnalysis,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceReport {
    pub name: String,
    pub kind: String,
    pub realm_id: Option<u64>,
    pub url: String,
    pub latest_checkpoint_id: Option<u64>,
    pub recent_checkpoint_roots: Vec<CheckpointRoot>,
    pub recent_global_chain_roots: Vec<CheckpointRoot>,
    pub realm_stats: Option<RealmLeafStats>,
    pub l2_state: Option<L2StateSummary>,
    pub contract_heights: Vec<u8>,
    pub sampled_user_leaves: Vec<UserLeafSummary>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckpointRoot {
    pub checkpoint_id: u64,
    pub root_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RealmLeafStats {
    pub guta_fees_collected: u64,
    pub da_fees_collected: u64,
    pub total_transactions: u64,
    pub user_ops_processed: u64,
    pub slots_modified: u64,
    pub block_time: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct L2StateSummary {
    pub checkpoint_id: u64,
    pub next_user_id: u64,
    pub next_contract_id: u64,
    pub next_deposit_id: Option<u64>,
    pub next_add_withdrawal_id: Option<u64>,
    pub next_process_withdrawal_id: Option<u64>,
    pub total_deposits_claimed_epoch: Option<u64>,
    pub end_balance: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UserLeafSummary {
    pub user_id: u64,
    pub balance: u64,
    pub nonce: u64,
    pub last_checkpoint_id: u64,
    pub event_index: u64,
    pub public_key_hex: String,
    pub user_state_tree_root_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SyncAnalysis {
    pub max_checkpoint_id: Option<u64>,
    pub min_checkpoint_id: Option<u64>,
    pub checkpoint_span: Option<u64>,
    pub warnings: Vec<String>,
    pub divergences: Vec<Divergence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Divergence {
    pub checkpoint_id: u64,
    pub roots_by_service: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct ResolvedNetwork {
    network_name: String,
    users_per_realm: u64,
    coordinator_url: String,
    realm_urls: Vec<(u64, String)>,
    prove_proxy_urls: Vec<String>,
    api_services_urls: Vec<String>,
}

pub async fn run(args: ChainInfoArgs) -> anyhow::Result<()> {
    loop {
        let report = build_report(&args).await?;
        match args.format {
            ChainInfoFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            ChainInfoFormat::Text => {
                display_report(&report);
            }
        }

        if !args.watch {
            break;
        }
        tokio::time::sleep(Duration::from_secs(args.interval_secs)).await;
        if matches!(args.format, ChainInfoFormat::Text) {
            println!("\n================ WATCH TICK ================\n");
        }
    }
    Ok(())
}

async fn build_report(args: &ChainInfoArgs) -> anyhow::Result<ChainInfoReport> {
    let resolved = resolve_network(args)?;
    let timeout = Duration::from_millis(args.connect_timeout_ms);

    let coordinator = query_coordinator(
        &resolved.coordinator_url,
        args.recent_checkpoints,
        timeout,
    )
    .await;

    let mut realms = Vec::new();
    for (realm_id, url) in &resolved.realm_urls {
        realms.push(
            query_realm(
                *realm_id,
                url,
                resolved.users_per_realm,
                args.recent_checkpoints,
                args.sample_users,
                args.contract_count,
                timeout,
            )
            .await,
        );
    }

    let mut services = Vec::new();
    services.push(coordinator.clone());
    services.extend(realms.iter().cloned());
    let sync_analysis = analyze_sync(&services);

    Ok(ChainInfoReport {
        network: resolved.network_name,
        users_per_realm: resolved.users_per_realm,
        coordinator_url: resolved.coordinator_url,
        realm_urls: resolved.realm_urls,
        prove_proxy_urls: resolved.prove_proxy_urls,
        api_services_urls: resolved.api_services_urls,
        coordinator,
        realms,
        sync_analysis,
    })
}

fn resolve_network(args: &ChainInfoArgs) -> anyhow::Result<ResolvedNetwork> {
    let mut cfg = PsyConfigGoldilocks::from_file(&args.config)
        .map_err(|e| anyhow::anyhow!("failed to load config {}: {}", args.config, e))?;
    if let Some(network_name) = &args.network {
        cfg.use_network(network_name)
            .map_err(|e| anyhow::anyhow!("failed to select network {}: {}", network_name, e))?;
    }
    let network_name = cfg.current_network_name().to_string();
    let net = cfg
        .get_current_network()
        .map_err(|e| anyhow::anyhow!("failed to read current network: {}", e))?;

    let coordinator_url = args.coordinator_url.clone().unwrap_or_else(|| {
        net.coordinator_configs
            .first()
            .and_then(|c| c.rpc_url.first())
            .cloned()
            .unwrap_or_default()
    });
    if coordinator_url.is_empty() {
        anyhow::bail!("no coordinator URL configured or provided");
    }

    let realm_urls = if !args.realm_urls.is_empty() {
        args.realm_urls
            .iter()
            .enumerate()
            .map(|(i, url)| (i as u64, url.clone()))
            .collect()
    } else {
        net.realm_configs
            .iter()
            .filter_map(|r| r.rpc_url.first().cloned().map(|url| (r.id, url)))
            .collect()
    };

    Ok(ResolvedNetwork {
        network_name,
        users_per_realm: net.users_per_realm,
        coordinator_url,
        realm_urls,
        prove_proxy_urls: net.prove_proxy_url.clone(),
        api_services_urls: net.api_services_url.clone().unwrap_or_default(),
    })
}

async fn make_client(url: &str, timeout: Duration) -> anyhow::Result<HttpClient> {
    HttpClientBuilder::default()
        .request_timeout(timeout)
        .build(url)
        .map_err(|e| anyhow::anyhow!("failed to build client for {}: {}", url, e))
}

async fn query_coordinator(url: &str, recent_checkpoints: usize, timeout: Duration) -> ServiceReport {
    match make_client(url, timeout).await {
        Ok(client) => {
            match query_service(ServiceKind::Coordinator, &client, recent_checkpoints, 0, 0, 0, url).await {
                Ok(r) => r,
                Err(e) => ServiceReport::error("Coordinator", "coordinator", None, url, e),
            }
        }
        Err(e) => ServiceReport::error("Coordinator", "coordinator", None, url, e),
    }
}

async fn query_realm(
    realm_id: u64,
    url: &str,
    users_per_realm: u64,
    recent_checkpoints: usize,
    sample_users: usize,
    contract_count: usize,
    timeout: Duration,
) -> ServiceReport {
    match make_client(url, timeout).await {
        Ok(client) => {
            match query_service(
                ServiceKind::Realm { realm_id, users_per_realm },
                &client,
                recent_checkpoints,
                sample_users,
                contract_count,
                users_per_realm,
                url,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => ServiceReport::error(&format!("Realm {}", realm_id), "realm", Some(realm_id), url, e),
            }
        }
        Err(e) => ServiceReport::error(&format!("Realm {}", realm_id), "realm", Some(realm_id), url, e),
    }
}

#[derive(Clone, Copy)]
enum ServiceKind {
    Coordinator,
    Realm { realm_id: u64, users_per_realm: u64 },
}

async fn query_service(
    kind: ServiceKind,
    client: &HttpClient,
    recent_checkpoints: usize,
    sample_users: usize,
    contract_count: usize,
    users_per_realm: u64,
    url: &str,
) -> anyhow::Result<ServiceReport> {
    let (name, kind_str, realm_id_opt) = match kind {
        ServiceKind::Coordinator => ("Coordinator".to_string(), "coordinator".to_string(), None),
        ServiceKind::Realm { realm_id, .. } => (format!("Realm {}", realm_id), "realm".to_string(), Some(realm_id)),
    };

    let latest_checkpoint_id = match kind {
        ServiceKind::Coordinator => {
            CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(client).await?
        }
        ServiceKind::Realm { .. } => {
            RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(client).await?
        }
    };

    let mut recent_checkpoint_roots = Vec::new();
    let mut recent_global_chain_roots = Vec::new();
    let start_checkpoint = latest_checkpoint_id.saturating_sub(recent_checkpoints.saturating_sub(1) as u64);
    for checkpoint_id in (start_checkpoint..=latest_checkpoint_id).rev() {
        match kind {
            ServiceKind::Coordinator => {
                if let Ok(root) = CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_tree_root(client, checkpoint_id).await {
                    recent_checkpoint_roots.push(CheckpointRoot {
                        checkpoint_id,
                        root_hex: qhash_hex(&root),
                    });
                }
                if let Ok(state_roots) = CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_global_state_roots(client, checkpoint_id).await {
                    let global_root = state_roots.qfhash::<PoseidonHasher>();
                    recent_global_chain_roots.push(CheckpointRoot {
                        checkpoint_id,
                        root_hex: qhash_hex(&global_root),
                    });
                }
            }
            ServiceKind::Realm { .. } => {
                if let Ok(root) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_tree_root(client, checkpoint_id).await {
                    recent_checkpoint_roots.push(CheckpointRoot {
                        checkpoint_id,
                        root_hex: qhash_hex(&root),
                    });
                }
                if let Ok(state_roots) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_global_state_roots(client, checkpoint_id).await {
                    let global_root = state_roots.qfhash::<PoseidonHasher>();
                    recent_global_chain_roots.push(CheckpointRoot {
                        checkpoint_id,
                        root_hex: qhash_hex(&global_root),
                    });
                }
            }
        }
    }

    let l2_state = match kind {
        ServiceKind::Coordinator => CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_l2_block_state(client)
            .await
            .ok()
            .map(|s| L2StateSummary {
                checkpoint_id: s.checkpoint_id,
                next_user_id: s.next_user_id,
                next_contract_id: s.next_contract_id as u64,
                next_deposit_id: Some(s.next_deposit_id),
                next_add_withdrawal_id: Some(s.next_add_withdrawal_id),
                next_process_withdrawal_id: Some(s.next_process_withdrawal_id),
                total_deposits_claimed_epoch: Some(s.total_deposits_claimed_epoch),
                end_balance: Some(s.end_balance),
            }),
        ServiceKind::Realm { .. } => RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_l2_block_state(client)
            .await
            .ok()
            .map(|s| L2StateSummary {
                checkpoint_id: s.checkpoint_id,
                next_user_id: s.next_user_id,
                next_contract_id: s.next_contract_id as u64,
                next_deposit_id: Some(s.next_deposit_id),
                next_add_withdrawal_id: Some(s.next_add_withdrawal_id),
                next_process_withdrawal_id: Some(s.next_process_withdrawal_id),
                total_deposits_claimed_epoch: Some(s.total_deposits_claimed_epoch),
                end_balance: Some(s.end_balance),
            }),
    };

    let mut realm_stats = None;
    let mut contract_heights = Vec::new();
    let mut sampled_user_leaves = Vec::new();

    if let ServiceKind::Realm { realm_id, .. } = kind {
        if let Ok(leaf) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_leaf_data(client, latest_checkpoint_id).await {
            realm_stats = Some(RealmLeafStats {
                guta_fees_collected: leaf.stats.guta_fees_collected.to_canonical_u64(),
                da_fees_collected: leaf.stats.da_fees_collected.to_canonical_u64(),
                total_transactions: leaf.stats.total_transactions.to_canonical_u64(),
                user_ops_processed: leaf.stats.user_ops_processed.to_canonical_u64(),
                slots_modified: leaf.stats.slots_modified.to_canonical_u64(),
                block_time: leaf.stats.block_time.to_canonical_u64(),
            });
        }

        let contract_ids: Vec<u64> = (0..contract_count as u64).collect();
        if !contract_ids.is_empty() {
            if let Ok(heights) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_contract_tree_state_heights(client, latest_checkpoint_id, contract_ids).await {
                contract_heights = heights;
            }
        }

        let base_user_id = realm_id.saturating_mul(users_per_realm);
        for i in 0..sample_users as u64 {
            let user_id = base_user_id + i;
            if let Ok(user_leaf) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_user_leaf_data(client, latest_checkpoint_id, user_id).await {
                sampled_user_leaves.push(UserLeafSummary {
                    user_id,
                    balance: user_leaf.balance.to_canonical_u64(),
                    nonce: user_leaf.nonce.to_canonical_u64(),
                    last_checkpoint_id: user_leaf.last_checkpoint_id.to_canonical_u64(),
                    event_index: user_leaf.event_index.to_canonical_u64(),
                    public_key_hex: qhash_hex(&user_leaf.public_key),
                    user_state_tree_root_hex: qhash_hex(&user_leaf.user_state_tree_root),
                });
            }
        }
    }

    Ok(ServiceReport {
        name,
        kind: kind_str,
        realm_id: realm_id_opt,
        url: url.to_string(),
        latest_checkpoint_id: Some(latest_checkpoint_id),
        recent_checkpoint_roots,
        recent_global_chain_roots,
        realm_stats,
        l2_state,
        contract_heights,
        sampled_user_leaves,
        error: None,
    })
}

impl ServiceReport {
    fn error(name: &str, kind: &str, realm_id: Option<u64>, url: &str, err: anyhow::Error) -> Self {
        Self {
            name: name.to_string(),
            kind: kind.to_string(),
            realm_id,
            url: url.to_string(),
            latest_checkpoint_id: None,
            recent_checkpoint_roots: Vec::new(),
            recent_global_chain_roots: Vec::new(),
            realm_stats: None,
            l2_state: None,
            contract_heights: Vec::new(),
            sampled_user_leaves: Vec::new(),
            error: Some(err.to_string()),
        }
    }
}

fn analyze_sync(services: &[ServiceReport]) -> SyncAnalysis {
    let checkpoint_ids: Vec<u64> = services.iter().filter_map(|s| s.latest_checkpoint_id).collect();
    if checkpoint_ids.is_empty() {
        return SyncAnalysis {
            max_checkpoint_id: None,
            min_checkpoint_id: None,
            checkpoint_span: None,
            warnings: vec!["no services returned checkpoint IDs".to_string()],
            divergences: Vec::new(),
        };
    }

    let max_checkpoint_id = *checkpoint_ids.iter().max().unwrap();
    let min_checkpoint_id = *checkpoint_ids.iter().min().unwrap();
    let checkpoint_span = max_checkpoint_id - min_checkpoint_id;

    let mut warnings = Vec::new();
    if checkpoint_span > 2 {
        warnings.push(format!(
            "checkpoint IDs span {} blocks ({}..={})",
            checkpoint_span, min_checkpoint_id, max_checkpoint_id
        ));
    }
    for service in services {
        if let Some(id) = service.latest_checkpoint_id {
            let diff = max_checkpoint_id - id;
            if diff > 3 {
                warnings.push(format!("{} is {} checkpoints behind", service.name, diff));
            }
        } else if let Some(err) = &service.error {
            warnings.push(format!("{} query failed: {}", service.name, err));
        }
    }

    let mut roots_by_checkpoint: BTreeMap<u64, BTreeMap<String, String>> = BTreeMap::new();
    for service in services {
        for root in &service.recent_checkpoint_roots {
            roots_by_checkpoint
                .entry(root.checkpoint_id)
                .or_default()
                .insert(service.name.clone(), root.root_hex.clone());
        }
    }

    let mut divergences = Vec::new();
    for (checkpoint_id, roots) in roots_by_checkpoint {
        if roots.len() < 2 {
            continue;
        }
        let mut values = roots.values();
        if let Some(first) = values.next() {
            if values.any(|v| v != first) {
                divergences.push(Divergence {
                    checkpoint_id,
                    roots_by_service: roots,
                });
            }
        }
    }

    SyncAnalysis {
        max_checkpoint_id: Some(max_checkpoint_id),
        min_checkpoint_id: Some(min_checkpoint_id),
        checkpoint_span: Some(checkpoint_span),
        warnings,
        divergences,
    }
}

fn display_report(report: &ChainInfoReport) {
    println!("=====================================");
    println!("Chain Info — network: {}", report.network);
    println!("users_per_realm: {}", report.users_per_realm);
    println!("coordinator: {}", report.coordinator_url);
    if !report.prove_proxy_urls.is_empty() {
        println!("prove_proxy_urls: {:?}", report.prove_proxy_urls);
    }
    if !report.api_services_urls.is_empty() {
        println!("api_services_urls: {:?}", report.api_services_urls);
    }
    println!("=====================================\n");

    display_service(&report.coordinator);
    for realm in &report.realms {
        display_service(realm);
    }

    println!("=== Sync Analysis ===");
    println!(
        "checkpoint range: {:?}..={:?} span={:?}",
        report.sync_analysis.min_checkpoint_id,
        report.sync_analysis.max_checkpoint_id,
        report.sync_analysis.checkpoint_span
    );
    for warning in &report.sync_analysis.warnings {
        println!("warning: {}", warning);
    }
    for divergence in &report.sync_analysis.divergences {
        println!("divergence at checkpoint {}:", divergence.checkpoint_id);
        for (service, root) in &divergence.roots_by_service {
            println!("  {} => {}", service, root);
        }
    }
    println!();
}

fn display_service(service: &ServiceReport) {
    println!("=== {} ===", service.name);
    println!("url: {}", service.url);
    if let Some(err) = &service.error {
        println!("error: {}", err);
        println!();
        return;
    }
    println!("latest_checkpoint_id: {:?}", service.latest_checkpoint_id);
    if !service.recent_checkpoint_roots.is_empty() {
        println!("recent checkpoint roots:");
        for root in &service.recent_checkpoint_roots {
            println!("  cp {} => {}", root.checkpoint_id, root.root_hex);
        }
    }
    if !service.recent_global_chain_roots.is_empty() {
        println!("recent global chain roots:");
        for root in &service.recent_global_chain_roots {
            println!("  cp {} => {}", root.checkpoint_id, root.root_hex);
        }
    }
    if let Some(stats) = &service.realm_stats {
        println!(
            "realm stats: guta={}, da={}, txs={}, user_ops={}, slots_modified={}, block_time={}",
            stats.guta_fees_collected,
            stats.da_fees_collected,
            stats.total_transactions,
            stats.user_ops_processed,
            stats.slots_modified,
            stats.block_time
        );
    }
    if let Some(state) = &service.l2_state {
        println!(
            "l2 state: checkpoint_id={}, next_user_id={}, next_contract_id={}",
            state.checkpoint_id, state.next_user_id, state.next_contract_id
        );
    }
    if !service.contract_heights.is_empty() {
        println!("contract heights: {:?}", service.contract_heights);
    }
    if !service.sampled_user_leaves.is_empty() {
        println!("sampled user leaves:");
        for u in &service.sampled_user_leaves {
            println!(
                "  user {} balance={} nonce={} last_cp={} event_index={} public_key={} user_state_root={}",
                u.user_id,
                u.balance,
                u.nonce,
                u.last_checkpoint_id,
                u.event_index,
                u.public_key_hex,
                u.user_state_tree_root_hex
            );
        }
    }
    println!();
}

fn reverse_bytes(bytes: [u8; 32]) -> Vec<u8> {
    bytes.iter().rev().cloned().collect()
}

fn qhash_hex<H: Q256BitHash>(hash: &H) -> String {
    hex::encode(reverse_bytes(hash.into_owned_32bytes()))
}
