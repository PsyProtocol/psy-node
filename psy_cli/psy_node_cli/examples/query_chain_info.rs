use clap::Parser;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_core::pgoldilocks::QHashOut;
use psy_api_core::{coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient, realm::standard_edge_rpc::RealmEdgeRpcClient};
use psy_core::job::job_id::QProvingJobDataID;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use parth_core::{
    crypto::hash::traits::QFieldHashable,
    protocol::core_types::Q256BitHash,
};
use std::collections::HashMap;

fn reverse_bytes(bytes: [u8; 32]) -> Vec<u8> {
    bytes.iter().rev().cloned().collect()
}

fn print_hash<H: Q256BitHash>(label: &str, hash: &H) {
    let bytes = hash.into_owned_32bytes();
    let reversed_bytes = reverse_bytes(bytes);
    println!("{}: {}", label, hex::encode(&reversed_bytes));
}

type F = parth_core::PF;
type Hash = QHashOut<F>;
type ZKProof = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:1337")]
    coordinator_url: String,
    #[arg(long, default_value = "http://127.0.0.1:1338")]
    realm0_url: String,
    #[arg(long, default_value = "http://127.0.0.1:1339")]
    realm1_url: String,
    #[arg(long, default_value = "http://127.0.0.1:1340")]
    realm2_url: String,
    #[arg(long, default_value = "http://127.0.0.1:1341")]
    realm3_url: String,
    #[arg(long, default_value = "5")]
    recent_checkpoints: usize,
}

#[derive(Clone)]
struct ServiceInfo {
    name: String,
    url: String,
    checkpoint_id: u64,
    recent_roots: Vec<(u64, Hash)>,
    global_chain_roots: Vec<(u64, Hash)>,
    leaf_stats: Option<(u64, u64, u64, u64, u64)>,
    l2_state: Option<String>,
    contract_heights: Vec<u8>,
    user_leaves: Vec<(u64, String)>,
    sync_status: String,
    realm_root: Option<Hash>,
    realm_last_modified_checkpoint: Option<u64>,
}

impl ServiceInfo {
    fn new(name: String, url: String) -> Self {
        Self {
            name,
            url,
            checkpoint_id: 0,
            recent_roots: Vec::new(),
            global_chain_roots: Vec::new(),
            leaf_stats: None,
            l2_state: None,
            contract_heights: Vec::new(),
            user_leaves: Vec::new(),
            sync_status: "Unknown".to_string(),
            realm_root: None,
            realm_last_modified_checkpoint: None,
        }
    }
}

async fn query_service_info(
    client: &HttpClient,
    service_name: &str,
    service_type: &str,
    recent_count: usize,
    service_url: &str,
) -> anyhow::Result<ServiceInfo> {
    let mut info = ServiceInfo::new(service_name.to_string(), service_url.to_string());

    info.checkpoint_id = match service_type {
        "coordinator" => {
            CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(client).await?
        }
        "realm" => {
            RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(client).await?
        }
        _ => return Err(anyhow::anyhow!("Unknown service type: {}", service_type)),
    };

    // Collect recent checkpoints from the service's current checkpoint backwards
    for i in 0..recent_count {
        if info.checkpoint_id >= i as u64 {
            let checkpoint_id = info.checkpoint_id - i as u64;
            match service_type {
                "coordinator" => {
                    if let Ok(root) = CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_tree_root(client, checkpoint_id).await {
                        info.recent_roots.push((checkpoint_id, root));
                    }
                }
                "realm" => {
                    if let Ok(root) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_tree_root(client, checkpoint_id).await {
                        info.recent_roots.push((checkpoint_id, root));
                    }
                }
                _ => {}
            }
        }
    }

    // Additionally, try to collect shared checkpoints (0 to min_checkpoint)
    // This is important for sync analysis
    if service_type == "coordinator" || service_type == "realm" {
        // Try to get data for checkpoints 0-20 (reasonable range for shared history)
        for checkpoint_id in 0..=20u64 {
            if checkpoint_id >= info.checkpoint_id {
                break; // Don't go beyond service's current checkpoint
            }
            if info.recent_roots.iter().any(|(id, _)| *id == checkpoint_id) {
                continue; // Already have this checkpoint
            }

            match service_type {
                "coordinator" => {
                    if let Ok(root) = CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_tree_root(client, checkpoint_id).await {
                        info.recent_roots.push((checkpoint_id, root));
                    }
                }
                "realm" => {
                    if let Ok(root) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_tree_root(client, checkpoint_id).await {
                        info.recent_roots.push((checkpoint_id, root));
                    }
                }
                _ => {}
            }
        }
    }

    for i in 0..recent_count {
        if info.checkpoint_id >= i as u64 {
            let checkpoint_id = info.checkpoint_id - i as u64;
            if service_type == "coordinator" || service_type == "realm" {
                let state_roots_result = match service_type {
                    "coordinator" => CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_global_state_roots(client, checkpoint_id).await,
                    "realm" => {
                        match RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_global_state_roots(client, checkpoint_id).await {
                            Ok(roots) => Ok(roots),
                            Err(_) => continue,
                        }
                    }
                    _ => continue,
                };

                if let Ok(state_roots) = state_roots_result {
                    use parth_core::pgoldilocks::PoseidonHasher;
                    let global_chain_root = state_roots.qfhash::<PoseidonHasher>();
                    info.global_chain_roots.push((checkpoint_id, global_chain_root));
                }
            }
        }
    }

    if service_type == "realm" {
        if let Ok(leaf) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_leaf_data(client, info.checkpoint_id).await {
            info.leaf_stats = Some((
                leaf.stats.fees_collected.to_canonical_u64(),
                leaf.stats.total_transactions.to_canonical_u64(),
                leaf.stats.user_ops_processed.to_canonical_u64(),
                leaf.stats.slots_modified.to_canonical_u64(),
                leaf.stats.block_time.to_canonical_u64(),
            ));
        }

        if let Ok(l2_state) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_l2_block_state(client).await {
            info.l2_state = Some(format!("next_contract_id={}, next_user_id={}, checkpoint_id={}",
                l2_state.next_contract_id, l2_state.next_user_id, l2_state.checkpoint_id));
        }

        let contract_ids = (0..5).collect::<Vec<u64>>();
        if let Ok(heights) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_contract_tree_state_heights(client, u64::MAX - 0xff, contract_ids).await {
            info.contract_heights = heights;
        }

        let user_ids = match service_name {
            "Realm 0" => vec![0, 1024],
            "Realm 1" => vec![1048576, 1049600],
            "Realm 2" => vec![2097152, 2098176],
            "Realm 3" => vec![3145728, 3146752],
            _ => vec![],
        };

        for user_id in user_ids {
            if let Ok(user_leaf) = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_user_leaf_data(client, info.checkpoint_id, user_id).await {
                let leaf_info = format!("user_id={}, balance={}, nonce={}, last_checkpoint_id={}, event_index={}, public_key={}, user_state_tree_root={}",
                    user_leaf.user_id.to_canonical_u64(),
                    user_leaf.balance.to_canonical_u64(),
                    user_leaf.nonce.to_canonical_u64(),
                    user_leaf.last_checkpoint_id,
                    user_leaf.event_index,
                    hex::encode(&reverse_bytes(user_leaf.public_key.into_owned_32bytes())),
                    hex::encode(&reverse_bytes(user_leaf.user_state_tree_root.into_owned_32bytes())));
                info.user_leaves.push((user_id, leaf_info));
            }
        }
    } else if service_type == "coordinator" {
        let dummy_pk = Hash::from_values(1, 2, 3, 4);
        if let Ok(user_ids) = CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_user_ids_for_public_key(client, dummy_pk, 0, 10).await {
            let mut l2_info = format!("registered_users={}", user_ids.len());

            // Get L2 block state for deployed contracts info
            if let Ok(l2_state) = CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_l2_block_state(client).await {
                l2_info.push_str(&format!(", deployed_contracts={}", l2_state.next_contract_id));
            }

            info.l2_state = Some(l2_info);
        }
    }

    Ok(info)
}

fn analyze_sync_status(services: &[ServiceInfo]) -> Vec<String> {
    let mut sync_statuses = Vec::new();

    if services.len() < 2 {
        return vec!["Need at least 2 services to analyze sync status".to_string()];
    }

    let max_checkpoint = services.iter().map(|s| s.checkpoint_id).max().unwrap_or(0);
    let min_checkpoint = services.iter().map(|s| s.checkpoint_id).min().unwrap_or(0);

    sync_statuses.push(format!("📊 Checkpoint ID Range: {} - {}", min_checkpoint, max_checkpoint));

    for service in services {
        let checkpoint_diff = max_checkpoint - service.checkpoint_id;
        if checkpoint_diff > 3 {
            sync_statuses.push(format!("⚠️  {} is {} checkpoints behind (ID: {})", service.name, checkpoint_diff, service.checkpoint_id));
        }
    }

    let checkpoint_range = max_checkpoint - min_checkpoint;
    if checkpoint_range > 2 {
        sync_statuses.push(format!("⚠️  Services have checkpoint IDs spanning {} blocks - some may be stuck", checkpoint_range));
    }

    // 3. Layered sync analysis
    sync_statuses.push("".to_string());
    sync_statuses.push("🔍 Synchronization Status Analysis:".to_string());

    // 3.1 Full sync range (checkpoints where all services have data)
    let full_sync_range_end = min_checkpoint;
    sync_statuses.push(format!("├── 🔍 Full sync range (checkpoint 0-{}): {} services", full_sync_range_end, services.len()));

    let mut full_sync_consistent = 0;
    let mut full_sync_total = 0;
    let mut divergence_point = None;

    // Check all checkpoints in the full sync range for consistency
    for checkpoint_id in 0..=full_sync_range_end {
        let mut roots = Vec::new();
        for service in services {
            if let Some((_, root)) = service.recent_roots.iter().find(|(id, _)| *id == checkpoint_id) {
                roots.push((service.name.as_str(), *root));
            }
        }

        if roots.len() == services.len() {  // All services have data for this checkpoint
            full_sync_total += 1;
            let first_root = roots[0].1;
            let all_same = roots.iter().all(|(_, root)| *root == first_root);
            if all_same {
                full_sync_consistent += 1;
            } else {
                // Found divergence point
                divergence_point = Some(checkpoint_id);
                sync_statuses.push(format!("│   🎯 DIVERGENCE POINT found at checkpoint {}", checkpoint_id));
                sync_statuses.push(format!("│   ❌ Checkpoint {}: Services have different roots!", checkpoint_id));
                for (service_name, root) in roots {
                        sync_statuses.push(format!("│      {}: {}", service_name, hex::encode(&reverse_bytes(root.into_owned_32bytes()))));
                }
                break; // Stop at first divergence
            }
        }
    }

    if divergence_point.is_none() {
        if full_sync_total > 0 {
            sync_statuses.push(format!("│   ✅ Full sync OK: {}/{} checkpoints consistent", full_sync_consistent, full_sync_total));
        } else {
            sync_statuses.push(format!("│   ℹ️  No full sync checkpoints to verify"));
        }
    }

    // 3.2 Partial sync range (checkpoints where only some services have data)
    if max_checkpoint > min_checkpoint {
        let partial_sync_start = min_checkpoint + 1;
        let partial_services: Vec<_> = services.iter().filter(|s| s.checkpoint_id > min_checkpoint).collect();
        sync_statuses.push(format!("├── 🔍 Partial sync range (checkpoint {}-{}): {} services",
            partial_sync_start, max_checkpoint, partial_services.len()));

        let mut partial_sync_consistent = 0;
        let mut partial_sync_total = 0;

        // Check recent 5 checkpoints for consistency among partial services
        for checkpoint_offset in 0..5 {
            if checkpoint_offset > max_checkpoint {
                continue;
            }

            let checkpoint_id = max_checkpoint - checkpoint_offset;
            let mut roots = Vec::new();

            for service in &partial_services {
                if let Some((_, root)) = service.recent_roots.iter().find(|(id, _)| *id == checkpoint_id) {
                    roots.push((service.name.as_str(), *root));
                }
            }

            if roots.len() >= 2 {
                partial_sync_total += 1;
                let first_root = roots[0].1;
                let all_same = roots.iter().all(|(_, root)| *root == first_root);

                if all_same {
                    partial_sync_consistent += 1;
                } else {
                    sync_statuses.push(format!("│   ❌ Checkpoint {}: Partial sync failed", checkpoint_id));
                    for (service_name, root) in roots {
                    sync_statuses.push(format!("│      {}: {}", service_name, hex::encode(&reverse_bytes(root.into_owned_32bytes()))));
                    }
                }
            }
        }

        if partial_sync_consistent > 0 {
            sync_statuses.push(format!("│   ✅ Partial sync OK: {}/{} checkpoints consistent", partial_sync_consistent, partial_sync_total));
        }

        // Clearly indicate which services are missing data
        let missing_data_services: Vec<_> = services.iter().filter(|s| s.checkpoint_id == min_checkpoint).collect();
        for service in missing_data_services {
            sync_statuses.push(format!("└── ⚠️  {} has no data after checkpoint {}", service.name, min_checkpoint));
        }

        // Summary about divergence
        if let Some(div_point) = divergence_point {
            sync_statuses.push(format!("🎯 SUMMARY: Services diverged at checkpoint {}", div_point));
        } else {
            sync_statuses.push(format!("🎯 SUMMARY: No divergence found in shared checkpoints (0-{})", min_checkpoint));
            sync_statuses.push(format!("🎯 SUMMARY: Issue appears after checkpoint {}", min_checkpoint));
        }
    } else {
        sync_statuses.push("└── ✅ All services have same checkpoint ID - no data gaps".to_string());
    }

    sync_statuses
}

fn display_service_info(info: &ServiceInfo) {
    println!("=== {} Info ===", info.name);
    println!("Latest Checkpoint ID: {}", info.checkpoint_id);

    if !info.recent_roots.is_empty() {
        println!("Recent Checkpoint Tree Roots:");
        for (checkpoint_id, root) in &info.recent_roots {
            print!("  ");
            print_hash(&format!("Checkpoint {}", checkpoint_id), root);
        }
    }

    if !info.global_chain_roots.is_empty() {
        println!("Recent Global Chain Roots:");
        for (checkpoint_id, root) in &info.global_chain_roots {
            print!("  ");
            print_hash(&format!("Checkpoint {}", checkpoint_id), root);
        }
    }

    if let Some((fees, txns, user_ops, slots, block_time)) = info.leaf_stats {
        println!("Checkpoint Stats: fees={}, transactions={}, user_ops={}, slots_modified={}, block_time={}",
            fees, txns, user_ops, slots, block_time);
    }

    if let (Some(realm_root), Some(last_modified)) = (info.realm_root.as_ref(), info.realm_last_modified_checkpoint) {
        println!("Realm Root:");
        print!("  ");
        print_hash("Realm Root", realm_root);
        println!("Realm Last Modified Checkpoint: {}", last_modified);
    }

    if let Some(ref l2_state) = info.l2_state {
        println!("L2 State: {}", l2_state);
    }

    if !info.contract_heights.is_empty() {
        println!("Contract Tree Heights: {:?}", info.contract_heights);
    }

    if !info.user_leaves.is_empty() {
        println!("User Leaves:");
        for (user_id, leaf_info) in &info.user_leaves {
            println!("  User {}: {}", user_id, leaf_info);
        }
    }

    println!();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("🔍 Psy Network Chain Information Query");
    println!("=====================================");
    println!("Coordinator URL: {}", args.coordinator_url);
    println!("Realm 0 URL: {}", args.realm0_url);
    println!("Realm 1 URL: {}", args.realm1_url);
    println!("Realm 2 URL: {}", args.realm2_url);
    println!("Realm 3 URL: {}", args.realm3_url);
    println!("Recent checkpoints to show: {}", args.recent_checkpoints);
    println!();

    let mut services = Vec::new();

    match HttpClientBuilder::default().build(&args.coordinator_url) {
        Ok(client) => {
            match query_service_info(&client, "Coordinator", "coordinator", args.recent_checkpoints, &args.coordinator_url).await {
                Ok(info) => services.push(info),
                Err(e) => println!("❌ Failed to query Coordinator: {}", e),
            }
        }
        Err(e) => println!("❌ Failed to connect to Coordinator: {}", e),
    }

    match HttpClientBuilder::default().build(&args.realm0_url) {
        Ok(client) => {
            match query_service_info(&client, "Realm 0", "realm", args.recent_checkpoints, &args.realm0_url).await {
                Ok(info) => services.push(info),
                Err(e) => println!("❌ Failed to query Realm 0: {}", e),
            }
        }
        Err(e) => println!("❌ Failed to connect to Realm 0: {}", e),
    }

    match HttpClientBuilder::default().build(&args.realm1_url) {
        Ok(client) => {
            match query_service_info(&client, "Realm 1", "realm", args.recent_checkpoints, &args.realm1_url).await {
                Ok(info) => services.push(info),
                Err(e) => println!("❌ Failed to query Realm 1: {}", e),
            }
        }
        Err(e) => println!("❌ Failed to connect to Realm 1: {}", e),
    }

    match HttpClientBuilder::default().build(&args.realm2_url) {
        Ok(client) => {
            match query_service_info(&client, "Realm 2", "realm", args.recent_checkpoints, &args.realm2_url).await {
                Ok(info) => services.push(info),
                Err(e) => println!("❌ Failed to query Realm 2: {}", e),
            }
        }
        Err(e) => println!("❌ Failed to connect to Realm 2: {}", e),
    }

    match HttpClientBuilder::default().build(&args.realm3_url) {
        Ok(client) => {
            match query_service_info(&client, "Realm 3", "realm", args.recent_checkpoints, &args.realm3_url).await {
                Ok(info) => services.push(info),
                Err(e) => println!("❌ Failed to query Realm 3: {}", e),
            }
        }
        Err(e) => println!("❌ Failed to connect to Realm 3: {}", e),
    }

    // Get realm root information from coordinator
    if let Some(coordinator) = services.iter().find(|s| s.name == "Coordinator") {
        println!("📡 Getting realm root information from coordinator...");
        match HttpClientBuilder::default().build(&coordinator.url) {
            Ok(coord_client) => {
                for service in &mut services {
                    if service.name.starts_with("Realm ") {
                        let realm_id = match service.name.as_str() {
                            "Realm 0" => 0,
                            "Realm 1" => 1,
                            "Realm 2" => 2,
                            "Realm 3" => 3,
                            _ => continue,
                        };

                        println!("  🔍 Getting realm {} root for checkpoint {}", realm_id, service.checkpoint_id);
                        match CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_realm_root_and_last_modified_checkpoint(&coord_client, service.checkpoint_id, realm_id).await {
                            Ok(realm_data) => {
                                service.realm_root = Some(realm_data.value);
                                service.realm_last_modified_checkpoint = Some(realm_data.checkpoint_id);
                                println!("    ✅ Got realm root: {}", hex::encode(&reverse_bytes(realm_data.value.into_owned_32bytes())));
                                println!("    📅 Last modified checkpoint: {}", realm_data.checkpoint_id);
                            }
                            Err(e) => {
                                println!("    ❌ Failed to get realm root: {}", e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("❌ Failed to connect to coordinator for realm root info: {}", e);
            }
        }
    } else {
        println!("⚠️  No coordinator found to get realm root information");
    }

    for service in &services {
        display_service_info(service);
    }

    if services.is_empty() {
        println!("❌ No services could be queried successfully.");
        println!("💡 Make sure the Psy network services are running.");
    } else {
        println!("✅ Query completed successfully!");
        println!("📊 Total services queried: {}", services.len());

        // Analyze sync status
        println!("\n🔄 Synchronization Analysis");
        println!("============================");
        let sync_statuses = analyze_sync_status(&services);
        for status in sync_statuses {
            println!("{}", status);
        }
    }

    Ok(())
}
