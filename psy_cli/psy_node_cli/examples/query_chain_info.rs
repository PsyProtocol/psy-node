use clap::Parser;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_core::pgoldilocks::QHashOut;
use psy_api_core::{coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient, realm::standard_edge_rpc::RealmEdgeRpcClient};
use psy_core::job::job_id::QProvingJobDataID;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // Query Coordinator
    println!("=== Coordinator Info ===");
    let coord_client: HttpClient = HttpClientBuilder::default().build(&args.coordinator_url)?;
    let coord_checkpoint = CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(&coord_client).await?;
    println!("Coordinator Latest Checkpoint ID: {}", coord_checkpoint);

    // Try to get user IDs for a dummy public key (may fail if no users)
    let dummy_pk = Hash::from_values(1, 2, 3, 4);
    match CoordinatorEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_user_ids_for_public_key(&coord_client, dummy_pk, 0, 10).await {
        Ok(user_ids) => println!("Coordinator User IDs for dummy PK: {:?}", user_ids),
        Err(e) => println!("Coordinator User IDs: No users or error ({})", e),
    }

    // Query Realm 0
    println!("\n=== Realm 0 Info ===");
    let realm0_client: HttpClient = HttpClientBuilder::default().build(&args.realm0_url)?;
    let realm0_checkpoint = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(&realm0_client).await?;
    println!("Realm 0 Latest Checkpoint ID: {}", realm0_checkpoint);

    // Get checkpoint leaf data
    match RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_leaf_data(&realm0_client, realm0_checkpoint).await {
        Ok(leaf) => println!("Realm 0 Checkpoint Leaf Stats: fees={}, txns={}", leaf.stats.fees_collected, leaf.stats.total_transactions),
        Err(e) => println!("Realm 0 Checkpoint Leaf: Error ({})", e),
    }

    // Get latest L2 block state
    match RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_l2_block_state(&realm0_client).await {
        Ok(l2_state) => println!("Realm 0 Latest L2 Block State: {:?}", l2_state),
        Err(e) => println!("Realm 0 L2 Block State: Not available ({})", e),
    }

    let contract_ids = (0..5).collect::<Vec<u64>>();
    let heights = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_contract_tree_state_heights(&realm0_client, u64::MAX - 0xff, contract_ids.clone()).await?;
    println!("Realm 0 Contract Heights: {:?}", heights);

    // Query Realm 1
    println!("\n=== Realm 1 Info ===");
    let realm1_client: HttpClient = HttpClientBuilder::default().build(&args.realm1_url)?;
    let realm1_checkpoint = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(&realm1_client).await?;
    println!("Realm 1 Latest Checkpoint ID: {}", realm1_checkpoint);

    // Get checkpoint leaf data
    match RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_checkpoint_leaf_data(&realm1_client, realm1_checkpoint).await {
        Ok(leaf) => println!("Realm 1 Checkpoint Leaf Stats: fees={}, txns={}", leaf.stats.fees_collected, leaf.stats.total_transactions),
        Err(e) => println!("Realm 1 Checkpoint Leaf: Error ({})", e),
    }

    // Get latest L2 block state
    match RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_l2_block_state(&realm1_client).await {
        Ok(l2_state) => println!("Realm 1 Latest L2 Block State: {:?}", l2_state),
        Err(e) => println!("Realm 1 L2 Block State: Not available ({})", e),
    }

    let heights1 = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_contract_tree_state_heights(&realm1_client, u64::MAX - 0xff, contract_ids).await?;
    println!("Realm 1 Contract Heights: {:?}", heights1);

    Ok(())
}
