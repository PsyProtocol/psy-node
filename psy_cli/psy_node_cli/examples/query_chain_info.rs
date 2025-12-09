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

    // Query Realm 0
    println!("\n=== Realm 0 Info ===");
    let realm0_client: HttpClient = HttpClientBuilder::default().build(&args.realm0_url)?;
    let realm0_checkpoint = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(&realm0_client).await?;
    println!("Realm 0 Latest Checkpoint ID: {}", realm0_checkpoint);
    let contract_ids = (0..5).collect::<Vec<u64>>();
    let heights = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_contract_tree_state_heights(&realm0_client, u64::MAX - 0xff, contract_ids.clone()).await?;
    println!("Realm 0 Contract Heights: {:?}", heights);

    // Query Realm 1
    println!("\n=== Realm 1 Info ===");
    let realm1_client: HttpClient = HttpClientBuilder::default().build(&args.realm1_url)?;
    let realm1_checkpoint = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_latest_checkpoint_id(&realm1_client).await?;
    println!("Realm 1 Latest Checkpoint ID: {}", realm1_checkpoint);
    let heights1 = RealmEdgeRpcClient::<F, Hash, QProvingJobDataID, ZKProof>::get_contract_tree_state_heights(&realm1_client, u64::MAX - 0xff, contract_ids).await?;
    println!("Realm 1 Contract Heights: {:?}", heights1);

    Ok(())
}
