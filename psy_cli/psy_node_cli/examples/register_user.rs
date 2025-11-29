use cf_utils::timer::DebugTimer;
use jsonrpsee::{
    RpcModule, core::RpcResult, http_client::{HttpClient, HttpClientBuilder}, proc_macros::rpc, server::{ServerBuilder, ServerHandle}, ws_client::{WsClient, WsClientBuilder}
};
use parth_core::{crypto::hash::traits::FieldQHasher, pgoldilocks::PoseidonHasher, protocol::core_types::QNetworkTypesConfigHelper};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};
use psy_api_core::{coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient, worker::standard_worker_rpc::NodeEdgeWorkerRpcClient};
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::v1::qdata::public_key::PZKPublicKeyInfo;
use psy_plonky2_circuits::protocol_types::ZKTypesPlonky2GoldilocksPoseidon;
use std::net::SocketAddr;


async fn test_client() -> anyhow::Result<()> {
    type F = parth_core::PF;
    type Hasher = PoseidonHasher;
    type Hash = parth_core::PHash;
    type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
    type ZKProof = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

    // Test WebSocket client
    use std::sync::Arc;
    /* 
    let ws_url = format!("ws://127.0.0.1:1337");
    let ws_client = WsClientBuilder::default().build(&ws_url).await?;
    let mut timer = DebugTimer::new("ws");
    for i in 0..1000 {
        let public_key_param = Hash::from_values(i,i, i, i);
        let fingerprint = Hasher::q_two_to_one(public_key_param, public_key_param);
        let zk_key = PZKPublicKeyInfo {
            public_key_param,
            fingerprint,
        };
        CoordinatorEdgeRpcClient::<N::F, N::QHash, <QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants> as QNetworkTypesConfig>::NetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants> as QNetworkTypesConfig>::JobId, <QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants> as QNetworkZKTypes>::ZKProof>::register_user(&ws_client, zk_key).await?;
    }
    

    timer.lap_batch("ws", "register_user", 1000);
    */
           
    println!("WebSocket client test passed.");

    let mut timer = DebugTimer::new("http");
    // Test HTTP client
    let http_url = format!("http://127.0.0.1:1337");
    let http_client: HttpClient = HttpClientBuilder::default().build(&http_url)?;
    for i in 0..20 {
        let public_key_param = Hash::from_values(i,i, i, i);
        let fingerprint = Hasher::q_two_to_one(public_key_param, public_key_param);
        let zk_key = PZKPublicKeyInfo {
            public_key_param,
            fingerprint,
        };
        let http_result: String = CoordinatorEdgeRpcClient::<
            F,
            Hash,
            QProvingJobDataID,
            ZKProof,
        >::register_user(&http_client, zk_key).await?;
        println!("Registered user with fingerprint: {}", http_result);
    }
    timer.lap_batch("http", "register_user", 20);
    
    println!("HTTP client test passed.");


    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    test_client().await?;

    Ok(())
}