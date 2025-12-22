use cf_utils::timer::DebugTimer;
use parth_core::utils::math::log2_strict;
use plonky2::{field::{extension::quadratic::QuadraticExtension, fft::FftRootTable, goldilocks_field::GoldilocksField, polynomial::PolynomialCoeffs}, hash::{hash_types::RichField, merkle_tree::MerkleTree, poseidon::PoseidonHash}, plonk::config::{CpuProverCompute, GenericConfig, Hasher, ProverCompute}};
use psy_core::constants::{
    chain_id::{PsyChainNetworkType, PsyNetworkTypeInput},
    proving_backends::{PsyChainProvingBackendType, PsyChainProvingBackendTypeInput},
};
use psy_jtmb_testing_core::{circuit_library::worker::get_simple_proof_miner_worker_for_network_jtmb, protocol_types::JTMBPoseidonGoldilocksConfig};
use psy_plonky2_circuits::circuit_library::get_simple_proof_miner_worker_for_network;
use psy_worker_core::config::{worker_cli_config::WorkerCliConfig, worker_config::WorkerStartupConfig};
use serde::Serialize;
use tracing::{error, info};

fn print_banner() {
    println!(
        r#"
               7PB&?                         ..........                                             
               G@@@!                        ~####&&&&##BPJ~                                         
               Y@@&^                        !@@@#PPPPGB&@@@B7                                       
        .      ?@@#.      .                 !@@@5      :!B@@@J                                      
   !?Y5G#P.    !@@G    ^?P#G.               !@@@5        :&@@@^       ...                           
   ^!J&@@&^    ^@@P    !&@@@J               !@@@5         P@@@!   ~YG#&&#BGY^ ~GGG?         ~GGG?   
      5@@&^    :@@Y     !@@@P               !@@@5        .#@@@^ .5@@@BP5PG#@!  5@@@!       .B@@&^   
      P@@#.    :&@J      B@@G               !@@@5       ^P@@@5  7@@@?     .^.  .G@@#:      Y@@@!    
      B@@B     :&@?      G@@J               !@@@BJJJJY5B@@@&Y   !@@@P~.         :#@@G     !@@@J     
      #@@#:    :&@?     :&@#.               !@@@@@@@@@@&#P?^     7B@@@&GY!.      ~&@@J   :#@@P      
      Y@@@?    :@@?    .G@#~                !@@@P^^^^^^:.          ~JG#@@@&5^     ?@@@!  5@@#:      
      .G@@@J:  :@@?   ~B@G^                 !@@@5                     .~J&@@&^     Y@@#:7@@&~       
        ?B@@&GYY@@5?5B@B7                   !@@@5               .:       ?@@@?      G@@B#@@?        
          ~?5GB&@@&G5?^                     !@@@5               J@GJ7~~!J#@@#:      :#@@@@P         
               Y@@5                         !&@@5               ?B&@@@@@@@#Y:        !@@@B:         
               P@@B                         .::::                 :^~!!!~^.          5@@&~          
              .B@@&.                                                                ?@@@?           
              ^&&BP:                                                               !@@@5            
               ^:                                                                 ^#@@B.            
                                                                                  P@@&~             
    "#
    );
}

/// Default CPU implementation of `ProverCompute`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CpuProverComputeLog;
impl<F: RichField, H: Hasher<F>> ProverCompute<F, H> for CpuProverComputeLog {
    fn commit_polynomials(
        polynomials: &[PolynomialCoeffs<F>],
        cap_height: usize,
        rate_bits: usize,
        blinding: bool,
        fft_root_table: Option<&FftRootTable<F>>,
    ) -> MerkleTree<F, H> {
        let mut timer = DebugTimer::new("CpuProverCompute::commit_polynomials");

        println!("cap_height: {}", cap_height);
        println!("rate_bits: {}", rate_bits);
        println!("blinding: {}", blinding);
        println!("fft_root_table is some: {}", fft_root_table.is_some());
        println!("polynomials len: {}", polynomials.len());
        let polys = polynomials.iter().map(|x| x.len()).collect::<Vec<_>>();
        println!("polynomial lengths: {:?}", polys);
        let degree = polynomials[0].len();
        println!("degree: {}", degree);
        let degree_bits = log2_strict(degree);
        println!("degree_bits: {}", degree_bits);
        let result = CpuProverCompute::commit_polynomials(
            polynomials,
            cap_height,
            rate_bits,
            blinding,
            fft_root_table,
        );
        timer.lap_micros("commit_polynomials");
        result
    }
}


/// Configuration using Poseidon over the Goldilocks field.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize)]
pub struct PoseidonGoldilocksLogConfig;
impl GenericConfig<2> for PoseidonGoldilocksLogConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonHash;
    type InnerHasher = PoseidonHash;
    type Compute = CpuProverComputeLog;
}

pub async fn run_worker_inner(
    network: PsyChainNetworkType,
    config: WorkerStartupConfig,
    proving_backend: PsyChainProvingBackendType,
) -> anyhow::Result<()> {
    // Placeholder for actual worker logic

    if proving_backend == PsyChainProvingBackendType::Plonky2PoseidonGoldilocks {
        type C = PoseidonGoldilocksLogConfig;
        const D: usize = 2;
        let worker = get_simple_proof_miner_worker_for_network::<C, D>(network, config).await?;

        worker.run_worker_loop(100).await?;
    } else if proving_backend == PsyChainProvingBackendType::JTMBPoseidonGoldilocks {
        let worker = get_simple_proof_miner_worker_for_network_jtmb::<JTMBPoseidonGoldilocksConfig>(network, config).await?;
        worker.run_worker_loop(100).await?;
    }
    Ok(())
}

pub async fn run(
    config: Option<String>,
    private_key: Option<String>,
    _keystore_path: Option<String>,
    _wallet_password: Option<String>,
    recipient: Option<u64>,
    network: Option<PsyNetworkTypeInput>,
    proving_backend: Option<PsyChainProvingBackendTypeInput>,
    realm_api_urls: Vec<String>,
    coordinator_api_urls: Vec<String>,
) -> anyhow::Result<()> {
    print_banner();
    info!("Worker starting...");
    let config = WorkerCliConfig::get_start_config(
        config,
        private_key,
        _keystore_path,
        _wallet_password,
        recipient,
        network,
        coordinator_api_urls,
        realm_api_urls,
    )
    .await?.with_unique_api_urls();
    let network = config.network.clone();

    let mut handles = Vec::new();

    let proving_backend = proving_backend
            .unwrap_or(PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks)
            .into();
    let handle = tokio::spawn(run_worker_inner(
        network,
        config,
        proving_backend,
    ));
    handles.push(handle);
    /*

    for coordinator_config in &network.coordinator_configs {
        for rpc_url in &coordinator_config.rpc_url {
            let handle = tokio::spawn(run_worker(
                rpc_url.clone(),
                JobLocation::Coordinator,
                job_tracker.clone(),
                prover.clone(),
                proof_verifier.clone(),
                wallet.clone(),
                worker_public_key.clone(),
                user_id,
            ));
            handles.push(handle);
        }
    }

    for realm_config in &network.realm_configs {
        for rpc_url in &realm_config.rpc_url {
            let handle = tokio::spawn(run_worker(
                rpc_url.clone(),
                JobLocation::Realm(realm_config.id),
                job_tracker.clone(),
                prover.clone(),
                proof_verifier.clone(),
                wallet.clone(),
                worker_public_key.clone(),
                user_id,
            ));
            handles.push(handle);
        }
    }*/

    info!("Started {} worker threads", handles.len());

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            info!("Ctrl-C signal received, cleaning up...");
        }
        _ = async {
            for handle in handles {
                if let Err(e) = handle.await {
                    error!("Worker thread failed: {:?}", e);
                }
            }
        } => {
            info!("All worker threads completed");
        }
    }

    info!("Worker exit.");
    Ok(())
}
