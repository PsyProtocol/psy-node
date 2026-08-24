use cf_utils::timer::DebugTimer;
use jsonrpsee::{
    http_client::{HttpClient, HttpClientBuilder}, ws_client::WsClientBuilder
};
use parth_core::{QJobIdBase, crypto::hash::traits::FieldQHasher, felt::QFelt64, pgoldilocks::PoseidonHasher, protocol::core_types::{QDBHashBase, QFHashBase, QHashBase}, utils::QPGenRandom};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};
use psy_api_core::coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::v1::qdata::{contract::{ContractCodeDefinition, ContractFunctionCodeDefinition, PQBCDeployContractV2, PQBCDeployContract}, public_key::PZKPublicKeyInfo};
pub fn gen_random_contract<Hash: QPGenRandom + QHashBase>(max_functions: usize) -> PQBCDeployContractV2<Hash> {
    let function_whitelist = Hash::qp_rand_gen_vec_in_range(1, max_functions);
    let code_root  = Hash::qp_rand_gen();
    let contract = PQBCDeployContract {
        deployer: Hash::qp_rand_gen(),
        code_definition: ContractCodeDefinition {
            state_tree_height: u16::qp_rand_gen() % 31 + 1,
            functions: (0..function_whitelist.len())
                .map(|i| {
                    ContractFunctionCodeDefinition{
                        method_id: i as u32,
                        num_inputs: u32::qp_rand_gen() % 10,
                        num_outputs: u32::qp_rand_gen() % 10,
                        vm_type: 0,
                        code: u8::qp_rand_gen_vec_in_range(100, 10000)
                    }
                })
                .collect(),
        },
        function_whitelist,
        code_root, 
    };

    PQBCDeployContractV2 {
        deploy_contract: contract,
        layout_protocol_version: 1,
        state_layout_root: Hash::get_zero_value(),
        state_layout_field_count: 0,
        state_layout_slot_count: 0,
        canonical_layout_verifier_fingerprint: Hash::get_zero_value(),
        canonical_layout_proof: vec![0],
    }
}

struct PsyCoordinatorHTTPClient<F: QFelt64, Hash: QFHashBase<F> + QDBHashBase + QPGenRandom, Hasher: FieldQHasher<F, Hash> ,JobId: QJobIdBase + Send + Sync + 'static, ZKProof: Send + Sync + 'static, C: CoordinatorEdgeRpcClient<F, Hash, JobId, ZKProof>> {
    pub client: C,
    _phantom_f: std::marker::PhantomData<F>,
    _phantom_hash: std::marker::PhantomData<Hash>,
    _phantom_job_id: std::marker::PhantomData<JobId>,
    _phantom_zk_proof: std::marker::PhantomData<ZKProof>,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
}

#[allow(dead_code)] 
impl<F: QFelt64, Hash: QFHashBase<F> + QDBHashBase + QPGenRandom, Hasher: FieldQHasher<F, Hash>, JobId: QJobIdBase + Send + Sync + 'static, ZKProof: Send + Sync + 'static, C: CoordinatorEdgeRpcClient<F, Hash, JobId, ZKProof>> PsyCoordinatorHTTPClient<F, Hash, Hasher, JobId, ZKProof, C> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            _phantom_f: std::marker::PhantomData,
            _phantom_hash: std::marker::PhantomData,
            _phantom_job_id: std::marker::PhantomData,
            _phantom_zk_proof: std::marker::PhantomData,
            _phantom_hasher: std::marker::PhantomData,
        }
    }
    pub fn get_client(&self) -> &C {
        &self.client
    }
    pub async fn register_random_users(&self, count: usize) -> anyhow::Result<()> {
        for i in 0..count {
            let public_key_param = Hash::from_u64s(i as u64,i as u64, i as u64, i as u64);
            let fingerprint = Hasher::q_two_to_one(public_key_param, public_key_param);
            let zk_key = PZKPublicKeyInfo {
                public_key_param,
                fingerprint,
            };
            let result: String = self.client.register_user(zk_key).await?;
            println!("Registered user with result: {}", result);
        }
        Ok(())
    }
    pub async fn deploy_random_contracts(&self, count: usize, max_functions: usize) -> anyhow::Result<()> {
        for _ in 0..count {
            let contract = gen_random_contract::<Hash>(max_functions);
            let result: String = self.client.deploy_contract(contract).await?;
            println!("Deployed contract with result hash: {}", result);
        }
        Ok(())
    }
}

async fn test_client() -> anyhow::Result<()> {
    type F = parth_core::PF;
    type Hasher = PoseidonHasher;
    type Hash = parth_core::PHash;
    type ZKProof = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

    // Test WebSocket client
    let ws_url = format!("ws://127.0.0.1:1337");
    let ws_client = WsClientBuilder::default().build(&ws_url).await?;
    let mut timer = DebugTimer::new("ws");
    let batch_size = 1000;
    for i in 0..batch_size {
        let public_key_param = Hash::from_values(i,i, i, i);
        let fingerprint = Hasher::q_two_to_one(public_key_param, public_key_param);
        let zk_key = PZKPublicKeyInfo {
            public_key_param,
            fingerprint,
        };
        CoordinatorEdgeRpcClient::<
            F,
            Hash,
            QProvingJobDataID,
            ZKProof,
        >::register_user(&ws_client, zk_key).await?;
    }
    

    timer.lap_batch("ws", "register_user", batch_size as usize);

           
    println!("WebSocket client test passed.");

    let mut timer = DebugTimer::new("http");

    // Test HTTP client
    let http_url = format!("http://127.0.0.1:1337");
    let http_client: HttpClient = HttpClientBuilder::default().build(&http_url)?;
    for i in 0..batch_size {
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
    timer.lap_batch("http", "register_user", batch_size as usize);
    
    println!("HTTP client test passed.");

    let _h_client = PsyCoordinatorHTTPClient::<F, Hash, Hasher, QProvingJobDataID, ZKProof, HttpClient>::new(http_client);


    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    test_client().await?;

    Ok(())
}