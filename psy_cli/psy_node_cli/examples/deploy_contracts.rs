use std::u64;

use cf_utils::timer::DebugTimer;
use jsonrpsee::
    http_client::{HttpClient, HttpClientBuilder}
;
use parth_core::{QJobIdBase, crypto::hash::traits::FieldQHasher, felt::QFelt64, pgoldilocks::PoseidonHasher, protocol::core_types::{QDBHashBase, QFHashBase, QHashBase}, utils::QPGenRandom};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};
use psy_api_core::coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::v1::qdata::{contract::{ContractCodeDefinition, ContractFunctionCodeDefinition, PQBCDeployContract}, public_key::PZKPublicKeyInfo};
pub fn gen_random_contract<Hash: QPGenRandom + QHashBase>(max_functions: usize) -> PQBCDeployContract<Hash> {
    let function_whitelist = Hash::qp_rand_gen_vec_in_range(1, max_functions);
    let code_root = Hash::qp_rand_gen();

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

    println!("generated contract_state_Tree_height: {}", contract.code_definition.state_tree_height);

    contract
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
    pub async fn get_contract_tree_state_heights(&self, min_contract_id: u64, max_contract_id: u64) -> anyhow::Result<Vec<u8>> {
        let ids = (min_contract_id..=max_contract_id).collect();
        let heights: Vec<u8> = self.client.get_contract_tree_state_heights(u64::MAX, ids).await?;
        let code = self.client.get_contract_code_definition(0).await?;
        println!("code.state_tree_height: {}", code.state_tree_height);

        Ok(heights)
    }
}

async fn test_client() -> anyhow::Result<()> {
    type F = parth_core::PF;
    type Hasher = PoseidonHasher;
    type Hash = parth_core::PHash;
    type ZKProof = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;
    // Test HTTP client
    let http_url = format!("http://127.0.0.1:1337");
    let http_client: HttpClient = HttpClientBuilder::default().build(&http_url)?;
    let client = PsyCoordinatorHTTPClient::<F, Hash, Hasher, QProvingJobDataID, ZKProof, HttpClient>::new(http_client);

    // Test WebSocket client
    let mut timer = DebugTimer::new("http");



    //let heights = client.get_contract_tree_state_heights(0,2000).await?;

    //println!("Contract tree state heights for contract IDs 0 to 2000: {:?}", heights);

    timer.lap("init");
    client.deploy_random_contracts(100, 10).await?;
    timer.lap_batch("http", "deploy_random_contracts", 100);
    


    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    test_client().await?;

    Ok(())
}