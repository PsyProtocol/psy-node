use std::sync::Arc;

use async_trait::async_trait;
use jsonrpsee::http_client::HttpClient;
use parth_core::protocol::core_types::{Q256BitHash, QNetworkTypesConfig};
use psy_api_core::realm::standard_edge_rpc::RealmEdgeRpcClient;
use rand::{Rng, RngCore};

use crate::{api::data_fetcher::{PsyRealmAPIUserContractDataFetcher, PsyUserContractDataFetcher, new_contract_data_fetcher_from_url}, dummy_ups_state::state::DummyUPSStateBuilder, traits::{DummyUPSEndCapProverHelper, DummyUPSProver}};

#[derive(Clone)]
pub struct PsyUPSDummyProverHelper<N: QNetworkTypesConfig + 'static, C: RealmEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>, Prover: DummyUPSProver<N::F, N::QHash>> {
    pub client: Arc<PsyRealmAPIUserContractDataFetcher<N, C>>,
    pub prover: Prover,
    pub known_contract_state_heights: Vec<(u64, u8)>,
}

impl<N: QNetworkTypesConfig + 'static, C: RealmEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof>, Prover: DummyUPSProver<N::F, N::QHash>> PsyUPSDummyProverHelper<N, C, Prover> {
    pub fn new(client: PsyRealmAPIUserContractDataFetcher<N, C>, prover: Prover) -> Self {
        Self { client: Arc::new(client), prover, known_contract_state_heights: Vec::new() }
    }
}
impl<N: QNetworkTypesConfig + 'static, C: RealmEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof> + Send + Sync + 'static, Prover: DummyUPSProver<N::F, N::QHash> + Send + Sync> PsyUPSDummyProverHelper<N, C, Prover> {

    pub async fn query_contract_state_heights(&mut self, min_contract_id: u64, max_contract_id: u64) -> anyhow::Result<()> {
        let ids = (min_contract_id..=max_contract_id).collect();
        let heights: Vec<u8> = self.client.df_get_contract_state_heights(u64::MAX, ids).await?;

        heights.iter().zip(min_contract_id..).for_each(|( height, contract_id)| {
            if *height > 0 {
                self.known_contract_state_heights.push((contract_id, *height));
            }
        });
        Ok(())
    }
    fn rand_hash() -> N::QHash {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        N::QHash::from_owned_32bytes(bytes)
    }
    pub async fn plan_random_contract_calls(&self, max_contract_calls: u32, max_updates_per_call: u32, min_updates_per_call: u32) -> anyhow::Result<Vec<(u32, u64, N::QHash)>> {
        // If no contracts exist, return empty vec instead of panicking
        if self.known_contract_state_heights.is_empty() {
            println!("No contracts available yet, skipping contract calls");
            return Ok(Vec::new());
        }

        let num_contract_calls = rand::thread_rng().gen_range(1u32..=max_contract_calls);
        let mut planned_calls = Vec::new();
        println!("known contracts: {:?}", self.known_contract_state_heights);

        print!("max_contract_calls: {}, num_contract_calls: {}\n", max_contract_calls, num_contract_calls);
        println!("max_updates_per_call: {}, min_updates_per_call: {}", max_updates_per_call, min_updates_per_call);

        for _ in 0..num_contract_calls {
            let contract_index = rand::thread_rng().gen_range(0..self.known_contract_state_heights.len());
            let (contract_id, contract_height) = self.known_contract_state_heights[contract_index];
            let num_updates = rand::thread_rng().gen_range(min_updates_per_call..=max_updates_per_call);
            println!("contract_height: {}, contract_id: {}, num_updates: {}", contract_height, contract_id, num_updates);
            for _ in 0..num_updates {
                let slot_index = rand::thread_rng().gen_range(0..(1u64 << contract_height));
                let value = Self::rand_hash();
                planned_calls.push((contract_id as u32, slot_index, value));
            }
        }
        Ok(planned_calls)
    }
    pub async fn prove_random_contract_calls_and_submit(&self, user_id: u64, max_contract_calls: u32, max_updates_per_call: u32, min_updates_per_call: u32) -> anyhow::Result<()> {
        let calls = self.plan_random_contract_calls(max_contract_calls, max_updates_per_call, min_updates_per_call).await?;
        self.generate_proof_for_updates_and_submit(user_id, &calls).await
    }
}
pub fn create_dummy_prover_helper<
    N: QNetworkTypesConfig + 'static,
    Prover: DummyUPSProver<N::F, N::QHash>,
>(
    api_url: &str,
    prover: Prover,
) -> anyhow::Result<PsyUPSDummyProverHelper<N, HttpClient, Prover>> {
    let client = new_contract_data_fetcher_from_url::<N>(api_url)?;

    Ok(PsyUPSDummyProverHelper::new(client, prover))
}


#[async_trait]
impl<N: QNetworkTypesConfig + 'static, C: RealmEdgeRpcClient<N::F, N::QHash, N::JobId, N::ZKProof> + Send + Sync + 'static, Prover: DummyUPSProver<N::F, N::QHash> + Send + Sync > DummyUPSEndCapProverHelper<N::F, N::QHash> for PsyUPSDummyProverHelper<N, C, Prover> {
    async fn generate_proof_for_updates_and_submit(
        &self,
        user_id: u64,
        updates: &[(u32, u64, N::QHash)],
    ) -> anyhow::Result<()> {
        if updates.is_empty() {
            println!("No updates to prove, skipping submission");
            return Ok(());
        }

        let checkpoint_id = self.client.df_get_latest_checkpoint().await?;

        println!("Generating proof for user_id: {}, checkpoint_id: {}", user_id, checkpoint_id);

    let mut state_builder = DummyUPSStateBuilder::<N::F, N::QHash, _, N::HasherBase>::new_init(self.client.clone(), N::GLOBAL_CONTRACT_TREE_HEIGHT, user_id, checkpoint_id).await?;

    for call in updates {
        state_builder.write_to_contract(call.0, call.1, call.2).await?;
    }

        let finalized = state_builder.finalize_and_build().await?;
        println!("finalized state built for user_id: {}, checkpoint_id: {}", user_id, checkpoint_id);
        let proof = self.prover.prove_end_cap_dummy_ups(N::GLOBAL_USER_TREE_HEIGHT, &finalized)?;

        self.client.df_submit_end_cap_proof(finalized, proof).await?;
        Ok(())
    }
}