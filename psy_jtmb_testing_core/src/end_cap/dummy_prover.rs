use std::sync::Arc;

use jsonrpsee::http_client::HttpClient;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_dummy_prover::{
    api::combo_dummy_fetcher::new_combo_fetcher_from_urls,
    helper::{create_dummy_prover_helper, PsyUPSDummyProverHelper},
    lite::runner::run_dummy_prover_lite,
};

use crate::{
    circuit_library::core::get_test_circuit_authority_key, proving::circuits::dummy_end_cap::DummyUPSStandardEndCapCircuit,
    utils::jtmb_standard_circuit::JTMBCircuitConfig,
};

pub fn create_jtmb_dummy_end_cap_prover<N: QNetworkTypesConfig<QHash = C::Hash, F = C::F>, C: JTMBCircuitConfig>(
    coordinator_api_url: &str,
    realm_api_url: &str,
    network: PsyChainNetworkType,
) -> anyhow::Result<PsyUPSDummyProverHelper<N, HttpClient, HttpClient, DummyUPSStandardEndCapCircuit<C>>> {
    let private_key = get_test_circuit_authority_key(network);
    let prover = DummyUPSStandardEndCapCircuit::<C>::new(&private_key);
    create_dummy_prover_helper::<N, DummyUPSStandardEndCapCircuit<C>>(coordinator_api_url, realm_api_url, prover)
}

pub async fn run_jtmb_dummy_prover_lite<N: QNetworkTypesConfig<QHash = C::Hash, F = C::F, HasherBase = C::Hasher> + 'static, C: JTMBCircuitConfig>(
    realm_api_url: &str,
    coordinator_api_url: &str,
    min_state_updates_per_call: u32,
    max_state_updates_per_call: u32,
    max_contract_calls_per_uop: u32,
    start_user_id: u64,
    count: u64,
    batches: u32,
    network: PsyChainNetworkType,
) -> anyhow::Result<()> {
    if count == 0 {
        anyhow::bail!("Count must be greater than zero");
    }
    let private_key = get_test_circuit_authority_key(network);
    let data_fetcher = new_combo_fetcher_from_urls::<N>(coordinator_api_url, realm_api_url)?;
    let prover = DummyUPSStandardEndCapCircuit::<C>::new(&private_key);
    run_dummy_prover_lite::<N::HasherBase, _, DummyUPSStandardEndCapCircuit<C>, N::F, N::QHash>(
        Arc::new(data_fetcher),
        &prover,
        start_user_id,
        start_user_id + count,
        min_state_updates_per_call,
        max_state_updates_per_call,
        max_contract_calls_per_uop,
        N::GLOBAL_CONTRACT_TREE_HEIGHT,
        N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
        N::REALM_GLOBAL_USER_TREE_HEIGHT,
        N::GROUP_REALM_HEIGHT,
        batches as usize,
    )
    .await?;

    Ok(())
}
