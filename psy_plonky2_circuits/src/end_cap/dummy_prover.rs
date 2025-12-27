use std::sync::Arc;

use jsonrpsee::http_client::HttpClient;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher},
    felt::QFelt64,
    pgoldilocks::{QGenericConfig, QHashOut},
    protocol::core_types::{Q256BitHash, QFHashBase, QNetworkTypesConfig},
};
use plonky2::{
    hash::hash_types::HashOut,
    plonk::config::AlgebraicHasher,
};
use psy_dummy_prover::{api::combo_dummy_fetcher::new_combo_fetcher_from_urls, helper::{PsyUPSDummyProverHelper, create_dummy_prover_helper}, lite::runner::run_dummy_prover_lite};

use crate::end_cap::dummy::DummyUPSStandardEndCapCircuit;

pub fn create_plonky2_dummy_end_cap_prover<N: QNetworkTypesConfig<QHash = QHashOut<C::F>, F = C::F>, C: QGenericConfig<D> + 'static, const D: usize>(
    coordinator_api_url: &str,
    realm_api_url: &str,
) -> anyhow::Result<PsyUPSDummyProverHelper<N, HttpClient, HttpClient, DummyUPSStandardEndCapCircuit<C, D>>>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + FieldQHasher<C::F, QHashOut<C::F>>,
    C::F: QFelt64,
    QHashOut<C::F>: QFHashBase<C::F>,
{
    let prover = DummyUPSStandardEndCapCircuit::<C, D>::new_with_config(false);
    create_dummy_prover_helper::<N, DummyUPSStandardEndCapCircuit<C, D>>(coordinator_api_url, realm_api_url, prover)
}


pub async fn run_plonky2_dummy_prover_lite<N: QNetworkTypesConfig<QHash = QHashOut<C::F>, F = C::F> + 'static, C: QGenericConfig<D> + 'static, const D: usize>(
    realm_api_url: &str,
    coordinator_api_url: &str,
    min_state_updates_per_call: u32,
    max_state_updates_per_call: u32,
    max_contract_calls_per_uop: u32,
    start_user_id: u64,
    count: u64,
    batches: u32,
) -> anyhow::Result<()> 
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + FieldQHasher<C::F, QHashOut<C::F>>,
    C::F: QFelt64,
    QHashOut<C::F>: QFHashBase<C::F> + Q256BitHash,
{
    if count == 0 {
        anyhow::bail!("Count must be greater than zero");
    }
    let data_fetcher = new_combo_fetcher_from_urls::<N>(coordinator_api_url, realm_api_url)?;
    let prover = DummyUPSStandardEndCapCircuit::<C, D>::new_with_config(false);
    run_dummy_prover_lite::<N::HasherBase, _, DummyUPSStandardEndCapCircuit<C, D>, N::F, N::QHash>(
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
