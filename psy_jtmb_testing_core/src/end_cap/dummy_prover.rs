use jsonrpsee::http_client::HttpClient;
use parth_core::
    protocol::core_types::QNetworkTypesConfig
;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_dummy_prover::helper::{create_dummy_prover_helper, PsyUPSDummyProverHelper};

use crate::{ circuit_library::core::get_test_circuit_authority_key, proving::circuits::dummy_end_cap::DummyUPSStandardEndCapCircuit, utils::jtmb_standard_circuit::JTMBCircuitConfig};

pub fn create_jtmb_dummy_end_cap_prover<N: QNetworkTypesConfig<QHash = C::Hash, F = C::F>, C: JTMBCircuitConfig>(
    coordinator_api_url: &str,
    realm_api_url: &str,
    network: PsyChainNetworkType,
) -> anyhow::Result<PsyUPSDummyProverHelper<N, HttpClient, HttpClient, DummyUPSStandardEndCapCircuit<C>>>
{
    let private_key = get_test_circuit_authority_key(network);
    let prover = DummyUPSStandardEndCapCircuit::<C>::new(&private_key);
    create_dummy_prover_helper::<N, DummyUPSStandardEndCapCircuit<C>>(coordinator_api_url, realm_api_url, prover)
}