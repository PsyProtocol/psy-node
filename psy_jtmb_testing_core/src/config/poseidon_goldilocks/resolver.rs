use parth_core::pgoldilocks::QHashOut;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::{
    config::network_config::{PsyNodeCircuitFingerprintConfig, PsyNodeCircuitFingerprintConfigProvider},
    genesis::genesis_block_setup::{PsyGenesisBlockSetupData, PsyGenesisBlockSetupDataProvider},
};

use crate::config::poseidon_goldilocks::local_devnet::{get_genesis_block_setup_data_for_local_devnet, get_psy_node_jtmb_poseidon_goldilocks_config_for_network};


type F = parth_core::PF;
type Hash = QHashOut<F>;

#[derive(Clone, Debug, Copy)]
pub struct PsyJTMBPoseidonGoldilocksNodeConfigResolver {}
impl PsyJTMBPoseidonGoldilocksNodeConfigResolver {
    pub fn new() -> Self {
        Self {}
    }
}
impl PsyNodeCircuitFingerprintConfigProvider<Hash> for PsyJTMBPoseidonGoldilocksNodeConfigResolver {
    fn get_circuit_fingerprint_config_for_network(&self, network: PsyChainNetworkType) -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>> {
        get_psy_node_jtmb_poseidon_goldilocks_config_for_network(network)
    }
}
impl PsyGenesisBlockSetupDataProvider<F, Hash> for PsyJTMBPoseidonGoldilocksNodeConfigResolver {
    fn get_genesis_block_setup_data_for_network(&self, network: PsyChainNetworkType) -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>> {
        match network {
            PsyChainNetworkType::LocalDevnet => get_genesis_block_setup_data_for_local_devnet(),
            _ => Err(anyhow::anyhow!("Unsupported network type for genesis block setup data: {:?}", network)),
        }
    }
}
