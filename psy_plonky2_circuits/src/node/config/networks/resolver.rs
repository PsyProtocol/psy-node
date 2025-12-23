use parth_core::pgoldilocks::QHashOut;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::{
    config::network_config::{PsyNodeCircuitFingerprintConfig, PsyNodeCircuitFingerprintConfigProvider},
    genesis::genesis_block_setup::{PsyGenesisBlockSetupData, PsyGenesisBlockSetupDataProvider},
};

use crate::node::config::networks::local_devnet::{get_genesis_block_setup_data_for_local_devnet, get_psy_node_circuit_config_for_local_devnet};

type F = parth_core::PF;
type Hash = QHashOut<F>;

#[derive(Clone, Debug, Copy)]
pub struct PsyPlonky2NodeConfigResolver {}
impl PsyPlonky2NodeConfigResolver {
    pub fn new() -> Self {
        Self {}
    }
}
impl PsyNodeCircuitFingerprintConfigProvider<Hash> for PsyPlonky2NodeConfigResolver {
    fn get_circuit_fingerprint_config_for_network(&self, network: PsyChainNetworkType) -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>> {
        match network {
            PsyChainNetworkType::LocalDevnet => get_psy_node_circuit_config_for_local_devnet(),
            _ => Err(anyhow::anyhow!("Unsupported network type for circuit fingerprint config: {:?}", network)),
        }
    }
}
impl PsyGenesisBlockSetupDataProvider<F, Hash> for PsyPlonky2NodeConfigResolver {
    fn get_genesis_block_setup_data_for_network(&self, network: PsyChainNetworkType, genesis_data_path: Option<String>) -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>> {
        match network {
            PsyChainNetworkType::LocalDevnet => get_genesis_block_setup_data_for_local_devnet(genesis_data_path),
            _ => Err(anyhow::anyhow!("Unsupported network type for genesis block setup data: {:?}", network)),
        }
    }
}
