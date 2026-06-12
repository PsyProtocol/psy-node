use parth_core::protocol::core_types::{QNetworkTreeCircuitSpecificConstantsData, QNetworkTreeConstantsData};
use psy_core::constants::chain_id::PsyChainNetworkType;

#[pderive::serialize_copy_ts_export]
pub struct PsyNetworkChainConfig {
    pub network_type: PsyChainNetworkType,
    pub tree_constants: QNetworkTreeConstantsData,
    pub circuit_constants: QNetworkTreeCircuitSpecificConstantsData,
}



#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct PsyNodeCircuitFingerprintConfig<Hash>{
    pub guta_circuit_whitelist_root: Hash,
    pub register_users_circuit_whitelist_root: Hash,
    pub deploy_contracts_circuit_whitelist_root: Hash,
    pub checkpoint_state_transition_circuit_fingerprint: Hash,
    pub genesis_checkpoint_state_transition_fingerprint: Hash,
}

pub trait PsyNodeCircuitFingerprintConfigProvider<Hash> {
    fn get_circuit_fingerprint_config_for_network(&self, network: PsyChainNetworkType) -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>>;
}