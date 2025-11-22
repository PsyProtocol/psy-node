use parth_core::protocol::core_types::QNetworkTreeCircuitSpecificConstantsData;

use crate::{constants::chain_id::PsyChainNetworkType, network_config::PsyNetworkLocalDevnetConstants};


pub fn get_circuit_config_for_network(network: PsyChainNetworkType) -> QNetworkTreeCircuitSpecificConstantsData {
    match network {
        PsyChainNetworkType::LocalDevnet => QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<PsyNetworkLocalDevnetConstants>(),
        PsyChainNetworkType::PsyTeamDevnet => QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<PsyNetworkLocalDevnetConstants>(),
        PsyChainNetworkType::InternalDevnet => QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<PsyNetworkLocalDevnetConstants>(),
        PsyChainNetworkType::InternalTestnet => QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<PsyNetworkLocalDevnetConstants>(),
        PsyChainNetworkType::InternalPreProduction => QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<PsyNetworkLocalDevnetConstants>(),
        PsyChainNetworkType::PsyPublicCanary => QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<PsyNetworkLocalDevnetConstants>(),
        PsyChainNetworkType::PsyPublicTestnet => QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<PsyNetworkLocalDevnetConstants>(),
        PsyChainNetworkType::PsyMainnet => QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<PsyNetworkLocalDevnetConstants>(),
    }
}