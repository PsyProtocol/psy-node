use serde::{Deserialize, Serialize};
use ts_rs::TS;

include!(concat!(env!("OUT_DIR"), "/chain_id.rs"));

#[derive(TS)]
#[ts(export)]
#[pderive::serialize_enum_repr_strum]
#[repr(u8)]
pub enum PsyChainNetworkType {
    LocalDevnet = 0,
    PsyTeamDevnet = 1,
    InternalDevnet = 2,
    InternalTestnet = 3,
    InternalPreProduction = 4,
    PsyPublicCanary = 5,
    PsyPublicTestnet = 6,
    PsyMainnet = 7,
}

impl PsyChainNetworkType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
    pub fn get_chain_id(&self) -> u64 {
        match self {
            PsyChainNetworkType::LocalDevnet => PSY_CHAIN_ID_LOCAL_DEVNET,
            PsyChainNetworkType::PsyPublicTestnet => PSY_CHAIN_ID_PSY_PUBLIC_TESTNET,
            PsyChainNetworkType::PsyMainnet => PSY_CHAIN_ID_PSY_MAINNET,
            _ => panic!("Unsupported network selector: {:?}", self),
        }
    }
    pub fn try_from_chain_id(chain_id: u64) -> anyhow::Result<Self> {
        match chain_id {
            PSY_CHAIN_ID_LOCAL_DEVNET => Ok(PsyChainNetworkType::LocalDevnet),
            PSY_CHAIN_ID_PSY_PUBLIC_TESTNET => Ok(PsyChainNetworkType::PsyPublicTestnet),
            PSY_CHAIN_ID_PSY_MAINNET => Ok(PsyChainNetworkType::PsyMainnet),
            _ => anyhow::bail!("Invalid network magic: {}", chain_id),
        }
    }
}
impl From<PsyChainNetworkType> for u8 {
    fn from(value: PsyChainNetworkType) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for PsyChainNetworkType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PsyChainNetworkType::LocalDevnet),
            1 => Ok(PsyChainNetworkType::PsyTeamDevnet),
            2 => Ok(PsyChainNetworkType::InternalDevnet),
            3 => Ok(PsyChainNetworkType::InternalTestnet),
            4 => Ok(PsyChainNetworkType::InternalPreProduction),
            5 => Ok(PsyChainNetworkType::PsyPublicCanary),
            6 => Ok(PsyChainNetworkType::PsyPublicTestnet),
            7 => Ok(PsyChainNetworkType::PsyMainnet),
            _ => Err(anyhow::format_err!("Invalid PsyChainNetworkType value: {}", value)),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "clap_cli", derive(clap::ValueEnum))]
pub enum PsyNetworkTypeInput {
    #[default]
    #[serde(rename = "local-devnet")]
    LocalDevnet,
    #[serde(rename = "psy-team-devnet")]
    PsyTeamDevnet,
    #[serde(rename = "internal-devnet")]
    InternalDevnet,
    #[serde(rename = "internal-testnet")]
    InternalTestnet,
    #[serde(rename = "internal-pre-production")]
    InternalPreProduction,
    #[serde(rename = "psy-public-canary")]
    PsyPublicCanary,
    #[serde(rename = "psy-public-testnet")]
    PsyPublicTestnet,
    #[serde(rename = "psy-mainnet")]
    PsyMainnet,
}

impl ToString for PsyNetworkTypeInput {
    fn to_string(&self) -> String {
        match self {
            PsyNetworkTypeInput::LocalDevnet => "local-devnet".to_string(),
            PsyNetworkTypeInput::PsyTeamDevnet => "psy-team-devnet".to_string(),
            PsyNetworkTypeInput::InternalDevnet => "internal-devnet".to_string(),
            PsyNetworkTypeInput::InternalTestnet => "internal-testnet".to_string(),
            PsyNetworkTypeInput::InternalPreProduction => "internal-pre-production".to_string(),
            PsyNetworkTypeInput::PsyPublicCanary => "psy-public-canary".to_string(),
            PsyNetworkTypeInput::PsyPublicTestnet => "psy-public-testnet".to_string(),
            PsyNetworkTypeInput::PsyMainnet => "psy-mainnet".to_string(),
        }
    }
}
impl TryFrom<&str> for PsyNetworkTypeInput {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "local-devnet" => Ok(PsyNetworkTypeInput::LocalDevnet),
            "psy-team-devnet" => Ok(PsyNetworkTypeInput::PsyTeamDevnet),
            "internal-devnet" => Ok(PsyNetworkTypeInput::InternalDevnet),
            "internal-testnet" => Ok(PsyNetworkTypeInput::InternalTestnet),
            "internal-pre-production" => Ok(PsyNetworkTypeInput::InternalPreProduction),
            "psy-public-canary" => Ok(PsyNetworkTypeInput::PsyPublicCanary),
            "psy-public-testnet" => Ok(PsyNetworkTypeInput::PsyPublicTestnet),
            "psy-mainnet" => Ok(PsyNetworkTypeInput::PsyMainnet),
            _ => anyhow::bail!("invalid network mode: {}", value),
        }
    }
}

impl From<PsyNetworkTypeInput> for PsyChainNetworkType {
    fn from(value: PsyNetworkTypeInput) -> Self {
        match value {
            PsyNetworkTypeInput::LocalDevnet => PsyChainNetworkType::LocalDevnet,
            PsyNetworkTypeInput::PsyTeamDevnet => PsyChainNetworkType::PsyTeamDevnet,
            PsyNetworkTypeInput::InternalDevnet => PsyChainNetworkType::InternalDevnet,
            PsyNetworkTypeInput::InternalTestnet => PsyChainNetworkType::InternalTestnet,
            PsyNetworkTypeInput::InternalPreProduction => PsyChainNetworkType::InternalPreProduction,
            PsyNetworkTypeInput::PsyPublicCanary => PsyChainNetworkType::PsyPublicCanary,
            PsyNetworkTypeInput::PsyPublicTestnet => PsyChainNetworkType::PsyPublicTestnet,
            PsyNetworkTypeInput::PsyMainnet => PsyChainNetworkType::PsyMainnet,
        }
    }
}
impl From<PsyChainNetworkType> for PsyNetworkTypeInput {
    fn from(value: PsyChainNetworkType) -> Self {
        match value {
            PsyChainNetworkType::LocalDevnet => PsyNetworkTypeInput::LocalDevnet,
            PsyChainNetworkType::PsyTeamDevnet => PsyNetworkTypeInput::PsyTeamDevnet,
            PsyChainNetworkType::InternalDevnet => PsyNetworkTypeInput::InternalDevnet,
            PsyChainNetworkType::InternalTestnet => PsyNetworkTypeInput::InternalTestnet,
            PsyChainNetworkType::InternalPreProduction => PsyNetworkTypeInput::InternalPreProduction,
            PsyChainNetworkType::PsyPublicCanary => PsyNetworkTypeInput::PsyPublicCanary,
            PsyChainNetworkType::PsyPublicTestnet => PsyNetworkTypeInput::PsyPublicTestnet,
            PsyChainNetworkType::PsyMainnet => PsyNetworkTypeInput::PsyMainnet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_network_identities_roundtrip() {
        for network in [PsyChainNetworkType::LocalDevnet, PsyChainNetworkType::PsyPublicTestnet, PsyChainNetworkType::PsyMainnet] {
            assert_eq!(PsyChainNetworkType::try_from_chain_id(network.get_chain_id()).unwrap(), network);
            assert_eq!(PsyChainNetworkType::try_from(network.to_u8()).unwrap(), network);
        }
        assert_eq!(PSY_CHAIN_ID_LOCAL_DEVNET, 1384803358401154921);
        assert!(PsyChainNetworkType::try_from_chain_id(0).is_err());
    }

    #[test]
    fn unsupported_networks_fail_closed() {
        for network in [PsyChainNetworkType::PsyTeamDevnet, PsyChainNetworkType::InternalDevnet, PsyChainNetworkType::InternalTestnet, PsyChainNetworkType::InternalPreProduction, PsyChainNetworkType::PsyPublicCanary] {
            assert!(std::panic::catch_unwind(|| network.get_chain_id()).is_err());
        }
    }
}