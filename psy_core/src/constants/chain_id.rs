use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub const PSY_CHAIN_ID_LOCAL_DEVNET: u32 = 0;
pub const PSY_CHAIN_ID_PSY_TEAM_DEVNET: u32 = 1;
pub const PSY_CHAIN_ID_INTERNAL_DEVNET: u32 = 2;
pub const PSY_CHAIN_ID_INTERNAL_TESTNET: u32 = 3;
pub const PSY_CHAIN_ID_INTERNAL_PRE_PRODUCTION: u32 = 4;
pub const PSY_CHAIN_ID_PSY_PUBLIC_CANARY: u32 = 0xCFCFCFCF; // CF for Carter Feldman
pub const PSY_CHAIN_ID_PSY_PUBLIC_TESTNET: u32 = 1337;
pub const PSY_CHAIN_ID_PSY_MAINNET: u32 = 0x69797350; // [0x50, 0x73, 0x79, 0x69] -> 0x69797350 in little-endian -> "Psyi"

/*


    let derive_serde: Attribute = syn::parse_quote!(
        #[derive(
            Debug,
            Copy,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde_repr::Serialize_repr,
            serde_repr::Deserialize_repr,
            strum_macros::FromRepr, 
            strum_macros::Display,
        )]
    );
    let derive_rkyv: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
    );
    let derive_speedy: Attribute = syn::parse_quote!(
        #[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
    );
*/

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
    pub fn get_chain_id(&self) -> u32 {
        match self {
            PsyChainNetworkType::LocalDevnet => PSY_CHAIN_ID_LOCAL_DEVNET,
            PsyChainNetworkType::PsyTeamDevnet => PSY_CHAIN_ID_PSY_TEAM_DEVNET,
            PsyChainNetworkType::InternalDevnet => PSY_CHAIN_ID_INTERNAL_DEVNET,
            PsyChainNetworkType::InternalTestnet => PSY_CHAIN_ID_INTERNAL_TESTNET,
            PsyChainNetworkType::InternalPreProduction => PSY_CHAIN_ID_INTERNAL_PRE_PRODUCTION,
            PsyChainNetworkType::PsyPublicCanary => PSY_CHAIN_ID_PSY_PUBLIC_CANARY,
            PsyChainNetworkType::PsyPublicTestnet => PSY_CHAIN_ID_PSY_PUBLIC_TESTNET,
            PsyChainNetworkType::PsyMainnet => PSY_CHAIN_ID_PSY_MAINNET,
        }
    }
    pub fn try_from_chain_id(chain_id: u32) -> anyhow::Result<Self> {
        match chain_id {
            PSY_CHAIN_ID_LOCAL_DEVNET => Ok(PsyChainNetworkType::LocalDevnet),
            PSY_CHAIN_ID_PSY_TEAM_DEVNET => Ok(PsyChainNetworkType::PsyTeamDevnet),
            PSY_CHAIN_ID_INTERNAL_DEVNET => Ok(PsyChainNetworkType::InternalDevnet),
            PSY_CHAIN_ID_INTERNAL_TESTNET => Ok(PsyChainNetworkType::InternalTestnet),
            PSY_CHAIN_ID_INTERNAL_PRE_PRODUCTION => Ok(PsyChainNetworkType::InternalPreProduction),
            PSY_CHAIN_ID_PSY_PUBLIC_CANARY => Ok(PsyChainNetworkType::PsyPublicCanary),
            PSY_CHAIN_ID_PSY_PUBLIC_TESTNET => Ok(PsyChainNetworkType::PsyPublicTestnet),
            PSY_CHAIN_ID_PSY_MAINNET => Ok(PsyChainNetworkType::PsyMainnet),
            _ => anyhow::bail!("Invalid chain ID: {}", chain_id),
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
    fn ensure_chain_id_equals_constant_roundtrip(chain_type: PsyChainNetworkType, expected_chain_id: u32) {
        let chain_id = chain_type.get_chain_id();
        let chain_type_u8 = chain_type.to_u8();
        let converted_chain_type = PsyChainNetworkType::try_from(chain_type_u8).unwrap();
        assert_eq!(chain_type, converted_chain_type);
        assert_eq!(chain_id, expected_chain_id);
        assert_eq!(
            PsyChainNetworkType::try_from_chain_id(chain_id).unwrap(),
            chain_type
        );
    }
    #[test]
    fn test_chain_id_conversion() {
        let chain_types = vec![
            PsyChainNetworkType::LocalDevnet,
            PsyChainNetworkType::PsyTeamDevnet,
            PsyChainNetworkType::InternalDevnet,
            PsyChainNetworkType::InternalTestnet,
            PsyChainNetworkType::InternalPreProduction,
            PsyChainNetworkType::PsyPublicCanary,
            PsyChainNetworkType::PsyPublicTestnet,
            PsyChainNetworkType::PsyMainnet,
        ];
        for chain_type in chain_types {
            let chain_id = chain_type.get_chain_id();
            let converted_chain_type = PsyChainNetworkType::try_from_chain_id(chain_id).unwrap();
            assert_eq!(chain_type, converted_chain_type);
        }
        ensure_chain_id_equals_constant_roundtrip(
            PsyChainNetworkType::LocalDevnet,
            PSY_CHAIN_ID_LOCAL_DEVNET,
        );
        ensure_chain_id_equals_constant_roundtrip(
            PsyChainNetworkType::PsyTeamDevnet,
            PSY_CHAIN_ID_PSY_TEAM_DEVNET,
        );
        ensure_chain_id_equals_constant_roundtrip(
            PsyChainNetworkType::InternalDevnet,
            PSY_CHAIN_ID_INTERNAL_DEVNET,
        );
        ensure_chain_id_equals_constant_roundtrip(
            PsyChainNetworkType::InternalTestnet,
            PSY_CHAIN_ID_INTERNAL_TESTNET,
        );
        ensure_chain_id_equals_constant_roundtrip(
            PsyChainNetworkType::InternalPreProduction,
            PSY_CHAIN_ID_INTERNAL_PRE_PRODUCTION,
        );
        ensure_chain_id_equals_constant_roundtrip(
            PsyChainNetworkType::PsyPublicCanary,
            PSY_CHAIN_ID_PSY_PUBLIC_CANARY,
        );
        ensure_chain_id_equals_constant_roundtrip(
            PsyChainNetworkType::PsyPublicTestnet,
            PSY_CHAIN_ID_PSY_PUBLIC_TESTNET,
        );
        ensure_chain_id_equals_constant_roundtrip(
            PsyChainNetworkType::PsyMainnet,
            PSY_CHAIN_ID_PSY_MAINNET,
        );
    }
}