use serde::{Deserialize, Serialize};
use ts_rs::TS;


#[derive(TS)]
#[ts(export)]
#[pderive::serialize_enum_repr_strum]
#[repr(u8)]
pub enum PsyChainProvingBackendType {
    Plonky2PoseidonGoldilocks = 0,
    JTMBPoseidonGoldilocks = 1,
    JTMBSha256U64 = 2,
}

impl PsyChainProvingBackendType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<PsyChainProvingBackendType> for u8 {
    fn from(value: PsyChainProvingBackendType) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for PsyChainProvingBackendType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PsyChainProvingBackendType::Plonky2PoseidonGoldilocks),
            1 => Ok(PsyChainProvingBackendType::JTMBPoseidonGoldilocks),
            2 => Ok(PsyChainProvingBackendType::JTMBSha256U64),
            _ => Err(anyhow::format_err!("Invalid PsyChainProvingBackendType value: {}", value)),
        }
    }   
}

#[derive(Clone, Debug, Serialize, Deserialize, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "clap_cli", derive(clap::ValueEnum))]
pub enum PsyChainProvingBackendTypeInput {
    #[default]
    #[serde(rename = "plonky2-poseidon-goldilocks")]
    Plonky2PoseidonGoldilocks,
    #[serde(rename = "jtmb-poseidon-goldilocks")]
    JTMBPoseidonGoldilocks,
    #[serde(rename = "jtmb-sha256-u64")]
    JTMBSha256U64,
}

impl ToString for PsyChainProvingBackendTypeInput {
    fn to_string(&self) -> String {
        match self {
            PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks => "plonky2-poseidon-goldilocks".to_string(),
            PsyChainProvingBackendTypeInput::JTMBPoseidonGoldilocks => "jtmb-poseidon-goldilocks".to_string(),
            PsyChainProvingBackendTypeInput::JTMBSha256U64 => "jtmb-sha256-u64".to_string(),
        }
    }
}
impl TryFrom<&str> for PsyChainProvingBackendTypeInput {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "plonky2-poseidon-goldilocks" => Ok(PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks),
            "jtmb-poseidon-goldilocks" => Ok(PsyChainProvingBackendTypeInput::JTMBPoseidonGoldilocks),
            "jtmb-sha256-u64" => Ok(PsyChainProvingBackendTypeInput::JTMBSha256U64),
            _ => anyhow::bail!("invalid proving backend type: {}", value),
        }
    }
}

impl From<PsyChainProvingBackendTypeInput> for PsyChainProvingBackendType {
    fn from(value: PsyChainProvingBackendTypeInput) -> Self {
        match value {
            PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks => PsyChainProvingBackendType::Plonky2PoseidonGoldilocks,
            PsyChainProvingBackendTypeInput::JTMBPoseidonGoldilocks => PsyChainProvingBackendType::JTMBPoseidonGoldilocks,
            PsyChainProvingBackendTypeInput::JTMBSha256U64 => PsyChainProvingBackendType::JTMBSha256U64,
        }
    }
}
impl From<PsyChainProvingBackendType> for PsyChainProvingBackendTypeInput {
    fn from(value: PsyChainProvingBackendType) -> Self {
        match value {
            PsyChainProvingBackendType::Plonky2PoseidonGoldilocks => PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks,
            PsyChainProvingBackendType::JTMBPoseidonGoldilocks => PsyChainProvingBackendTypeInput::JTMBPoseidonGoldilocks,
            PsyChainProvingBackendType::JTMBSha256U64 => PsyChainProvingBackendTypeInput::JTMBSha256U64,
        }
    }
}
