use serde::{Deserialize, Serialize};
use ts_rs::TS;


#[derive(TS)]
#[ts(export)]
#[pderive::serialize_enum_repr_strum]
#[repr(u8)]
pub enum PsyAPIURLRotationStrategy {
    RoundRobin = 0,
    Random = 1,
    ContinueUntilFailure = 2,
    ContinueUntilFailureOrNoWorkFor3Seconds = 3,
    SmartSwapV1 = 4,
}

impl PsyAPIURLRotationStrategy {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl From<PsyAPIURLRotationStrategy> for u8 {
    fn from(value: PsyAPIURLRotationStrategy) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for PsyAPIURLRotationStrategy {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PsyAPIURLRotationStrategy::RoundRobin),
            1 => Ok(PsyAPIURLRotationStrategy::Random),
            2 => Ok(PsyAPIURLRotationStrategy::ContinueUntilFailure),
            3 => Ok(PsyAPIURLRotationStrategy::ContinueUntilFailureOrNoWorkFor3Seconds),
            4 => Ok(PsyAPIURLRotationStrategy::SmartSwapV1),
            _ => Err(anyhow::format_err!("Invalid PsyAPIURLRotationStrategy value: {}", value)),
        }
    }   
}

#[derive(Clone, Debug, Serialize, Deserialize, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "clap_cli", derive(clap::ValueEnum))]
pub enum PsyAPIURLRotationStrategyInput {
    #[default]
    #[serde(rename = "round-robin")]
    RoundRobin,
    #[serde(rename = "random")]
    Random,
    #[serde(rename = "continue-until-failure")]
    ContinueUntilFailure,
    #[serde(rename = "continue-until-failure-or-no-work-for-3-seconds")]
    ContinueUntilFailureOrNoWorkFor3Seconds,
    #[serde(rename = "smart-swap-v1")]
    SmartSwapV1,
}

impl ToString for PsyAPIURLRotationStrategyInput {
    fn to_string(&self) -> String {
        match self {
            PsyAPIURLRotationStrategyInput::RoundRobin => "round-robin".to_string(),
            PsyAPIURLRotationStrategyInput::Random => "random".to_string(),
            PsyAPIURLRotationStrategyInput::ContinueUntilFailure => "continue-until-failure".to_string(),
            PsyAPIURLRotationStrategyInput::ContinueUntilFailureOrNoWorkFor3Seconds => "continue-until-failure-or-no-work-for-3-seconds".to_string(),
            PsyAPIURLRotationStrategyInput::SmartSwapV1 => "smart-swap-v1".to_string(),
        }
    }
}
impl TryFrom<&str> for PsyAPIURLRotationStrategyInput {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "round-robin" => Ok(PsyAPIURLRotationStrategyInput::RoundRobin),
            "random" => Ok(PsyAPIURLRotationStrategyInput::Random),
            "continue-until-failure" => Ok(PsyAPIURLRotationStrategyInput::ContinueUntilFailure),
            "continue-until-failure-or-no-work-for-3-seconds" => Ok(PsyAPIURLRotationStrategyInput::ContinueUntilFailureOrNoWorkFor3Seconds),
            "smart-swap-v1" => Ok(PsyAPIURLRotationStrategyInput::SmartSwapV1),
            _ => anyhow::bail!("invalid proving backend type: {}", value),
        }
    }
}

impl From<PsyAPIURLRotationStrategyInput> for PsyAPIURLRotationStrategy {
    fn from(value: PsyAPIURLRotationStrategyInput) -> Self {
        match value {
            PsyAPIURLRotationStrategyInput::RoundRobin => PsyAPIURLRotationStrategy::RoundRobin,
            PsyAPIURLRotationStrategyInput::Random => PsyAPIURLRotationStrategy::Random,
            PsyAPIURLRotationStrategyInput::ContinueUntilFailure => PsyAPIURLRotationStrategy::ContinueUntilFailure,
            PsyAPIURLRotationStrategyInput::ContinueUntilFailureOrNoWorkFor3Seconds => PsyAPIURLRotationStrategy::ContinueUntilFailureOrNoWorkFor3Seconds,
            PsyAPIURLRotationStrategyInput::SmartSwapV1 => PsyAPIURLRotationStrategy::SmartSwapV1,
        }
    }
}
impl From<PsyAPIURLRotationStrategy> for PsyAPIURLRotationStrategyInput {
    fn from(value: PsyAPIURLRotationStrategy) -> Self {
        match value {
            PsyAPIURLRotationStrategy::RoundRobin => PsyAPIURLRotationStrategyInput::RoundRobin,
            PsyAPIURLRotationStrategy::Random => PsyAPIURLRotationStrategyInput::Random,
            PsyAPIURLRotationStrategy::ContinueUntilFailure => PsyAPIURLRotationStrategyInput::ContinueUntilFailure,
            PsyAPIURLRotationStrategy::ContinueUntilFailureOrNoWorkFor3Seconds => PsyAPIURLRotationStrategyInput::ContinueUntilFailureOrNoWorkFor3Seconds,
            PsyAPIURLRotationStrategy::SmartSwapV1 => PsyAPIURLRotationStrategyInput::SmartSwapV1,
        }
    }
}
