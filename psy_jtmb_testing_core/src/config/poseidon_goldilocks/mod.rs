use crate::{protocol_types::JTMBPoseidonGoldilocksConfig, zk_verifier::PsyJTMBZKVerifier};

pub mod resolver;
mod local_devnet;

pub type PsyJTMBZKVerifierPoseidonGoldilocks = PsyJTMBZKVerifier<JTMBPoseidonGoldilocksConfig>;