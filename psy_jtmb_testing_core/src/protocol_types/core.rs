use parth_core::{data::hash::hash256::Hash256, pgoldilocks::PoseidonHasher, protocol::core_types::{QNetworkHashTypes, QNetworkZKTypes}};
use parth_crypto::hash::sha256::CoreSha256Hasher;


use crate::{proof::PsyTestJTMBProof, utils::jtmb_standard_circuit::JTMBCircuitConfig, zk_verifier::PsyJTMBZKVerifier};

pub struct JTMBPoseidonGoldilocksConfig;
impl JTMBCircuitConfig for JTMBPoseidonGoldilocksConfig {
    type Hash = parth_core::PHash;
    type Hasher = PoseidonHasher;
    type F = parth_core::PF;
}

#[derive(Debug, Clone, Default)]
pub struct ZKTypesJTMBGoldilocksPoseidon;


impl QNetworkHashTypes for ZKTypesJTMBGoldilocksPoseidon {
    type QHash = parth_core::PHash;

    type HasherBase = PoseidonHasher;

    type F = parth_core::PF;
}

impl QNetworkZKTypes for ZKTypesJTMBGoldilocksPoseidon {
    type ZKProof = PsyTestJTMBProof<parth_core::PHash>;
    type ZKVerifier = PsyJTMBZKVerifier<JTMBPoseidonGoldilocksConfig>;
}


pub struct JTMBSha256U64Config;
impl JTMBCircuitConfig for JTMBSha256U64Config {
    type Hash = Hash256;
    type Hasher = CoreSha256Hasher;
    type F = u64;
}

#[derive(Debug, Clone, Default)]
pub struct ZKTypesJTMBSha256U64;


impl QNetworkHashTypes for ZKTypesJTMBSha256U64 {
    type QHash = Hash256;

    type HasherBase = CoreSha256Hasher;

    type F = u64;
}

impl QNetworkZKTypes for ZKTypesJTMBSha256U64 {
    type ZKProof = PsyTestJTMBProof<Hash256>;
    type ZKVerifier = PsyJTMBZKVerifier<JTMBSha256U64Config>;
}