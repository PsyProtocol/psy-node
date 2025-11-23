use parth_core::{pgoldilocks::{PoseidonHasher, QHashOut}, protocol::core_types::{QNetworkHashTypes, QNetworkZKTypes, QNetworkZKTypesCopier}};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs}};

use crate::zk_verifier::PsyPlonky2ZKVerifier;

#[derive(Debug, Clone, Default)]
pub struct ZKTypesPlonky2GoldilocksPoseidon;


impl QNetworkHashTypes for ZKTypesPlonky2GoldilocksPoseidon {
    type QHash = QHashOut<GoldilocksField>;

    type HasherBase = PoseidonHasher;

    type F = GoldilocksField;
}

impl QNetworkZKTypes for ZKTypesPlonky2GoldilocksPoseidon {
    type ZKProof = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;
    type ZKVerifier = PsyPlonky2ZKVerifier<PoseidonGoldilocksConfig, 2>;
}