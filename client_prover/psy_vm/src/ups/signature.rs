use plonky2::field::goldilocks_field::GoldilocksField;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SDKeyPlonky2CircuitWitnessInput {
    pub state_reader_results: crate::ups::state_reader::StateReaderResults<GoldilocksField>,
    pub circuit_inputs: Vec<GoldilocksField>,
}
