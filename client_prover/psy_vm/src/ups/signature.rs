use plonky2::field::goldilocks_field::GoldilocksField;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::vm::cfc_input::DapenContractFunctionCircuitInput;

type GF = GoldilocksField;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct DPNSoftwareDefinedSignatureInput {
    pub cfc_input: DapenContractFunctionCircuitInput<GF>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plonky2SoftwareDefinedSignatureInput {
    pub state_reader_results: crate::ups::state_reader::StateReaderResults<GoldilocksField>,
    pub circuit_inputs: Vec<GoldilocksField>,
}
