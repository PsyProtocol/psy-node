//! Bridge aggregation re-exports.
//!
//! The orchestrator layer was moved into `BridgeAggFinalCircuit::prove_range()`
//! and `BridgeAggFinalCircuit::prebuild_final_circuit()`. This module only
//! re-exports the result type for backward compatibility.

pub use super::bridge_agg_final::BridgeAggProveResult;
