// RealmFinalizeGUTA proof input is RealmFinalizeGUTAInput itself (in psy_data::guta::realm_finalize).
// No wrapper struct needed — proofs/verifier data arrive as worker child dependencies.
// This module re-exports the input type for use in proof_input path resolution.

pub use crate::guta::realm_finalize::RealmFinalizeGUTAInput as RealmFinalizeGUTACircuitInput;