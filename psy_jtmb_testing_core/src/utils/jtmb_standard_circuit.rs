use parth_core::{crypto::hash::traits::FieldQHasher, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;

use crate::{proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData}, utils::circuit_info_library::PsyJTMBCircuitInfoLibrary};
pub trait JTMBCircuitConfig {
    type F: QFelt64;
    type Hash: QFHashBase<Self::F> + Q256BitHash + PartialEq + Copy;
    type Hasher: FieldQHasher<Self::F, Self::Hash>;
}
pub trait QJTMBProofCircuitBase<Hash> {
    fn get_circuit_type(&self) -> ProvingJobCircuitType;
    fn get_verifier_data(&self) -> &PsyTestJTMBProofVerifierData;
    fn get_fingerprint(&self) -> Hash;
}
pub trait QJTMBProofCircuit<C: JTMBCircuitConfig, L: PsyJTMBCircuitInfoLibrary<C::Hash>>: QJTMBProofCircuitBase<C::Hash> {
    fn jtmb_prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<C::Hash, QProvingJobDataID>,
        worker_reward_tag: C::Hash,
    ) -> anyhow::Result<PsyTestJTMBProof<C::Hash>>;
}