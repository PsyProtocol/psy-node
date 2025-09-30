use serde::{Deserialize, Serialize};

use crate::common::core::{data::job_id::ProvingJobCircuitType, protocol::QHashBase, serializable::QPDSerializable};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> Hash: Deserialize<'de2>")]
pub struct QDevDummyProof<Hash: QHashBase> {
    pub circuit_type: ProvingJobCircuitType,
    pub public_inputs: Hash, // the public inputs of the proof is a hash which is the hash of the QParthProofPublicInputsPreimage
    pub is_valid: bool, // used for debuggin around invalid proofs
}

impl<Hash: QHashBase> QPDSerializable for QDevDummyProof<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }
}






