use serde::Deserialize;

use crate::{crypto::hash::merkle_proof::MerkleProofCore, data::parth::public_preimage::QParthProofPublicInputsPreimage, protocol::core_types::QHashBase, QJobIdBase};


#[pderive::serialize_clone]
#[serde(bound = "for<'de2> Hash: Deserialize<'de2>")]
pub struct QParthSingleRecursiveWitness<Hash: QHashBase, JobID: QJobIdBase> {
    pub job_id: JobID,
    pub whitelist_inclusion_proof: MerkleProofCore<Hash>,
    pub public_preimage: QParthProofPublicInputsPreimage<Hash>,
}

impl<Hash: QHashBase, JobID: QJobIdBase> QParthSingleRecursiveWitness<Hash, JobID> {
    pub fn new(
        job_id: JobID,
        whitelist_inclusion_proof: MerkleProofCore<Hash>,
        public_preimage: QParthProofPublicInputsPreimage<Hash>,
    ) -> Self {
        Self {
            job_id,
            whitelist_inclusion_proof,
            public_preimage,
        }
    }
}
pub struct QParthComboWitness<Hash: QHashBase, JobID: QJobIdBase> {
    pub left_job_id: JobID,
    pub left_public: QParthProofPublicInputsPreimage<Hash>,
    pub right_job_id: JobID,
    pub right_public: QParthProofPublicInputsPreimage<Hash>,

    pub left_sibling: Hash,
    pub right_sibling: Hash,
    pub left_proof: Option<Hash>,
    pub right_proof: Option<Hash>,
}