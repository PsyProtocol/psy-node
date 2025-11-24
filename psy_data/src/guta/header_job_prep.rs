use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, data::hash::merkle_node_key::SimpleMerkleNodeKey, felt::{QFelt64, ToU64Value}, protocol::core_types::QFHashBase, utils::QPGenRandom};
use psy_core::job::job_id::QProvingJobDataID;

use crate::{guta::header::GlobalUserTreeAggregatorHeader, worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId};


#[pderive::serialize_clone_f_hash]
#[repr(C)]
pub struct GUTAHeaderWithJobMetadata<F, Hash> {
    pub header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub metadata: PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>,
}

impl<F: ToU64Value, Hash> GUTAHeaderWithJobMetadata<F, Hash> {
    pub fn get_global_user_tree_key(&self) -> SimpleMerkleNodeKey {
        SimpleMerkleNodeKey::new(
            self.header.state_transition.node_level.to_u64_value() as u8,
            self.header.state_transition.node_index.to_u64_value(),
        )
    }
}
impl<F: ToU64Value, Hash> GUTAHeaderWithJobMetadata<F, Hash> {
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GUTAHeaderWithJobMetadata<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.header.qfhash::<H>()
    }
}


impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAHeaderWithJobMetadata<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        GUTAHeaderWithJobMetadata {
            header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            metadata: PsyProvingJobMetadataWithJobId::qp_rand_gen(),
        }
    }
}