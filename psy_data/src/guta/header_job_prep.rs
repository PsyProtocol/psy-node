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

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{felt::FromPrimitiveValuesFelt, pgoldilocks::{PoseidonHasher, QHashOut}, PF};

    type Hash = QHashOut<PF>;

    #[test]
    fn job_metadata_hash_matches_bare_header_hash() {
        let value = GUTAHeaderWithJobMetadata::<PF, Hash>::qp_rand_gen();
        assert_eq!(
            value.qfhash::<PoseidonHasher>(),
            value.header.qfhash::<PoseidonHasher>()
        );
    }

    #[test]
    fn global_user_tree_key_reflects_transition_position() {
        let mut value = GUTAHeaderWithJobMetadata::<PF, Hash>::qp_rand_gen();
        value.header.state_transition.node_level = PF::from_u64_value(9);
        value.header.state_transition.node_index = PF::from_u64_value(1234);

        let key = value.get_global_user_tree_key();
        assert_eq!(key, SimpleMerkleNodeKey { level: 9, index: 1234 });
    }

    #[test]
    fn rand_gen_produces_distinct_values() {
        let first = GUTAHeaderWithJobMetadata::<PF, Hash>::qp_rand_gen();
        let second = GUTAHeaderWithJobMetadata::<PF, Hash>::qp_rand_gen();
        assert_ne!(first, second);
    }
}