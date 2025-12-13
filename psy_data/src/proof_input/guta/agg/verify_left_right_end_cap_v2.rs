#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
use parth_core::protocol::core_types::Q256BitHash;
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{FieldQHasher, QFieldHashable},
    },
    felt::{QFelt, QFelt64},
    protocol::core_types::QFHashBase,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{
    guta::{
        header::GlobalUserTreeAggregatorHeader, header_extended::GlobalUserTreeAggregatorHeaderWithJobId,
        sub_tree_transition::SubTreeNodeStateTransition,
    },
    proof_input::guta::VerifyEndCapSimpleStandardInput,
    v1::qdata::user_end_cap_result::PUPSEndCapResultCompact,
    worker::{
        metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyLeftGUTARightEndCapCircuitInputV2<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
}

impl<F: QFelt, Hash: Copy> GUTAVerifyLeftGUTARightEndCapCircuitInputV2<F, Hash> {
    pub fn get_end_cap_result_b(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.right_global_user_tree_delta_merkle_proof.old_value,
            end_user_leaf_hash: self.right_global_user_tree_delta_merkle_proof.new_value,
            checkpoint_tree_root_hash: self.right_end_cap.checkpoint_root,
            user_id: F::from_u64_value(self.right_global_user_tree_delta_merkle_proof.index),
        }
    }
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self, global_user_tree_height: usize) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.left_header.checkpoint_tree_root,
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.right_global_user_tree_delta_merkle_proof.old_value,
                new_node_value: self.right_global_user_tree_delta_merkle_proof.new_value,
                node_index: F::from_u64_value(self.right_global_user_tree_delta_merkle_proof.index),
                node_level: F::from_u64_value(global_user_tree_height as u64),
            },
            stats: self.right_end_cap.guta_stats,
            total_aggregation_proofs_generated: F::ZERO_VALUE,
        }
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.left_header.checkpoint_tree_root,
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_header.state_transition.old_node_value,
                new_node_value: self.right_global_user_tree_delta_merkle_proof.new_root,
                node_index: self.left_header.state_transition.node_index,
                node_level: self.left_header.state_transition.node_level,
            },
            stats: self.left_header.stats.combine_with(&self.right_end_cap.guta_stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated + F::from_u8_value(1),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyLeftGUTARightEndCapCircuitInputV2<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }

    pub fn get_job_witness_and_new_guta<Hasher: FieldQHasher<F, Hash>>(
        &self,
        unique_pending_id: u64,
        level: u8,
        index: u64,
        left_job_id: QProvingJobDataID,
        right_job_id: QProvingJobDataID,
    ) -> (
        PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>,
        GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>,
    ) {
        let job_id = QProvingJobDataID::guta_left_linear_right_end_cap_proof(unique_pending_id, level as u32, index);
        let new_guta_header = GlobalUserTreeAggregatorHeaderWithJobId {
            job_id,
            header: self.get_new_guta_header(),
        };
        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id: job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: self.get_public_inputs_hash_no_rewards_tag::<Hasher>(),
                reward_tree_node_index: index,
                reward_tree_node_level: 0,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD,
                reward_tree_node_children: 1,
                dependencies: vec![left_job_id, right_job_id],
            },
        };
        (job_metadata, new_guta_header)
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyRightGUTALeftEndCapCircuitInputV2<F, Hash> {
    pub left_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub left_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
    pub left_historical_checkpoint_merkle_proof: MerkleProofCore<Hash>,
    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
}

impl<F: QFelt, Hash: Copy> GUTAVerifyRightGUTALeftEndCapCircuitInputV2<F, Hash> {
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_end_cap_result_a(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.left_global_user_tree_delta_merkle_proof.old_value,
            end_user_leaf_hash: self.left_global_user_tree_delta_merkle_proof.new_value,
            checkpoint_tree_root_hash: self.left_historical_checkpoint_merkle_proof.root,
            user_id: F::from_u64_value(self.left_global_user_tree_delta_merkle_proof.index),
        }
    }
    pub fn get_guta_header_a(&self, global_user_tree_height: usize) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.right_header.checkpoint_tree_root,
            guta_circuit_whitelist: self.right_header.guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_global_user_tree_delta_merkle_proof.old_value,
                new_node_value: self.left_global_user_tree_delta_merkle_proof.new_value,
                node_index: F::from_u64_value(self.left_global_user_tree_delta_merkle_proof.index),
                node_level: F::from_u64_value(global_user_tree_height as u64),
            },
            stats: self.left_end_cap.guta_stats,
            total_aggregation_proofs_generated: F::ZERO_VALUE,
        }
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.right_header.checkpoint_tree_root,
            guta_circuit_whitelist: self.right_header.guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_global_user_tree_delta_merkle_proof.old_root,
                new_node_value: self.right_header.state_transition.new_node_value,
                node_index: self.right_header.state_transition.node_index,
                node_level: self.right_header.state_transition.node_level,
            },
            stats: self.left_end_cap.guta_stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.right_header.total_aggregation_proofs_generated + F::from_u8_value(1),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyRightGUTALeftEndCapCircuitInputV2<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }
}
#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyTwoEndCapCircuitInputV2<F, Hash> {
    pub left_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub left_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
    pub right_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
}

impl<F: QFelt, Hash: Copy> GUTAVerifyTwoEndCapCircuitInputV2<F, Hash> {
    pub fn get_end_cap_result_a(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.left_global_user_tree_delta_merkle_proof.old_value,
            end_user_leaf_hash: self.left_global_user_tree_delta_merkle_proof.new_value,
            checkpoint_tree_root_hash: self.left_end_cap.checkpoint_historical_merkle_proof.root,
            user_id: F::from_u64_value(self.left_global_user_tree_delta_merkle_proof.index),
        }
    }
    pub fn get_end_cap_result_b(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.right_global_user_tree_delta_merkle_proof.old_value,
            end_user_leaf_hash: self.right_global_user_tree_delta_merkle_proof.new_value,
            checkpoint_tree_root_hash: self.right_end_cap.checkpoint_historical_merkle_proof.root,
            user_id: F::from_u64_value(self.right_global_user_tree_delta_merkle_proof.index),
        }
    }
    pub fn get_guta_header_a(&self, global_user_tree_height: usize, guta_circuit_whitelist: Hash) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.left_end_cap.checkpoint_historical_merkle_proof.root,
            guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_global_user_tree_delta_merkle_proof.old_value,
                new_node_value: self.left_global_user_tree_delta_merkle_proof.new_value,
                node_index: F::from_u64_value(self.left_global_user_tree_delta_merkle_proof.index),
                node_level: F::from_u64_value(global_user_tree_height as u64),
            },
            stats: self.left_end_cap.guta_stats,
            total_aggregation_proofs_generated: F::ZERO_VALUE,
        }
    }
    pub fn get_guta_header_b(&self, global_user_tree_height: usize, guta_circuit_whitelist: Hash) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.right_end_cap.checkpoint_historical_merkle_proof.root,
            guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.right_global_user_tree_delta_merkle_proof.old_value,
                new_node_value: self.right_global_user_tree_delta_merkle_proof.new_value,
                node_index: F::from_u64_value(self.right_global_user_tree_delta_merkle_proof.index),
                node_level: F::from_u64_value(global_user_tree_height as u64),
            },
            stats: self.right_end_cap.guta_stats,
            total_aggregation_proofs_generated: F::ZERO_VALUE,
        }
    }
    pub fn get_new_guta_header(&self, global_user_tree_height: usize, guta_circuit_whitelist: Hash) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.right_end_cap.checkpoint_historical_merkle_proof.root,
            guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_global_user_tree_delta_merkle_proof.old_root,
                new_node_value: self.right_global_user_tree_delta_merkle_proof.new_root,
                node_index: F::from_u64_value(self.right_global_user_tree_delta_merkle_proof.index),
                node_level: F::from_u64_value((global_user_tree_height - self.right_global_user_tree_delta_merkle_proof.siblings.len()) as u64),
            },
            stats: self.left_end_cap.guta_stats.combine_with(&self.right_end_cap.guta_stats),
            total_aggregation_proofs_generated: F::from_u8_value(1),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyTwoEndCapCircuitInputV2<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(
        &self,
        global_user_tree_height: usize,
        guta_circuit_whitelist: Hash,
    ) -> Hash {
        let new_guta_header = self.get_new_guta_header(global_user_tree_height, guta_circuit_whitelist);
        new_guta_header.qfhash::<Hasher>()
    }
}

// START SERIALIZATION HELPERS
// ================================================================================================
// GUTAVerifyLeftGUTARightEndCapCircuitInputV2
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAVerifyLeftGUTARightEndCapCircuitInputV2<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            right_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAVerifyLeftGUTARightEndCapCircuitInputV2<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAVerifyLeftGUTARightEndCapCircuitInputV2<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.left_header.pio_serialized_size()
            + self.right_end_cap.pio_serialized_size()
            + self.right_global_user_tree_delta_merkle_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_header.pio_write_to_io(writer)?;
        self.right_end_cap.pio_write_to_io(writer)?;
        self.right_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let right_end_cap = VerifyEndCapSimpleStandardInput::<F, Hash>::pio_read_from_io(reader)?;
        let right_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            left_header,
            right_end_cap,
            right_global_user_tree_delta_merkle_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAVerifyLeftGUTARightEndCapCircuitInputV2,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for GUTAVerifyLeftGUTARightEndCapCircuitInputV2<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    GUTAVerifyLeftGUTARightEndCapCircuitInputV2,
    { parth_core::PF, parth_core::PHash },
    guta_verify_left_guta_right_end_cap_circuit_input_v2_tests
);

// ================================================================================================
// GUTAVerifyRightGUTALeftEndCapCircuitInputV2
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAVerifyRightGUTALeftEndCapCircuitInputV2<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            left_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
            left_historical_checkpoint_merkle_proof: MerkleProofCore::qp_rand_gen(),
            right_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAVerifyRightGUTALeftEndCapCircuitInputV2<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAVerifyRightGUTALeftEndCapCircuitInputV2<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.left_end_cap.pio_serialized_size()
            + self.left_global_user_tree_delta_merkle_proof.pio_serialized_size()
            + self.left_historical_checkpoint_merkle_proof.pio_serialized_size()
            + self.right_header.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_end_cap.pio_write_to_io(writer)?;
        self.left_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        self.left_historical_checkpoint_merkle_proof.pio_write_to_io(writer)?;
        self.right_header.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_end_cap = VerifyEndCapSimpleStandardInput::<F, Hash>::pio_read_from_io(reader)?;
        let left_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let left_historical_checkpoint_merkle_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let right_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            left_end_cap,
            left_global_user_tree_delta_merkle_proof,
            left_historical_checkpoint_merkle_proof,
            right_header,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAVerifyRightGUTALeftEndCapCircuitInputV2,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for GUTAVerifyRightGUTALeftEndCapCircuitInputV2<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    GUTAVerifyRightGUTALeftEndCapCircuitInputV2,
    { parth_core::PF, parth_core::PHash },
    guta_verify_right_guta_left_end_cap_circuit_input_v2_tests
);

// ================================================================================================
// GUTAVerifyTwoEndCapCircuitInputV2
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAVerifyTwoEndCapCircuitInputV2<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            left_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
            right_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAVerifyTwoEndCapCircuitInputV2<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAVerifyTwoEndCapCircuitInputV2<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.left_end_cap.pio_serialized_size()
            + self.left_global_user_tree_delta_merkle_proof.pio_serialized_size()
            + self.right_end_cap.pio_serialized_size()
            + self.right_global_user_tree_delta_merkle_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_end_cap.pio_write_to_io(writer)?;
        self.left_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        self.right_end_cap.pio_write_to_io(writer)?;
        self.right_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_end_cap = VerifyEndCapSimpleStandardInput::<F, Hash>::pio_read_from_io(reader)?;
        let left_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let right_end_cap = VerifyEndCapSimpleStandardInput::<F, Hash>::pio_read_from_io(reader)?;
        let right_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            left_end_cap,
            left_global_user_tree_delta_merkle_proof,
            right_end_cap,
            right_global_user_tree_delta_merkle_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAVerifyTwoEndCapCircuitInputV2,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GUTAVerifyTwoEndCapCircuitInputV2<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    GUTAVerifyTwoEndCapCircuitInputV2,
    { parth_core::PF, parth_core::PHash },
    guta_verify_two_end_cap_circuit_input_v2_tests
);
// END SERIALIZATION HELPERS
