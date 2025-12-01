use std::hash::Hash;

#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{FieldQHasher, QFieldHashable},
    },
    felt::{QFelt, QFelt64},
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{
    guta::{
        header::GlobalUserTreeAggregatorHeader, header_extended::GlobalUserTreeAggregatorHeaderWithJobId,
        sub_tree_transition::SubTreeNodeStateTransition,
    },
    worker::{
        metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
}
impl<F: QFelt, Hash: Copy> GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.left_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_header.state_transition.old_node_value,
                new_node_value: self.right_header.state_transition.new_node_value,
                node_index: self.left_header.state_transition.node_index,
                node_level: self.left_header.state_transition.node_level,
            },
            stats: self.left_header.stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated
                + self.right_header.total_aggregation_proofs_generated
                + F::from_u8_value(1),
        }
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
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
        let job_id = QProvingJobDataID::guta_two_linear_proof(
            unique_pending_id,
            level as u32,
            index,
        );
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
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
                reward_tree_node_children: 2,
                dependencies: vec![left_job_id, right_job_id],
            },
        };
        (job_metadata, new_guta_header)
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub left_historical_checkpoint_proof: MerkleProofCore<Hash>,
    pub right_historical_checkpoint_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt, Hash: Copy> GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.left_historical_checkpoint_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_header.state_transition.old_node_value,
                new_node_value: self.right_header.state_transition.new_node_value,
                node_index: self.left_header.state_transition.node_index,
                node_level: self.left_header.state_transition.node_level,
            },
            stats: self.left_header.stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated
                + self.right_header.total_aggregation_proofs_generated
                + F::from_u8_value(1),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }
}
#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
    pub right_historical_checkpoint_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt, Hash: Copy> GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.left_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_header.state_transition.old_node_value,
                new_node_value: self.right_header.state_transition.new_node_value,
                node_index: self.left_header.state_transition.node_index,
                node_level: self.left_header.state_transition.node_level,
            },
            stats: self.left_header.stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated
                + self.right_header.total_aggregation_proofs_generated
                + F::from_u8_value(1),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }
}
// ================================================================================================
// GUTAVerifyTwoGUTALinearCircuitInput
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            right_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 2 * GlobalUserTreeAggregatorHeader::<F, Hash>::FIXED_SIZE;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_header.pio_write_to_io(writer)?;
        self.right_header.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let right_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;

        Ok(Self { left_header, right_header })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAVerifyTwoGUTALinearCircuitInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GUTAVerifyTwoGUTALinearCircuitInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    GUTAVerifyTwoGUTALinearCircuitInput,
    { parth_core::PF, parth_core::PHash },
    guta_verify_two_guta_linear_circuit_input_tests
);

// ================================================================================================
// GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            right_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            left_historical_checkpoint_proof: MerkleProofCore::qp_rand_gen(),
            right_historical_checkpoint_proof: MerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.left_header.pio_serialized_size()
            + self.right_header.pio_serialized_size()
            + self.left_historical_checkpoint_proof.pio_serialized_size()
            + self.right_historical_checkpoint_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_header.pio_write_to_io(writer)?;
        self.right_header.pio_write_to_io(writer)?;
        self.left_historical_checkpoint_proof.pio_write_to_io(writer)?;
        self.right_historical_checkpoint_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let right_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let left_historical_checkpoint_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let right_historical_checkpoint_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            left_header,
            right_header,
            left_historical_checkpoint_proof,
            right_historical_checkpoint_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput,
    { parth_core::PF, parth_core::PHash },
    guta_verify_two_guta_linear_upgrade_checkpoint_circuit_input_tests
);

// ================================================================================================
// GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            right_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
            right_historical_checkpoint_proof: MerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.left_header.pio_serialized_size()
            + self.right_header.pio_serialized_size()
            + self.right_global_user_tree_delta_merkle_proof.pio_serialized_size()
            + self.right_historical_checkpoint_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_header.pio_write_to_io(writer)?;
        self.right_header.pio_write_to_io(writer)?;
        self.right_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        self.right_historical_checkpoint_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let right_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let right_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let right_historical_checkpoint_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            left_header,
            right_header,
            right_global_user_tree_delta_merkle_proof,
            right_historical_checkpoint_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput,
    { parth_core::PF, parth_core::PHash },
    guta_verify_two_guta_left_linear_right_child_right_upgrade_tests
);
