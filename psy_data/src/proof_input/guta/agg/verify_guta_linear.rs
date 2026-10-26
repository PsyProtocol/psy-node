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
use psy_core::job::job_id::QProvingJobDataID;
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
        println!("GUTAVerifyTwoGUTALinearCircuitInput new_guta_header {:?}", new_guta_header);
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
                // Use the delta merkle proof's new_root, not right_header.new_node_value
                // The circuit computes new_root from the delta proof gadget
                new_node_value: self.right_global_user_tree_delta_merkle_proof.new_root,
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

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{crypto::hash::traits::QFieldHashable, felt::FromPrimitiveValuesFelt, pgoldilocks::{PoseidonHasher, QHashOut}, utils::QPGenRandom, PF};
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    type Hash = QHashOut<PF>;

    #[test]
    fn linear_aggregation_preserves_endpoints_and_combines_stats() {
        let input = GUTAVerifyTwoGUTALinearCircuitInput::<PF, Hash>::qp_rand_gen();
        assert_eq!(input.get_guta_header_a(), input.left_header);
        assert_eq!(input.get_guta_header_b(), input.right_header);
        let combined = input.get_new_guta_header();
        assert_eq!(combined.state_transition.old_node_value, input.left_header.state_transition.old_node_value);
        assert_eq!(combined.state_transition.new_node_value, input.right_header.state_transition.new_node_value);
        assert_eq!(combined.stats, input.left_header.stats.combine_with(&input.right_header.stats));
        assert_eq!(input.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>(), combined.qfhash::<PoseidonHasher>());
        let left = QProvingJobDataID::qp_rand_gen();
        let right = QProvingJobDataID::qp_rand_gen();
        let (metadata, header) = input.get_job_witness_and_new_guta::<PoseidonHasher>(4, 2, 8, left, right);
        assert_eq!(metadata.job_id, header.job_id);
        assert_eq!(metadata.metadata.dependencies, vec![left, right]);
        assert_eq!(metadata.metadata.expected_public_inputs_hash, header.header.qfhash::<PoseidonHasher>());
    }

    #[test]
    fn checkpoint_upgrade_variants_select_their_documented_roots() {
        let input = GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput::<PF, Hash>::qp_rand_gen();
        let combined = input.get_new_guta_header();
        assert_eq!(combined.checkpoint_tree_root, input.left_historical_checkpoint_proof.root);
        assert_eq!(input.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>(), combined.qfhash::<PoseidonHasher>());

        let leaf = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput::<PF, Hash>::qp_rand_gen();
        let combined_leaf = leaf.get_new_guta_header();
        assert_eq!(combined_leaf.checkpoint_tree_root, leaf.left_header.checkpoint_tree_root);
        assert_eq!(combined_leaf.state_transition.new_node_value, leaf.right_global_user_tree_delta_merkle_proof.new_root);
        assert_eq!(leaf.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>(), combined_leaf.qfhash::<PoseidonHasher>());
    }

    #[test]
    fn linear_new_header_keeps_left_checkpoint_whitelist_and_position() {
        let input = GUTAVerifyTwoGUTALinearCircuitInput::<PF, Hash>::qp_rand_gen();
        let combined = input.get_new_guta_header();
        assert_eq!(combined.checkpoint_tree_root, input.left_header.checkpoint_tree_root);
        assert_eq!(combined.guta_circuit_whitelist, input.left_header.guta_circuit_whitelist);
        assert_eq!(combined.state_transition.node_index, input.left_header.state_transition.node_index);
        assert_eq!(combined.state_transition.node_level, input.left_header.state_transition.node_level);
        assert_eq!(
            combined.total_aggregation_proofs_generated,
            input.left_header.total_aggregation_proofs_generated
                + input.right_header.total_aggregation_proofs_generated
                + PF::from_u8_value(1)
        );
    }

    // The fallback writer must emit exactly the canonical (speedy) encoding, and
    // that payload must round-trip through the canonical reader. The fallback
    // reader itself cannot be exercised here: chained nested speedy stream reads
    // desynchronize the shared cursor (reported production bug).
    #[test]
    fn linear_inputs_fallback_write_matches_canonical_encoding() {
        let linear = GUTAVerifyTwoGUTALinearCircuitInput::<PF, Hash>::qp_rand_gen();
        assert!(GUTAVerifyTwoGUTALinearCircuitInput::<PF, Hash>::IS_FIXED_SIZE);
        assert_eq!(
            linear.fallback_pio_serialized_size(),
            GUTAVerifyTwoGUTALinearCircuitInput::<PF, Hash>::FIXED_SIZE
        );
        let bytes = linear.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), 2 * GlobalUserTreeAggregatorHeader::<PF, Hash>::FIXED_SIZE);
        assert_eq!(bytes, linear.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(GUTAVerifyTwoGUTALinearCircuitInput::<PF, Hash>::psy_ser_from_slice(&bytes).unwrap(), linear);

        let upgrade = GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput::<PF, Hash>::qp_rand_gen();
        let bytes = upgrade.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), upgrade.fallback_pio_serialized_size());
        assert_eq!(bytes, upgrade.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(GUTAVerifyTwoGUTALinearUpgradeCheckpointCircuitInput::<PF, Hash>::psy_ser_from_slice(&bytes).unwrap(), upgrade);

        let leaf = GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput::<PF, Hash>::qp_rand_gen();
        let bytes = leaf.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), leaf.fallback_pio_serialized_size());
        assert_eq!(bytes, leaf.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(GUTAVerifyLeftLinearRightLeafUpgradeCheckpointCircuitInput::<PF, Hash>::psy_ser_from_slice(&bytes).unwrap(), leaf);
    }
}
