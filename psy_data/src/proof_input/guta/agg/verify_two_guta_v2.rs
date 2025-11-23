#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
use parth_core::protocol::core_types::Q256BitHash;
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{FieldQHasher, QFieldHashable},
    },
    felt::QFelt64,
    protocol::core_types::QFHashBase,
};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition};

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyTwoGUTACircuitInputV2<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub left_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,

    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
}

impl<F: QFelt64, Hash: Copy> GUTAVerifyTwoGUTACircuitInputV2<F, Hash> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.left_header.checkpoint_tree_root,
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_global_user_tree_delta_merkle_proof.old_root,
                new_node_value: self.right_global_user_tree_delta_merkle_proof.new_root,
                node_index: F::from_u64_value(
                    self.left_header.state_transition.node_index.to_u64_value() >> self.left_global_user_tree_delta_merkle_proof.siblings.len(),
                ),
                node_level: F::from_u64_value(
                    (self.left_header.state_transition.node_level.to_u64_value() as i64
                        - self.left_global_user_tree_delta_merkle_proof.siblings.len() as i64)
                        .max(0) as u64,
                ),
            },
            stats: self.left_header.stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated
                + self.right_header.total_aggregation_proofs_generated
                + F::from_u8_value(1),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyTwoGUTACircuitInputV2<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }
}
#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2<F, Hash> {
    pub left_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub left_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
    pub left_historical_checkpoint_merkle_proof: MerkleProofCore<Hash>,

    pub right_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore<Hash>,
    pub right_historical_checkpoint_merkle_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt64, Hash: Copy> GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2<F, Hash> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.left_header
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        self.right_header
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            checkpoint_tree_root: self.left_historical_checkpoint_merkle_proof.root,
            guta_circuit_whitelist: self.left_header.guta_circuit_whitelist,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.left_global_user_tree_delta_merkle_proof.old_root,
                new_node_value: self.right_global_user_tree_delta_merkle_proof.new_root,
                node_index: F::from_u64_value(
                    self.left_header.state_transition.node_index.to_u64_value() >> self.left_global_user_tree_delta_merkle_proof.siblings.len(),
                ),
                node_level: F::from_u64_value(
                    (self.left_header.state_transition.node_level.to_u64_value() as i64
                        - self.left_global_user_tree_delta_merkle_proof.siblings.len() as i64)
                        .max(0) as u64,
                ),
            },
            stats: self.left_header.stats.combine_with(&self.right_header.stats),
            total_aggregation_proofs_generated: self.left_header.total_aggregation_proofs_generated
                + self.right_header.total_aggregation_proofs_generated
                + F::from_u8_value(1),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let new_guta_header = self.get_new_guta_header();
        new_guta_header.qfhash::<Hasher>()
    }
}

// START SERIALIZATION HELPERS
// ================================================================================================
// GUTAVerifyTwoGUTACircuitInputV2
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAVerifyTwoGUTACircuitInputV2<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            left_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
            right_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAVerifyTwoGUTACircuitInputV2<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAVerifyTwoGUTACircuitInputV2<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.left_header.pio_serialized_size()
            + self.left_global_user_tree_delta_merkle_proof.pio_serialized_size()
            + self.right_header.pio_serialized_size()
            + self.right_global_user_tree_delta_merkle_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_header.pio_write_to_io(writer)?;
        self.left_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        self.right_header.pio_write_to_io(writer)?;
        self.right_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let left_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let right_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let right_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            left_header,
            left_global_user_tree_delta_merkle_proof,
            right_header,
            right_global_user_tree_delta_merkle_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAVerifyTwoGUTACircuitInputV2,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GUTAVerifyTwoGUTACircuitInputV2<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    GUTAVerifyTwoGUTACircuitInputV2,
    { parth_core::PF, parth_core::PHash },
    guta_verify_two_guta_circuit_input_v2_tests
);

// ================================================================================================
// GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2
// ================================================================================================

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            left_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            left_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
            left_historical_checkpoint_merkle_proof: MerkleProofCore::qp_rand_gen(),
            right_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            right_global_user_tree_delta_merkle_proof: DeltaMerkleProofCore::qp_rand_gen(),
            right_historical_checkpoint_merkle_proof: MerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.left_header.pio_serialized_size()
            + self.left_global_user_tree_delta_merkle_proof.pio_serialized_size()
            + self.left_historical_checkpoint_merkle_proof.pio_serialized_size()
            + self.right_header.pio_serialized_size()
            + self.right_global_user_tree_delta_merkle_proof.pio_serialized_size()
            + self.right_historical_checkpoint_merkle_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.left_header.pio_write_to_io(writer)?;
        self.left_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        self.left_historical_checkpoint_merkle_proof.pio_write_to_io(writer)?;
        self.right_header.pio_write_to_io(writer)?;
        self.right_global_user_tree_delta_merkle_proof.pio_write_to_io(writer)?;
        self.right_historical_checkpoint_merkle_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let left_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let left_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let left_historical_checkpoint_merkle_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let right_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let right_global_user_tree_delta_merkle_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let right_historical_checkpoint_merkle_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            left_header,
            left_global_user_tree_delta_merkle_proof,
            left_historical_checkpoint_merkle_proof,
            right_header,
            right_global_user_tree_delta_merkle_proof,
            right_historical_checkpoint_merkle_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInputV2,
    { parth_core::PF, parth_core::PHash },
    guta_verify_two_guta_upgrade_checkpoint_circuit_input_v2_tests
);
// END SERIALIZATION HELPERS
