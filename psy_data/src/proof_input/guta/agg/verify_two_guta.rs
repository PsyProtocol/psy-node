use std::{hash::Hash, ops::Add};

#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore, compute_historical_and_current_merkle_roots_core_gt}, nca::nca_proof::PartialUpdateNearestCommonAncestorProof, traits::{FieldQHasher, MerkleHasher, MerkleZeroHasher, QFieldHashable, ZeroableHash}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}};
use psy_core::job::job_id::{self, QProvingJobDataID};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{guta::{header::GlobalUserTreeAggregatorHeader, header_extended::GlobalUserTreeAggregatorHeaderWithTagValue, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition}, v1::qdata::{checkpoint::PQEDCheckpointLeafCompactWithStateRoots, user::PQEDUserLeaf, user_end_cap_result::PUPSEndCapResultCompact}};
use psy_serialize::FallbackPsySerializeCanonical;


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub b_checkpoint_tree_root: Hash,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
    pub total_aggregation_proofs_generated_a: F,
    pub total_aggregation_proofs_generated_b: F,
}
impl<F: Add<Output = F> + Copy, Hash> VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash> {
    pub fn get_combined_stats(&self) -> GUTAStats<F> {
        self.stats_a.combine_with(&self.stats_b)
    }

    pub fn check_witness(&self) -> anyhow::Result<()> {
        // todo: check nca proof
        Ok(())
    }
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_tree_root: Hash::qp_rand_gen(),
            b_checkpoint_tree_root: Hash::qp_rand_gen(),
            stats_a: GUTAStats::qp_rand_gen(),
            stats_b: GUTAStats::qp_rand_gen(),
            nca_proof: PartialUpdateNearestCommonAncestorProof::qp_rand_gen(),
            total_aggregation_proofs_generated_a: F::qp_rand_gen(),
            total_aggregation_proofs_generated_b: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
        + 32
        + self.stats_a.pio_serialized_size()
        + self.stats_b.pio_serialized_size()
        + self.nca_proof.pio_serialized_size()
        + 8
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.b_checkpoint_tree_root.into_owned_32bytes())?;
        self.stats_a.pio_write_to_io(writer)?;
        self.stats_b.pio_write_to_io(writer)?;
        self.nca_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_a.to_u64_value())?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_b.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let b_checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let stats_a = GUTAStats::pio_read_from_io(reader)?;
        let stats_b = GUTAStats::pio_read_from_io(reader)?;
        let nca_proof = PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        let total_aggregation_proofs_generated_a = F::from_u64_value(reader.psy_read_u64()?);
        let total_aggregation_proofs_generated_b = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            checkpoint_tree_root,
            b_checkpoint_tree_root,
            stats_a,
            stats_b,
            nca_proof,
            total_aggregation_proofs_generated_a,
            total_aggregation_proofs_generated_b,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyTwoGUTAProofGadgetStandardInputSimple,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyTwoGUTAProofGadgetStandardInputSimple,
    { parth_core::PF, parth_core::PHash },
    verify_two_guta_proof_gadget_standard_input_simple_ser_tests
);


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoGUTAProofGadgetStandardInput<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub b_checkpoint_tree_root: Hash,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

    pub guta_inclusion_proof_a: MerkleProofCore<Hash>,
    pub guta_inclusion_proof_b: MerkleProofCore<Hash>,
    pub total_aggregation_proofs_generated_a: F,
    pub total_aggregation_proofs_generated_b: F,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyTwoGUTAProofGadgetStandardInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_tree_root: Hash::qp_rand_gen(),
            b_checkpoint_tree_root: Hash::qp_rand_gen(),
            stats_a: GUTAStats::qp_rand_gen(),
            stats_b: GUTAStats::qp_rand_gen(),
            nca_proof: PartialUpdateNearestCommonAncestorProof::qp_rand_gen(),
            guta_inclusion_proof_a: MerkleProofCore::qp_rand_gen(),
            guta_inclusion_proof_b: MerkleProofCore::qp_rand_gen(),
            total_aggregation_proofs_generated_a: F::qp_rand_gen(),
            total_aggregation_proofs_generated_b: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyTwoGUTAProofGadgetStandardInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyTwoGUTAProofGadgetStandardInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
        + 32
        + self.stats_a.pio_serialized_size()
        + self.stats_b.pio_serialized_size()
        + self.nca_proof.pio_serialized_size()
        + self.guta_inclusion_proof_a.pio_serialized_size()
        + self.guta_inclusion_proof_b.pio_serialized_size()
        + 8
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.b_checkpoint_tree_root.into_owned_32bytes())?;
        self.stats_a.pio_write_to_io(writer)?;
        self.stats_b.pio_write_to_io(writer)?;
        self.nca_proof.pio_write_to_io(writer)?;
        self.guta_inclusion_proof_a.pio_write_to_io(writer)?;
        self.guta_inclusion_proof_b.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_a.to_u64_value())?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_b.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let b_checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let stats_a = GUTAStats::pio_read_from_io(reader)?;
        let stats_b = GUTAStats::pio_read_from_io(reader)?;
        let nca_proof = PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        let guta_inclusion_proof_a = MerkleProofCore::pio_read_from_io(reader)?;
        let guta_inclusion_proof_b = MerkleProofCore::pio_read_from_io(reader)?;
        let total_aggregation_proofs_generated_a = F::from_u64_value(reader.psy_read_u64()?);
        let total_aggregation_proofs_generated_b = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            checkpoint_tree_root,
            b_checkpoint_tree_root,
            stats_a,
            stats_b,
            nca_proof,
            guta_inclusion_proof_a,
            guta_inclusion_proof_b,
            total_aggregation_proofs_generated_a,
            total_aggregation_proofs_generated_b,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyTwoGUTAProofGadgetStandardInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyTwoGUTAProofGadgetStandardInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyTwoGUTAProofGadgetStandardInput,
    { parth_core::PF, parth_core::PHash },
    verify_two_guta_proof_gadget_standard_input_ser_tests
);

impl<F: QFelt64, Hash: Copy> VerifyTwoGUTAProofGadgetStandardInput<F, Hash> {

    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: self.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_a_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
            total_aggregation_proofs_generated: self.total_aggregation_proofs_generated_a,
        }
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: self.b_checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_b_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
            total_aggregation_proofs_generated: self.total_aggregation_proofs_generated_b,
        }
    }

}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    pub historical_checkpoint_proof_a: MerkleProofCore<Hash>,
    pub historical_checkpoint_proof_b: MerkleProofCore<Hash>,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
    pub total_aggregation_proofs_generated_a: F,
    pub total_aggregation_proofs_generated_b: F,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            historical_checkpoint_proof_a: MerkleProofCore::qp_rand_gen(),
            historical_checkpoint_proof_b: MerkleProofCore::qp_rand_gen(),
            stats_a: GUTAStats::qp_rand_gen(),
            stats_b: GUTAStats::qp_rand_gen(),
            nca_proof: PartialUpdateNearestCommonAncestorProof::qp_rand_gen(),
            total_aggregation_proofs_generated_a: F::qp_rand_gen(),
            total_aggregation_proofs_generated_b: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.historical_checkpoint_proof_a.pio_serialized_size()
        + self.historical_checkpoint_proof_b.pio_serialized_size()
        + self.stats_a.pio_serialized_size()
        + self.stats_b.pio_serialized_size()
        + self.nca_proof.pio_serialized_size()
        + 8
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.historical_checkpoint_proof_a.pio_write_to_io(writer)?;
        self.historical_checkpoint_proof_b.pio_write_to_io(writer)?;
        self.stats_a.pio_write_to_io(writer)?;
        self.stats_b.pio_write_to_io(writer)?;
        self.nca_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_a.to_u64_value())?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_b.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let historical_checkpoint_proof_a = MerkleProofCore::pio_read_from_io(reader)?;
        let historical_checkpoint_proof_b = MerkleProofCore::pio_read_from_io(reader)?;
        let stats_a = GUTAStats::pio_read_from_io(reader)?;
        let stats_b = GUTAStats::pio_read_from_io(reader)?;
        let nca_proof = PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        let total_aggregation_proofs_generated_a = F::from_u64_value(reader.psy_read_u64()?);
        let total_aggregation_proofs_generated_b = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            historical_checkpoint_proof_a,
            historical_checkpoint_proof_b,
            stats_a,
            stats_b,
            nca_proof,
            total_aggregation_proofs_generated_a,
            total_aggregation_proofs_generated_b,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple,
    { parth_core::PF, parth_core::PHash },
    verify_two_guta_proof_upgrade_checkpoint_standard_input_simple_ser_tests
);

impl<F: Add<Output = F> + Copy, Hash> VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    pub fn get_combined_stats(&self) -> GUTAStats<F> {
        self.stats_a.combine_with(&self.stats_b)
    }
}

impl<F, Hash: PartialEq + Copy> VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        let (_historical_root_a, current_root_a) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.historical_checkpoint_proof_a);
        let (_historical_root_b, current_root_b) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.historical_checkpoint_proof_b);
        if current_root_a != self.historical_checkpoint_proof_a.root {
            return Err(anyhow::anyhow!("two guta upgrade checkpoint historical_checkpoint_proof_a not match"));
        }
        if current_root_b != self.historical_checkpoint_proof_b.root {
            return Err(anyhow::anyhow!("two guta upgrade checkpoint historical_checkpoint_proof_b not match"));
        }
        if current_root_a != current_root_b {
            return Err(anyhow::anyhow!("two guta upgrade checkpoint current checkpoint root not match"));
        }
        Ok(())
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoGUTAProofUpgradeCheckpointStandardInput<F, Hash> {
    pub historical_checkpoint_proof_a: MerkleProofCore<Hash>,
    pub historical_checkpoint_proof_b: MerkleProofCore<Hash>,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

    pub guta_inclusion_proof_a: MerkleProofCore<Hash>,
    pub guta_inclusion_proof_b: MerkleProofCore<Hash>,
    pub total_aggregation_proofs_generated_a: F,
    pub total_aggregation_proofs_generated_b: F,
}



impl<F: QFelt64, Hash: Copy> VerifyTwoGUTAProofUpgradeCheckpointStandardInput<F, Hash> {
    pub fn get_guta_header_a<H: MerkleZeroHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: compute_historical_and_current_merkle_roots_core_gt::<Hash, H>(
                &self.historical_checkpoint_proof_a
            ).0,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_a_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
            total_aggregation_proofs_generated: self.total_aggregation_proofs_generated_a,
        }
    }
    pub fn get_guta_header_b<H: MerkleZeroHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: compute_historical_and_current_merkle_roots_core_gt::<Hash, H>(
                &self.historical_checkpoint_proof_b
            ).0,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_b_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
            total_aggregation_proofs_generated: self.total_aggregation_proofs_generated_b,
        }
    }
}