use std::{hash::Hash};

#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{crypto::hash::{merkle_proof::{MerkleProofCore, compute_historical_and_current_merkle_roots_core_gt}, nca::nca_proof::PartialUpdateNearestCommonAncestorProof, traits::MerkleZeroHasher}, felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{guta::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition}, proof_input::guta::VerifyEndCapSimpleStandardInput, v1::qdata::user_end_cap_result::PUPSEndCapResultCompact};
use psy_serialize::FallbackPsySerializeCanonical;



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyLeftGUTARightEndCapInputSimple<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub stats_a: GUTAStats<F>,
    pub b_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
    pub total_aggregation_proofs_generated_a: F,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyLeftGUTARightEndCapInputSimple<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_tree_root: Hash::qp_rand_gen(),
            stats_a: GUTAStats::qp_rand_gen(),
            b_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            nca_proof: PartialUpdateNearestCommonAncestorProof::qp_rand_gen(),
            total_aggregation_proofs_generated_a: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyLeftGUTARightEndCapInputSimple<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyLeftGUTARightEndCapInputSimple<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
        + self.stats_a.pio_serialized_size()
        + self.b_end_cap.pio_serialized_size()
        + self.nca_proof.pio_serialized_size()
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        self.stats_a.pio_write_to_io(writer)?;
        self.b_end_cap.pio_write_to_io(writer)?;
        self.nca_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_a.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let stats_a = GUTAStats::pio_read_from_io(reader)?;
        let b_end_cap = VerifyEndCapSimpleStandardInput::pio_read_from_io(reader)?;
        let nca_proof = PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        let total_aggregation_proofs_generated_a = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            checkpoint_tree_root,
            stats_a,
            b_end_cap,
            nca_proof,
            total_aggregation_proofs_generated_a,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyLeftGUTARightEndCapInputSimple,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyLeftGUTARightEndCapInputSimple<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyLeftGUTARightEndCapInputSimple,
    { parth_core::PF, parth_core::PHash },
    verify_left_guta_right_end_cap_input_simple_ser_tests
);



impl<F, Hash: Copy + PartialEq> VerifyLeftGUTARightEndCapInputSimple<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        self.b_end_cap.check_witness::<Hasher>()?;
        let (_historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.b_end_cap.checkpoint_historical_merkle_proof);
        if current_root != self.checkpoint_tree_root {
            return Err(anyhow::anyhow!("left guta right endcap checkpoint tree root not match"));
        }
        if current_root != self.b_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("right endcap historical merkel proof not match"));
        }
        Ok(())
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyLeftGUTARightEndCapInput<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub stats_a: GUTAStats<F>,
    pub b_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

    pub guta_inclusion_proof_a: MerkleProofCore<Hash>,
    pub total_aggregation_proofs_generated_a: F,
}


#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyLeftGUTARightEndCapInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_tree_root: Hash::qp_rand_gen(),
            stats_a: GUTAStats::qp_rand_gen(),
            b_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            nca_proof: PartialUpdateNearestCommonAncestorProof::qp_rand_gen(),
            guta_inclusion_proof_a: MerkleProofCore::qp_rand_gen(),
            total_aggregation_proofs_generated_a: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyLeftGUTARightEndCapInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyLeftGUTARightEndCapInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
        + self.stats_a.pio_serialized_size()
        + self.b_end_cap.pio_serialized_size()
        + self.nca_proof.pio_serialized_size()
        + self.guta_inclusion_proof_a.pio_serialized_size()
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        self.stats_a.pio_write_to_io(writer)?;
        self.b_end_cap.pio_write_to_io(writer)?;
        self.nca_proof.pio_write_to_io(writer)?;
        self.guta_inclusion_proof_a.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_a.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let stats_a = GUTAStats::pio_read_from_io(reader)?;
        let b_end_cap = VerifyEndCapSimpleStandardInput::pio_read_from_io(reader)?;
        let nca_proof = PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        let guta_inclusion_proof_a = MerkleProofCore::pio_read_from_io(reader)?;
        let total_aggregation_proofs_generated_a = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            checkpoint_tree_root,
            stats_a,
            b_end_cap,
            nca_proof,
            guta_inclusion_proof_a,
            total_aggregation_proofs_generated_a,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyLeftGUTARightEndCapInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyLeftGUTARightEndCapInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyLeftGUTARightEndCapInput,
    { parth_core::PF, parth_core::PHash },
    verify_left_guta_right_end_cap_input_ser_tests
);


impl<F: QFelt64, Hash: Copy> VerifyLeftGUTARightEndCapInput<F, Hash> {

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
    pub fn get_end_result_b(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_b.old_value,
            end_user_leaf_hash: self.nca_proof.child_b.new_value,
            checkpoint_tree_root_hash: self.b_end_cap.checkpoint_root,
            user_id: F::from_u64_value(self.nca_proof.child_b.index),
        }
    }

}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyLeftEndCapRightGUTAInputSimple<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub stats_b: GUTAStats<F>,
    pub a_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
    pub total_aggregation_proofs_generated_b: F,

}

impl<F, Hash: Copy + PartialEq> VerifyLeftEndCapRightGUTAInputSimple<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        self.a_end_cap.check_witness::<Hasher>()?;
        let (_historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.a_end_cap.checkpoint_historical_merkle_proof);
        if current_root != self.checkpoint_tree_root {
            return Err(anyhow::anyhow!("left endcap right guta checkpoint tree root not match"));
        }
        if current_root != self.a_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("left endcap historical merkel proof not match"));
        }
        Ok(())
    }
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyLeftEndCapRightGUTAInputSimple<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_tree_root: Hash::qp_rand_gen(),
            stats_b: GUTAStats::qp_rand_gen(),
            a_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            nca_proof: PartialUpdateNearestCommonAncestorProof::qp_rand_gen(),
            total_aggregation_proofs_generated_b: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyLeftEndCapRightGUTAInputSimple<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyLeftEndCapRightGUTAInputSimple<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
        + self.stats_b.pio_serialized_size()
        + self.a_end_cap.pio_serialized_size()
        + self.nca_proof.pio_serialized_size()
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        self.stats_b.pio_write_to_io(writer)?;
        self.a_end_cap.pio_write_to_io(writer)?;
        self.nca_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_b.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let stats_b = GUTAStats::pio_read_from_io(reader)?;
        let a_end_cap = VerifyEndCapSimpleStandardInput::pio_read_from_io(reader)?;
        let nca_proof = PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        let total_aggregation_proofs_generated_b = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            checkpoint_tree_root,
            stats_b,
            a_end_cap,
            nca_proof,
            total_aggregation_proofs_generated_b,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyLeftEndCapRightGUTAInputSimple,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyLeftEndCapRightGUTAInputSimple<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyLeftEndCapRightGUTAInputSimple,
    { parth_core::PF, parth_core::PHash },
    verify_left_end_cap_right_guta_input_simple_ser_tests
);







#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyLeftEndCapRightGUTAInput<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub stats_b: GUTAStats<F>,
    pub a_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

    pub guta_inclusion_proof_b: MerkleProofCore<Hash>,
    pub total_aggregation_proofs_generated_b: F,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyLeftEndCapRightGUTAInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_tree_root: Hash::qp_rand_gen(),
            stats_b: GUTAStats::qp_rand_gen(),
            a_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            nca_proof: PartialUpdateNearestCommonAncestorProof::qp_rand_gen(),
            guta_inclusion_proof_b: MerkleProofCore::qp_rand_gen(),
            total_aggregation_proofs_generated_b: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyLeftEndCapRightGUTAInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyLeftEndCapRightGUTAInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
        + self.stats_b.pio_serialized_size()
        + self.a_end_cap.pio_serialized_size()
        + self.nca_proof.pio_serialized_size()
        + self.guta_inclusion_proof_b.pio_serialized_size()
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        self.stats_b.pio_write_to_io(writer)?;
        self.a_end_cap.pio_write_to_io(writer)?;
        self.nca_proof.pio_write_to_io(writer)?;
        self.guta_inclusion_proof_b.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated_b.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let stats_b = GUTAStats::pio_read_from_io(reader)?;
        let a_end_cap = VerifyEndCapSimpleStandardInput::pio_read_from_io(reader)?;
        let nca_proof = PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        let guta_inclusion_proof_b = MerkleProofCore::pio_read_from_io(reader)?;
        let total_aggregation_proofs_generated_b = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            checkpoint_tree_root,
            stats_b,
            a_end_cap,
            nca_proof,
            guta_inclusion_proof_b,
            total_aggregation_proofs_generated_b,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyLeftEndCapRightGUTAInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyLeftEndCapRightGUTAInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyLeftEndCapRightGUTAInput,
    { parth_core::PF, parth_core::PHash },
    verify_left_end_cap_right_guta_input_ser_tests
);



impl<F: QFelt64, Hash: PartialEq + Copy> VerifyLeftEndCapRightGUTAInput<F, Hash> {

    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: self.checkpoint_tree_root,
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
    pub fn get_end_result_a(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_a.old_value,
            end_user_leaf_hash: self.nca_proof.child_a.new_value,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: F::from_u64_value(self.nca_proof.child_a.index),
        }
    }

}

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
    use parth_core::{crypto::hash::traits::FromU64x4, pgoldilocks::{PoseidonHasher, QHashOut}, utils::QPGenRandom, PF};

    type Hash = QHashOut<PF>;

    fn make_nca_shallow(nca: &mut PartialUpdateNearestCommonAncestorProof<Hash>) {
        nca.nearest_common_ancestor_level = 0;
        nca.child_a.index = 0;
        nca.child_a.siblings.clear();
        nca.child_b.index = 1;
        nca.child_b.siblings.clear();
    }

    /// Builds an end cap whose witness is genuinely consistent: the merkle proof
    /// comes from a real in-memory tree, and the checkpoint root is the historical
    /// root of that proof.
    fn consistent_end_cap(height: u8, leaf_index: u64, salt: u64) -> VerifyEndCapSimpleStandardInput<PF, Hash> {
        let mut tree = SimpleMemoryMerkleStoreV3::<PoseidonHasher, Hash>::new(height);
        let leaf_value = Hash::from_u64x4([salt, salt + 1, salt + 2, salt + 3]);
        let delta = tree.set_leaf(leaf_index, leaf_value);
        let proof = MerkleProofCore {
            root: delta.new_root,
            value: leaf_value,
            index: leaf_index,
            siblings: delta.siblings.clone(),
        };
        let (historical_root, current_root) =
            compute_historical_and_current_merkle_roots_core_gt::<Hash, PoseidonHasher>(&proof);
        assert_eq!(current_root, proof.root);
        VerifyEndCapSimpleStandardInput {
            guta_stats: GUTAStats::qp_rand_gen(),
            checkpoint_root: historical_root,
            checkpoint_historical_merkle_proof: proof,
        }
    }

    #[test]
    fn left_guta_right_end_cap_simple_witness_accepts_consistent_checkpoint_root() {
        let end_cap = consistent_end_cap(4, 2, 13);
        let mut input = VerifyLeftGUTARightEndCapInputSimple::<PF, Hash>::qp_rand_gen();
        input.b_end_cap = end_cap.clone();
        let (_historical_root, current_root) =
            compute_historical_and_current_merkle_roots_core_gt::<Hash, PoseidonHasher>(&end_cap.checkpoint_historical_merkle_proof);
        input.checkpoint_tree_root = current_root;
        assert!(input.check_witness::<PoseidonHasher>().is_ok());

        input.checkpoint_tree_root = Hash::from_u64x4([9, 9, 9, 9]);
        let err = input.check_witness::<PoseidonHasher>().unwrap_err();
        assert!(err.to_string().contains("left guta right endcap checkpoint tree root not match"));
    }

    #[test]
    fn left_end_cap_right_guta_simple_witness_accepts_consistent_checkpoint_root() {
        let end_cap = consistent_end_cap(4, 5, 17);
        let mut input = VerifyLeftEndCapRightGUTAInputSimple::<PF, Hash>::qp_rand_gen();
        input.a_end_cap = end_cap.clone();
        let (_historical_root, current_root) =
            compute_historical_and_current_merkle_roots_core_gt::<Hash, PoseidonHasher>(&end_cap.checkpoint_historical_merkle_proof);
        input.checkpoint_tree_root = current_root;
        assert!(input.check_witness::<PoseidonHasher>().is_ok());

        input.checkpoint_tree_root = Hash::from_u64x4([8, 8, 8, 8]);
        let err = input.check_witness::<PoseidonHasher>().unwrap_err();
        assert!(err.to_string().contains("left endcap right guta checkpoint tree root not match"));
    }

    #[test]
    fn left_guta_right_end_cap_projects_header_and_end_result() {
        let mut input = VerifyLeftGUTARightEndCapInput::<PF, Hash>::qp_rand_gen();
        make_nca_shallow(&mut input.nca_proof);
        let header = input.get_guta_header_a();
        let result = input.get_end_result_b();
        assert_eq!(header.guta_circuit_whitelist, input.guta_inclusion_proof_a.root);
        assert_eq!(header.checkpoint_tree_root, input.checkpoint_tree_root);
        assert_eq!(header.state_transition.old_node_value, input.nca_proof.child_a.old_value);
        assert_eq!(result.start_user_leaf_hash, input.nca_proof.child_b.old_value);
        assert_eq!(result.end_user_leaf_hash, input.nca_proof.child_b.new_value);
        assert_eq!(result.checkpoint_tree_root_hash, input.b_end_cap.checkpoint_root);
    }

    #[test]
    fn left_end_cap_right_guta_projects_header_and_end_result() {
        let mut input = VerifyLeftEndCapRightGUTAInput::<PF, Hash>::qp_rand_gen();
        make_nca_shallow(&mut input.nca_proof);
        let header = input.get_guta_header_b();
        let result = input.get_end_result_a();
        assert_eq!(header.guta_circuit_whitelist, input.guta_inclusion_proof_b.root);
        assert_eq!(header.checkpoint_tree_root, input.checkpoint_tree_root);
        assert_eq!(header.state_transition.new_node_value, input.nca_proof.child_b.new_value);
        assert_eq!(result.start_user_leaf_hash, input.nca_proof.child_a.old_value);
        assert_eq!(result.end_user_leaf_hash, input.nca_proof.child_a.new_value);
        assert_eq!(result.checkpoint_tree_root_hash, input.a_end_cap.checkpoint_root);
    }

    #[test]
    fn simple_witnesses_reject_random_inconsistent_end_caps() {
        let left = VerifyLeftGUTARightEndCapInputSimple::<PF, Hash>::qp_rand_gen();
        let right = VerifyLeftEndCapRightGUTAInputSimple::<PF, Hash>::qp_rand_gen();
        assert!(left.check_witness::<parth_core::pgoldilocks::PoseidonHasher>().is_err());
        assert!(right.check_witness::<parth_core::pgoldilocks::PoseidonHasher>().is_err());
    }
}
