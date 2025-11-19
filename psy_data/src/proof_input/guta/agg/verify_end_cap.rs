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
pub struct VerifyEndCapSimpleStandardInput<F, Hash> {
    pub guta_stats: GUTAStats<F>,
    pub checkpoint_root: Hash,
    pub checkpoint_historical_merkle_proof: MerkleProofCore<Hash>,
}

impl<F, Hash: Copy + PartialEq> VerifyEndCapSimpleStandardInput<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        let (historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.checkpoint_historical_merkle_proof);
        if self.checkpoint_root != historical_root {
            return Err(anyhow::anyhow!("end result historical root not match"));
        }
        if current_root != self.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("end result current root not match"));
        }
        Ok(())
    }
}
#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyEndCapSimpleStandardInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            guta_stats: GUTAStats::qp_rand_gen(),
            checkpoint_root: Hash::qp_rand_gen(),
            checkpoint_historical_merkle_proof: MerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyEndCapSimpleStandardInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyEndCapSimpleStandardInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.guta_stats.pio_serialized_size()
        + 32
        + self.checkpoint_historical_merkle_proof.pio_serialized_size()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.guta_stats.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.checkpoint_root.into_owned_32bytes())?;
        self.checkpoint_historical_merkle_proof.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let guta_stats = GUTAStats::pio_read_from_io(reader)?;
        let checkpoint_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let checkpoint_historical_merkle_proof = MerkleProofCore::pio_read_from_io(reader)?;
        Ok(Self {
            guta_stats,
            checkpoint_root,
            checkpoint_historical_merkle_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyEndCapSimpleStandardInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyEndCapSimpleStandardInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyEndCapSimpleStandardInput,
    { parth_core::PF, parth_core::PHash },
    verify_end_cap_simple_standard_input_ser_tests
);



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoEndCapCircuitWithIdsInput<F, Hash> {
    pub input: VerifyTwoEndCapCircuitInput<F, Hash>,

    pub proof_a_id: QProvingJobDataID,
    pub proof_b_id: QProvingJobDataID,
}


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoEndCapCircuitInput<F, Hash> {
    pub guta_circuit_whitelist: Hash,
    
    pub a_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,

    pub b_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,

    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
}
#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyTwoEndCapCircuitInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            guta_circuit_whitelist: Hash::qp_rand_gen(),
            a_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            b_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            nca_proof: PartialUpdateNearestCommonAncestorProof::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyTwoEndCapCircuitInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyTwoEndCapCircuitInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
        + self.a_end_cap.pio_serialized_size()
        + self.b_end_cap.pio_serialized_size()
        + self.nca_proof.pio_serialized_size()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.guta_circuit_whitelist.into_owned_32bytes())?;
        self.a_end_cap.pio_write_to_io(writer)?;
        self.b_end_cap.pio_write_to_io(writer)?;
        self.nca_proof.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let guta_circuit_whitelist = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let a_end_cap = VerifyEndCapSimpleStandardInput::pio_read_from_io(reader)?;
        let b_end_cap = VerifyEndCapSimpleStandardInput::pio_read_from_io(reader)?;
        let nca_proof = PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        Ok(Self {
            guta_circuit_whitelist,
            a_end_cap,
            b_end_cap,
            nca_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyTwoEndCapCircuitInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyTwoEndCapCircuitInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyTwoEndCapCircuitInput,
    { parth_core::PF, parth_core::PHash },
    verify_two_end_cap_circuit_input_ser_tests
);



impl<F: QFelt64, Hash: Copy> VerifyTwoEndCapCircuitInput<F, Hash> {

    pub fn get_end_result_a(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_a.old_value,
            end_user_leaf_hash: self.nca_proof.child_a.new_value,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: F::from_u64_value(self.nca_proof.child_a.index),
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

    pub fn get_new_guta_header<Hasher: MerkleHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_historical_merkle_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.compute_old_nca_value::<Hasher>(),
                new_node_value: self.nca_proof.compute_new_nca_value::<Hasher>(),
                node_index: F::from_u64_value(self.nca_proof.get_nca_index()),
                node_level: F::from_u8_value(self.nca_proof.nearest_common_ancestor_level),
            },
            stats: self.a_end_cap.guta_stats.combine_with(&self.b_end_cap.guta_stats),
            total_aggregation_proofs_generated: F::from_u64_value(1),
        }
    }

}
impl<F: QFelt64, Hash: Copy + PartialEq> VerifyTwoEndCapCircuitInput<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        self.a_end_cap.check_witness::<Hasher>()?;
        self.b_end_cap.check_witness::<Hasher>()?;

        if self.a_end_cap.checkpoint_historical_merkle_proof.root != self.b_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("two endcap current checkpoint root not match"));
        }
        // todo: check nca proof

        Ok(())
    }
}





#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifySingleEndCapInput<F, Hash> {
    pub guta_circuit_whitelist: Hash,

    pub a_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,

    pub start_user_leaf_hash: Hash,
    pub end_user_leaf_hash: Hash,
    pub user_id: F,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifySingleEndCapInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            guta_circuit_whitelist: Hash::qp_rand_gen(),
            a_end_cap: VerifyEndCapSimpleStandardInput::qp_rand_gen(),
            start_user_leaf_hash: Hash::qp_rand_gen(),
            end_user_leaf_hash: Hash::qp_rand_gen(),
            user_id: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifySingleEndCapInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifySingleEndCapInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32
        + self.a_end_cap.pio_serialized_size()
        + 32
        + 32
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.guta_circuit_whitelist.into_owned_32bytes())?;
        self.a_end_cap.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.start_user_leaf_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.end_user_leaf_hash.into_owned_32bytes())?;
        writer.psy_write_u64(self.user_id.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let guta_circuit_whitelist = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let a_end_cap = VerifyEndCapSimpleStandardInput::pio_read_from_io(reader)?;
        let start_user_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let end_user_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let user_id = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            guta_circuit_whitelist,
            a_end_cap,
            start_user_leaf_hash,
            end_user_leaf_hash,
            user_id,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifySingleEndCapInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifySingleEndCapInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifySingleEndCapInput,
    { parth_core::PF, parth_core::PHash },
    verify_single_end_cap_input_ser_tests
);


impl<F: QFelt64, Hash: Copy> VerifySingleEndCapInput<F, Hash> {

    pub fn get_guta_header_a(&self, global_user_tree_height: u8) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.start_user_leaf_hash,
                new_node_value: self.end_user_leaf_hash,
                node_index: self.user_id,
                node_level: F::from_u8_value(global_user_tree_height),
            },
            stats: self.a_end_cap.guta_stats,
            total_aggregation_proofs_generated: F::from_u64_value(0),
        }
    }
    pub fn get_new_guta_header(&self, global_user_tree_height: u8) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_historical_merkle_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.start_user_leaf_hash,
                new_node_value: self.end_user_leaf_hash,
                node_index: self.user_id,
                node_level: F::from_u8_value(global_user_tree_height),
            },
            stats: self.a_end_cap.guta_stats,
            total_aggregation_proofs_generated: F::from_u64_value(1),
        }
    }
}
impl<F: QFelt64, Hash: Copy + PartialEq> VerifySingleEndCapInput<F, Hash> {
    pub fn get_end_result_a(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.start_user_leaf_hash,
            end_user_leaf_hash: self.end_user_leaf_hash,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: self.user_id,
        }
    }
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self, global_user_tree_height: u8) -> anyhow::Result<()> {
        self.a_end_cap.check_witness::<Hasher>()?;
        let end_result = self.get_end_result_a();
        let guta_new_header = self.get_new_guta_header(global_user_tree_height);
        if end_result.start_user_leaf_hash != guta_new_header.state_transition.old_node_value ||
            end_result.end_user_leaf_hash != guta_new_header.state_transition.new_node_value ||
            end_result.user_id != guta_new_header.state_transition.node_index {
            return Err(anyhow::anyhow!("end result not match"));
        }

        let (historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.a_end_cap.checkpoint_historical_merkle_proof);
        if historical_root != end_result.checkpoint_tree_root_hash {
            return Err(anyhow::anyhow!("historical root not match"));
        }
        if current_root != guta_new_header.checkpoint_tree_root {
            return Err(anyhow::anyhow!("current root not match"));
        }

        Ok(())
    }
}


