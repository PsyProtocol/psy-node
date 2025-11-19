
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
pub struct VerifyGUTAToCapCircuitInputSimple<F, Hash> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub top_line_siblings: Vec<Hash>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyGUTAToCapCircuitInputSimple<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            guta_proof_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            top_line_siblings: QPGenRandom::qp_rand_gen_vec(rand::random::<u8>() as usize % 10 + 1),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyGUTAToCapCircuitInputSimple<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyGUTAToCapCircuitInputSimple<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.guta_proof_header.pio_serialized_size()
        + 4 + self.top_line_siblings.len() * 32
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.guta_proof_header.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.top_line_siblings.len())?;
        for sibling in &self.top_line_siblings {
            writer.psy_write_bytes_fixed(&sibling.into_owned_32bytes())?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let guta_proof_header = GlobalUserTreeAggregatorHeader::pio_read_from_io(reader)?;
        let siblings_len = reader.psy_read_vec_length()?;
        let mut top_line_siblings = Vec::with_capacity(siblings_len);
        for _ in 0..siblings_len {
            top_line_siblings.push(Hash::from_owned_32bytes(reader.psy_read_bytes_32()?));
        }
        Ok(Self {
            guta_proof_header,
            top_line_siblings,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyGUTAToCapCircuitInputSimple,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyGUTAToCapCircuitInputSimple<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyGUTAToCapCircuitInputSimple,
    { parth_core::PF, parth_core::PHash },
    verify_guta_to_cap_circuit_input_simple_ser_tests
);

impl<F: QFelt64, Hash: PartialEq + Copy> VerifyGUTAToCapCircuitInputSimple<F, Hash> {
    pub fn get_new_state_transition<H: MerkleHasher<Hash>>(&self) -> SubTreeNodeStateTransition<F, Hash> {

        if self.top_line_siblings.len() == 0 {
            self.guta_proof_header.state_transition.clone()
        }else{


            let new_dmp = DeltaMerkleProofCore::from_params::<H>(
                self.guta_proof_header.state_transition.node_index.to_u64_value(),
                self.guta_proof_header.state_transition.old_node_value,
                self.guta_proof_header.state_transition.new_node_value,
                self.top_line_siblings.clone(),
            );

            SubTreeNodeStateTransition{
                old_node_value: new_dmp.old_root,
                new_node_value: new_dmp.new_root,
                node_index:F::from_u64_value (
                    self.guta_proof_header.state_transition.node_index.to_u64_value()>>(self.top_line_siblings.len() as u64)
                ),
                node_level: F::from_u64_value (
                    self.guta_proof_header.state_transition.node_level.to_u64_value()-(self.top_line_siblings.len() as u64)
                ),
            }
        }

    }
    pub fn get_new_guta_header<H: MerkleHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {


        GlobalUserTreeAggregatorHeader{
            guta_circuit_whitelist: self.guta_proof_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.guta_proof_header.checkpoint_tree_root,
            state_transition: self.get_new_state_transition::<H>(),
            stats: self.guta_proof_header.stats,
            total_aggregation_proofs_generated: self.guta_proof_header.total_aggregation_proofs_generated + F::from_u64_value(1),
        }

    }
}



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub top_line_siblings: Vec<Hash>,
    pub historical_checkpoint_proof: MerkleProofCore<Hash>,
    pub total_aggregation_proofs_generated: F,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            guta_proof_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            top_line_siblings: QPGenRandom::qp_rand_gen_vec(rand::random::<u8>() as usize % 10 + 1),
            historical_checkpoint_proof: MerkleProofCore::qp_rand_gen(),
            total_aggregation_proofs_generated: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.guta_proof_header.pio_serialized_size()
        + 4 + self.top_line_siblings.len() * 32
        + self.historical_checkpoint_proof.pio_serialized_size()
        + 8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.guta_proof_header.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.top_line_siblings.len())?;
        for sibling in &self.top_line_siblings {
            writer.psy_write_bytes_fixed(&sibling.into_owned_32bytes())?;
        }
        self.historical_checkpoint_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_aggregation_proofs_generated.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let guta_proof_header = GlobalUserTreeAggregatorHeader::pio_read_from_io(reader)?;
        let siblings_len = reader.psy_read_vec_length()?;
        let mut top_line_siblings = Vec::with_capacity(siblings_len);
        for _ in 0..siblings_len {
            top_line_siblings.push(Hash::from_owned_32bytes(reader.psy_read_bytes_32()?));
        }
        let historical_checkpoint_proof = MerkleProofCore::pio_read_from_io(reader)?;
        let total_aggregation_proofs_generated = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            guta_proof_header,
            top_line_siblings,
            historical_checkpoint_proof,
            total_aggregation_proofs_generated,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple,
    { parth_core::PF, parth_core::PHash },
    verify_guta_to_cap_upgrade_checkpoint_circuit_input_simple_ser_tests
);

impl<F: QFelt64, Hash: PartialEq + Copy> VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash> {
    pub fn get_new_state_transition<H: MerkleHasher<Hash>>(&self) -> SubTreeNodeStateTransition<F, Hash> {

        if self.top_line_siblings.len() == 0 {
            self.guta_proof_header.state_transition.clone()
        }else{


            let new_dmp = DeltaMerkleProofCore::from_params::<H>(
                self.guta_proof_header.state_transition.node_index.to_u64_value(),
                self.guta_proof_header.state_transition.old_node_value,
                self.guta_proof_header.state_transition.new_node_value,
                self.top_line_siblings.clone(),
            );

            SubTreeNodeStateTransition{
                old_node_value: new_dmp.old_root,
                new_node_value: new_dmp.new_root,
                node_index:F::from_u64_value (
                    self.guta_proof_header.state_transition.node_index.to_u64_value()>>(self.top_line_siblings.len() as u64)
                ),
                node_level: F::from_u64_value (
                    self.guta_proof_header.state_transition.node_level.to_u64_value()-(self.top_line_siblings.len() as u64)
                ),
            }
        }

    }
    pub fn get_new_guta_header<H: MerkleHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {


        GlobalUserTreeAggregatorHeader{
            guta_circuit_whitelist: self.guta_proof_header.guta_circuit_whitelist,
            // upgraded to the new root for the new header
            checkpoint_tree_root: self.historical_checkpoint_proof.root,
            state_transition: self.get_new_state_transition::<H>(),
            stats: self.guta_proof_header.stats,
            total_aggregation_proofs_generated: self.total_aggregation_proofs_generated + F::from_u64_value(0),
        }

    }
}

