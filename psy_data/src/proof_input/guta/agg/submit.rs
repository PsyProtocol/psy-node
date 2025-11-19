use std::hash::Hash;

#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{guta::{header_extended::GlobalUserTreeAggregatorHeaderWithTagValue, stats::GUTAStats}, v1::qdata::{user::PQEDUserLeaf, user_end_cap_result::PUPSEndCapResultCompact}};
use psy_serialize::FallbackPsySerializeCanonical;




#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct SubmitUserEndCapNonProofCoreInput<F, Hash> {
    pub checkpoint_id: F,
    pub stats: GUTAStats<F>,
    pub state_transition: PUPSEndCapResultCompact<F, Hash>,
    pub new_user_leaf: PQEDUserLeaf<F, Hash>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for SubmitUserEndCapNonProofCoreInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_id: F::qp_rand_gen(),
            stats: GUTAStats::qp_rand_gen(),
            state_transition: PUPSEndCapResultCompact::qp_rand_gen(),
            new_user_leaf: PQEDUserLeaf::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for SubmitUserEndCapNonProofCoreInput<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 8 
        + GUTAStats::<F>::FIXED_SIZE 
        + PUPSEndCapResultCompact::<F, Hash>::FIXED_SIZE 
        + PQEDUserLeaf::<F, Hash>::FIXED_SIZE;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for SubmitUserEndCapNonProofCoreInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.checkpoint_id.to_u64_value())?;
        self.stats.pio_write_to_io(writer)?;
        self.state_transition.pio_write_to_io(writer)?;
        self.new_user_leaf.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_id = F::from_u64_value(reader.psy_read_u64()?);
        let stats = GUTAStats::pio_read_from_io(reader)?;
        let state_transition = PUPSEndCapResultCompact::pio_read_from_io(reader)?;
        let new_user_leaf = PQEDUserLeaf::pio_read_from_io(reader)?;
        Ok(Self {
            checkpoint_id,
            stats,
            state_transition,
            new_user_leaf,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    SubmitUserEndCapNonProofCoreInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for SubmitUserEndCapNonProofCoreInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    SubmitUserEndCapNonProofCoreInput,
    { parth_core::PF, parth_core::PHash },
    submit_user_end_cap_non_proof_core_input_ser_tests
);


impl<F : QFelt64, Hash: QFHashBase<F>> SubmitUserEndCapNonProofCoreInput<F, Hash> {

    pub fn get_proof_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self, global_user_tree_height: u8) -> Hash {
        Hasher::q_two_to_one(
            self.state_transition.qfhash_with_guta_height::<Hasher>(global_user_tree_height),
            self.stats.qfhash::<Hasher>()
        )
    }
}


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct SubmitGUTARealmResultAPINoProofInput<F, Hash> {
    pub guta_header: GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash>,
    pub circuit_type: ProvingJobCircuitType,
}

#[pderive::serialize_clone_f_hash_proof]
//#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash, Proof = Vec<u8>))]
pub struct SubmitGUTARealmResultAPIWithProof<F, Hash, Proof> {
    pub input: SubmitGUTARealmResultAPINoProofInput<F, Hash>,
    pub proof: Proof,
}