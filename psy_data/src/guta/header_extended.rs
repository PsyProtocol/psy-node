use parth_core::{
    QJOB_ID_SERIALIZED_SIZE, QJobIdSerialized, crypto::hash::{tag_tree::TagTreeNodePreimage, traits::{FieldQHasher, QFieldHashable}}, data::queue::queue_key::PCoreQueueItemBase, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}, utils::QPGenRandom
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::guta::header::GlobalUserTreeAggregatorHeader;
#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct GlobalUserTreeAggregatorHeaderWithProofStats<F, Hash > {
    pub base_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub total_guta_proofs_generated: F,
}



impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GlobalUserTreeAggregatorHeaderWithProofStats<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let base_header_hash = self.base_header.qfhash::<H>();
        let base_header_hash_elements = base_header_hash.to_4_felts();
        H::q_hash_many(&[
            base_header_hash_elements[0],
            base_header_hash_elements[1],
            base_header_hash_elements[2],
            base_header_hash_elements[3],
            self.total_guta_proofs_generated,
        ])
    }
}





impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GlobalUserTreeAggregatorHeaderWithProofStats<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        GlobalUserTreeAggregatorHeaderWithProofStats {
            base_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
            total_guta_proofs_generated: F::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GlobalUserTreeAggregatorHeaderWithProofStats<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 8 + GlobalUserTreeAggregatorHeader::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithProofStats<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         8 + GlobalUserTreeAggregatorHeader::<F, Hash>::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.base_header.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.total_guta_proofs_generated.to_u64_value())?;
        
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let base_header = GlobalUserTreeAggregatorHeader::pio_read_from_io(reader)?;
        let total_guta_proofs_generated = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            base_header,
            total_guta_proofs_generated,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GlobalUserTreeAggregatorHeaderWithProofStats,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithProofStats<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GlobalUserTreeAggregatorHeaderWithProofStats,
    { parth_core::PF, parth_core::PHash },
    global_user_tree_agg_header_with_proof_stats_tests
);






// with tag value

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash > {
    pub header_with_stats: GlobalUserTreeAggregatorHeaderWithProofStats<F, Hash>,
    pub new_tag_tree_node_value: Hash,
}



impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let header_with_stats_hash = self.header_with_stats.qfhash::<H>();

        H::q_two_to_one(
            header_with_stats_hash,
            self.new_tag_tree_node_value,
        )
    }
}





impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        GlobalUserTreeAggregatorHeaderWithTagValue {
            header_with_stats: GlobalUserTreeAggregatorHeaderWithProofStats::qp_rand_gen(),
            new_tag_tree_node_value: Hash::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32 + GlobalUserTreeAggregatorHeaderWithProofStats::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         32 + GlobalUserTreeAggregatorHeaderWithProofStats::<F, Hash>::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.header_with_stats.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.new_tag_tree_node_value.into_owned_32bytes())?;
        
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let header_with_stats = GlobalUserTreeAggregatorHeaderWithProofStats::pio_read_from_io(reader)?;
        let new_tag_tree_node_value = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        Ok(Self {
            header_with_stats,
            new_tag_tree_node_value,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GlobalUserTreeAggregatorHeaderWithTagValue,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GlobalUserTreeAggregatorHeaderWithTagValue,
    { parth_core::PF, parth_core::PHash },
    global_user_tree_agg_header_with_tag_value_tests
);



// with tag preimage

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct GlobalUserTreeAggregatorHeaderWithTagPreimage<F, Hash > {
    pub header_with_stats: GlobalUserTreeAggregatorHeaderWithProofStats<F, Hash>,
    pub new_tag_tree_node_preimage: TagTreeNodePreimage<Hash>,
}



impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GlobalUserTreeAggregatorHeaderWithTagPreimage<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let header_with_stats_hash = self.header_with_stats.qfhash::<H>();
        let new_tag_tree_node_preimage_hash = self.new_tag_tree_node_preimage.get_node_hash::<H>();


        H::q_two_to_one(
            header_with_stats_hash,
            new_tag_tree_node_preimage_hash,
        )
    }
}





impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GlobalUserTreeAggregatorHeaderWithTagPreimage<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        GlobalUserTreeAggregatorHeaderWithTagPreimage {
            header_with_stats: GlobalUserTreeAggregatorHeaderWithProofStats::qp_rand_gen(),
            new_tag_tree_node_preimage: TagTreeNodePreimage::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GlobalUserTreeAggregatorHeaderWithTagPreimage<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32*3 + GlobalUserTreeAggregatorHeaderWithProofStats::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagPreimage<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         32*3 + GlobalUserTreeAggregatorHeaderWithProofStats::<F, Hash>::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.header_with_stats.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.new_tag_tree_node_preimage.left.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_tag_tree_node_preimage.right.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_tag_tree_node_preimage.tag.into_owned_32bytes())?;
        
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let header_with_stats = GlobalUserTreeAggregatorHeaderWithProofStats::pio_read_from_io(reader)?;
        let new_tag_tree_node_preimage_left = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let new_tag_tree_node_preimage_right = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let new_tag_tree_node_preimage_tag = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        Ok(Self {
            header_with_stats,
            new_tag_tree_node_preimage: TagTreeNodePreimage {
                left: new_tag_tree_node_preimage_left,
                right: new_tag_tree_node_preimage_right,
                tag: new_tag_tree_node_preimage_tag,
            },
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GlobalUserTreeAggregatorHeaderWithTagPreimage,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagPreimage<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GlobalUserTreeAggregatorHeaderWithTagPreimage,
    { parth_core::PF, parth_core::PHash },
    global_user_tree_agg_header_with_tag_preimage_tests
);

// with job type


#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash> {
    pub header: GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash>,
    pub job_type_u32: u32,
}



impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.header.qfhash::<H>()
    }
}





impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
            header: GlobalUserTreeAggregatorHeaderWithTagValue::qp_rand_gen(),
            job_type_u32: u32::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 4 + GlobalUserTreeAggregatorHeaderWithTagValue::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         4 + GlobalUserTreeAggregatorHeaderWithTagValue::<F, Hash>::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.header.pio_write_to_io(writer)?;
        writer.psy_write_u32(self.job_type_u32)?;
        
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let header = GlobalUserTreeAggregatorHeaderWithTagValue::pio_read_from_io(reader)?;
        let job_type_u32 = reader.psy_read_u32()?;
        Ok(Self {
            header,
            job_type_u32,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
    { parth_core::PF, parth_core::PHash },
    global_user_tree_agg_header_with_tag_value_and_job_type_tests
);


// with serialized job id

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID<F, Hash> {
    pub header: GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash>,
    pub serialized_job_id: QJobIdSerialized,
}



impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.header.qfhash::<H>()
    }
}





impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID {
            header: GlobalUserTreeAggregatorHeaderWithTagValue::qp_rand_gen(),
            serialized_job_id: QJobIdSerialized::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = QJOB_ID_SERIALIZED_SIZE + GlobalUserTreeAggregatorHeaderWithTagValue::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         QJOB_ID_SERIALIZED_SIZE + GlobalUserTreeAggregatorHeaderWithTagValue::<F, Hash>::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.header.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.serialized_job_id)?;

        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let header = GlobalUserTreeAggregatorHeaderWithTagValue::pio_read_from_io(reader)?;
        let serialized_job_id = reader.psy_read_bytes_fixed()?;
        Ok(Self {
            header,
            serialized_job_id,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID<F, Hash> {}



pser::impl_psy_ser_basic_tests_fallback!(
    GlobalUserTreeAggregatorHeaderWithTagValueAndSerializedJobID,
    { parth_core::PF, parth_core::PHash },
    global_user_tree_agg_header_with_tag_value_and_serialized_job_id_tests
);


// with job id


#[pderive::serialize_copy_f_hash_no_rkyv_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {
    pub header: GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash>,
    pub job_id: QProvingJobDataID,
}



impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        self.header.qfhash::<H>()
    }
}





impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobID {
            header: GlobalUserTreeAggregatorHeaderWithTagValue::qp_rand_gen(),
            job_id: QProvingJobDataID::qp_rand_gen(),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = QJOB_ID_SERIALIZED_SIZE + GlobalUserTreeAggregatorHeaderWithTagValue::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         QJOB_ID_SERIALIZED_SIZE + GlobalUserTreeAggregatorHeaderWithTagValue::<F, Hash>::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.header.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.job_id.to_fixed_bytes())?;

        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let header = GlobalUserTreeAggregatorHeaderWithTagValue::pio_read_from_io(reader)?;
        let job_id = QProvingJobDataID::try_from_byte_vec(&reader.psy_read_bytes_fixed::<QJOB_ID_SERIALIZED_SIZE>()?)?;
        Ok(Self {
            header,
            job_id,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {}



pser::impl_psy_ser_basic_tests_fallback!(
    GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    { parth_core::PF, parth_core::PHash },
    global_user_tree_agg_header_with_tag_value_and_job_id_tests
);

impl<F: QFelt64, Hash: Q256BitHash> PCoreQueueItemBase for GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash> {
    fn is_queue_item(data: &[u8]) -> bool {
        data.len() == Self::FIXED_SIZE
    }

    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        Self::psy_ser_from_slice(data)
    }

    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
       self.psy_ser_to_bytes_vec()
    }

    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.job_id.to_fixed_bytes().to_vec()
    }

    fn get_size_hint() -> usize {
        Self::FIXED_SIZE
    }

    fn has_fixed_size() -> bool {
        true
    }
}