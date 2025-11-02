use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, felt::QFelt64, impl_qpd_serialize_params, protocol::core_types::{Q256BitHash, QDBHashBase, QFHashBase}, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};
use parth_core::data::serializable::QPDSerializable;
use pser::{QBytesSerialize, QBytesDeserialize};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct SubTreeNodeStateTransition<F, Hash> {
    pub old_node_value: Hash,
    pub new_node_value: Hash,
    pub node_index: F,
    pub node_level: F,
}


impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for SubTreeNodeStateTransition<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            old_node_value: Hash::qp_rand_gen(),
            new_node_value: Hash::qp_rand_gen(),
            node_index: F::qp_rand_gen(),
            node_level: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for SubTreeNodeStateTransition<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let old_node_value = self.old_node_value.to_4_felts();
        let new_node_value = self.new_node_value.to_4_felts();
        let node_change_combo = H::q_hash_many(&[
            self.node_index,
            old_node_value[0],
            old_node_value[1],
            old_node_value[2],
            old_node_value[3],
            new_node_value[0],
            new_node_value[1],
            new_node_value[2],
            new_node_value[3],
            self.node_level,
        ]);
        node_change_combo
    }
}




impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for SubTreeNodeStateTransition<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32+32+8+8; // = 80 bytes
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for SubTreeNodeStateTransition<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
       32+32+8+8
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.old_node_value.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_node_value.into_owned_32bytes())?;
        writer.psy_write_u64(self.node_index.to_u64_value())?;
        writer.psy_write_u64(self.node_level.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let old_node_value = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let new_node_value = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let node_index = F::from_u64_value(reader.psy_read_u64()?);
        let node_level = F::from_u64_value(reader.psy_read_u64()?);
        Ok(Self {
            old_node_value,
            new_node_value,
            node_index,
            node_level,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    SubTreeNodeStateTransition,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for SubTreeNodeStateTransition<F, Hash> {}


pser::impl_psy_ser_basic_tests!(
    SubTreeNodeStateTransition,
    // Note the use of concrete types here
    {  parth_core::PF, parth_core::PHash },
    sub_tree_state_transition_basic_ser_tests
);


impl_qpd_serialize_params!(
    SubTreeNodeStateTransition,
    { F: QFelt64, Hash: QDBHashBase } => { F, Hash }
);
