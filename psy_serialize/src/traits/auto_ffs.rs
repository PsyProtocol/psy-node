use psy_io::PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE;

use crate::{
    FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate, PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate,
    PsyCanonicalDatabaseSerializeFixedBase, PsyCanonicalSerializeMetadata, PsyIOReadWriteFixedTemplate,
};

pub trait AutoDatabaseSerializationUseFastFixedSerialize<const N: usize>: FastFixedSerializable<N> + Sized + PsyCanonicalSerializeMetadata {}

impl<const SIZE: usize, T: FastFixedSerializable<SIZE> + PsyCanonicalSerializeMetadata> PsyIOReadWriteFixedTemplate<SIZE> for T {}

impl<const SIZE: usize, T: AutoDatabaseSerializationUseFastFixedSerialize<SIZE>> PsyCanonicalDatabaseSerializeFixedBase<SIZE> for T {

    #[inline(always)]
    fn psy_ser_fixed_to_bytes(&self) -> [u8; SIZE] {
        self.ffs_to_bytes()
    }
    #[inline(always)]
    fn psy_ser_fixed_from_bytes_ref(bytes: &[u8; SIZE]) -> anyhow::Result<Self> {
        Self::ffs_try_from_slice(bytes)
    }

    #[inline(always)]
    fn psy_ser_fixed_from_owned_bytes(bytes: [u8; SIZE]) -> anyhow::Result<Self> {
        Ok(Self::ffs_from_owned_bytes(bytes))
    }

    fn psy_ser_fixed_many_from_bytes_ref(bytes: &[u8]) -> anyhow::Result<Vec<Self>> {
        if bytes.len() % SIZE != 0 {
            anyhow::bail!("Invalid bytes length for many_from_bytes_ref: not a multiple of SIZE");
        }
        let count = bytes.len() / SIZE;
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let start = i * SIZE;
            let end = start + SIZE;
            let array: &[u8; SIZE] = bytes[start..end]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert slice to array"))?;
            result.push(Self::psy_ser_fixed_from_bytes_ref(array)?);
        }
        Ok(result)
    }

    #[inline(always)]
    fn psy_ser_fixed_into_bytes(self) -> [u8; SIZE] {
        self.ffs_into_bytes()
    }
}

impl<const N: usize, T: AutoDatabaseSerializationUseFastFixedSerialize<N>> PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<N> for T {
    #[inline(always)]
    fn fx_tpl_psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        Self::ffs_try_from_slice(data)
    }

    #[inline(always)]
    fn fx_tpl_psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.ffs_to_bytes().to_vec())
    }

    #[inline(always)]
    fn fx_tpl_psy_ser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
        Ok(self.ffs_into_bytes().to_vec())
    }

    #[inline(always)]
    fn fx_tpl_psy_ser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self::ffs_from_owned_bytes(data.try_into().map_err(|e| anyhow::anyhow!("{:?}", e))?))
    }
}

impl<const N: usize, T: AutoDatabaseSerializationUseFastFixedSerialize<N>> PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<N> for T {
    
    #[inline]
    fn fx_tpl_psy_ser_serialize_vec_of_self_ref(data: &[Self], write_fixed_items_count: bool) -> Vec<u8> {
        if write_fixed_items_count {
            let mut bytes = Vec::with_capacity(data.len() * N + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE);
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            <T as FastFixedSerializable<N>>::write_ffs_serialize_vec_of_self(data, &mut bytes);
            bytes
        } else {
            <T as FastFixedSerializable<N>>::ffs_serialize_vec_of_self_ref(data)
        }
    }

    #[inline]
    fn fx_tpl_psy_ser_serialize_vec_of_self(data: Vec<Self>, write_fixed_items_count: bool) -> Vec<u8> {
        if write_fixed_items_count {
            let len = data.len();
            let mut item_bytes = <T as FastFixedSerializable<N>>::ffs_serialize_vec_of_self(data);
            let mut bytes = Vec::with_capacity(item_bytes.len() + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE);
            bytes.extend_from_slice(&(len as u32).to_le_bytes());
            bytes.append(&mut item_bytes);
            bytes
        } else {
            <T as FastFixedSerializable<N>>::ffs_serialize_vec_of_self(data)
        }
    }

    #[inline]
    fn fx_tpl_psy_ser_deserialize_vec_of_self(data: &[u8], include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if include_size_for_fixed {
            if data.len() < PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                anyhow::bail!("Data length {} is too small to contain fixed items count", data.len());
            }
            let count_bytes: [u8; PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE] = data[0..PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE].try_into().unwrap();
            let count = u32::from_le_bytes(count_bytes) as usize;
            let expected_len = PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE + count * N;
            if data.len() != expected_len {
                anyhow::bail!(
                    "Data length {} does not match expected size {} for count {}",
                    data.len(),
                    expected_len,
                    count
                );
            }
            let items_data = &data[PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE..];
            <T as FastFixedSerializable<N>>::ffs_deserialize_vec_of_self(items_data)
        } else {
            <T as FastFixedSerializable<N>>::ffs_deserialize_vec_of_self(data)
        }
    }

    #[inline]
    fn fx_tpl_psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if include_size_for_fixed {
            if data.len() < PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                anyhow::bail!("Data length {} is too small to contain fixed items count", data.len());
            }
            let count_bytes: [u8; PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE] = data[0..PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE].try_into().unwrap();
            let count = u32::from_le_bytes(count_bytes) as usize;
            let expected_len = PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE + count * N;
            if data.len() != expected_len {
                anyhow::bail!(
                    "Data length {} does not match expected size {} for count {}",
                    data.len(),
                    expected_len,
                    count
                );
            }
            let items_data = &data[PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE..];
            <T as FastFixedSerializable<N>>::ffs_deserialize_vec_of_self(items_data)
        } else {
            <T as FastFixedSerializable<N>>::ffs_deserialize_vec_of_self_owned(data)
        }
    }
}
