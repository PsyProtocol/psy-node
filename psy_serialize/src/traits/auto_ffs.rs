use crate::{FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate, PsyCanonicalDatabaseSerializeFixedBase, PsyCanonicalSerializeMetadata, PsyIOReadWriteFixedTemplate};

pub trait AutoDatabaseSerializationUseFastFixedSerialize<const N: usize>: FastFixedSerializable<N> + Sized + PsyCanonicalSerializeMetadata {}

impl<const SIZE: usize, T: FastFixedSerializable<SIZE> + PsyCanonicalSerializeMetadata> PsyIOReadWriteFixedTemplate<SIZE> for T {}

impl<const SIZE: usize, T: AutoDatabaseSerializationUseFastFixedSerialize<SIZE>> PsyCanonicalDatabaseSerializeFixedBase<SIZE> for T {
    fn psydbser_fixed_to_bytes(&self) -> [u8; SIZE] {
        self.ffs_to_bytes()
    }

    fn psydbser_fixed_from_bytes_ref(bytes: &[u8; SIZE]) -> anyhow::Result<Self> {
        Self::ffs_try_from_slice(bytes)
    }

    fn psydbser_fixed_from_owned_bytes(bytes: [u8; SIZE]) -> anyhow::Result<Self> {
        Ok(Self::ffs_from_owned_bytes(bytes))
    }

    fn psydbser_fixed_many_from_bytes_ref(bytes: &[u8]) -> anyhow::Result<Vec<Self>> {
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
            result.push(Self::psydbser_fixed_from_bytes_ref(array)?);
        }
        Ok(result)
    }

    fn psydbser_fixed_into_bytes(self) -> [u8; SIZE] {
        self.ffs_into_bytes()
    }
}



impl<const N: usize, T: AutoDatabaseSerializationUseFastFixedSerialize<N>> PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<N> for T {
    fn fx_tpl_psydbser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        Self::ffs_try_from_slice(data)
    }

    fn fx_tpl_psydbser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.ffs_to_bytes().to_vec())
    }
    
    fn fx_tpl_psydbser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
        Ok(self.ffs_into_bytes().to_vec())
    }
    
    fn fx_tpl_psydbser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self::ffs_from_owned_bytes(data.try_into().map_err(|e| anyhow::anyhow!("{:?}",e))?))
    }
}
