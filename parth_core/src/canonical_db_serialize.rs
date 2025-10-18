
/* 
    impl<const N: usize> PsyCanonicalDatabaseSerializeBaseMulti for ExFFS {
        fn psydbser_serialize_vec_of_self_ref(data: &[Self], write_fixed_items_count: bool) -> Vec<u8> {
            if write_fixed_items_count {
                // if write fixed item count, we need to make a copy of the dat because we need
                // to write the count first
                let mut bytes = Vec::with_capacity(data.len() * Self::FIXED_SIZE + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE);
                bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                Self::write_ffs_serialize_vec_of_self(data, &mut bytes);
                bytes
            } else {
                Self::ffs_serialize_vec_of_self_ref(data)
            }
        }

        fn psydbser_serialize_vec_of_self(data: Vec<Self>, write_fixed_items_count: bool) -> Vec<u8> {
            if write_fixed_items_count {
                // if write fixed item count, we need to make a copy of the dat because we need
                // to write the count first
                let mut bytes = Vec::with_capacity(data.len() * Self::FIXED_SIZE + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE);
                bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                Self::write_ffs_serialize_vec_of_self(&data, &mut bytes);
                bytes
            } else {
                Self::ffs_serialize_vec_of_self(data)
            }
        }

        fn psydbser_deserialize_vec_of_self(data: &[u8], include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
            if include_size_for_fixed {
                if data.len() < PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                    anyhow::bail!("Data length {} is too small to contain fixed items count", data.len());
                }
                let count_bytes: [u8; PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE] = data[0..PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE].try_into().unwrap();
                let count = u32::from_le_bytes(count_bytes) as usize;
                let expected_len = PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE + count * Self::FIXED_SIZE;
                if data.len() != expected_len {
                    anyhow::bail!(
                        "Data length {} does not match expected size {} for count {}",
                        data.len(),
                        expected_len,
                        count
                    );
                }
                let items_data = &data[PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE..];
                Self::ffs_deserialize_vec_of_self(items_data)
            } else {
                Self::ffs_deserialize_vec_of_self(data)
            }
        }

        fn psydbser_deserialize_vec_of_self_owned(data: Vec<u8>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
            if include_size_for_fixed {
                if data.len() < PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                    anyhow::bail!("Data length {} is too small to contain fixed items count", data.len());
                }
                let read_len = u32::from_le_bytes(data[0..PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE].try_into().unwrap()) as usize;
                let expected_len = PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE + read_len * Self::FIXED_SIZE;
                if data.len() != expected_len {
                    anyhow::bail!(
                        "Data length {} does not match expected size {} for count {}",
                        data.len(),
                        expected_len,
                        read_len
                    );
                }
                // TODO: is there a zero copy way to chop off the first 4 bytes of data Vec<u8>
                // so we can do ffs_deserialize_vec_of_self_owned?
                Self::ffs_deserialize_vec_of_self(&data[PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE..])
            } else {
                Self::ffs_deserialize_vec_of_self_owned(data)
            }
        }
#[cfg(test)]
mod tests {
    use psy_io::PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE;

    use crate::{
        canonical_db_serialize::{
            AutoFFSPsyCanonicalDatabaseSerializeFixedBase, PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle,
            PsyCanonicalSerializeMetadata, PsyIOReadWrite,
        },
        utils::QPGenRandom,
    };
use psy_serialize::FastFixedSerializable;
    #[pderive::serialize_copy]
    #[derive(bytemuck::Pod, bytemuck::Zeroable)]
    #[repr(transparent)]
    struct ExFFS(pub [u8; 8]);
    impl QPGenRandom for ExFFS {
        fn qp_rand_gen() -> Self {
            let data: [u8; 8] = QPGenRandom::qp_rand_gen();
            Self(data)
        }
    }

    impl FastFixedSerializable<8> for ExFFS {
        fn ffs_from_owned_bytes(data: [u8; 8]) -> Self {
            // zero copy
            bytemuck::cast(data)
        }

        fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
            if data.len() != 8 {
                panic!("Invalid data length for ExFFS");
            }
            let data_array: [u8; 8] = data.try_into().unwrap(); // only one copy
            bytemuck::cast(data_array)
        }

        fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
            if data.len() != 8 {
                anyhow::bail!("Invalid data length for ExFFS");
            }
            let data_array: [u8; 8] = data.try_into().unwrap(); // only one copy
            Ok(bytemuck::cast(data_array))
        }

        fn ffs_to_bytes(&self) -> [u8; 8] {
            self.0 // only one copy
        }

        fn ffs_into_bytes(self) -> [u8; 8] {
            bytemuck::cast(self) // zero copy
        }
    }

    impl PsyCanonicalSerializeMetadata for ExFFS {
        const IS_FIXED_SIZE: bool = true;
        const FIXED_SIZE: usize = 8;
    }
    impl AutoFFSPsyCanonicalDatabaseSerializeFixedBase<8> for ExFFS {}

    impl PsyIOReadWrite for ExFFS {
        fn pio_serialized_size(&self) -> usize {
            8
        }

        fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
            writer.write_all(&self.ffs_to_bytes())?;
            Ok(())
        }

        fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(Self::ffs_from_owned_bytes(buf))
        }
    }
    impl PsyCanonicalDatabaseSerializeBaseSingle for ExFFS {
        fn psydbser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
            if data.len() != Self::FIXED_SIZE {
                anyhow::bail!("Invalid data length, expected {}, got {}", Self::FIXED_SIZE, data.len());
            }
            let mut arr = [0u8; Self::FIXED_SIZE];
            arr.copy_from_slice(data);
            Ok(Self::ffs_from_owned_bytes(arr))
        }

        fn psydbser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
            Ok(self.ffs_to_bytes().to_vec())
        }
        fn psydbser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
            Ok(self.ffs_into_bytes().to_vec())
        }
        fn psydbser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
            if data.len() != Self::FIXED_SIZE {
                anyhow::bail!("Invalid data length, expected {}, got {}", Self::FIXED_SIZE, data.len());
            }
            Ok(Self::ffs_from_owned_bytes(data.try_into().unwrap()))
        }
    }

    impl PsyCanonicalDatabaseSerializeBaseMulti for ExFFS {
        fn psydbser_serialize_vec_of_self_ref(data: &[Self], write_fixed_items_count: bool) -> Vec<u8> {
            if write_fixed_items_count {
                // if write fixed item count, we need to make a copy of the dat because we need
                // to write the count first
                let mut bytes = Vec::with_capacity(data.len() * Self::FIXED_SIZE + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE);
                bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                Self::write_ffs_serialize_vec_of_self(data, &mut bytes);
                bytes
            } else {
                Self::ffs_serialize_vec_of_self_ref(data)
            }
        }

        fn psydbser_serialize_vec_of_self(data: Vec<Self>, write_fixed_items_count: bool) -> Vec<u8> {
            if write_fixed_items_count {
                // if write fixed item count, we need to make a copy of the dat because we need
                // to write the count first
                let mut bytes = Vec::with_capacity(data.len() * Self::FIXED_SIZE + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE);
                bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
                Self::write_ffs_serialize_vec_of_self(&data, &mut bytes);
                bytes
            } else {
                Self::ffs_serialize_vec_of_self(data)
            }
        }

        fn psydbser_deserialize_vec_of_self(data: &[u8], include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
            if include_size_for_fixed {
                if data.len() < PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                    anyhow::bail!("Data length {} is too small to contain fixed items count", data.len());
                }
                let count_bytes: [u8; PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE] = data[0..PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE].try_into().unwrap();
                let count = u32::from_le_bytes(count_bytes) as usize;
                let expected_len = PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE + count * Self::FIXED_SIZE;
                if data.len() != expected_len {
                    anyhow::bail!(
                        "Data length {} does not match expected size {} for count {}",
                        data.len(),
                        expected_len,
                        count
                    );
                }
                let items_data = &data[PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE..];
                Self::ffs_deserialize_vec_of_self(items_data)
            } else {
                Self::ffs_deserialize_vec_of_self(data)
            }
        }

        fn psydbser_deserialize_vec_of_self_owned(data: Vec<u8>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
            if include_size_for_fixed {
                if data.len() < PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                    anyhow::bail!("Data length {} is too small to contain fixed items count", data.len());
                }
                let read_len = u32::from_le_bytes(data[0..PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE].try_into().unwrap()) as usize;
                let expected_len = PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE + read_len * Self::FIXED_SIZE;
                if data.len() != expected_len {
                    anyhow::bail!(
                        "Data length {} does not match expected size {} for count {}",
                        data.len(),
                        expected_len,
                        read_len
                    );
                }
                // TODO: is there a zero copy way to chop off the first 4 bytes of data Vec<u8>
                // so we can do ffs_deserialize_vec_of_self_owned?
                Self::ffs_deserialize_vec_of_self(&data[PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE..])
            } else {
                Self::ffs_deserialize_vec_of_self_owned(data)
            }
        }
    }
}

*/