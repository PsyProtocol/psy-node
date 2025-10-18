use psy_io::{
    p_read_fixed_items_many_count, p_read_varuint, p_varuint_size, p_write_fixed_items_manycount, p_write_varuint, PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE,
};

use crate::data::serializable::FastFixedSerializable;
pub trait PsyCanonicalSerializeMetadata {
    const IS_FIXED_SIZE: bool;
    const FIXED_SIZE: usize;
}
pub trait PsyIOReadWrite: PsyCanonicalSerializeMetadata + Sized {
    fn pio_serialized_size(&self) -> usize;

    fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()>;
    fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self>;
    #[inline(always)]
    fn pio_get_variable_serialized_size(&self) -> usize {
        if Self::IS_FIXED_SIZE {
            Self::FIXED_SIZE
        } else {
            let base_size = self.pio_serialized_size();
            base_size + p_varuint_size(base_size)
        }
    }
    #[inline(always)]
    fn pio_write_to_io_many<W: psy_io::Write>(items: &[Self], writer: &mut W, write_fixed_items_count: bool) -> anyhow::Result<()> {
        if Self::IS_FIXED_SIZE {
            if write_fixed_items_count {
                p_write_fixed_items_manycount(items.len(), writer)?;
            }
            for item in items {
                item.pio_write_to_io(writer)?;
            }
            Ok(())
        } else {
            p_write_varuint(items.len(), writer)?;
            for item in items {
                let size = item.pio_serialized_size();
                p_write_varuint(size, writer)?;
                item.pio_write_to_io(writer)?;
            }
            Ok(())
        }
    }
    #[inline(always)]
    fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_size: Option<usize>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if !include_size_for_fixed && known_size.is_none() && Self::IS_FIXED_SIZE {
            anyhow::bail!("Cannot read fixed size items without known size if include_size_for_fixed is false");
        }
        let len = if let Some(size) = known_size {
            if include_size_for_fixed {
                let read_size = p_read_fixed_items_many_count(reader)?;
                if read_size != size {
                    anyhow::bail!("Mismatched fixed items count: expected {}, got {}", size, read_size);
                }
            }
            size
        } else {
            if Self::IS_FIXED_SIZE {
                p_read_fixed_items_many_count(reader)?
            } else {
                p_read_varuint(reader)?
            }
        };
        let mut items = Vec::with_capacity(len);
        if Self::IS_FIXED_SIZE {
            for _ in 0..len {
                let item = Self::pio_read_from_io(reader)?;
                items.push(item);
            }
            Ok(items)
        } else {
            for _ in 0..len {
                let size = p_read_varuint(reader)?;
                let mut buf = vec![0u8; size];
                reader.read_exact(&mut buf)?;
                let item = Self::pio_read_from_io(&mut &buf[..])?;
                items.push(item);
            }
            Ok(items)
        }
    }
    fn pio_serialized_size_vec(items: &[Self], include_size_for_fixed: bool) -> usize {
        if Self::IS_FIXED_SIZE {
            items.len() * Self::FIXED_SIZE + if include_size_for_fixed { PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE } else { 0 }
        } else {
            let mut total_size = p_varuint_size(items.len());

            for item in items {
                let item_size = item.pio_serialized_size();
                total_size += p_varuint_size(item_size) + item_size;
            }
            total_size
        }
    }
    fn pio_read_many_from_ref_bytes(data: &[u8], known_size: Option<usize>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let data_len = data.len();
        if let Some(known_sz) = known_size {
            if Self::IS_FIXED_SIZE {
                if !include_size_for_fixed && data_len != known_sz * Self::FIXED_SIZE {
                    anyhow::bail!(
                        "Data length {} does not match expected size {} for known size {}",
                        data_len,
                        known_sz * Self::FIXED_SIZE,
                        known_sz
                    );
                } else if include_size_for_fixed && data_len != known_sz * Self::FIXED_SIZE + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                    anyhow::bail!(
                        "Data length {} does not match expected size {} for known size {}",
                        data_len,
                        known_sz * Self::FIXED_SIZE + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE,
                        known_sz
                    );
                }
            }
        } else if Self::IS_FIXED_SIZE {
            if data_len % Self::FIXED_SIZE != 0 {
                anyhow::bail!("Data length {} is not a multiple of fixed size {}", data_len, Self::FIXED_SIZE);
            }
        }

        let mut cursor = psy_io::Cursor::new(data);
        Self::pio_read_from_io_many(&mut cursor, known_size, include_size_for_fixed)
    }
    fn pio_write_many_to_bytes(items: &[Self], write_fixed_items_count: bool) -> anyhow::Result<Vec<u8>> {
        let total_size = Self::pio_serialized_size_vec(items, write_fixed_items_count);
        let mut buffer = Vec::with_capacity(total_size);
        {
            let mut writer = psy_io::Cursor::new(&mut buffer);
            Self::pio_write_to_io_many(items, &mut writer, write_fixed_items_count)?;
        }
        Ok(buffer)
    }
}

pub trait PsyIOReadWriteFixedTemplate<const N: usize>: PsyCanonicalSerializeMetadata + FastFixedSerializable<N> + Sized {
    fn fx_tpl_pio_serialized_size(&self) -> usize {
        N
    }
    #[inline(always)]
    fn fx_tpl_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.write_all(&self.ffs_to_bytes())?;
        Ok(())
    }
    #[inline(always)]
    fn fx_tpl_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let mut buf = [0u8; N];
        reader.read_exact(&mut buf)?;
        Ok(Self::ffs_from_owned_bytes(buf))
    }

    #[inline(always)]
    fn fx_tpl_pio_get_variable_serialized_size(&self) -> usize {
        N
    }
    #[inline(always)]
    fn fx_tpl_pio_write_to_io_many<W: psy_io::Write>(items: &[Self], writer: &mut W, write_fixed_items_count: bool) -> anyhow::Result<()> {
        if write_fixed_items_count {
            p_write_fixed_items_manycount(items.len(), writer)?;
        }
        const BATCH_SIZE_BYTES: usize = 1024 * 100;

        let batch_size_count: usize = (BATCH_SIZE_BYTES / N).max(1);
        for chunk in items.chunks(batch_size_count) {
            writer.write_all(&Self::ffs_serialize_vec_of_self_ref(&chunk))?;
        }
        Ok(())
    }
    #[inline(always)]
    fn fx_tpl_pio_read_from_io_many<R: psy_io::Read>(
        reader: &mut R,
        known_size: Option<usize>,
        include_size_for_fixed: bool,
    ) -> anyhow::Result<Vec<Self>> {
        if !include_size_for_fixed && known_size.is_none() {
            anyhow::bail!("Cannot read fixed size items without known size if include_size_for_fixed is false");
        }
        let len = if let Some(size) = known_size {
            if include_size_for_fixed {
                let read_size = p_read_fixed_items_many_count(reader)?;
                if read_size != size {
                    anyhow::bail!("Mismatched fixed items count: expected {}, got {}", size, read_size);
                }
            }
            size
        } else {
            p_read_fixed_items_many_count(reader)?
        };
        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            let item = Self::fx_tpl_pio_read_from_io(reader)?;
            items.push(item);
        }
        Ok(items)
    }
    #[inline(always)]
    fn fx_tpl_pio_serialized_size_vec(items: &[Self], include_size_for_fixed: bool) -> usize {
        items.len() * Self::FIXED_SIZE + if include_size_for_fixed { PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE } else { 0 }
    }

    #[inline(always)]
    fn fx_tpl_pio_read_many_from_ref_bytes(data: &[u8], known_size: Option<usize>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let data_len = data.len();
        if let Some(known_sz) = known_size {
            if !include_size_for_fixed && data_len != known_sz * Self::FIXED_SIZE {
                anyhow::bail!(
                    "Data length {} does not match expected size {} for known size {}",
                    data_len,
                    known_sz * Self::FIXED_SIZE,
                    known_sz
                );
            } else if include_size_for_fixed && data_len != known_sz * Self::FIXED_SIZE + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                anyhow::bail!(
                    "Data length {} does not match expected size {} for known size {}",
                    data_len,
                    known_sz * Self::FIXED_SIZE + PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE,
                    known_sz
                );
            }
        } else {
            if data_len % Self::FIXED_SIZE != 0 {
                anyhow::bail!("Data length {} is not a multiple of fixed size {}", data_len, Self::FIXED_SIZE);
            }
        }
        if include_size_for_fixed {
            Self::ffs_deserialize_vec_of_self(&data[PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE..])
        } else {
            Self::ffs_deserialize_vec_of_self(&data)
        }
    }
}

pub trait PsyCanonicalDatabaseSerializeBaseSingle: PsyIOReadWrite {
    fn psydbser_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn psydbser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>>;
    fn psydbser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
        self.psydbser_to_bytes_vec()
    }
    fn psydbser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
        Self::psydbser_from_slice(&data)
    }
}


pub trait PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<const N: usize>: PsyIOReadWriteFixedTemplate<N> {
    fn fx_tpl_psydbser_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn fx_tpl_psydbser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>>;
    fn fx_tpl_psydbser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
        self.fx_tpl_psydbser_to_bytes_vec()
    }
    fn fx_tpl_psydbser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
        Self::fx_tpl_psydbser_from_slice(&data)
    }
}

impl<const N: usize, T: AutoFFSPsyCanonicalDatabaseSerializeFixedBase<N>> PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<N> for T {
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

pub trait PsyCanonicalDatabaseSerializeBaseMulti: PsyCanonicalDatabaseSerializeBaseSingle {
    fn psydbser_serialize_vec_of_self_ref(data: &[Self], write_fixed_items_count: bool) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        } else {
            Self::pio_write_many_to_bytes(data, write_fixed_items_count).expect("Failed to serialize vec of self")
        }
    }

    fn psydbser_serialize_vec_of_self(data: Vec<Self>, write_fixed_items_count: bool) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        } else {
            Self::pio_write_many_to_bytes(&data, write_fixed_items_count).expect("Failed to serialize vec of self")
        }
    }
    fn psydbser_deserialize_vec_of_self(data: &[u8], include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let known_sz = if Self::IS_FIXED_SIZE {
            let data_len = data.len();
            if include_size_for_fixed {
                if data_len < PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE {
                    anyhow::bail!("Data length {} is too small to contain fixed items count", data.len());
                } else if (data_len - PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE) % Self::FIXED_SIZE != 0 {
                    anyhow::bail!(
                        "Data length {} minus fixed items count size is not a multiple of fixed size {}",
                        data_len,
                        Self::FIXED_SIZE
                    );
                }
                Some((data_len - PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE) / Self::FIXED_SIZE)
            } else {
                if data_len % Self::FIXED_SIZE != 0 {
                    anyhow::bail!("Data length {} is not a multiple of fixed size {}", data_len, Self::FIXED_SIZE);
                }
                Some((data_len) / Self::FIXED_SIZE)
            }
        } else {
            None
        };
        Self::pio_read_many_from_ref_bytes(data, known_sz, include_size_for_fixed)
    }
    fn psydbser_deserialize_vec_of_self_owned(data: Vec<u8>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
        let items = Self::psydbser_deserialize_vec_of_self(&data, include_size_for_fixed)?;
        Ok(items)
    }
}

pub trait PsyCanonicalDatabaseSerializeFixedBase<const SIZE: usize>: Sized + PsyCanonicalSerializeMetadata {
    fn psydbser_fixed_to_bytes(&self) -> [u8; SIZE];
    fn psydbser_fixed_into_bytes(self) -> [u8; SIZE];
    fn psydbser_fixed_from_bytes_ref(bytes: &[u8; SIZE]) -> anyhow::Result<Self>;
    fn psydbser_fixed_from_owned_bytes(bytes: [u8; SIZE]) -> anyhow::Result<Self>;
    fn psydbser_fixed_many_from_bytes_ref(bytes: &[u8]) -> anyhow::Result<Vec<Self>>;
    fn psydbser_fixed_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * SIZE);
        for item in data {
            bytes.extend_from_slice(&item.psydbser_fixed_to_bytes());
        }
        bytes
    }
    fn psydbser_fixed_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * SIZE);
        for item in data {
            bytes.extend_from_slice(&item.psydbser_fixed_into_bytes());
        }
        bytes
    }
    fn psydbser_fixed_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
        if data.len() % SIZE != 0 {
            anyhow::bail!("Data length {} is not a multiple of object size {}", data.len(), SIZE);
        }

        // Use chunks_exact to iterate over the byte slice in SIZE-sized chunks.
        // This is highly optimized by the compiler (often using SIMD).
        data.chunks_exact(SIZE)
            .map(|chunk| {
                // For each chunk, call the single-item deserializer.
                // try_into().unwrap() is safe because chunks_exact guarantees length N.
                Self::psydbser_fixed_from_owned_bytes(chunk.try_into().unwrap())
            })
            .collect::<anyhow::Result<Vec<Self>>>()
    }
    fn psydbser_fixed_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
        Self::psydbser_fixed_deserialize_vec_of_self(&data)
    }
}

pub trait AutoFFSPsyCanonicalDatabaseSerializeFixedBase<const SIZE: usize>: FastFixedSerializable<SIZE> + PsyCanonicalSerializeMetadata {}
impl<const SIZE: usize, T: FastFixedSerializable<SIZE> + PsyCanonicalSerializeMetadata> PsyIOReadWriteFixedTemplate<SIZE> for T {}
/*
let ex = clip_first_4_bytes(vec![1,2,3,4,5,6,7,8]);
assert_eq!(ex, vec![5,6,7,8]);
*/
impl<const SIZE: usize, T: AutoFFSPsyCanonicalDatabaseSerializeFixedBase<SIZE>> PsyCanonicalDatabaseSerializeFixedBase<SIZE> for T {
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

#[cfg(test)]
mod tests {
    use psy_io::PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE;

    use crate::{
        canonical_db_serialize::{
            AutoFFSPsyCanonicalDatabaseSerializeFixedBase, PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle,
            PsyCanonicalSerializeMetadata, PsyIOReadWrite,
        },
        data::serializable::FastFixedSerializable,
        utils::QPGenRandom,
    };

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
