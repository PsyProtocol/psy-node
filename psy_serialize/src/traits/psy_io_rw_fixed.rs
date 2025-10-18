use anyhow::Context;
use psy_io::{
    p_read_fixed_items_many_count, p_write_fixed_items_manycount,
    PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE,
};
use crate::traits::metadata::PsyIOWithMaxVecLength;
use crate::{FastFixedSerializable, PsyCanonicalSerializeMetadata};

pub trait PsyIOReadWriteFixedTemplate<const N: usize>: PsyCanonicalSerializeMetadata + FastFixedSerializable<N> + Sized {
    #[inline(always)]
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

    #[inline]
    fn fx_tpl_pio_write_to_io_many<W: psy_io::Write>(items: &[Self], writer: &mut W, write_count: bool) -> anyhow::Result<()> {
        if write_count {
            p_write_fixed_items_manycount(items.len(), writer)?;
        }
        if !items.is_empty() {
            let serialized_data = Self::ffs_serialize_vec_of_self_ref(items);
            writer.write_all(&serialized_data)?;
        }
        Ok(())
    }

    #[inline]
    fn fx_tpl_pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
        let length = match known_count {
            Some(len) => len,
            None => p_read_fixed_items_many_count(reader)?,
        };

        if length > Self::psy_io_max_vec_length() {
            anyhow::bail!("Read count {} exceeds maximum allowed length {}", length, Self::psy_io_max_vec_length());
        }
        if length == 0 {
            return Ok(Vec::new());
        }

        let total_bytes = length.checked_mul(N).context("Total byte size for vector of fixed structs exceeds usize::MAX")?;
        let mut data = vec![0u8; total_bytes];
        reader.read_exact(&mut data)?;
        Self::ffs_deserialize_vec_of_self_owned(data)
    }

    #[inline]
    fn fx_tpl_pio_serialized_size_vec(items: &[Self], include_size: bool) -> usize {
        items.len() * Self::FIXED_SIZE + if include_size { PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE } else { 0 }
    }

    #[inline]
    fn fx_tpl_pio_read_many_from_ref_bytes(data: &[u8], known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
        let view = if let Some(count) = known_count {
            let expected_len = count * N;
            if data.len() < expected_len {
                anyhow::bail!(
                    "Data length {} is too small for expected count {} of fixed size {} (needs {} bytes)",
                    data.len(),
                    count,
                    N,
                    expected_len
                );
            }
            &data[..expected_len]
        } else {
            // Data does not include a count prefix, so deserialize the whole slice.
            if data.len() % N != 0 {
                anyhow::bail!("Data length {} is not a multiple of fixed size {}", data.len(), N);
            }
            data
        };

        if view.is_empty() {
            return Ok(Vec::new());
        }

        Self::ffs_deserialize_vec_of_self(view)
    }

    #[inline]
    fn fx_tpl_pio_write_many_to_bytes(items: &[Self], write_count: bool) -> anyhow::Result<Vec<u8>> {
        if !write_count {
            Ok(Self::ffs_serialize_vec_of_self_ref(items))
        }else{
            let mut buffer = Vec::with_capacity(Self::fx_tpl_pio_serialized_size_vec(items, write_count));
            Self::fx_tpl_pio_write_to_io_many(items, &mut buffer, write_count)?;
            Ok(buffer)
        }
    }
    
}