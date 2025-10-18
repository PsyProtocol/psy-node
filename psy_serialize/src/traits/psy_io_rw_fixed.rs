use anyhow::Context;
use psy_io::{p_read_fixed_items_many_count, p_write_fixed_items_manycount, PsyIOReadableFixedSizeCanonicalStruct, PsyIOWritableCanonicalStruct, PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE, PsyReaderExtensions, PsyWriterExtensions};

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


    #[inline]
    fn fx_tpl_pio_read_from_io_many<R: psy_io::Read>(
        reader: &mut R,
        known_size: Option<usize>,
    ) -> anyhow::Result<Vec<Self>> {
        let length = match known_size {
            Some(len) => {
                len
            },
            None => {
                reader.psy_read_vec_length()?
            }
        };
        if length > Self::psy_io_max_vec_length() {
            anyhow::bail!("Read size {} exceeds maximum allowed length {}", length, Self::psy_io_max_vec_length());
        }
        let total_bytes = length.checked_mul(N)
            .context("Total byte size for vector of fixed structs exceeds usize::MAX")?;
        let mut data = vec![0u8; total_bytes];
        reader.read_exact(&mut data)?;
        Self::ffs_deserialize_vec_of_self_owned(data)
    }
    #[inline]
    fn fx_tpl_pio_serialized_size_vec(items: &[Self], include_size_for_fixed: bool) -> usize {
        items.len() * Self::FIXED_SIZE + if include_size_for_fixed { PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE } else { 0 }
    }

    #[inline]
    fn fx_tpl_pio_read_many_from_ref_bytes(data: &[u8], known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
        let count = match known_count {
            Some(len) => {
                if len * Self::FIXED_SIZE > data.len() {
                    anyhow::bail!("Data length {} is too small for expected count {} of fixed size {}", data.len(), len, Self::FIXED_SIZE);
                }
                len
            },
            None => {
                let data_len = data.len();
                if data_len % Self::FIXED_SIZE != 0 {
                    anyhow::bail!("Data length {} is not a multiple of fixed size {}", data_len, Self::FIXED_SIZE);
                }
                data_len / Self::FIXED_SIZE
            }
        };
        if count > Self::psy_io_max_vec_length() {
            anyhow::bail!("Read size {} exceeds maximum allowed length {}", count, Self::psy_io_max_vec_length());
        }
        Self::ffs_deserialize_vec_of_self(data)
    }
}