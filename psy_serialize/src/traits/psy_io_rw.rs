use crate::PsyCanonicalSerializeMetadata;
use psy_io::{
    p_read_fixed_items_many_count, p_read_varuint, p_varuint_size, p_write_fixed_items_manycount, p_write_varuint,
    PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE,
};
use crate::traits::metadata::PsyIOWithMaxVecLength;

pub trait PsyIOReadWrite: PsyCanonicalSerializeMetadata + Sized {
    fn pio_serialized_size(&self) -> usize;

    fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()>;

    fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self>;

    #[inline(always)]
    fn pio_get_variable_serialized_size(&self) -> usize {
        if Self::IS_FIXED_SIZE {
            Self::FIXED_SIZE
        } else {
            // For variable sized items, we don't prefix with size. The item's own serialization handles it.
            self.pio_serialized_size()
        }
    }

    #[inline(always)]
    fn pio_write_to_io_many<W: psy_io::Write>(items: &[Self], writer: &mut W, write_count: bool) -> anyhow::Result<()> {
        if write_count {
            if Self::IS_FIXED_SIZE {
                p_write_fixed_items_manycount(items.len(), writer)?;
            } else {
                p_write_varuint(items.len(), writer)?;
            }
        }
        for item in items {
            item.pio_write_to_io(writer)?;
        }
        Ok(())
    }

    #[inline(always)]
    fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
        let len = match known_count {
            Some(count) => count,
            None => {
                if Self::IS_FIXED_SIZE {
                    p_read_fixed_items_many_count(reader)?
                } else {
                    p_read_varuint(reader)?
                }
            }
        };

        if len > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", len, Self::psy_io_max_vec_length());
        }

        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(Self::pio_read_from_io(reader)?);
        }
        Ok(items)
    }

    #[inline]
    fn pio_serialized_size_vec(items: &[Self], include_size: bool) -> usize {
        let count_size = if include_size {
            if Self::IS_FIXED_SIZE {
                PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE
            } else {
                p_varuint_size(items.len())
            }
        } else {
            0
        };

        let items_size: usize = if Self::IS_FIXED_SIZE {
            items.len() * Self::FIXED_SIZE
        } else {
            items.iter().map(|item| item.pio_serialized_size()).sum()
        };

        count_size + items_size
    }

    #[inline]
    fn pio_read_many_from_ref_bytes(data: &[u8], known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
        if data.is_empty() && known_count.unwrap_or(0) == 0 {
            return Ok(Vec::new());
        }
        let mut cursor = psy_io::Cursor::new(data);
        Self::pio_read_from_io_many(&mut cursor, known_count)
    }


    #[inline]
    fn pio_write_many_to_bytes_standard(items: &[Self], write_count: bool) -> anyhow::Result<Vec<u8>> {
        let total_size = Self::pio_serialized_size_vec(items, write_count);
        let mut buffer = Vec::with_capacity(total_size);
        Self::pio_write_to_io_many(items, &mut buffer, write_count)?;
        Ok(buffer)
    }

    #[inline]
    fn pio_write_many_to_bytes(items: &[Self], write_count: bool) -> anyhow::Result<Vec<u8>> {
        let total_size = Self::pio_serialized_size_vec(items, write_count);
        let mut buffer = Vec::with_capacity(total_size);
        Self::pio_write_to_io_many(items, &mut buffer, write_count)?;
        Ok(buffer)
    }
}


impl PsyIOReadWrite for u8 {
    fn pio_serialized_size(&self) -> usize {
        1
    }

    fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.write_all(&[*self]).map_err(|e| anyhow::anyhow!(e))
    }

    fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).map_err(|e| anyhow::anyhow!(e))?;
        Ok(buf[0])
    }
}