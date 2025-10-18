use psy_io::{p_read_fixed_items_many_count, p_read_varuint, p_varuint_size, p_write_fixed_items_manycount, p_write_varuint, PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE};

use crate::{FastFixedSerializable, PsyCanonicalSerializeMetadata};


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
