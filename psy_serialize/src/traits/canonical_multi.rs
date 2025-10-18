use psy_io::PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE;

use crate::PsyCanonicalDatabaseSerializeBaseSingle;


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