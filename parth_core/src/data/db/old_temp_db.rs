use std::hash::Hash;

use crate::data::{fixed_serializable::QPDFixedSizeSerializable, serializable::{QPDSerializable, QPDSerializableFixed}};
use serde::{de::DeserializeOwned, Serialize};

pub trait TempTablePrefixIdentifierCoreBaseForKey<const COMBINED_SIZE: usize, K>: Sized + Copy + Clone + Send + Sync + PartialEq + Eq + Hash + Ord + PartialOrd {
    fn ttp_get_tablet_prefix_size() -> usize;
    fn ttp_get_inner_key_size() -> usize;
    fn ttp_get_prefix_size() -> usize {
        COMBINED_SIZE - Self::ttp_get_inner_key_size()
    }
    fn ttp_get_full_key_sized(&self, key: &K) -> [u8; COMBINED_SIZE];
    fn ttp_get_key_min_range(&self) -> [u8; COMBINED_SIZE];
    fn ttp_get_tablet_min_range() -> [u8; COMBINED_SIZE];

    fn ttp_get_key_prefix_bytes_ref(&self) -> &[u8];
    fn ttp_get_key_prefix_bytes_vec(&self) -> Vec<u8>;
    fn ttp_from_full_key_bytes(key_bytes: &[u8]) -> anyhow::Result<K>;
    fn ttp_from_full_key_bytes_with_prefix(key_bytes: &[u8]) -> anyhow::Result<(Self, K)>;
}
pub trait TempTablePrefixAutoIdentifierCoreBaseForKey<const COMBINED_SIZE: usize, K>: TempTablePrefixIdentifierCoreBaseForKey<COMBINED_SIZE, K> {
}

pub trait TempTablePrefixIdentifierBaseForKey<const COMBINED_SIZE: usize, K>: TempTablePrefixIdentifierCoreBaseForKey<COMBINED_SIZE, K> {
    fn ttp_get_full_key_vec(&self, key: &K) -> Vec<u8> {
        self.ttp_get_full_key_sized(key).to_vec()
    }
    fn ttp_is_key_prefix_match(&self, key_bytes: &[u8]) -> bool;
    // useful for range scans
    fn ttp_get_key_max_range(&self) -> [u8; COMBINED_SIZE];
    fn ttp_get_tablet_max_range() -> [u8; COMBINED_SIZE];
    fn ttp_is_key_match(key_bytes: &[u8]) -> bool;
}
impl<const COMBINED_SIZE: usize, K, T: TempTablePrefixAutoIdentifierCoreBaseForKey<COMBINED_SIZE, K>> TempTablePrefixIdentifierBaseForKey<COMBINED_SIZE, K> for T {
/* 
    fn ttp_get_tablet_prefix_size() -> usize;
    fn ttp_get_inner_key_size() -> usize;
    fn ttp_get_prefix_size() -> usize {
        COMBINED_SIZE - Self::ttp_get_inner_key_size()
    }
    fn ttp_get_full_key_sized(&self, key: &K) -> [u8; COMBINED_SIZE];
    fn ttp_get_tablet_prefix_ref() -> &'static [u8];
    fn ttp_get_key_prefix_bytes_ref(&self) -> &[u8];
    fn ttp_get_key_prefix_bytes_vec(&self) -> Vec<u8>;

    */
    fn ttp_is_key_prefix_match(&self, key_bytes: &[u8]) -> bool {
        if key_bytes.len() < T::ttp_get_prefix_size() {
            return false;
        }
        self.ttp_get_key_prefix_bytes_ref() == &key_bytes[0..T::ttp_get_prefix_size()]
    }
    fn ttp_get_tablet_max_range() -> [u8; COMBINED_SIZE] {
        let mut min_range_key = Self::ttp_get_tablet_min_range();
        for i in Self::ttp_get_tablet_prefix_size()..COMBINED_SIZE {
            min_range_key[i] = 0xFF;
        }
        min_range_key
    }

    fn ttp_get_key_max_range(&self) -> [u8; COMBINED_SIZE] {
        let mut max_range_key = self.ttp_get_key_min_range();
        for i in Self::ttp_get_prefix_size()..COMBINED_SIZE {
            max_range_key[i] = 0xFF;
        }
        max_range_key
    }

    fn ttp_is_key_match(key_bytes: &[u8]) -> bool {
        if key_bytes.len() != COMBINED_SIZE {
            return false;
        }
        let tablet_min = &Self::ttp_get_tablet_min_range()[0..Self::ttp_get_tablet_prefix_size()];
        tablet_min == &key_bytes[0..Self::ttp_get_tablet_prefix_size()]
    }
}
pub trait TP:  Sized + Copy + Send + Sync + Eq + PartialEq + Clone + Serialize + DeserializeOwned + Ord + PartialOrd {
    type KK: Sized + Copy + Send + Sync + Eq + PartialEq + Clone + Serialize + DeserializeOwned + Ord + PartialOrd;
}
impl TP for u64 {
    type KK = u64;
}
pub trait TempTableInnerKeyBase<const KEY_SIZE: usize>: Sized + Copy + Send + Sync {
    const KS: usize = KEY_SIZE;
    type KZ: TP;
    fn tt_key_write_at_buffer(&self, buffer: &mut [u8]) -> anyhow::Result<()>;
    fn tt_key_to_fixed_bytes(&self) ->[u8; KEY_SIZE];
    fn tt_key_from_bytes(bytes: &[u8]) -> anyhow::Result<Self>;
    fn tt_key_get_size() -> usize {
        KEY_SIZE
    }
}
pub trait QPDFixedSizeSerializableTempTableInnerAutoKey<const KEY_SIZE: usize>: QPDFixedSizeSerializable<KEY_SIZE> + Copy + Send + Sync {}

impl<const KEY_SIZE: usize, T: QPDFixedSizeSerializableTempTableInnerAutoKey<KEY_SIZE>> TempTableInnerKeyBase<KEY_SIZE> for T {
    type KZ = u64;
    fn tt_key_write_at_buffer(&self, buffer: &mut [u8]) -> anyhow::Result<()> {
        if buffer.len() < KEY_SIZE {
            anyhow::bail!("Buffer too small to write key at position: buffer size {}, key size {}", buffer.len(), KEY_SIZE);
        }
        let key_bytes = self.to_fixed_size_bytes();
        buffer[0..KEY_SIZE].copy_from_slice(&key_bytes);
        Ok(())
    }
    fn tt_key_to_fixed_bytes(&self) -> [u8; KEY_SIZE] {
        self.to_fixed_size_bytes()
    }
    fn tt_key_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        T::from_fixed_size_bytes(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Copy, Hash, Eq, PartialOrd, Ord)]
pub struct TempTablePrefixIdentifierRealm<const TABLE_TYPE: u16, const KEY_SIZE: usize, const COMBINED_SIZE: usize> {
    pub realm_id: u32,
    pub realm_sub_id : u16,
    pub prefix_template_u64: u64,
    pub prefix_template_bytes: [u8; 8],
}
impl<const TABLE_TYPE: u16, const KEY_SIZE: usize, const COMBINED_SIZE: usize> TempTablePrefixIdentifierRealm<TABLE_TYPE, KEY_SIZE, COMBINED_SIZE> {
    pub fn new(realm_id: u32, realm_sub_id: u16) -> Self {
        let mut prefix_template_bytes = [0u8; 8];
        prefix_template_bytes[0..2].copy_from_slice(&TABLE_TYPE.to_be_bytes());
        prefix_template_bytes[2..6].copy_from_slice(&realm_id.to_be_bytes());
        prefix_template_bytes[6..8].copy_from_slice(&realm_sub_id.to_be_bytes());
        let prefix_template_u64 = u64::from_be_bytes(prefix_template_bytes);
        Self { realm_id, realm_sub_id, prefix_template_u64, prefix_template_bytes}
    }
}
impl<const TABLE_TYPE: u16, const KEY_SIZE: usize, const COMBINED_SIZE: usize, K: TempTableInnerKeyBase<KEY_SIZE>> TempTablePrefixIdentifierCoreBaseForKey<COMBINED_SIZE, K> for TempTablePrefixIdentifierRealm<TABLE_TYPE, KEY_SIZE, COMBINED_SIZE> {
    fn ttp_get_tablet_prefix_size() -> usize {
        8
    }
    fn ttp_get_inner_key_size() -> usize {
        KEY_SIZE
    }
    fn ttp_get_full_key_sized(&self, key: &K) -> [u8; COMBINED_SIZE] {
        let mut full_key = [0u8; COMBINED_SIZE];
        full_key[0..8].copy_from_slice(&self.prefix_template_bytes);
        key.tt_key_write_at_buffer(&mut full_key[8..COMBINED_SIZE]).expect("buffer size is correct");
        full_key
    }
    fn ttp_get_key_min_range(&self) -> [u8; COMBINED_SIZE] {
        let mut min_range_key = [0u8; COMBINED_SIZE];
        min_range_key[0..8].copy_from_slice(&self.prefix_template_bytes);
        min_range_key
    }
    fn ttp_get_tablet_min_range() -> [u8; COMBINED_SIZE] {
        let mut min_range_key = [0u8; COMBINED_SIZE];
        min_range_key[0..2].copy_from_slice(&TABLE_TYPE.to_be_bytes());
        min_range_key[2..6].copy_from_slice(&0u32.to_be_bytes());
        min_range_key[6..8].copy_from_slice(&0u16.to_be_bytes());
        min_range_key
    }
    fn ttp_get_key_prefix_bytes_ref(&self) -> &[u8] {
        &self.prefix_template_bytes
    }
    fn ttp_get_key_prefix_bytes_vec(&self) -> Vec<u8> {
        self.prefix_template_bytes.to_vec()
    }
    fn ttp_from_full_key_bytes(key_bytes: &[u8]) -> anyhow::Result<K> {
        if key_bytes.len() != COMBINED_SIZE {
            anyhow::bail!("invalid size, expected {} bytes, got {}", COMBINED_SIZE, key_bytes.len());
        }
        K::tt_key_from_bytes(&key_bytes[8..COMBINED_SIZE])
    }
    fn ttp_from_full_key_bytes_with_prefix(key_bytes: &[u8]) -> anyhow::Result<(Self, K)> {
        if key_bytes.len() != COMBINED_SIZE {
            anyhow::bail!("invalid size, expected {} bytes, got {}", COMBINED_SIZE, key_bytes.len());
        }
        let realm_id = u32::from_be_bytes([key_bytes[2], key_bytes[3], key_bytes[4], key_bytes[5]]);
        let realm_sub_id = u16::from_be_bytes([key_bytes[6], key_bytes[7]]);
        let prefix_template_bytes = {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&key_bytes[0..8]);
            arr
        };
        let prefix_template_u64 = u64::from_be_bytes(prefix_template_bytes);
        let key = K::tt_key_from_bytes(&key_bytes[8..COMBINED_SIZE])?;
        Ok((Self { realm_id, realm_sub_id, prefix_template_u64, prefix_template_bytes}, key))
    }
    
}
impl<const TABLE_TYPE: u16, const KEY_SIZE: usize, const COMBINED_SIZE: usize, K: TempTableInnerKeyBase<KEY_SIZE>> TempTablePrefixAutoIdentifierCoreBaseForKey<COMBINED_SIZE, K> for TempTablePrefixIdentifierRealm<TABLE_TYPE, KEY_SIZE, COMBINED_SIZE> {
}

/*
pub trait QTempDatabaseBytesTableIdentifier<K> {
    fn is_key_match(key_bytes: &[u8]) -> bool;
    fn get_full_key_size(key: &K) -> usize;
    fn to_full_key_bytes(key: &K) -> Vec<u8>;
    fn from_full_key_bytes(key_bytes: &[u8]) -> anyhow::Result<K>;
}

pub trait QTempDatabaseSizedKeyBytesTableIdentifier<K: Sized>: QTempDatabaseBytesTableIdentifier<K> {
    fn get_full_key_fixed_size() -> usize;
}

pub struct QTempDatabaseSimplePrefixTableIdentifier<const TABLE_TYPE: u16> {
}
impl<const TABLE_TYPE: u16, K: QPDSerializableFixed> QTempDatabaseBytesTableIdentifier<K> for QTempDatabaseSimplePrefixTableIdentifier<TABLE_TYPE> {
    fn is_key_match(key_bytes: &[u8]) -> bool {
        if key_bytes.len() < 2 {
            return false;
        }
        let table_type = u16::from_be_bytes([key_bytes[0], key_bytes[1]]);
        table_type == TABLE_TYPE
    }
    fn get_full_key_size(key: &K) -> usize {
        2 + K::get_fixed_size()
    }
    fn to_full_key_bytes(key: &K) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + K::get_fixed_size());
        bytes.extend_from_slice(&TABLE_TYPE.to_be_bytes());
        bytes.extend_from_slice(&key.to_bytes().unwrap());
        bytes
    }
    
    fn from_full_key_bytes(key_bytes: &[u8]) -> anyhow::Result<K> {
        if key_bytes.len() < 2 + K::get_fixed_size() {
            anyhow::bail!("Invalid key length for QTempDatabaseSimplePrefixTableIdentifier: expected at least {}, got {}", 2 + K::get_fixed_size(), key_bytes.len());
        }
        let table_type = u16::from_be_bytes([key_bytes[0], key_bytes[1]]);
        if table_type != TABLE_TYPE {
            anyhow::bail!("Table type mismatch for QTempDatabaseSimplePrefixTableIdentifier: expected {}, got {}", TABLE_TYPE, table_type);
        }
        K::from_bytes(&key_bytes[2..2 + K::get_fixed_size()])
    }
}

*/

/*
pub trait QTempDatabaseKeyFixedKnownSizeSerialized<const N: usize> {
    fn to_fixed_size_bytes(&self) -> [u8; N];
    fn from_fixed_size_bytes(bytes: &[u8]) -> anyhow::Result<Self> where Self: Sized;
    fn write_at_position(&self, buffer: &mut [u8], position: usize) -> anyhow::Result<()> {
        if buffer.len() < position + N {
            anyhow::bail!("Buffer too small to write key at position: buffer size {}, position {}, key size {}", buffer.len(), position, N);
        }
        let key_bytes = self.to_fixed_size_bytes();
        buffer[position..position + N].copy_from_slice(&key_bytes);
        Ok(())
    }
}

pub trait QTempDatabasePrefixBytesTableIdentifier<K> {
    fn is_key_match(key_bytes: &[u8]) -> bool;
    fn get_full_key_size(key: &K) -> usize;
    fn to_full_key_bytes(key: &K) -> Vec<u8>;
    fn from_full_key_bytes(key_bytes: &[u8]) -> anyhow::Result<K>;
}
pub trait QTempDatabasePrefixFixedBytesTableIdentifier<const PN: usize> {
    fn get_prefix_bytes() -> [u8; PN];
}

#[pderive::serialize_copy]
pub struct QTempDatabaseRealmIdentifiedKey {
    pub table_type: u32,
    pub realm_id: u32,
    pub realm_sub_id: u32,
}

impl QTempDatabaseRealmIdentifiedKey {
    pub fn new(table_type: u32, realm_id: u32, realm_sub_id: u32) -> Self {
        Self { table_type, realm_id, realm_sub_id }
    }
    pub fn create_combined_key<const N: usize, K: QTempDatabaseKeyFixedKnownSizeSerialized<N>>(&self, key: &K) -> [u8; 12 + N] {
        let mut combined_key = [0u8; 12 + N];
        combined_key[0..4].copy_from_slice(&self.table_type.to_be_bytes());
        combined_key[4..8].copy_from_slice(&self.realm_id.to_be_bytes());
        combined_key[8..12].copy_from_slice(&self.realm_sub_id.to_be_bytes());
        key.write_at_position(&mut combined_key, 12).unwrap();
        combined_key
    }
}
    */