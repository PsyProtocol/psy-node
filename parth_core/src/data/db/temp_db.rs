use serde::{de::DeserializeOwned, Serialize};

use crate::{
    data::{fixed_serializable::QPDFixedSizeSerializable, hash::hash256::Hash256, serializable::QPDSerializable},
    QJobIdSerialized, QJOB_ID_SERIALIZED_SIZE, QJOB_ID_WITH_REALM_PREFIX_SERIALIZED_SIZE,
    QJOB_ID_WITH_UNIQUE_PENDING_ID_AND_REALM_PREFIX_SERIALIZED_SIZE, QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE,
};

pub trait TempTablePrefixIdentifierCoreBaseForKey<const COMBINED_SIZE: usize, K>: Sized + Copy + Clone + Send + Sync {
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
pub trait TempTablePrefixAutoIdentifierCoreBaseForKey<const COMBINED_SIZE: usize, K>:
    TempTablePrefixIdentifierCoreBaseForKey<COMBINED_SIZE, K>
{
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
pub trait TempTablePrefixIdentifierKey<const COMBINED_SIZE: usize, K>: TempTablePrefixIdentifierBaseForKey<COMBINED_SIZE, K> {}
impl<T: TempTablePrefixIdentifierBaseForKey<COMBINED_SIZE, K>, const COMBINED_SIZE: usize, K> TempTablePrefixIdentifierKey<COMBINED_SIZE, K> for T {}

impl<const COMBINED_SIZE: usize, K, T: TempTablePrefixAutoIdentifierCoreBaseForKey<COMBINED_SIZE, K>>
    TempTablePrefixIdentifierBaseForKey<COMBINED_SIZE, K> for T
{
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
pub trait TempTableInnerKeyBase<const KEY_SIZE: usize>: Sized + Copy + Send + Sync {
    fn tt_key_write_at_buffer(&self, buffer: &mut [u8]) -> anyhow::Result<()>;
    fn tt_key_to_fixed_bytes(&self) -> [u8; KEY_SIZE];
    fn tt_key_from_bytes(bytes: &[u8]) -> anyhow::Result<Self>;
    fn tt_key_get_size() -> usize {
        KEY_SIZE
    }
}

pub trait QPDFixedSizeSerializableTempTableInnerAutoKey<const KEY_SIZE: usize>: QPDFixedSizeSerializable<KEY_SIZE> + Copy + Send + Sync {}

impl<const KEY_SIZE: usize, T: QPDFixedSizeSerializableTempTableInnerAutoKey<KEY_SIZE>> TempTableInnerKeyBase<KEY_SIZE> for T {
    fn tt_key_write_at_buffer(&self, buffer: &mut [u8]) -> anyhow::Result<()> {
        if buffer.len() < KEY_SIZE {
            anyhow::bail!(
                "Buffer too small to write key at position: buffer size {}, key size {}",
                buffer.len(),
                KEY_SIZE
            );
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

#[derive(Debug, Clone, PartialEq, Copy, Hash)]
pub struct TempTablePrefixIdentifierRealm<
    const TABLE_TYPE: u16,
    const KEY_SIZE: usize,
    const COMBINED_SIZE: usize,
    K: TempTableInnerKeyBase<KEY_SIZE>,
> {
    pub realm_id: u32,
    pub realm_sub_id: u16,
    pub prefix_template_u64: u64,
    pub prefix_template_bytes: [u8; 8],
    _k_marker: std::marker::PhantomData<K>,
}
impl<const TABLE_TYPE: u16, const KEY_SIZE: usize, const COMBINED_SIZE: usize, K: TempTableInnerKeyBase<KEY_SIZE>>
    TempTablePrefixIdentifierRealm<TABLE_TYPE, KEY_SIZE, COMBINED_SIZE, K>
{
    pub fn new(realm_id: u32, realm_sub_id: u16) -> Self {
        let mut prefix_template_bytes = [0u8; 8];
        prefix_template_bytes[0..2].copy_from_slice(&TABLE_TYPE.to_be_bytes());
        prefix_template_bytes[2..6].copy_from_slice(&realm_id.to_be_bytes());
        prefix_template_bytes[6..8].copy_from_slice(&realm_sub_id.to_be_bytes());
        let prefix_template_u64 = u64::from_be_bytes(prefix_template_bytes);
        Self {
            realm_id,
            realm_sub_id,
            prefix_template_u64,
            prefix_template_bytes,
            _k_marker: std::marker::PhantomData,
        }
    }
}
impl<const TABLE_TYPE: u16, const KEY_SIZE: usize, const COMBINED_SIZE: usize, K: TempTableInnerKeyBase<KEY_SIZE>>
    TempTablePrefixIdentifierCoreBaseForKey<COMBINED_SIZE, K> for TempTablePrefixIdentifierRealm<TABLE_TYPE, KEY_SIZE, COMBINED_SIZE, K>
{
    fn ttp_get_tablet_prefix_size() -> usize {
        8
    }
    fn ttp_get_inner_key_size() -> usize {
        KEY_SIZE
    }
    fn ttp_get_full_key_sized(&self, key: &K) -> [u8; COMBINED_SIZE] {
        let mut full_key = [0u8; COMBINED_SIZE];
        full_key[0..8].copy_from_slice(&self.prefix_template_bytes);
        key.tt_key_write_at_buffer(&mut full_key[8..COMBINED_SIZE])
            .expect("buffer size is correct");
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
        Ok((
            Self {
                realm_id,
                realm_sub_id,
                prefix_template_u64,
                prefix_template_bytes,
                _k_marker: std::marker::PhantomData,
            },
            key,
        ))
    }
}
impl<const TABLE_TYPE: u16, const KEY_SIZE: usize, const COMBINED_SIZE: usize, K: TempTableInnerKeyBase<KEY_SIZE>>
    TempTablePrefixAutoIdentifierCoreBaseForKey<COMBINED_SIZE, K> for TempTablePrefixIdentifierRealm<TABLE_TYPE, KEY_SIZE, COMBINED_SIZE, K>
{
}

pub trait TTPSerializeValue: Clone + Send + Sync {
    fn ttp_to_bytes(&self) -> anyhow::Result<Vec<u8>>;
    fn ttp_from_bytes(data: &[u8]) -> anyhow::Result<Self>;
}
impl TTPSerializeValue for u64 {
    fn ttp_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
    fn ttp_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 8 {
            anyhow::bail!("Invalid data length for u64: expected 8, got {}", data.len());
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&data[0..8]);
        Ok(u64::from_be_bytes(arr))
    }
}
impl TTPSerializeValue for Vec<u8> {
    fn ttp_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.clone())
    }
    fn ttp_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        Ok(data.to_vec())
    }
}
impl<const N: usize> TTPSerializeValue for [u8; N] {
    fn ttp_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_vec())
    }
    fn ttp_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != N {
            anyhow::bail!("Invalid data length for [u8; {}]: expected {}, got {}", N, N, data.len());
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&data[0..N]);
        Ok(arr)
    }
}
impl TTPSerializeValue for String {
    fn ttp_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
    fn ttp_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        Ok(String::from_utf8(data.to_vec())?)
    }
}
impl TTPSerializeValue for bool {
    fn ttp_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(vec![*self as u8])
    }
    fn ttp_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 1 {
            anyhow::bail!("Invalid data length for bool: expected 1, got {}", data.len());
        }
        Ok(data[0] != 0)
    }
}
impl TTPSerializeValue for Hash256 {
    fn ttp_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.to_vec())
    }
    fn ttp_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 32 {
            anyhow::bail!("Invalid data length for Hash256: expected 32, got {}", data.len());
        }
        Hash256::from_bytes(data).map_err(|e| anyhow::anyhow!(e.to_string()))
    }
}
pub trait SerdeAutoTTPSerializeValue: Serialize + DeserializeOwned + Clone + Send + Sync {}
impl<T: SerdeAutoTTPSerializeValue> TTPSerializeValue for T {
    fn ttp_to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e.to_string()))
    }
    fn ttp_from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow::anyhow!(e.to_string()))
    }
}

pub trait TempTableDefintion<const COMBINED_KEY_SIZE: usize, const KEY_SIZE: usize>: Sized + Clone + Send + Sync {
    type Key: TempTableInnerKeyBase<KEY_SIZE> + Copy + Send + Sync;
    type Value: TTPSerializeValue + Clone + Send + Sync;
    type KeyPrefix: TempTablePrefixIdentifierKey<COMBINED_KEY_SIZE, Self::Key>;
    fn get_key_prefix(&self) -> &Self::KeyPrefix;
}
#[derive(Debug, Clone)]
pub struct QSTempTableDefintionRealm<
    const TABLE_TYPE: u16,
    const COMBINED_KEY_SIZE: usize,
    const KEY_SIZE: usize,
    K: TempTableInnerKeyBase<KEY_SIZE> + Send + Sync,
    V: TTPSerializeValue + Clone + Send + Sync,
> {
    key_prefix: TempTablePrefixIdentifierRealm<TABLE_TYPE, KEY_SIZE, COMBINED_KEY_SIZE, K>,
    _v_marker: std::marker::PhantomData<V>,
}

impl<
        const TABLE_TYPE: u16,
        const COMBINED_KEY_SIZE: usize,
        const KEY_SIZE: usize,
        K: TempTableInnerKeyBase<KEY_SIZE> + Send + Sync,
        V: TTPSerializeValue + Clone + Send + Sync,
    > QSTempTableDefintionRealm<TABLE_TYPE, COMBINED_KEY_SIZE, KEY_SIZE, K, V>
{
    pub fn new(realm_id: u32, realm_sub_id: u16) -> Self {
        Self {
            key_prefix: TempTablePrefixIdentifierRealm::new(realm_id, realm_sub_id),
            _v_marker: std::marker::PhantomData,
        }
    }
}
impl<
        const TABLE_TYPE: u16,
        const COMBINED_KEY_SIZE: usize,
        const KEY_SIZE: usize,
        K: TempTableInnerKeyBase<KEY_SIZE> + Copy + Send + Sync,
        V: TTPSerializeValue + Clone + Send + Sync,
    > TempTableDefintion<COMBINED_KEY_SIZE, KEY_SIZE> for QSTempTableDefintionRealm<TABLE_TYPE, COMBINED_KEY_SIZE, KEY_SIZE, K, V>
{
    type Key = K;
    type Value = V;
    type KeyPrefix = TempTablePrefixIdentifierRealm<TABLE_TYPE, KEY_SIZE, COMBINED_KEY_SIZE, K>;
    fn get_key_prefix(&self) -> &Self::KeyPrefix {
        &self.key_prefix
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Copy, Hash, PartialOrd, Ord, Default)]
pub struct TempTableJobIdForPendingCheckpointKey<const TABLE_TYPE: u16> {
    pub unique_pending_id: u64,
    pub job_id_data: QJobIdSerialized,
}
impl<const TABLE_TYPE: u16> TempTableInnerKeyBase<QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE>
    for TempTableJobIdForPendingCheckpointKey<TABLE_TYPE>
{
    fn tt_key_write_at_buffer(&self, buffer: &mut [u8]) -> anyhow::Result<()> {
        if buffer.len() < QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE {
            anyhow::bail!(
                "Buffer too small to write key at position: buffer size {}, key size {}",
                buffer.len(),
                QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE
            );
        }
        buffer[0..8].copy_from_slice(&self.unique_pending_id.to_be_bytes());
        buffer[8..QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE].copy_from_slice(&self.job_id_data);
        Ok(())
    }
    fn tt_key_to_fixed_bytes(&self) -> [u8; QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE] {
        let mut arr = [0u8; QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE];
        arr[0..8].copy_from_slice(&self.unique_pending_id.to_be_bytes());
        arr[8..QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE].copy_from_slice(&self.job_id_data);
        arr
    }
    fn tt_key_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE {
            anyhow::bail!(
                "Invalid size, expected {} bytes, got {}",
                QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE,
                bytes.len()
            );
        }
        Ok(Self {
            unique_pending_id: u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]),
            job_id_data: bytes[8..QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE].try_into().unwrap(),
        })
    }
    fn tt_key_get_size() -> usize {
        QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE
    }
}

#[derive(Debug, Clone)]
pub struct QSTempTableJobIdForPendingCheckpointDefintionRealm<const TABLE_TYPE: u16, V: TTPSerializeValue + Clone + Send + Sync> {
    key_prefix: TempTablePrefixIdentifierRealm<
        TABLE_TYPE,
        QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE,
        QJOB_ID_WITH_UNIQUE_PENDING_ID_AND_REALM_PREFIX_SERIALIZED_SIZE,
        TempTableJobIdForPendingCheckpointKey<TABLE_TYPE>,
    >,
    _v_marker: std::marker::PhantomData<V>,
}

impl<const TABLE_TYPE: u16, V: TTPSerializeValue + Clone + Send + Sync> QSTempTableJobIdForPendingCheckpointDefintionRealm<TABLE_TYPE, V> {
    pub fn new(realm_id: u32, realm_sub_id: u16) -> Self {
        Self {
            key_prefix: TempTablePrefixIdentifierRealm::new(realm_id, realm_sub_id),
            _v_marker: std::marker::PhantomData,
        }
    }
}
impl<const TABLE_TYPE: u16, V: TTPSerializeValue + Clone + Send + Sync>
    TempTableDefintion<QJOB_ID_WITH_UNIQUE_PENDING_ID_AND_REALM_PREFIX_SERIALIZED_SIZE, QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE>
    for QSTempTableJobIdForPendingCheckpointDefintionRealm<TABLE_TYPE, V>
{
    type Key = TempTableJobIdForPendingCheckpointKey<TABLE_TYPE>;
    type Value = V;
    type KeyPrefix = TempTablePrefixIdentifierRealm<
        TABLE_TYPE,
        QJOB_ID_WITH_UNIQUE_PENDING_ID_SERIALIZED_SIZE,
        QJOB_ID_WITH_UNIQUE_PENDING_ID_AND_REALM_PREFIX_SERIALIZED_SIZE,
        TempTableJobIdForPendingCheckpointKey<TABLE_TYPE>,
    >;
    fn get_key_prefix(&self) -> &Self::KeyPrefix {
        &self.key_prefix
    }
}

pub type QSTempTableJobIdDefintionRealm<const TABLE_TYPE: u16, V> =
    QSTempTableDefintionRealm<TABLE_TYPE, QJOB_ID_WITH_REALM_PREFIX_SERIALIZED_SIZE, QJOB_ID_SERIALIZED_SIZE, QJobIdSerialized, V>;
