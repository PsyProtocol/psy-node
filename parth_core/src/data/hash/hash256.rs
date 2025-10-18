use std::fmt::Display;

use hex::FromHexError;
use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};
use rand::RngCore;
use serde_with::serde_as;
use ts_rs::TS;

use crate::{
    crypto::hash::traits::{CodeSerializableHash, FromU64x4, HashTo4Felts, RandomHash, ToU64x4, ZeroableHash}, data::serializable::{QPDSerializable, QPDSerializableFixed}, generic_traits::QStaticNamedType, protocol::core_types::{Q256BitHash, Q256BitHashTransparent, QHashBase}, utils::debug_code_string::QToCodeString
};

#[serde_as]
#[pderive::serialize_copy]
#[derive(TS)]
#[cfg_attr(feature = "serialize_bytemuck", derive(bytemuck::Pod, bytemuck::Zeroable))]
#[repr(transparent)]
pub struct Hash256(
    #[serde_as(as = "serde_with::hex::Hex")]
    #[ts(type = "string")]
    pub [u8; 32]
);
impl Default for Hash256 {
    fn default() -> Self {
        Self([0u8; 32])
    }
}
impl ZeroableHash for Hash256 {
    fn get_zero_value() -> Self {
        Self([0u8; 32])
    }
}

impl RandomHash for Hash256 {
    fn rand_hash() -> Self {
        Self::rand()
    }
}
impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn to_le_u64_x4(&self) -> [u64; 4] {
        [
            u64::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7]]),
            u64::from_le_bytes([
                self.0[8], self.0[9], self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15],
            ]),
            u64::from_le_bytes([
                self.0[16], self.0[17], self.0[18], self.0[19], self.0[20], self.0[21], self.0[22], self.0[23],
            ]),
            u64::from_le_bytes([
                self.0[24], self.0[25], self.0[26], self.0[27], self.0[28], self.0[29], self.0[30], self.0[31],
            ]),
        ]
    }
    pub fn rand() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Hash256(bytes)
    }
    pub fn from_u64_le_values(a: u64, b: u64, c: u64, d: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&a.to_le_bytes());
        bytes[8..16].copy_from_slice(&b.to_le_bytes());
        bytes[16..24].copy_from_slice(&c.to_le_bytes());
        bytes[24..32].copy_from_slice(&d.to_le_bytes());
        Hash256(bytes)
    }
    pub fn to_u64_le_values(&self) -> (u64, u64, u64, u64) {
        let a = u64::from_le_bytes(self.0[0..8].try_into().unwrap());
        let b = u64::from_le_bytes(self.0[8..16].try_into().unwrap());
        let c = u64::from_le_bytes(self.0[16..24].try_into().unwrap());
        let d = u64::from_le_bytes(self.0[24..32].try_into().unwrap());
        (a, b, c, d)
    }
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
}

impl Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
impl TryFrom<&str> for Hash256 {
    type Error = FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Hash256::from_hex_string(value)
    }
}
impl TryFrom<String> for Hash256 {
    type Error = FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Hash256::from_hex_string(&value)
    }
}

impl QPDSerializable for Hash256 {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!("expected 32 bytes for deserializing Hash256, got {} bytes", bytes.len());
        }
        let mut inner_data = [0u8; 32];
        inner_data.copy_from_slice(bytes);
        Ok(Hash256(inner_data))
    }
}
impl QPDSerializableFixed for Hash256 {
    fn get_fixed_size() -> usize {
        32
    }
}
impl CodeSerializableHash for Hash256 {
    fn to_constant_code(&self) -> String {
        let bytes_str = self.0.iter().map(|b| format!("0x{:02x}u8", b)).collect::<Vec<_>>().join(", ");
        format!("Hash256([{}])", bytes_str)
    }

    fn get_type_name() -> String {
        "Hash256".to_string()
    }
}

impl ToU64x4 for Hash256 {
    fn to_u64x4(&self) -> [u64; 4] {
        self.to_le_u64_x4()
    }
    fn into_u64x4_serialize_non_canonical(self) -> [u64; 4] {
        self.to_le_u64_x4()
    }
}
impl HashTo4Felts<u64> for Hash256 {
    fn to_4_felts(&self) -> [u64; 4] {
        self.to_le_u64_x4()
    }

    fn from_4_felts(felts: [u64; 4]) -> Self {
        Self::from_u64_le_values(felts[0], felts[1], felts[2], felts[3])
    }
}
impl FromU64x4 for Hash256 {
    fn from_u64x4(data: [u64; 4]) -> Self {
        Self::from_u64_le_values(data[0], data[1], data[2], data[3])
    }
}


impl Q256BitHash for Hash256 {
    fn from_owned_32bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    fn into_owned_32bytes(self) -> [u8; 32] {
        self.0
    }
    fn from_ref_32bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }
    fn from_slice_32bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!("expected 32 bytes for deserializing Hash256, got {} bytes", bytes.len());
        }
        let mut inner_data = [0u8; 32];
        inner_data.copy_from_slice(bytes);
        Ok(Hash256(inner_data))
    }
    fn to_vec_32bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// SECURITY: [START UNSAFE CODE BLOCK]
impl Q256BitHashTransparent for Hash256 {
    fn from_ref_32bytes_transparent(bytes: &[u8; 32]) -> &Self {
        // SAFETY: This is safe because Hash256 is a transparent wrapper around [u8; 32]
        unsafe { &*(bytes as *const [u8; 32] as *const Hash256) }
    }

    fn as_ref_32bytes_transparent(&self) -> &[u8; 32] {
        // SAFETY: This is safe because Hash256 is a transparent wrapper around [u8; 32]
        unsafe { &*(self as *const Hash256 as *const [u8; 32]) }
    }
}
// SECURITY: [END UNSAFE CODE BLOCK]

impl QStaticNamedType for Hash256 {
    fn q_static_type_name() -> &'static str {
        "Hash256"
    }
}

impl FastFixedSerializable<32> for Hash256 {
    fn ffs_from_owned_bytes(data: [u8; 32]) -> Self {
        Self(data)
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != 32 {
            panic!("Invalid number of bytes for Hash256");
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(data);
        Self(array)
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 32 {
            anyhow::bail!("Invalid number of bytes for Hash256");
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(data);
        Ok(Self(array))
    }

    fn ffs_to_bytes(&self) -> [u8; 32] {
        self.0
    }

    fn ffs_into_bytes(self) -> [u8; 32] {
        self.0
    }

    #[inline]
    fn write_ffs_serialize_vec_of_self(data: &[Self], bytes: &mut Vec<u8>) {
        for item in data {
            bytes.extend_from_slice(&item.ffs_to_bytes());
        }
    }

    #[inline]
    fn ffs_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 * data.len());
        for item in data {
            bytes.extend_from_slice(&item.0);
        }
        bytes
    }

    #[inline]
    fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * 32);
        for item in data {
            bytes.extend_from_slice(&item.ffs_to_bytes());
        }
        bytes
    }

    #[inline]
    fn ffs_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
        if data.len() % 32 != 0 {
            anyhow::bail!("Data length {} is not a multiple of object size {}", data.len(), 32);
        }

        let mut new_vec = Vec::with_capacity(data.len() / 32);
        let count = data.len() / 32;
        for i in 0..count {
            new_vec.push(Self( data[(i*32)..(i*32+32)].try_into().unwrap()));
        }
        Ok(new_vec)
    }

    #[inline]
    fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
        Self::ffs_deserialize_vec_of_self(&data)
    }
}
impl PsyCanonicalSerializeMetadata for Hash256 {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32;
}
impl AutoDatabaseSerializationUseFastFixedSerialize<32> for Hash256 {}

psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    Hash256,
    32
);


pser::impl_bytemuck_ffs_tests!(Hash256, {}, 32, true);

impl QHashBase for Hash256 {}


impl QToCodeString for Hash256 {
    fn to_debug_code_string(&self) -> String {
        format!("Hash256::from_hex_string(\"{}\").unwrap()", self.to_hex_string())
    }
}