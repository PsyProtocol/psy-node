use std::fmt::Display;

use hex::FromHexError;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{crypto::hash::traits::{CodeSerializableHash, ZeroableHash}, data::serializable::{QPDSerializable, QPDSerializableFixed}};


#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug, Eq, Hash, PartialOrd, Ord)]
pub struct Hash256(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);
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
            anyhow::bail!(
                "expected 32 bytes for deserializing Hash256, got {} bytes",
                bytes.len()
            );
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