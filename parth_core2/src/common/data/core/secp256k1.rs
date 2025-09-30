use std::fmt::Display;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::common::data::core::hash::hash256::Hash256;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct QPSecp256K1CompressedPublicKey(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 33]);
impl From<[u8; 33]> for QPSecp256K1CompressedPublicKey {
    fn from(value: [u8; 33]) -> Self {
        Self(value)
    }
}
impl From<&[u8; 33]> for QPSecp256K1CompressedPublicKey {
    fn from(value: &[u8; 33]) -> Self {
        Self(*value)
    }
}

impl Display for QPSecp256K1CompressedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct QPSecp256K1Signature(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 64]);
impl From<[u8; 64]> for QPSecp256K1Signature {
    fn from(value: [u8; 64]) -> Self {
        Self(value)
    }
}
impl From<&[u8; 64]> for QPSecp256K1Signature {
    fn from(value: &[u8; 64]) -> Self {
        Self(*value)
    }
}
impl Display for QPSecp256K1Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash)]
pub struct QPCompressedSecp256K1SignatureFull {
    pub public_key: QPSecp256K1CompressedPublicKey,
    pub signature: QPSecp256K1Signature,
    pub message: Hash256,
}