/*use serde::{de::DeserializeOwned, Serialize};

pub type QBytes = std::vec::Vec<u8>;
pub trait QBytesSerialize: Serialize {
    fn to_qbytes(&self) -> anyhow::Result<QBytes>;
    fn to_qbytes_unwrap(&self) -> QBytes;
}
impl<T: Serialize> QBytesSerialize for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        Ok(bincode::serde::encode_to_vec(self, bincode::config::standard())?)
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}
pub trait QBytesDeserialize: DeserializeOwned {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self>;
    fn from_qbytes_unwrap(bytes: &[u8]) -> Self;
}
impl<T: DeserializeOwned> QBytesDeserialize for T {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::serde::decode_from_slice(bytes, bincode::config::standard())?.0)
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).unwrap().0
    }
}*/
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub type QBytes = std::vec::Vec<u8>;
pub trait QBytesSerialize {
    fn to_qbytes(&self) -> anyhow::Result<QBytes>;
    fn to_qbytes_unwrap(&self) -> QBytes;
}
pub trait QBytesDeserialize {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> where for<'de> Self: Deserialize<'de>;
    fn from_qbytes_unwrap(bytes: &[u8]) -> Self;
}

/* 
impl<T> QBytesDeserialize for T where for<'de> T: Deserialize<'de>,{
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

*/
/* 
// bincode 2.0.1
impl<T: DeserializeOwned> QBytesDeserialize for T {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(bincode::serde::decode_from_slice(bytes, bincode::config::standard())?.0)
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).unwrap().0
    }
}

impl<T: Serialize> QBytesSerialize for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        Ok(bincode::serde::encode_to_vec(self, bincode::config::standard())?)
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }
}
*/
/*
// postcard
impl<T: DeserializeOwned> QBytesDeserialize for T {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        postcard::from_bytes(bytes).unwrap()
    }
}

impl<T: Serialize> QBytesSerialize for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        postcard::to_stdvec(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        postcard::to_stdvec(self).unwrap()
    }
}

*/

impl<T: DeserializeOwned> QBytesDeserialize for T {
    fn from_qbytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_qbytes_unwrap(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

impl<T: Serialize> QBytesSerialize for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        bincode::serialize(self).unwrap()
    }
}

#[inline]
pub fn serialize<T: QBytesSerialize>(value: &T) -> anyhow::Result<QBytes> {
    value.to_qbytes()
}

#[inline]
pub fn deserialize<T: QBytesDeserialize>(bytes: &[u8]) -> anyhow::Result<T> where for<'de> T: Deserialize<'de> {
    T::from_qbytes(bytes)
}
