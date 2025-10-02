/*use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub type QBytes = std::vec::Vec<u8>;
pub trait ToQBytes: Serialize {
    fn to_qbytes(&self) -> anyhow::Result<QBytes>;
    fn to_qbytes_unwrap(&self) -> QBytes;
}
impl<T: Serialize> ToQBytes for T {
    fn to_qbytes(&self) -> anyhow::Result<QBytes> {
        Ok(postcard::to_stdvec(self)?)
    }

    fn to_qbytes_unwrap(&self) -> QBytes {
        postcard::to_stdvec(self).unwrap()
    }
}


pub trait FromQBytes<'de>: Sized + Deserialize<'de> {
    /// Deserializes a byte slice into an instance of `Self`.
    /// The lifetime `'de` ensures that if `Self` contains any references,
    /// they are correctly bound to the lifetime of the input slice.
    fn from_bytes(bytes: &'de [u8]) -> anyhow::Result<Self> {
        Ok(postcard::from_bytes(bytes)?)
    }
    fn from_bytes_owned(bytes: Vec<u8>) -> anyhow::Result<Self>
    where
        Self: DeserializeOwned,
    {
        // The implementation is the same, but the bound `DeserializeOwned` on `Self`
        // guarantees to the compiler that no lifetimes from `bytes` escape.
        postcard::from_bytes(bytes)
    }
}*/