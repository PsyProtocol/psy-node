pub mod constants;
pub mod crypto;
pub mod data;
pub mod jobs;
pub mod protocol;
pub mod utils;
pub mod store;
pub mod node;

#[macro_export]
macro_rules! impl_qpq_serialize_primitive {
    ($($typ:ty),+ $(,)?) => {
        $(
            impl QPDSerializable for $typ {
                fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
                    Ok(self.to_be_bytes().to_vec())
                }
                fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
                    Ok(<$typ>::from_be_bytes(bytes.try_into()?))
                }
            }
        )+
    };
}


#[macro_export]
macro_rules! impl_qpq_serialize_bincode {
    ($($typ:ty),+ $(,)?) => {
        $(
            impl QPDSerializable for $typ {
                fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
                    //b1incode::serialize(self).map_err(|e| anyhow::anyhow!(e))
                    self.to_qbytes()
                }

                fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
                    //bi1ncode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
                    Self::from_qbytes(bytes)
                }
            }
        )+
    };
}
