pub mod common;
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
                    bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
                }

                fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
                    bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
                }
            }
        )+
    };
}
