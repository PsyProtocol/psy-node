#[cfg(feature = "ptypes_goldilocks_qhashout")]
pub mod pgoldilocks;
mod ptypes;
pub use ptypes::*;
pub mod constants;
pub mod felt;
pub mod crypto;
pub mod data;
pub mod protocol;
pub mod utils;
pub mod store;
pub mod node;
mod job_id_base;
pub use job_id_base::*;
mod protocol_types;
pub use protocol_types::*;
pub mod proof_hasher;
pub mod generic_traits;

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

/*
expected one of `where` or `{`, found `<`
expected one of `where` or `{`rustcClick for full compiler diagnostic
user.rs(32, 1):

*/

#[macro_export]
macro_rules! impl_qpd_serialize_params {
    (
        $typ:ident,
        { $($impl_generics:tt)* } => { $($type_generics:tt)* }
    ) => {
        impl<$($impl_generics)*> QPDSerializable for $typ<$($type_generics)*> {
            fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
                //bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
                self.to_qbytes()
            }

            fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
                //bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
                Self::from_qbytes(bytes)
            }
        }
    };
}
#[macro_export]
macro_rules! impl_qpq_serialize_bincode_f {
    ($($typ:ty),+ $(,)?) => {
        $(
            impl<F: QFelt> QPDSerializable for $typ<F> {
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
