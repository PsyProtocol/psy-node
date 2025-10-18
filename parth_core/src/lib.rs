#[cfg(feature = "ptypes_goldilocks_qhashout")]
pub mod pgoldilocks;
mod ptypes;
//mod canonical_serialize;
//pub use canonical_serialize::*;
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
/*
How to make a Macro that I can call like:
impl_bytemuck_pod_and_zeroable!(MyType, F, Hash);

that produces:
#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
unsafe impl<F: bytemuck::Pod, Hash: bytemuck::Pod> bytemuck::Zeroable for MyType<F, Hash>
{
}

#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
unsafe impl<F: bytemuck::Pod, Hash: bytemuck::Pod> bytemuck::Pod for MyType<F, Hash>
{
}


Or:

impl_bytemuck_pod_and_zeroable!(MyOtherType, V);

that produces:
#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
unsafe impl<V: bytemuck::Pod> bytemuck::Zeroable for MyOtherType<V>
{
}

#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
unsafe impl<V: bytemuck::Pod> bytemuck::Pod for MyOtherType<V>
{
}

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



#[macro_export]
macro_rules! impl_psyser_for_ffs {
    // The macro takes the Type and its fixed Size as arguments.
    ($type:ty, $size:expr) => {
        impl parth_core::PsyCanonicalSer for $type {
            #[inline]
            fn psyser_serialize<W: ::std::io::Write>(&self, writer: &mut W) -> ::std::io::Result<()> {
                // This relies on the type implementing FastFixedSerializable<$size>
                let bytes = self.ffs_to_bytes();
                writer.write_all(&bytes)
            }

            #[inline]
            fn psyser_deserialize<R: ::std::io::Read>(reader: &mut R) -> ::std::io::Result<Self> {
                let mut buf = [0u8; $size];
                reader.read_exact(&mut buf)?;
                // This relies on the type implementing FastFixedSerializable<$size>
                Ok(Self::ffs_from_owned_bytes(buf))
            }

            #[inline(always)]
            fn psyser_serialized_size(&self) -> usize {
                $size
            }

            const FIXED_SERIALIZED_SIZE: Option<usize> = Some($size);
        }
    };
}


#[macro_export]
macro_rules! impl_psyser_for_ffs_crate {
    // The macro takes the Type and its fixed Size as arguments.
    ($type:ty, $size:expr) => {
        impl $crate::PsyCanonicalSer for $type {
            #[inline]
            fn psyser_serialize<W: ::std::io::Write>(&self, writer: &mut W) -> ::std::io::Result<()> {
                // This relies on the type implementing FastFixedSerializable<$size>
                let bytes = self.ffs_to_bytes();
                writer.write_all(&bytes)
            }

            #[inline]
            fn psyser_deserialize<R: ::std::io::Read>(reader: &mut R) -> ::std::io::Result<Self> {
                let mut buf = [0u8; $size];
                reader.read_exact(&mut buf)?;
                // This relies on the type implementing FastFixedSerializable<$size>
                Ok(Self::ffs_from_bytes(buf))
            }

            #[inline(always)]
            fn psyser_serialized_size(&self) -> usize {
                $size
            }

            const FIXED_SERIALIZED_SIZE: Option<usize> = Some($size);
        }
    };
}
/*

#[macro_export]
macro_rules! impl_psyser_for_ffs_with_params {
    // The macro takes the Type, its generic parameters, and its fixed Size as arguments.
    (
        $type:ident,
        { $($impl_generics:tt)* } => { $($type_generics:tt)* },
        $size:expr
    ) => {
        impl<$($impl_generics)*> parth_core::PsyCanonicalSer for $type<$($type_generics)*> {
            #[inline]
            fn psyser_serialize<W: ::std::io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
                // This relies on the type implementing FastFixedSerializable<$size>
                let bytes = self.ffs_to_bytes();
                writer.write_all(&bytes).map_err(Into::into)
            }

            #[inline]
            fn psyser_deserialize<R: ::std::io::Read>(reader: &mut R) -> anyhow::Result<Self> {
                let mut buf = [0u8; $size];
                reader.read_exact(&mut buf)?;
                // This relies on the type implementing FastFixedSerializable<$size>
                Ok(Self::ffs_from_owned_bytes(buf))
            }

            #[inline(always)]
            fn psyser_serialized_size(&self) -> usize {
                $size
            }

            const FIXED_SERIALIZED_SIZE: Option<usize> = Some($size);
        }
    };
}*/