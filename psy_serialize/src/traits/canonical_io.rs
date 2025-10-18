// src/canonical_io.rs

use crate::{FastFixedSerializable, PsyCanonicalSerializeMaxVecLength};
use anyhow::Context;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};

// --- Base IO Traits ---

/// Trait for writing a variable-sized canonical struct to an IO stream.
pub trait PsyIOWritableCanonicalStruct: PsyCanonicalSerializeMaxVecLength + Sized {
    fn psy_io_write_canonical_struct_to<W: psy_io::Write + ?Sized>(&self, writer: &mut W) -> anyhow::Result<()>;

    fn psy_io_write_vec_of_canonical_structs_to<W: psy_io::Write + ?Sized>(vec: &[Self], writer: &mut W) -> anyhow::Result<()> {
        if vec.len() > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec.len(), Self::psy_io_max_vec_length());
        }
        writer.psy_write_vec_length(vec.len())?;
        for item in vec {
            item.psy_io_write_canonical_struct_to(writer)?;
        }
        Ok(())
    }
}

/// Trait for reading a variable-sized canonical struct from an IO stream.
pub trait PsyIOReadableCanonicalStruct: PsyCanonicalSerializeMaxVecLength + Sized {
    fn psy_io_read_canonical_struct_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Self>;

    fn psy_io_read_vec_of_canonical_structs_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Vec<Self>> {
        let vec_length = reader.psy_read_vec_length()?;
        if vec_length > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec_length, Self::psy_io_max_vec_length());
        }
        let mut output = Vec::<Self>::with_capacity(vec_length);
        for _ in 0..vec_length {
            output.push(Self::psy_io_read_canonical_struct_from(reader)?);
        }
        Ok(output)
    }
}

// --- Fixed-Size Optimized IO Traits ---

/// Trait for writing a fixed-size canonical struct to an IO stream.
pub trait PsyIOWritableFixedSizeCanonicalStruct<const SIZE: usize>: PsyCanonicalSerializeMaxVecLength + Sized {
    fn psy_io_write_fixed_canonical_struct_to<W: psy_io::Write + ?Sized>(&self, writer: &mut W) -> anyhow::Result<()>;

    fn psy_io_write_vec_of_fixed_canonical_structs_to<W: psy_io::Write + ?Sized>(vec: &[Self], writer: &mut W) -> anyhow::Result<()> {
        if vec.len() > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec.len(), Self::psy_io_max_vec_length());
        }
        writer.psy_write_vec_length(vec.len())?;
        if !vec.is_empty() {
            let total_bytes = vec.len() * SIZE;
            let mut buffer = Vec::with_capacity(total_bytes);
            for item in vec {
                item.psy_io_write_fixed_canonical_struct_to(&mut buffer)?;
            }
            writer.write_all(&buffer).context("Failed to write buffered vector of fixed canonical structs")?;
        }
        Ok(())
    }
}

/// Trait for reading a fixed-size canonical struct from an IO stream.
pub trait PsyIOReadableFixedSizeCanonicalStruct<const SIZE: usize>: PsyCanonicalSerializeMaxVecLength + Sized {
    fn psy_io_read_fixed_canonical_struct_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Self>;

    fn psy_io_read_vec_of_fixed_canonical_structs_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Vec<Self>> {
        let vec_length = reader.psy_read_vec_length()?;
        if vec_length > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec_length, Self::psy_io_max_vec_length());
        }
        if vec_length == 0 {
            return Ok(Vec::new());
        }
        let total_bytes = vec_length.checked_mul(SIZE).context("Total byte size for vector of fixed structs exceeds usize::MAX")?;
        let mut buffer = vec![0u8; total_bytes];
        reader.read_exact(&mut buffer).context("Failed to bulk-read vector of fixed structs")?;

        let mut output = Vec::with_capacity(vec_length);
        for chunk in buffer.chunks_exact(SIZE) {
            let mut cursor = psy_io::Cursor::new(chunk);
            output.push(Self::psy_io_read_fixed_canonical_struct_from(&mut cursor)?);
        }
        Ok(output)
    }
}

// --- Blanket Impls for FastFixedSerializable Types ---

impl<const N: usize, T: FastFixedSerializable<N>> PsyIOWritableCanonicalStruct for T {
    #[inline(always)]
    fn psy_io_write_canonical_struct_to<W: psy_io::Write + ?Sized>(&self, writer: &mut W) -> anyhow::Result<()> {
        <Self as PsyIOWritableFixedSizeCanonicalStruct<N>>::psy_io_write_fixed_canonical_struct_to(self, writer)
    }

    #[inline(always)]
    fn psy_io_write_vec_of_canonical_structs_to<W: psy_io::Write + ?Sized>(vec: &[Self], writer: &mut W) -> anyhow::Result<()> {
        <Self as PsyIOWritableFixedSizeCanonicalStruct<N>>::psy_io_write_vec_of_fixed_canonical_structs_to(vec, writer)
    }
}

impl<const N: usize, T: FastFixedSerializable<N>> PsyIOWritableFixedSizeCanonicalStruct<N> for T {
    #[inline(always)]
    fn psy_io_write_fixed_canonical_struct_to<W: psy_io::Write + ?Sized>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.write_all(&self.ffs_to_bytes()).context(format!("Failed to write {} fixed bytes", N))
    }

    #[inline(always)]
    fn psy_io_write_vec_of_fixed_canonical_structs_to<W: psy_io::Write + ?Sized>(vec: &[Self], writer: &mut W) -> anyhow::Result<()> {
        if vec.len() > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec.len(), Self::psy_io_max_vec_length());
        }
        writer.psy_write_vec_length(vec.len())?;
        if !vec.is_empty() {
            let byte_vec = T::ffs_serialize_vec_of_self_ref(vec);
            writer.write_all(&byte_vec).context("Failed to write FFS-serialized vector of fixed canonical structs")?;
        }
        Ok(())
    }
}

impl<const N: usize, T: FastFixedSerializable<N>> PsyIOReadableCanonicalStruct for T {
    #[inline(always)]
    fn psy_io_read_canonical_struct_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Self> {
        <Self as PsyIOReadableFixedSizeCanonicalStruct<N>>::psy_io_read_fixed_canonical_struct_from(reader)
    }

    #[inline(always)]
    fn psy_io_read_vec_of_canonical_structs_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Vec<Self>> {
        <Self as PsyIOReadableFixedSizeCanonicalStruct<N>>::psy_io_read_vec_of_fixed_canonical_structs_from(reader)
    }
}

impl<const N: usize, T: FastFixedSerializable<N>> PsyIOReadableFixedSizeCanonicalStruct<N> for T {
    #[inline(always)]
    fn psy_io_read_fixed_canonical_struct_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Self> {
        let buf = reader.psy_read_bytes_fixed::<N>()?;
        Ok(T::ffs_from_owned_bytes(buf))
    }

    #[inline(always)]
    fn psy_io_read_vec_of_fixed_canonical_structs_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Vec<Self>> {
        let vec_length = reader.psy_read_vec_length()?;
        if vec_length > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec_length, Self::psy_io_max_vec_length());
        }
        if vec_length == 0 {
            return Ok(Vec::new());
        }
        let total_bytes = vec_length.checked_mul(N).context("Total byte size for vector of fixed structs exceeds usize::MAX")?;
        let mut buffer = vec![0u8; total_bytes];
        reader.read_exact(&mut buffer).context("Failed to bulk-read vector of fixed structs")?;

        T::ffs_deserialize_vec_of_self_owned(buffer)
    }
}