use crate::{FastFixedSerializable, PsyIOWithMaxVecLength};
use anyhow::Context;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};

// These traits are for serializing fields within larger structs, where the field
// itself is a struct or a Vec of structs.

pub trait PsyIOWritableCanonicalStruct: PsyIOWithMaxVecLength + Sized {
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

pub trait PsyIOReadableCanonicalStruct: PsyIOWithMaxVecLength + Sized {
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

// --- Auto-implementations for FastFixedSerializable types ---

impl<const SIZE: usize, T> PsyIOWritableCanonicalStruct for T
where
    T: FastFixedSerializable<SIZE> + PsyIOWithMaxVecLength,
{
    #[inline(always)]
    fn psy_io_write_canonical_struct_to<W: psy_io::Write + ?Sized>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.write_all(&self.ffs_to_bytes()).context("Failed to write FFS struct")
    }

    #[inline(always)]
    fn psy_io_write_vec_of_canonical_structs_to<W: psy_io::Write + ?Sized>(vec: &[Self], writer: &mut W) -> anyhow::Result<()> {
        if vec.len() > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec.len(), Self::psy_io_max_vec_length());
        }
        writer.psy_write_vec_length(vec.len())?;

        // OPTIMIZATION: Use the high-performance FFS method to serialize the entire vector at once.
        if !vec.is_empty() {
            let buffer = T::ffs_serialize_vec_of_self_ref(vec);
            writer.write_all(&buffer).context("Failed to write buffered vector of FFS structs")?;
        }
        Ok(())
    }
}

impl<const SIZE: usize, T> PsyIOReadableCanonicalStruct for T
where
    T: FastFixedSerializable<SIZE> + PsyIOWithMaxVecLength,
{
    #[inline(always)]
    fn psy_io_read_canonical_struct_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Self> {
        let mut buf = [0u8; SIZE];
        reader.read_exact(&mut buf).context("Failed to read FFS struct")?;
        Ok(T::ffs_from_owned_bytes(buf))
    }

    #[inline(always)]
    fn psy_io_read_vec_of_canonical_structs_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Vec<Self>> {
        let vec_length = reader.psy_read_vec_length()?;
        if vec_length > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec_length, Self::psy_io_max_vec_length());
        }

        if vec_length == 0 {
            return Ok(Vec::new());
        }

        // OPTIMIZATION: Read all bytes for the vector content in a single call.
        let total_bytes = vec_length
            .checked_mul(SIZE)
            .context("Total byte size for vector of fixed structs exceeds usize::MAX")?;

        let mut buffer = vec![0u8; total_bytes];
        reader.read_exact(&mut buffer).context("Failed to bulk-read vector of fixed structs")?;

        // OPTIMIZATION: Use the high-performance FFS method to deserialize the entire vector at once.
        T::ffs_deserialize_vec_of_self_owned(buffer)
    }
}