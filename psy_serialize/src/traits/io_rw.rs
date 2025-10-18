use anyhow::Context;
use psy_io::{PsyWriterExtensions, PsyReaderExtensions};

use crate::PsyIOWithMaxVecLength;


pub trait PsyIOWritableCanonicalStruct: PsyIOWithMaxVecLength + Sized {
    // FIX: Add `+ ?Sized` to allow this method to be called on trait objects
    fn psy_io_write_canonical_struct_to<W: psy_io::Write + ?Sized>(&self, writer: &mut W) -> anyhow::Result<()>;
    // FIX: Add `+ ?Sized` here as well
    fn psy_io_write_vec_of_canonical_structs_to<W: psy_io::Write + ?Sized>(vec: &[Self], writer: &mut W) -> anyhow::Result<()>{
        // default, overridable implementation
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
pub trait PsyIOWritableFixedSizeCanonicalStruct<const SIZE: usize>: PsyIOWithMaxVecLength + Sized {
    // FIX: Add `+ ?Sized`
    fn psy_io_write_fixed_canonical_struct_to<W: psy_io::Write + ?Sized>(&self, writer: &mut W) -> anyhow::Result<()>;
    // FIX: Add `+ ?Sized`
    fn psy_io_write_vec_of_fixed_canonical_structs_to<W: psy_io::Write + ?Sized>(vec: &[Self], writer: &mut W) -> anyhow::Result<()>{
        // default, overridable implementation
        if vec.len() > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec.len(), Self::psy_io_max_vec_length());
        }
        writer.psy_write_vec_length(vec.len())?;

        // OPTIMIZATION: Serialize all fixed-size items into a single buffer
        // and write it in one call to minimize I/O overhead.
        let total_bytes = vec.len().saturating_mul(SIZE);
        if total_bytes > 0 {
            let mut buffer = Vec::with_capacity(total_bytes);
            for item in vec {
                // Since `buffer` is a `Vec<u8>`, it implements `Write` and is Sized.
                item.psy_io_write_fixed_canonical_struct_to(&mut buffer)?;
            }
            writer.write_all(&buffer).context("Failed to write buffered vector of fixed canonical structs")?;
        }

        Ok(())
    }
}
pub trait PsyIOReadableCanonicalStruct: PsyIOWithMaxVecLength + Sized {
    // FIX: Add `+ ?Sized`
    fn psy_io_read_canonical_struct_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Self>;
    // FIX: Add `+ ?Sized`
    fn psy_io_read_vec_of_canonical_structs_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Vec<Self>>{
        // default, overridable implementation
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
pub trait PsyIOReadableFixedSizeCanonicalStruct<const SIZE: usize>: PsyIOWithMaxVecLength + Sized {
    // FIX: Add `+ ?Sized`
    fn psy_io_read_fixed_canonical_struct_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Self>;
    // FIX: Add `+ ?Sized`
    fn psy_io_read_vec_of_fixed_canonical_structs_from<R: psy_io::Read + ?Sized>(reader: &mut R) -> anyhow::Result<Vec<Self>>{
        // default, overridable implementation
        let vec_length = reader.psy_read_vec_length()?;
        if vec_length > Self::psy_io_max_vec_length() {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", vec_length, Self::psy_io_max_vec_length());
        }

        if vec_length == 0 {
            return Ok(Vec::new());
        }

        // OPTIMIZATION: Read all bytes for the vector content in a single call.
        let total_bytes = vec_length.checked_mul(SIZE)
            .context("Total byte size for vector of fixed structs exceeds usize::MAX")?;

        let mut buffer = vec![0u8; total_bytes];
        reader.read_exact(&mut buffer).context("Failed to bulk-read vector of fixed structs")?;

        // Now, parse the in-memory buffer, which is much faster than repeated I/O.
        let mut output = Vec::with_capacity(vec_length);
        for chunk in buffer.chunks_exact(SIZE) {
            let mut cursor = psy_io::Cursor::new(chunk);
            output.push(Self::psy_io_read_fixed_canonical_struct_from(&mut cursor)?);
        }

        Ok(output)
    }
}