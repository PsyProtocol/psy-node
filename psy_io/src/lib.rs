#![cfg_attr(not(feature = "std"), no_std)]

use anyhow::Context;


#[cfg(feature = "alloc")]
extern crate alloc;

// Synchronous I/O re-exports: Use std::io when "std" feature is enabled, else embedded-io
#[cfg(feature = "std")]
pub use std::io::{Error, ErrorKind, Read, Write, Seek, SeekFrom, BufRead, Cursor};

#[cfg(not(feature = "std"))]
pub use embedded_io::{Error, ErrorKind, ErrorType, Read, Write, Seek, SeekFrom, BufRead};

#[cfg(not(feature = "std"))]
mod cursor;

#[cfg(not(feature = "std"))]
pub use cursor::Cursor;


// Custom IoError: Only in no-std mode, as a concrete error type mimicking std::io::Error
#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub struct IoError {
    kind: ErrorKind,
}

#[cfg(not(feature = "std"))]
impl Error for IoError {
    fn kind(&self) -> ErrorKind {
        self.kind
    }
}



#[inline(always)]
pub fn p_write_varuint<W: Write>(mut n: usize, writer: &mut W) -> anyhow::Result<()> {
    if n < 128 {
        return writer.write_all(&[n as u8]).context("Failed to write single-byte varint");
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    loop {
        let mut byte = (n as u8) & 0x7F;
        n >>= 7;
        if n != 0 { byte |= 0x80; }
        buf[i] = byte;
        i += 1;
        if n == 0 { break; }
    }
    writer.write_all(&buf[..i]).context("Failed to write multi-byte varint")
}

#[inline(always)]
pub fn p_read_varuint<R: Read>(reader: &mut R) -> anyhow::Result<usize> {
    let mut result = 0usize;
    let mut shift = 0;
    let mut buf = [0u8; 1];
    loop {
        if shift >= usize::BITS {
            anyhow::bail!("Varint overflow: larger than supported usize");
        }
        reader.read_exact(&mut buf).context("Failed to read varint byte from stream")?;
        let byte = buf[0];
        result |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 { return Ok(result); }
        shift += 7;
    }
}

#[inline(always)]
pub const fn p_varuint_size(n: usize) -> usize {
    if n == 0 { return 1; }
    let bits = usize::BITS - n.leading_zeros();
    (bits as usize + 6) / 7
}


pub const PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE: usize = 4;

#[inline(always)]
pub fn p_write_fixed_items_manycount<W: Write>(n: usize, writer: &mut W) -> anyhow::Result<()> {
    if n > u32::MAX as usize {
        anyhow::bail!("Size too large to write as fixed u32");
    }
    let n_u32 = n as u32;
    let bytes = n_u32.to_le_bytes();
    writer.write_all(&bytes).context("Failed to write fixed u32 size")
}
pub fn p_read_fixed_items_many_count<R: Read>(reader: &mut R) -> anyhow::Result<usize> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).context("Failed to read fixed u32 size")?;
    let n_u32 = u32::from_le_bytes(buf);
    Ok(n_u32 as usize)
}
pub fn p_fixed_items_count_many_size() -> usize {
    PSY_IO_FIXED_ITEMS_MANY_COUNT_SIZE
}