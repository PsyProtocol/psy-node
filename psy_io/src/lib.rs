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

/* 

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
*/


// we will make these u32s for simplicity and speed
#[inline(always)]
pub fn p_write_varuint<W: Write>(n: usize, writer: &mut W) -> anyhow::Result<()> {
    if n >= u32::MAX as usize {
        anyhow::bail!("Size too large to write as varuint u32, {}", n);
    }
    writer.write_all(&(n as u32).to_le_bytes()).context("Failed to write multi-byte varint")
}

#[inline(always)]
pub fn p_read_varuint<R: Read>(reader: &mut R) -> anyhow::Result<usize> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).context("Failed to read varint bytes from stream")?;
    let n_u32 = u32::from_le_bytes(buf);
    Ok(n_u32 as usize)
}

#[inline(always)]
pub const fn p_varuint_size(_n: usize) -> usize {
    4
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

#[cfg(test)]
mod tests {
    // test varuint write and read
    use super::*;
    use std::io::Cursor;
    #[test]
    fn test_varuint() {
        let test_values = [0usize, 1, 127, 128, 255, 300, 16384, 2097151, 268435455, usize::MAX, 1338, 2];
        for &value in &test_values {
            let mut buf = Vec::new();
            p_write_varuint(value, &mut buf).expect("Failed to write varuint");
            let mut cursor = Cursor::new(buf);
            let read_value = p_read_varuint(&mut cursor).expect("Failed to read varuint");
            assert_eq!(value, read_value, "Mismatch for value {}", value);
        }
        let mut buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&buf);
        p_write_varuint(2, &mut buf).unwrap();
        p_write_varuint(76, &mut buf).unwrap();
        buf.write_all(&[1u8; 76]).unwrap(); // padding
        p_write_varuint(76, &mut buf).unwrap();
        buf.write_all(&[2u8; 76]).unwrap(); // padding

        let mut cursor = Cursor::new(&buf);
        let v1 = p_read_varuint(&mut cursor).unwrap();
        assert_eq!(v1, 2);
        let v2 = p_read_varuint(&mut cursor).unwrap();
        assert_eq!(v2, 76);
        let mut padding1 = vec![0u8; 76];
        cursor.read_exact(&mut padding1).unwrap();
        assert_eq!(padding1, vec![1u8; 76]);
        let v3 = p_read_varuint(&mut cursor).unwrap();
        assert_eq!(v3, 76);
        let mut padding2 = vec![0u8; 76];
        cursor.read_exact(&mut padding2).unwrap();
        assert_eq!(padding2, vec![2u8; 76]);

        
    }
}