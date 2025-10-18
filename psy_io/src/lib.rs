#![cfg_attr(not(feature = "std"), no_std)]

use anyhow::Context;


#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;


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


pub trait PsyReaderExtensions {
    fn psy_read_u8(&mut self) -> anyhow::Result<u8>;
    fn psy_read_u16(&mut self) -> anyhow::Result<u16>;
    fn psy_read_u32(&mut self) -> anyhow::Result<u32>;
    fn psy_read_u64(&mut self) -> anyhow::Result<u64>;
    fn psy_read_u128(&mut self) -> anyhow::Result<u128>;
    fn psy_read_i8(&mut self) -> anyhow::Result<i8>;
    fn psy_read_i16(&mut self) -> anyhow::Result<i16>;
    fn psy_read_i32(&mut self) -> anyhow::Result<i32>;
    fn psy_read_i64(&mut self) -> anyhow::Result<i64>;
    fn psy_read_i128(&mut self) -> anyhow::Result<i128>;
    fn psy_read_bytes_4(&mut self) -> anyhow::Result<[u8; 4]>;
    fn psy_read_bytes_16(&mut self) -> anyhow::Result<[u8; 16]>;
    fn psy_read_bytes_32(&mut self) -> anyhow::Result<[u8; 32]>;
    fn psy_read_bytes_fixed<const N: usize>(&mut self) -> anyhow::Result<[u8; N]>;
    fn psy_read_vec_length(&mut self) -> anyhow::Result<usize>;
    fn psy_read_vec_of_fixed_bytes<const N: usize>(&mut self) -> anyhow::Result<Vec<[u8; N]>>;
    fn psy_read_bytes_of_length(&mut self, length: usize) -> anyhow::Result<Vec<u8>>;
    fn psy_read_bytes_vec(&mut self) -> anyhow::Result<Vec<u8>>;
    fn psy_read_bytes_vec_with_max_length(&mut self, max_length: usize) -> anyhow::Result<Vec<u8>>;
}

pub trait PsyWriterExtensions {
    fn psy_write_u8(&mut self, value: u8) -> anyhow::Result<()>;
    fn psy_write_u16(&mut self, value: u16) -> anyhow::Result<()>;
    fn psy_write_u32(&mut self, value: u32) -> anyhow::Result<()>;
    fn psy_write_u64(&mut self, value: u64) -> anyhow::Result<()>;
    fn psy_write_u128(&mut self, value: u128) -> anyhow::Result<()>;
    fn psy_write_i8(&mut self, value: i8) -> anyhow::Result<()>;
    fn psy_write_i16(&mut self, value: i16) -> anyhow::Result<()>;
    fn psy_write_i32(&mut self, value: i32) -> anyhow::Result<()>;
    fn psy_write_i64(&mut self, value: i64) -> anyhow::Result<()>;
    fn psy_write_i128(&mut self, value: i128) -> anyhow::Result<()>;
    fn psy_write_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()>;
    fn psy_write_bytes_vec(&mut self, bytes: &[u8]) -> anyhow::Result<()>;
    fn psy_write_bytes_fixed<const N: usize>(&mut self, bytes: &[u8; N]) -> anyhow::Result<()>;
    fn psy_write_vec_length(&mut self, length: usize) -> anyhow::Result<()>;
}

impl<R: Read + ?Sized> PsyReaderExtensions for R {
    #[inline]
    fn psy_read_u8(&mut self) -> anyhow::Result<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf).context("Failed to read u8")?;
        Ok(buf[0])
    }

    #[inline]
    fn psy_read_u16(&mut self) -> anyhow::Result<u16> {
        let buf = self.psy_read_bytes_fixed::<2>().context("Failed to read u16")?;
        Ok(u16::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_u32(&mut self) -> anyhow::Result<u32> {
        let buf = self.psy_read_bytes_fixed::<4>().context("Failed to read u32")?;
        Ok(u32::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_u64(&mut self) -> anyhow::Result<u64> {
        let buf = self.psy_read_bytes_fixed::<8>().context("Failed to read u64")?;
        Ok(u64::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_u128(&mut self) -> anyhow::Result<u128> {
        let buf = self.psy_read_bytes_fixed::<16>().context("Failed to read u128")?;
        Ok(u128::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_i8(&mut self) -> anyhow::Result<i8> {
        let buf = self.psy_read_bytes_fixed::<1>().context("Failed to read i8")?;
        Ok(i8::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_i16(&mut self) -> anyhow::Result<i16> {
        let buf = self.psy_read_bytes_fixed::<2>().context("Failed to read i16")?;
        Ok(i16::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_i32(&mut self) -> anyhow::Result<i32> {
        let buf = self.psy_read_bytes_fixed::<4>().context("Failed to read i32")?;
        Ok(i32::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_i64(&mut self) -> anyhow::Result<i64> {
        let buf = self.psy_read_bytes_fixed::<8>().context("Failed to read i64")?;
        Ok(i64::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_i128(&mut self) -> anyhow::Result<i128> {
        let buf = self.psy_read_bytes_fixed::<16>().context("Failed to read i128")?;
        Ok(i128::from_le_bytes(buf))
    }

    #[inline]
    fn psy_read_bytes_4(&mut self) -> anyhow::Result<[u8; 4]> {
        self.psy_read_bytes_fixed::<4>()
    }

    #[inline]
    fn psy_read_bytes_16(&mut self) -> anyhow::Result<[u8; 16]> {
        self.psy_read_bytes_fixed::<16>()
    }

    #[inline]
    fn psy_read_bytes_32(&mut self) -> anyhow::Result<[u8; 32]> {
        self.psy_read_bytes_fixed::<32>()
    }

    #[inline]
    fn psy_read_bytes_fixed<const N: usize>(&mut self) -> anyhow::Result<[u8; N]> {
        let mut buf = [0u8; N];
        self.read_exact(&mut buf).context(format!("Failed to read {} fixed bytes", N))?;
        Ok(buf)
    }

    #[inline]
    fn psy_read_vec_length(&mut self) -> anyhow::Result<usize> {
        // 4-byte u32 stores length of a vector
        let len_u32 = self.psy_read_u32()?;
        Ok(len_u32 as usize)
    }

    #[inline]
    fn psy_read_vec_of_fixed_bytes<const N: usize>(&mut self) -> anyhow::Result<Vec<[u8; N]>> {
        let length = self.psy_read_vec_length()?;
        let mut vec = Vec::with_capacity(length);
        for _ in 0..length {
            let item = self.psy_read_bytes_fixed::<N>()?;
            vec.push(item);
        }
        Ok(vec)
    }
    
    #[inline]
    fn psy_read_bytes_vec(&mut self) -> anyhow::Result<Vec<u8>> {
        let length = self.psy_read_vec_length()?;
        let mut buf = vec![0u8; length];
        self.read_exact(&mut buf).context(format!("Failed to read {} bytes into vec", length))?;
        Ok(buf)
    }
    
    #[inline]
    fn psy_read_bytes_of_length(&mut self, length: usize) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![0u8; length];
        self.read_exact(&mut buf).context(format!("Failed to read {} bytes into vec", length))?;
        Ok(buf)
    }
    
    #[inline]
    fn psy_read_bytes_vec_with_max_length(&mut self, max_length: usize) -> anyhow::Result<Vec<u8>> {
        let length = self.psy_read_vec_length()?;
        if length > max_length {
            anyhow::bail!("Vector length {} exceeds maximum allowed {}", length, max_length);
        }
        let mut buf = vec![0u8; length];
        self.read_exact(&mut buf).context(format!("Failed to read {} bytes into vec", length))?;
        Ok(buf)
    }

}

impl<W: Write + ?Sized> PsyWriterExtensions for W {
    #[inline]
    fn psy_write_u8(&mut self, value: u8) -> anyhow::Result<()> {
        self.write_all(&[value]).context("Failed to write u8")
    }

    #[inline]
    fn psy_write_u16(&mut self, value: u16) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write u16")
    }

    #[inline]
    fn psy_write_u32(&mut self, value: u32) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write u32")
    }

    #[inline]
    fn psy_write_u64(&mut self, value: u64) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write u64")
    }

    #[inline]
    fn psy_write_u128(&mut self, value: u128) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write u128")
    }

    #[inline]
    fn psy_write_i8(&mut self, value: i8) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write i8")
    }

    #[inline]
    fn psy_write_i16(&mut self, value: i16) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write i16")
    }

    #[inline]
    fn psy_write_i32(&mut self, value: i32) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write i32")
    }

    #[inline]
    fn psy_write_i64(&mut self, value: i64) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write i64")
    }

    #[inline]
    fn psy_write_i128(&mut self, value: i128) -> anyhow::Result<()> {
        self.write_all(&value.to_le_bytes()).context("Failed to write i128")
    }

    #[inline]
    fn psy_write_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.write_all(bytes).context("Failed to write bytes")
    }

    #[inline]
    fn psy_write_bytes_fixed<const N: usize>(&mut self, bytes: &[u8; N]) -> anyhow::Result<()> {
        self.write_all(bytes).context("Failed to write fixed-size bytes")
    }

    #[inline]
    fn psy_write_vec_length(&mut self, length: usize) -> anyhow::Result<()> {
        // 4-byte u32 stores length of a vector
        let len_u32 = u32::try_from(length)
            .context("Vector length exceeds u32::MAX")?;
        self.psy_write_u32(len_u32)
    }
    
    fn psy_write_bytes_vec(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.psy_write_vec_length(bytes.len())?;
        self.write_all(bytes).context("Failed to write bytes vec")
    }
}

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
pub fn p_write_inner_vec_size<W: Write>(n: usize, writer: &mut W) -> anyhow::Result<()> {
    if n >= u32::MAX as usize {
        anyhow::bail!("Size too large to write as varuint u32, {}", n);
    }
    writer.write_all(&(n as u32).to_le_bytes()).context("Failed to write multi-byte varint")
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
        let test_values = [0usize, 1, 127, 128, 255, 300, 16384, 2097151, 268435455, 1338, 2];
        for &value in &test_values {
            let mut buf = Vec::new();
            p_write_varuint(value, &mut buf).expect("Failed to write varuint");
            let mut cursor = Cursor::new(buf);
            let read_value = p_read_varuint(&mut cursor).expect("Failed to read varuint");
            assert_eq!(value, read_value, "Mismatch for value {}", value);
        }
        let mut buf = Vec::<u8>::new();
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