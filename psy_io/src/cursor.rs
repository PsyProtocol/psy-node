
#![cfg_attr(not(feature = "std"), no_std)]
/*
MIT License

Copyright (c) 2024 embedded-io-cursor contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


//! A `no_std`-compatible Cursor implementation designed for use with `embedded-io`.
//!
//! This crate provides a `Cursor` type that wraps an in-memory buffer and implements
//! the `embedded-io` traits (`Read`, `Write`, `BufRead`, and `Seek`). It serves as
//! the `embedded-io` ecosystem's equivalent to `std::io::Cursor`, optimized for
//! embedded and `no_std` environments while maintaining API compatibility where possible.

use core::cmp;
use embedded_io::{BufRead, Error, ErrorKind, ErrorType, Read, Seek, SeekFrom, Write};

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};

/// A `Cursor` wraps an in-memory buffer and provides `embedded-io` trait implementations.
///
/// This is the `embedded-io` equivalent of `std::io::Cursor`, designed for
/// `no_std` environments. It implements the `embedded-io` traits (`Read`, `Write`,
/// `BufRead`, and `Seek`) for various buffer types.
///
/// `Cursor`s are used with in-memory buffers (anything implementing [`AsRef<[u8]>`])
/// to allow them to implement `embedded-io` traits, making these buffers usable
/// anywhere you need an `embedded-io` reader, writer, or seeker.
///
/// Supported buffer types include `&[u8]`, `[u8; N]`, `&mut [u8]`, and with the
/// `alloc` feature: `Vec<u8>` and `Box<[u8]>`.
///
/// # Examples
///
/// Examples of using the Cursor for writing and reading can be found in the comprehensive
/// test suite in the `tests/` directory.
///
/// Reading from a buffer using `embedded-io` traits:
///
/// ```
/// use embedded_io::Read;
/// use embedded_io_cursor::Cursor;
///
/// let mut cursor = Cursor::new(&b"hello world"[..]);
/// let mut buf = [0u8; 5];
/// cursor.read_exact(&mut buf).unwrap();
/// assert_eq!(&buf, b"hello");
/// ```
#[derive(Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Cursor<T> {
    inner: T,
    pos: u64,
}

impl<T> Cursor<T> {
    /// Creates a new cursor wrapping the provided underlying in-memory buffer.
    ///
    /// Cursor initial position is `0` even if underlying buffer (e.g., `Vec`)
    /// is not empty. So writing to cursor starts with overwriting `Vec`
    /// content, not with appending to it.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_cursor::Cursor;
    ///
    /// let cursor = Cursor::new(Vec::<u8>::new());
    /// # let _ = cursor;
    /// ```
    pub const fn new(inner: T) -> Cursor<T> {
        Cursor { pos: 0, inner }
    }

    /// Consumes this cursor, returning the underlying value.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_cursor::Cursor;
    ///
    /// let buff = Cursor::new(Vec::<u8>::new());
    /// let vec = buff.into_inner();
    /// ```
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Gets a reference to the underlying value in this cursor.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_cursor::Cursor;
    ///
    /// let buff = Cursor::new(Vec::<u8>::new());
    /// let reference = buff.get_ref();
    /// ```
    pub const fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Gets a mutable reference to the underlying value in this cursor.
    ///
    /// Care should be taken to avoid modifying the internal I/O state of the
    /// underlying value as it may corrupt this cursor's position.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_cursor::Cursor;
    ///
    /// let mut buff = Cursor::new(Vec::<u8>::new());
    /// let reference = buff.get_mut();
    /// ```
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Returns the current position of this cursor.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io::{Seek, SeekFrom};
    /// use embedded_io_cursor::Cursor;
    ///
    /// let mut buff = Cursor::new(&[1u8, 2, 3, 4, 5][..]);
    /// assert_eq!(buff.position(), 0);
    ///
    /// buff.seek(SeekFrom::Current(2)).unwrap();
    /// assert_eq!(buff.position(), 2);
    ///
    /// buff.seek(SeekFrom::Current(-1)).unwrap();
    /// assert_eq!(buff.position(), 1);
    /// ```
    pub const fn position(&self) -> u64 {
        self.pos
    }

    /// Sets the position of this cursor.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_cursor::Cursor;
    ///
    /// let mut buff = Cursor::new(&[1u8, 2, 3, 4, 5][..]);
    /// assert_eq!(buff.position(), 0);
    ///
    /// buff.set_position(2);
    /// assert_eq!(buff.position(), 2);
    ///
    /// buff.set_position(4);
    /// assert_eq!(buff.position(), 4);
    /// ```
    pub fn set_position(&mut self, pos: u64) {
        self.pos = pos;
    }
}

impl<T> Cursor<T>
where
    T: AsRef<[u8]>,
{
    /// Returns the remaining slice from the current position.
    ///
    /// This method returns the portion of the underlying buffer that
    /// can still be read from the current cursor position.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_cursor::Cursor;
    ///
    /// let mut cursor = Cursor::new(&[1u8, 2, 3, 4, 5][..]);
    /// assert_eq!(cursor.remaining_slice(), &[1, 2, 3, 4, 5]);
    ///
    /// cursor.set_position(2);
    /// assert_eq!(cursor.remaining_slice(), &[3, 4, 5]);
    ///
    /// cursor.set_position(10);
    /// assert_eq!(cursor.remaining_slice(), &[]);
    /// ```
    pub fn remaining_slice(&self) -> &[u8] {
        let pos = cmp::min(self.pos, self.inner.as_ref().len() as u64) as usize;
        &self.inner.as_ref()[pos..]
    }

    /// Returns `true` if there are no more bytes to read from the cursor.
    ///
    /// This is equivalent to checking if `remaining_slice().is_empty()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use embedded_io_cursor::Cursor;
    ///
    /// let mut cursor = Cursor::new(&[1u8, 2, 3][..]);
    /// assert!(!cursor.is_empty());
    ///
    /// cursor.set_position(3);
    /// assert!(cursor.is_empty());
    ///
    /// cursor.set_position(10);
    /// assert!(cursor.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.pos >= self.inner.as_ref().len() as u64
    }
}

impl<T> Clone for Cursor<T>
where
    T: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Cursor {
            inner: self.inner.clone(),
            pos: self.pos,
        }
    }

    #[inline]
    fn clone_from(&mut self, other: &Self) {
        self.inner.clone_from(&other.inner);
        self.pos = other.pos;
    }
}

impl<T> ErrorType for Cursor<T> {
    type Error = ErrorKind;
}

// Read implementation for AsRef<[u8]> types
impl<T> Read for Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let remaining = self.remaining_slice();
        let n = cmp::min(buf.len(), remaining.len());

        if n > 0 {
            buf[..n].copy_from_slice(&remaining[..n]);
        }

        self.pos += n as u64;
        Ok(n)
    }
}

// BufRead implementation for AsRef<[u8]> types
impl<T> BufRead for Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn fill_buf(&mut self) -> Result<&[u8], Self::Error> {
        Ok(self.remaining_slice())
    }

    fn consume(&mut self, amt: usize) {
        self.pos += amt as u64;
    }
}

// Seek implementation for AsRef<[u8]> types
impl<T> Seek for Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn seek(&mut self, style: SeekFrom) -> Result<u64, Self::Error> {
        let (base_pos, offset) = match style {
            SeekFrom::Start(n) => {
                self.pos = n;
                return Ok(n);
            }
            SeekFrom::End(n) => (self.inner.as_ref().len() as u64, n),
            SeekFrom::Current(n) => (self.pos, n),
        };

        match base_pos.checked_add_signed(offset) {
            Some(n) => {
                self.pos = n;
                Ok(self.pos)
            }
            None => Err(ErrorKind::InvalidInput),
        }
    }
}

/// Helper function for writing to fixed-size slices
fn slice_write(pos_mut: &mut u64, slice: &mut [u8], buf: &[u8]) -> Result<usize, ErrorKind> {
    let pos = cmp::min(*pos_mut, slice.len() as u64) as usize;
    let amt = (&mut slice[pos..]).write(buf).map_err(|err| err.kind())?;
    *pos_mut += amt as u64;
    Ok(amt)
}

/// Helper function for writing to resizable vectors
#[cfg(feature = "alloc")]
fn vec_write(pos_mut: &mut u64, vec: &mut Vec<u8>, buf: &[u8]) -> usize {
    let pos = *pos_mut as usize;
    let end_pos = pos + buf.len();

    // Ensure the vector is large enough
    if end_pos > vec.len() {
        vec.resize(end_pos, 0);
    }

    vec[pos..end_pos].copy_from_slice(buf);
    *pos_mut += buf.len() as u64;
    buf.len()
}

// Write implementation for &mut [u8]
impl Write for Cursor<&mut [u8]> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        slice_write(&mut self.pos, self.inner, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Write implementation for arrays
impl<const N: usize> Write for Cursor<&mut [u8; N]> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        slice_write(&mut self.pos, &mut self.inner[..], buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Write implementation for owned arrays
impl<const N: usize> Write for Cursor<[u8; N]> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        slice_write(&mut self.pos, &mut self.inner[..], buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// Alloc-specific implementations
#[cfg(feature = "alloc")]
impl Write for Cursor<&mut Vec<u8>> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(vec_write(&mut self.pos, self.inner, buf))
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl Write for Cursor<Vec<u8>> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(vec_write(&mut self.pos, &mut self.inner, buf))
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl Write for Cursor<Box<[u8]>> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        slice_write(&mut self.pos, &mut self.inner, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}