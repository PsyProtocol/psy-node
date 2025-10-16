// This is the master switch. It enables `no_std` only when the "std" feature is OFF.
#![cfg_attr(not(feature = "std"), no_std)]

// ============================================================================
// 0. Conditional Imports and Type Aliases
// ============================================================================

// --- `alloc` is only needed for `no_std` builds that need heap allocation. ---
#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::{self, Vec};

// --- In `std` builds, `Vec` is in the prelude or `std::vec`. ---
#[cfg(feature = "std")]
use std::vec::Vec;


// --- Universal imports that work in both modes. ---
use core::mem;
use anyhow::{bail, Context};

// --- Conditionally select the I/O traits and Cursor. ---
#[cfg(feature = "std")]
pub mod io {
    // In std mode, our I/O traits are just aliases for std::io's traits.
    pub use std::io::{Read, Write, Cursor};
}

#[cfg(not(feature = "std"))]
pub mod io {
    // In no_std mode, we use the `embedded-io` traits.
    pub use embedded_io::{Read, Write};

    // We also provide our own no_std-compatible Cursor implementation.
    pub struct Cursor<'a> {
        slice: &'a [u8],
        pos: usize,
    }
    impl<'a> Cursor<'a> {
        pub fn new(slice: &'a [u8]) -> Self { Self { slice, pos: 0 } }
        pub fn position(&self) -> usize { self.pos }
    }
    impl<'a> embedded_io::ErrorType for Cursor<'a> {
        type Error = core::convert::Infallible;
    }
    impl<'a> Read for Cursor<'a> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let bytes_to_read = core::cmp::min(buf.len(), self.slice.len() - self.pos);
            let end = self.pos + bytes_to_read;
            buf[..bytes_to_read].copy_from_slice(&self.slice[self.pos..end]);
            self.pos = end;
            Ok(bytes_to_read)
        }
    }
}

// By aliasing here, the rest of the code can just use `Read` and `Write`
// without caring where they came from.
use io::{Read, Write, Cursor};


// Our result type is universal thanks to anyhow.
pub type SerResult<T> = anyhow::Result<T>;

// ============================================================================
// 1. Varint Helpers (Unaffected by std/no_std)
// ============================================================================

#[inline(always)]
fn write_varint<W: Write>(mut n: usize, writer: &mut W) -> SerResult<()> {
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
fn read_varint<R: Read>(reader: &mut R) -> SerResult<usize> {
    let mut result = 0usize;
    let mut shift = 0;
    let mut buf = [0u8; 1];
    loop {
        if shift >= usize::BITS {
            bail!("Varint overflow: larger than supported usize");
        }
        reader.read_exact(&mut buf).context("Failed to read varint byte from stream")?;
        let byte = buf[0];
        result |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 { return Ok(result); }
        shift += 7;
    }
}

#[inline(always)]
const fn varint_size(n: usize) -> usize {
    if n == 0 { return 1; }
    let bits = usize::BITS - n.leading_zeros();
    (bits as usize + 6) / 7
}

// ============================================================================
// 2. The Main Trait (Now generic over the selected I/O traits)
// ============================================================================

pub trait PsyCanonicalSer: Sized {
    fn psyser_serialize<W: Write>(&self, writer: &mut W) -> SerResult<()>;
    fn psyser_deserialize<R: Read>(reader: &mut R) -> SerResult<Self>;
    fn psyser_serialized_size(&self) -> usize;
    const FIXED_SERIALIZED_SIZE: Option<usize> = None;

    #[inline]
    fn psyser_to_vec(&self) -> SerResult<Vec<u8>> {
        let mut vec = Vec::with_capacity(self.psyser_serialized_size());
        // In std mode, Vec implements Write. In no_std, we depend on a crate
        // or a feature of embedded-io to do this. For simplicity here, we assume
        // a `Write` impl for `Vec` is available. `embedded-io` provides this
        // behind its "alloc" feature.
        self.psyser_serialize(&mut vec)?;
        Ok(vec)
    }

    #[inline]
    fn psyser_from_bytes(bytes: &[u8]) -> SerResult<Self> {
        let mut cursor = Cursor::new(bytes);
        Self::psyser_deserialize(&mut cursor)
    }
}

// ============================================================================
// 3. Primitives Implementation (Unaffected by std/no_std)
// ============================================================================

macro_rules! impl_primitive {
    ($($t:ty),*) => {
        $(
            impl PsyCanonicalSer for $t {
                #[inline(always)]
                fn psyser_serialize<W: Write>(&self, writer: &mut W) -> SerResult<()> {
                    writer.write_all(&self.to_le_bytes())
                        .with_context(|| format!("Failed to serialize primitive <{}>", stringify!($t)))
                }

                #[inline(always)]
                fn psyser_deserialize<R: Read>(reader: &mut R) -> SerResult<Self> {
                    let mut buf = [0u8; mem::size_of::<Self>()];
                    reader.read_exact(&mut buf)
                        .with_context(|| format!("Failed to deserialize primitive <{}>", stringify!($t)))?;
                    Ok(Self::from_le_bytes(buf))
                }

                #[inline(always)]
                fn psyser_serialized_size(&self) -> usize { mem::size_of::<Self>() }
                const FIXED_SERIALIZED_SIZE: Option<usize> = Some(mem::size_of::<Self>());
            }
        )*
    };
}
impl_primitive!(u8, u16, u32, u64, i8, i16, i32, i64, f32, f64);
impl PsyCanonicalSer for bool {
    #[inline(always)]
    fn psyser_serialize<W: Write>(&self, writer: &mut W) -> SerResult<()> {
        writer.write_all(&[*self as u8]).context("Failed to serialize bool")
    }
    #[inline(always)]
    fn psyser_deserialize<R: Read>(reader: &mut R) -> SerResult<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).context("Failed to deserialize bool")?;
        Ok(buf[0] != 0)
    }
    fn psyser_serialized_size(&self) -> usize { 1 }
    const FIXED_SERIALIZED_SIZE: Option<usize> = Some(1);
}


// ============================================================================
// 5. Collection Implementations (Unaffected by std/no_std)
// ============================================================================

impl<T: PsyCanonicalSer> PsyCanonicalSer for Vec<T> {
    fn psyser_serialize<W: Write>(&self, writer: &mut W) -> SerResult<()> {
        write_varint(self.len(), writer)?;
        for item in self {
            item.psyser_serialize(writer)?;
        }
        Ok(())
    }

    fn psyser_deserialize<R: Read>(reader: &mut R) -> SerResult<Self> {
        let len = read_varint(reader)?;
        const MAX_VEC_LEN: usize = 1024 * 1024 * 64; // 64 MiB
        if len > MAX_VEC_LEN {
            bail!("Vec length ({}) exceeds max limit ({})", len, MAX_VEC_LEN);
        }
        let mut vec = Vec::new();
        if T::FIXED_SERIALIZED_SIZE.is_some() {
            vec.reserve_exact(len);
        } else {
            vec.reserve(len.min(4096));
        }
        for i in 0..len {
            vec.push(
                T::psyser_deserialize(reader)
                    .with_context(|| format!("Failed to deserialize item {} in Vec", i))?
            );
        }
        Ok(vec)
    }

    #[inline]
    fn psyser_serialized_size(&self) -> usize {
        let len = self.len();
        let header_size = varint_size(len);
        if let Some(item_fixed_size) = T::FIXED_SERIALIZED_SIZE {
            header_size + (len * item_fixed_size)
        } else {
            self.iter().fold(header_size, |acc, item| acc + item.psyser_serialized_size())
        }
    }
}


pub struct PsyByteBuf(pub Vec<u8>);

impl PsyCanonicalSer for PsyByteBuf {
    fn psyser_serialize<W: Write>(&self, writer: &mut W) -> SerResult<()> {
        write_varint(self.0.len(), writer)?;
        writer.write_all(&self.0).context("Failed to write byte buffer contents")
    }

    fn psyser_deserialize<R: Read>(reader: &mut R) -> SerResult<Self> {
        let len = read_varint(reader)?;
        let mut vec = vec![0u8; len];
        reader.read_exact(&mut vec).context("Failed to read byte buffer contents")?;
        Ok(PsyByteBuf(vec))
    }

    fn psyser_serialized_size(&self) -> usize {
        varint_size(self.0.len()) + self.0.len()
    }
}