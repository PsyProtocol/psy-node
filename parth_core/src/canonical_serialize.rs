use std::io::{self, Read, Write, Cursor};
use std::mem;


// ============================================================================
// 1. Varint Helpers (Performance Critical)
// ============================================================================

/// Minimal efficient Varint (LEB128ish) writing for usize.
/// Used for Vec lengths.
#[inline(always)]
fn write_varint<W: Write>(mut n: usize, writer: &mut W) -> io::Result<()> {
    // Optimize for small lengths common in networking
    if n < 128 {
        return writer.write_all(&[n as u8]);
    }

    let mut buf = [0u8; 10]; // Max usize (u64) takes 10 bytes
    let mut i = 0;
    loop {
        let mut byte = (n as u8) & 0x7F;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        buf[i] = byte;
        i += 1;
        if n == 0 {
            break;
        }
    }
    writer.write_all(&buf[..i])
}

#[inline(always)]
fn read_varint<R: Read>(reader: &mut R) -> io::Result<usize> {
    let mut result = 0usize;
    let mut shift = 0;
    let mut buf = [0u8; 1];

    loop {
        if shift >= usize::BITS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Varint overflow"));
        }
        reader.read_exact(&mut buf)?;
        let byte = buf[0];
        result |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

/// Returns number of bytes required to serialize len as varint
#[inline(always)]
const fn varint_size(n: usize) -> usize {
    if n == 0 { return 1; }
    // Fast log2 approximation logic for varint size
    let bits = (usize::BITS as usize) - n.leading_zeros() as usize;
    (bits + 6) / 7
}

// ============================================================================
// 2. The Main Trait
// ============================================================================

/// The unique, canonical serialization trait.
/// Implementors must implement 3 things: serialize, deserialize, and size_hint.
pub trait PsyCanonicalSer: Sized {
    /// Write canonical format to a generic writer.
    fn psyser_serialize<W: Write>(&self, writer: &mut W) -> io::Result<()>;

    /// Read canonical format from a generic reader.
    fn psyser_deserialize<R: Read>(reader: &mut R) -> io::Result<Self>;

    /// Returns the exact number of bytes this instance will write.
    /// Crucial for pre-allocating buffers to avoid re-allocations.
    fn psyser_serialized_size(&self) -> usize;

    /// Compile-time hint: If Some(N), every instance of this type is exactly N bytes.
    /// Enables O(1) size calculation for containers (Vec).
    const FIXED_SERIALIZED_SIZE: Option<usize> = None;

    // ------------------------------------------------------------------------
    // Convenience methods (Default implementations provided using std::io::Cursor)
    // DO NOT override these unless you have a specific optimization reason.
    // ------------------------------------------------------------------------

    #[inline]
    fn psyser_to_vec(&self) -> io::Result<Vec<u8>> {
        // Pre-allocate exact size for performance
        let mut vec = Vec::with_capacity(self.psyser_serialized_size());
        self.psyser_serialize(&mut vec)?;
        Ok(vec)
    }

    #[inline]
    fn psyser_to_writer<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.psyser_serialize(writer)
    }

    #[inline]
    fn psyser_write_to_slice(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut cursor = Cursor::new(buffer);
        self.psyser_serialize(&mut cursor)?;
        Ok(cursor.position() as usize)
    }

    #[inline]
    fn psyser_from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let res = Self::psyser_deserialize(&mut cursor)?;
        // Optional: Check if all bytes were consumed if strictness is required
        // if cursor.position() as usize != bytes.len() { return Err(...) }
        Ok(res)
    }

    /// Reads from slice, returns (Self, bytes_consumed)
    #[inline]
    fn psyser_read_from_slice(bytes: &[u8]) -> io::Result<(Self, usize)> {
        let mut cursor = Cursor::new(bytes);
        let obj = Self::psyser_deserialize(&mut cursor)?;
        Ok((obj, cursor.position() as usize))
    }
}

// ============================================================================
// 3. Basic Primitives Implementation (Endianness definition)
// ============================================================================

// Example: Defines canonical format as Little Endian for primitives.
macro_rules! impl_primitive {
    ($($t:ty),*) => {
        $(
            impl PsyCanonicalSer for $t {
                #[inline(always)]
                fn psyser_serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
                    writer.write_all(&self.to_le_bytes())
                }

                #[inline(always)]
                fn psyser_deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
                    let mut buf = [0u8; mem::size_of::<Self>()];
                    reader.read_exact(&mut buf)?;
                    Ok(Self::from_le_bytes(buf))
                }

                #[inline(always)]
                fn psyser_serialized_size(&self) -> usize {
                    mem::size_of::<Self>()
                }

                const FIXED_SERIALIZED_SIZE: Option<usize> = Some(mem::size_of::<Self>());
            }
        )*
    };
}

impl_primitive!(u8, u16, u32, u64, i8, i16, i32, i64, f32, f64);
// bool is often treated as u8
impl PsyCanonicalSer for bool {
    #[inline(always)]
    fn psyser_serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[*self as u8])
    }
    #[inline(always)]
    fn psyser_deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0] != 0)
    }
    fn psyser_serialized_size(&self) -> usize { 1 }
    const FIXED_SERIALIZED_SIZE: Option<usize> = Some(1);
}


// ============================================================================
// 5. Efficient Vec<T> Implementation
// ============================================================================

impl<T: PsyCanonicalSer> PsyCanonicalSer for Vec<T> {
    fn psyser_serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        // 1. Write Length (Varint)
        write_varint(self.len(), writer)?;

        // 2. Write items
        // Note: If T is u8, LLVM optimizes this loop into a memcpy automatically
        // when writer is a generic buffer.
        for item in self {
            item.psyser_serialize(writer)?;
        }
        Ok(())
    }

    fn psyser_deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        // 1. Read Length
        let len = read_varint(reader)?;

        // Security: Put a hard cap on allocation based on use case to prevent OOM attacks.
        // e.g., if max message size is 64MB, len cannot exceed that.
        const MAX_VEC_LEN: usize = 1024 * 1024 * 64; // Example limit
        if len > MAX_VEC_LEN {
             return Err(io::Error::new(io::ErrorKind::InvalidData, "Vec len exceeds max limit"));
        }

        // 2. Allocate efficiently
        let mut vec = Vec::new();

        if let Some(_fixed_size) = T::FIXED_SERIALIZED_SIZE {
            // If items are fixed size, we know exactly how many we need.
            // Rust's Vec handles zero-sized types (ZSTs) correctly here too.
            vec.reserve_exact(len);
        } else {
            // Variable sized items. Reserve hesitantly to prevent malicious
            // input saying "len = 10Billion" followed by 1 byte of data.
            vec.reserve(len.min(4096));
        }

        // 3. Read items
        for _ in 0..len {
            vec.push(T::psyser_deserialize(reader)?);
        }

        Ok(vec)
    }

    #[inline]
    fn psyser_serialized_size(&self) -> usize {
        let len = self.len();
        let header_size = varint_size(len);

        // OPTIMIZATION: Check compile-time constant
        if let Some(item_fixed_size) = T::FIXED_SERIALIZED_SIZE {
            // O(1) calculation
            header_size + (len * item_fixed_size)
        } else {
            // O(N) calculation for variable sized items
            self.iter()
                .fold(header_size, |acc, item| acc + item.psyser_serialized_size())
        }
    }

    // A Vec itself implies variable total size.
    const FIXED_SERIALIZED_SIZE: Option<usize> = None;
}

// Optimized specialization for Byte Arrays (Vec<u8>)
// NOTE: In stable Rust, we can't have impl<T> for Vec<T> AND impl for Vec<u8>.
// The generic impl above relies on LLVM optimizing the loop for u8.
// Alternatively, wrap Vec<u8> in a newtype `pub struct ByteBuf(pub Vec<u8>);`
// and implement specific bulk I/O for ByteBuf.

/// Wrapper for raw byte buffers to ensure bulk I/O performance.
pub struct PsyByteBuf(pub Vec<u8>);

impl PsyCanonicalSer for PsyByteBuf {
    fn psyser_serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        write_varint(self.0.len(), writer)?;
        writer.write_all(&self.0) // Uses efficient memcpy
    }

    fn psyser_deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let len = read_varint(reader)?;
        // Add sanity limits here
        let mut vec = vec![0u8; len]; // Allocate and zero
        reader.read_exact(&mut vec)?; // Bulk read
        Ok(PsyByteBuf(vec))
    }

    fn psyser_serialized_size(&self) -> usize {
        varint_size(self.0.len()) + self.0.len()
    }
}