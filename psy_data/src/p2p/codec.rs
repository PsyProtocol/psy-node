//! Strict `protocol_encode` helpers.
//!
//! Grammar (normative):
//! - integers are fixed-width little-endian
//! - `bool` is `0x00` / `0x01` only
//! - `[u8; N]` is raw bytes with no length prefix
//! - variable bytes are `u32_le(len) || bytes` with a caller-supplied max
//! - enum tags are one `u8`
//! - decoders reject trailing bytes, unknown tags, and non-canonical crypto encodings

use super::error::{ProtocolError, ProtocolResult};
use super::limits::NODE_ID_RAW_LEN;
use sha2::{Digest, Sha256};
use std::io::Cursor;

/// Goldilocks prime `2^64 - 2^32 + 1`.
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// Trait implemented by every Phase 1 wire object.
pub trait ProtocolEncode {
    /// Append the canonical protocol encoding of `self` to `out`.
    fn protocol_encode(&self, out: &mut Vec<u8>);

    /// Allocate and return the canonical protocol encoding.
    fn protocol_encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.protocol_encode(&mut out);
        out
    }
}

/// Strict sequential reader over protocol bytes.
#[derive(Debug)]
pub struct ProtocolReader<'a> {
    cursor: Cursor<&'a [u8]>,
}

impl<'a> ProtocolReader<'a> {
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(bytes),
        }
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        let pos = self.cursor.position() as usize;
        self.cursor.get_ref().len().saturating_sub(pos)
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.cursor.position() as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Reject any unread trailing bytes.
    pub fn finish(self) -> ProtocolResult<()> {
        let remaining = self.remaining();
        if remaining != 0 {
            return Err(ProtocolError::TrailingBytes { remaining });
        }
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8], context: &'static str) -> ProtocolResult<()> {
        use std::io::Read;
        self.cursor
            .read_exact(buf)
            .map_err(|_| ProtocolError::unexpected_eof(context))
    }

    #[inline]
    pub fn read_u8(&mut self) -> ProtocolResult<u8> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf, "u8")?;
        Ok(buf[0])
    }

    #[inline]
    pub fn read_u16(&mut self) -> ProtocolResult<u16> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf, "u16")?;
        Ok(u16::from_le_bytes(buf))
    }

    #[inline]
    pub fn read_u32(&mut self) -> ProtocolResult<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf, "u32")?;
        Ok(u32::from_le_bytes(buf))
    }

    #[inline]
    pub fn read_u64(&mut self) -> ProtocolResult<u64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf, "u64")?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Decode a protocol `bool` (`0x00` / `0x01` only).
    pub fn read_bool(&mut self) -> ProtocolResult<bool> {
        match self.read_u8()? {
            0x00 => Ok(false),
            0x01 => Ok(true),
            value => Err(ProtocolError::InvalidBool { value }),
        }
    }

    pub fn read_fixed<const N: usize>(&mut self) -> ProtocolResult<[u8; N]> {
        let mut buf = [0u8; N];
        self.read_exact(&mut buf, "fixed bytes")?;
        Ok(buf)
    }

    pub fn read_bytes_32(&mut self) -> ProtocolResult<[u8; 32]> {
        self.read_fixed::<32>()
    }

    /// Read `u32_le(len) || bytes` and reject `len > max`.
    pub fn read_bytes_u32(&mut self, what: &'static str, max: u32) -> ProtocolResult<Vec<u8>> {
        let len = self.read_u32()?;
        if len > max {
            return Err(ProtocolError::LengthLimit {
                what,
                got: len as u64,
                max: max as u64,
            });
        }
        let mut buf = vec![0u8; len as usize];
        self.read_exact(&mut buf, what)?;
        Ok(buf)
    }

    /// Read exactly `len` raw bytes (no length prefix).
    pub fn read_raw(&mut self, len: usize, what: &'static str) -> ProtocolResult<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf, what)?;
        Ok(buf)
    }

    /// Read a production hash encoded as four reduced Goldilocks limbs (32 bytes).
    pub fn read_hash32_canonical(&mut self) -> ProtocolResult<[u8; 32]> {
        let bytes = self.read_bytes_32()?;
        validate_hash32_canonical(&bytes)?;
        Ok(bytes)
    }
}

/// Append little-endian integers / fixed bytes.
#[inline]
pub fn write_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

#[inline]
pub fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[inline]
pub fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[inline]
pub fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[inline]
pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(if value { 0x01 } else { 0x00 });
}

#[inline]
pub fn write_fixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes);
}

/// Encode variable bytes as `u32_le(len) || bytes`.
pub fn write_bytes_u32(out: &mut Vec<u8>, bytes: &[u8]) -> ProtocolResult<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| ProtocolError::Overflow {
        context: "bytes_u32 length",
    })?;
    write_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Reject a Goldilocks limb that is not strictly reduced.
#[inline]
pub fn validate_goldilocks_limb(value: u64) -> ProtocolResult<()> {
    if value >= GOLDILOCKS_MODULUS {
        return Err(ProtocolError::NonCanonicalField { value });
    }
    Ok(())
}

/// Validate four LE u64 limbs of a 32-byte production hash.
pub fn validate_hash32_canonical(bytes: &[u8; 32]) -> ProtocolResult<()> {
    for i in 0..4 {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        validate_goldilocks_limb(u64::from_le_bytes(limb))?;
    }
    Ok(())
}

/// Interpret eight bytes as a little-endian `u64` and require a reduced Goldilocks limb.
pub fn field_from_le_bytes(bytes: &[u8; 8]) -> ProtocolResult<u64> {
    let value = u64::from_le_bytes(*bytes);
    validate_goldilocks_limb(value)?;
    Ok(value)
}

/// Split a 32-byte digest into four reduced Goldilocks limbs (rejecting non-field limbs).
pub fn digest_to_field_limbs(digest: &[u8; 32]) -> ProtocolResult<[u64; 4]> {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&digest[i * 8..(i + 1) * 8]);
        limbs[i] = field_from_le_bytes(&chunk)?;
    }
    Ok(limbs)
}

/// SHA-256 of arbitrary bytes.
#[inline]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Decode a value that occupies the entire buffer (no trailing bytes).
pub fn decode_exact<T, F>(bytes: &[u8], f: F) -> ProtocolResult<T>
where
    F: FnOnce(&mut ProtocolReader<'_>) -> ProtocolResult<T>,
{
    let mut reader = ProtocolReader::new(bytes);
    let value = f(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

/// Encode the fixed 38-byte NodeId raw value with its `u32_le(38)` length prefix.
pub fn encode_node_id_raw(out: &mut Vec<u8>, raw38: &[u8; NODE_ID_RAW_LEN]) {
    write_u32(out, NODE_ID_RAW_LEN as u32);
    out.extend_from_slice(raw38);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_roundtrip_and_reject() {
        let mut buf = Vec::new();
        write_bool(&mut buf, true);
        write_bool(&mut buf, false);
        let mut r = ProtocolReader::new(&buf);
        assert!(r.read_bool().unwrap());
        assert!(!r.read_bool().unwrap());
        r.finish().unwrap();

        let err = ProtocolReader::new(&[0x02]).read_bool().unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidBool { value: 0x02 }));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let err = decode_exact(&[1u8, 2u8], |r| {
            let _ = r.read_u8()?;
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, ProtocolError::TrailingBytes { remaining: 1 }));
    }

    #[test]
    fn bytes_u32_max_enforced() {
        let mut buf = Vec::new();
        write_bytes_u32(&mut buf, &[1, 2, 3]).unwrap();
        let mut r = ProtocolReader::new(&buf);
        assert_eq!(r.read_bytes_u32("data", 3).unwrap(), vec![1, 2, 3]);

        let mut r = ProtocolReader::new(&buf);
        let err = r.read_bytes_u32("data", 2).unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::LengthLimit {
                got: 3,
                max: 2,
                ..
            }
        ));
    }

    #[test]
    fn goldilocks_limb_reject() {
        assert!(validate_goldilocks_limb(GOLDILOCKS_MODULUS - 1).is_ok());
        assert!(validate_goldilocks_limb(GOLDILOCKS_MODULUS).is_err());
    }
}
