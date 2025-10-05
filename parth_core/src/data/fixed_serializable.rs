
pub trait QPDFixedSizeSerializable<const N: usize>: Sized + Send + Sync + Clone + PartialEq {
    fn to_fixed_size_bytes(&self) -> [u8; N];
    fn from_fixed_size_bytes(bytes: &[u8]) -> anyhow::Result<Self>;
    fn write_at_position(&self, buffer: &mut [u8], position: usize) -> anyhow::Result<()> {
        if buffer.len() < position + N {
            anyhow::bail!("Buffer too small to write key at position: buffer size {}, position {}, key size {}", buffer.len(), position, N);
        }
        let key_bytes = self.to_fixed_size_bytes();
        buffer[position..position + N].copy_from_slice(&key_bytes);
        Ok(())
    }
}
impl<const N: usize> QPDFixedSizeSerializable<N> for [u8; N] {
    fn to_fixed_size_bytes(&self) -> [u8; N] {
        *self
    }
    fn from_fixed_size_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != N {
            anyhow::bail!("invalid size, expected {} bytes, got {}", N, bytes.len());
        }

        let mut inner_data = [0u8; N];
        inner_data.copy_from_slice(bytes);
        Ok(inner_data)
    }
}
impl QPDFixedSizeSerializable<8> for u64 {
    fn to_fixed_size_bytes(&self) -> [u8; 8] {
        self.to_le_bytes()
    }
    fn from_fixed_size_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 8 {
            anyhow::bail!("invalid size, expected 8 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[0..8]);
        Ok(u64::from_le_bytes(arr))
    }
}


impl QPDFixedSizeSerializable<2> for u16 {
    fn to_fixed_size_bytes(&self) -> [u8; 2] {
        self.to_le_bytes()
    }
    fn from_fixed_size_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 2 {
            anyhow::bail!("invalid size, expected 2 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 2];
        arr.copy_from_slice(&bytes[0..2]);
        Ok(u16::from_le_bytes(arr))
    }
}

impl QPDFixedSizeSerializable<4> for u32 {
    fn to_fixed_size_bytes(&self) -> [u8; 4] {
        self.to_le_bytes()
    }
    fn from_fixed_size_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 4 {
            anyhow::bail!("invalid size, expected 4 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&bytes[0..4]);
        Ok(u32::from_le_bytes(arr))
    }
}
impl QPDFixedSizeSerializable<16> for u128 {
    fn to_fixed_size_bytes(&self) -> [u8; 16] {
        self.to_le_bytes()
    }
    fn from_fixed_size_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 16 {
            anyhow::bail!("invalid size, expected 16 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes[0..16]);
        Ok(u128::from_le_bytes(arr))
    }
}
