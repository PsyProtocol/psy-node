pub trait FastFixedSerializable<const N: usize>: Sized {
    fn ffs_from_owned_bytes(data: [u8; N]) -> Self;
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self;
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn ffs_to_bytes(&self) -> [u8; N];
    fn ffs_into_bytes(self) -> [u8; N];

    #[inline]
    fn write_ffs_serialize_vec_of_self(data: &[Self], bytes: &mut Vec<u8>) {
        for item in data {
            bytes.extend_from_slice(&item.ffs_to_bytes());
        }
    }

    #[inline]
    fn ffs_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * N);
        for item in data {
            bytes.extend_from_slice(&item.ffs_to_bytes());
        }
        bytes
    }

    #[inline]
    fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * N);
        for item in data {
            bytes.extend_from_slice(&item.ffs_to_bytes());
        }
        bytes
    }

    #[inline]
    fn ffs_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
        if data.len() % N != 0 {
            anyhow::bail!("Data length {} is not a multiple of object size {}", data.len(), N);
        }

        // Use chunks_exact to iterate over the byte slice in N-sized chunks.
        // This is highly optimized by the compiler (often using SIMD).
        Ok(data
            .chunks_exact(N)
            .map(|chunk| {
                // For each chunk, call the single-item deserializer.
                // try_into().unwrap() is safe because chunks_exact guarantees length N.
                Self::ffs_from_owned_bytes(chunk.try_into().unwrap())
            })
            .collect())
    }

    #[inline]
    fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
        Self::ffs_deserialize_vec_of_self(&data)
    }
}
