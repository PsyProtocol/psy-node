use crate::PsyCanonicalSerializeMetadata;


pub trait PsyCanonicalDatabaseSerializeFixedBase<const SIZE: usize>: Sized + PsyCanonicalSerializeMetadata {
    fn psydbser_fixed_to_bytes(&self) -> [u8; SIZE];
    fn psydbser_fixed_into_bytes(self) -> [u8; SIZE];
    fn psydbser_fixed_from_bytes_ref(bytes: &[u8; SIZE]) -> anyhow::Result<Self>;
    fn psydbser_fixed_from_owned_bytes(bytes: [u8; SIZE]) -> anyhow::Result<Self>;
    fn psydbser_fixed_many_from_bytes_ref(bytes: &[u8]) -> anyhow::Result<Vec<Self>>;
    fn psydbser_fixed_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * SIZE);
        for item in data {
            bytes.extend_from_slice(&item.psydbser_fixed_to_bytes());
        }
        bytes
    }
    fn psydbser_fixed_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * SIZE);
        for item in data {
            bytes.extend_from_slice(&item.psydbser_fixed_into_bytes());
        }
        bytes
    }
    fn psydbser_fixed_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
        if data.len() % SIZE != 0 {
            anyhow::bail!("Data length {} is not a multiple of object size {}", data.len(), SIZE);
        }

        // Use chunks_exact to iterate over the byte slice in SIZE-sized chunks.
        // This is highly optimized by the compiler (often using SIMD).
        data.chunks_exact(SIZE)
            .map(|chunk| {
                // For each chunk, call the single-item deserializer.
                // try_into().unwrap() is safe because chunks_exact guarantees length N.
                Self::psydbser_fixed_from_owned_bytes(chunk.try_into().unwrap())
            })
            .collect::<anyhow::Result<Vec<Self>>>()
    }
    fn psydbser_fixed_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
        Self::psydbser_fixed_deserialize_vec_of_self(&data)
    }
}
