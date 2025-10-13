
pub trait BasicDataHasher<Data, Hash: PartialEq> {
    fn hash_data(data: Data) -> Hash;
}

pub trait BasicBytesHasher<Hash: PartialEq> {
    fn hash_bytes(data: &[u8]) -> Hash;
}
