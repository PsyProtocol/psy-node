use async_trait::async_trait;
use scylla::client::session::Session;



pub trait ZeroableHash: Sized + Copy + Clone {
    fn get_zero_value() -> Self;
}

pub trait MerkleHasher<Hash: PartialEq> {
    fn two_to_one(left: &Hash, right: &Hash) -> Hash;
    fn two_to_one_swap(swap: bool, left: &Hash, right: &Hash) -> Hash {
        if swap {
            Self::two_to_one(right, left)
        }else{
            Self::two_to_one(left, right)
        }
    }
}

/*
The zero cache trait is implemented for several different hash types where:
get_zero_hash(0) -> Hash::get_zero_value()
get_zero_hash(n) -> Hasher::two_to_one(&get_zero_hash(n-1), &get_zero_hash(n-1))

This is useful for large sparse merkle trees where we want to avoid storing sub-trees with completely empty leaves. 
*/
pub trait MerkleZeroHasher<Hash: PartialEq>: MerkleHasher<Hash> {
    fn get_zero_hash(reverse_level: usize) -> Hash;
}

// used for serializing/deserializing objects to/from scylla
pub trait ScyllaSerializable: Sized {
    fn to_db_bytes(&self) -> Vec<u8>;
    fn from_db_bytes(bytes: &[u8]) -> anyhow::Result<Self>;

}

pub trait ScyllaSerializableHash: ScyllaSerializable {
    fn to_db_bytes_fixed(&self) -> [u8; 32];
    fn to_db_bytes_ref(&self) -> &[u8];
}
pub trait QHashBase: ScyllaSerializableHash + ZeroableHash + Sized + Copy + Clone + PartialEq + Send + Sync {
}

#[async_trait]
pub trait ScyllaStandardPreparedTableStatements: Sized {
    async fn create_table_standard(session: &Session, keyspace: &str, table_name: &str) -> anyhow::Result<Self>;
}
