use crate::crypto::hash::traits::{MerkleHasher, MerkleZeroHasher};


pub trait FieldQHasher<F, Hash>: Sized + MerkleHasher<Hash> + MerkleZeroHasher<Hash> {
    fn q_hash_many(elements: &[F]) -> Hash;
    fn q_hash_many_pad(elements: &[F]) -> Hash;
    fn q_two_to_one(left: Hash, right: Hash) -> Hash;
    fn q_two_to_one_ref(left: &Hash, right: &Hash) -> Hash;
}


pub trait QFieldHashable<F, Hash>: Sized {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash;
}

pub trait HashTo4Felts<F: Copy>: Sized {
    fn to_4_felts(&self) -> [F; 4];
    fn from_4_felts(felts: [F; 4]) -> Self;
    fn from_4_felts_slice(felts: &[F]) -> Self{
        if felts.len() != 4 {
            panic!("from_4_felts_slice called with a slice that is not length 4");
        }
        Self::from_4_felts([felts[0], felts[1], felts[2], felts[3]])
    }
    fn from_felts(f0: F, f1: F, f2: F, f3: F) -> Self {
        Self::from_4_felts([f0, f1, f2, f3])
    }
}