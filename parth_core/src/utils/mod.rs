use rand::{Rng, RngCore};

use crate::{crypto::hash::traits::RandomHash, data::hash::hash256::Hash256};
pub mod debug_code_string;
pub mod math;
pub mod auto_implement;
pub mod signed_helpers;

pub fn qp_random_bytes_vec_insecure(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}
pub fn qp_random_bytes_vec_in_range_insecure(min_len: usize, max_len: usize) -> Vec<u8> {
    let len = rand::thread_rng().gen_range(min_len..=max_len);
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}
pub trait QPGenRandom {
    fn qp_rand_gen_vec(len: usize) -> Vec<Self> where Self: Sized {
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(Self::qp_rand_gen());
        }
        vec
    }
    fn qp_rand_gen() -> Self where Self: Sized;

}

impl QPGenRandom for u8 {
    fn qp_rand_gen() -> Self where Self: Sized {
        rand::random::<u8>()
    }
}

impl QPGenRandom for u16 {
    fn qp_rand_gen() -> Self where Self: Sized {
        rand::random::<u16>()
    }
}
impl QPGenRandom for u32 {
    fn qp_rand_gen() -> Self where Self: Sized {
        rand::random::<u32>()
    }
}

impl QPGenRandom for Hash256 {
    fn qp_rand_gen() -> Self where Self: Sized {
        Hash256::rand_hash()
    }
}


impl<const N: usize> QPGenRandom for [u8; N] {
    fn qp_rand_gen() -> Self where Self: Sized {
        let mut bytes = [0u8; N];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }
}