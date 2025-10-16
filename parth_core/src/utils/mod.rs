use rand::RngCore;

use crate::{crypto::hash::traits::RandomHash, data::hash::hash256::Hash256};

pub mod math;
pub mod auto_implement;
pub mod signed_helpers;

pub trait QPGenRandom {
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