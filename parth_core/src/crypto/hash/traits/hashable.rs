
pub trait QHasher<Hash: Sized>: Sized {
    fn q_hash<T: QHashable<Hash, Self>>(target: &T) -> Hash;
}

pub trait QHashable<Hash: Sized, QH: QHasher<Hash>> {
    fn get_q_hash(&self) -> Hash;
}
