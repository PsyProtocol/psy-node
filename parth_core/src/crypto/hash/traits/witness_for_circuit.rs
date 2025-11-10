use crate::crypto::hash::traits::FieldQHasher;

pub trait PCircuitWitness<F, Hash> {
    fn get_expected_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash;
}
