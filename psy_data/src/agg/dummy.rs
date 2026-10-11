use parth_core::{crypto::hash::traits::{FieldQHasher, PCircuitWitness}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}};
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};


#[pderive::serialize_copy_hash]
pub struct DummyAggStateTransition<Hash> {
    pub unmodified_state_tree_root: Hash,
    pub allowed_circuit_hashes_root: Hash,
    pub is_deploy_contracts: bool,
    pub is_register_users: bool,
}

#[pderive::serialize_copy_hash]
pub struct DummyAggStateTransitionWithEvents<Hash> {
    pub unmodified_state_tree_root: Hash,
    pub event_transition_hash: Hash,
    pub allowed_circuit_hashes_root: Hash,
}



#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for DummyAggStateTransition<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            unmodified_state_tree_root: Hash::qp_rand_gen(),
            allowed_circuit_hashes_root: Hash::qp_rand_gen(),
            is_deploy_contracts: rand::random(),
            is_register_users: rand::random(),
        }
    }
}



impl<F: QFelt64, Hash: QFHashBase<F>> PCircuitWitness<F, Hash> for DummyAggStateTransition<Hash> {
    fn get_expected_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let allowed_and_state_transition_hash = Hasher::two_to_one(
            &self.allowed_circuit_hashes_root,
            &Hasher::two_to_one(&self.unmodified_state_tree_root, &self.unmodified_state_tree_root),
        ).to_4_felts();

        Hasher::q_hash_many(&[
            allowed_and_state_transition_hash[0],
            allowed_and_state_transition_hash[1],
            allowed_and_state_transition_hash[2],
            allowed_and_state_transition_hash[3],
            F::from_u8_value(1),
        ])
    }
}



impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for DummyAggStateTransition<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32*2 + 2;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for DummyAggStateTransition<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32*2 + 2

    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.unmodified_state_tree_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.allowed_circuit_hashes_root.into_owned_32bytes())?;
        writer.psy_write_u8(self.is_deploy_contracts as u8)?;
        writer.psy_write_u8(self.is_register_users as u8)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let unmodified_state_tree_root_bytes = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let allowed_circuit_hashes_root_bytes = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed()?);
        let is_deploy_contracts = reader.psy_read_u8()? != 0;
        let is_register_users = reader.psy_read_u8()? != 0;
        Ok(Self {
            unmodified_state_tree_root: unmodified_state_tree_root_bytes,
            allowed_circuit_hashes_root: allowed_circuit_hashes_root_bytes,
            is_deploy_contracts,
            is_register_users,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    DummyAggStateTransition,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for DummyAggStateTransition<Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    DummyAggStateTransition,
    // Note the use of concrete types here
    {  parth_core::PHash },
    dummy_agg_state_transition_basic_ser_tests
);

#[cfg(test)]
mod behavior_tests {
    use parth_core::crypto::hash::traits::{HashTo4Felts, MerkleHasher};
    use parth_core::felt::FromPrimitiveValuesFelt;
    use parth_core::pgoldilocks::{PoseidonHasher, QHashOut};
    use parth_core::PF;

    use super::*;

    type Hash = QHashOut<PF>;

    fn hash(value: u64) -> Hash {
        Hash::from_values(value, 0, 0, 0)
    }

    fn witness(unmodified: u64, allowed: u64) -> DummyAggStateTransition<Hash> {
        DummyAggStateTransition {
            unmodified_state_tree_root: hash(unmodified),
            allowed_circuit_hashes_root: hash(allowed),
            is_deploy_contracts: false,
            is_register_users: false,
        }
    }

    fn expected_public_inputs_hash(unmodified_state_tree_root: Hash, allowed_circuit_hashes_root: Hash) -> Hash {
        let allowed_and_state_transition_hash = PoseidonHasher::two_to_one(
            &allowed_circuit_hashes_root,
            &PoseidonHasher::two_to_one(&unmodified_state_tree_root, &unmodified_state_tree_root),
        )
        .to_4_felts();

        PoseidonHasher::q_hash_many(&[
            allowed_and_state_transition_hash[0],
            allowed_and_state_transition_hash[1],
            allowed_and_state_transition_hash[2],
            allowed_and_state_transition_hash[3],
            PF::from_u8_value(1),
        ])
    }

    #[test]
    fn dummy_witness_public_inputs_hash_matches_composition() {
        let value = witness(1, 2);
        assert_eq!(
            value.get_expected_public_inputs_hash::<PoseidonHasher>(),
            expected_public_inputs_hash(hash(1), hash(2))
        );

        // The hash only commits to the two roots, not the boolean flags.
        let mut flagged = witness(1, 2);
        flagged.is_deploy_contracts = true;
        flagged.is_register_users = true;
        assert_eq!(
            flagged.get_expected_public_inputs_hash::<PoseidonHasher>(),
            value.get_expected_public_inputs_hash::<PoseidonHasher>()
        );

        assert_ne!(
            witness(3, 2).get_expected_public_inputs_hash::<PoseidonHasher>(),
            value.get_expected_public_inputs_hash::<PoseidonHasher>()
        );
        assert_ne!(
            witness(1, 4).get_expected_public_inputs_hash::<PoseidonHasher>(),
            value.get_expected_public_inputs_hash::<PoseidonHasher>()
        );
    }

    #[cfg(feature = "rand_gen")]
    #[test]
    fn dummy_witness_random_generation_is_self_consistent() {
        let value = DummyAggStateTransition::<Hash>::qp_rand_gen();
        assert_eq!(
            value.get_expected_public_inputs_hash::<PoseidonHasher>(),
            value.get_expected_public_inputs_hash::<PoseidonHasher>()
        );
        assert_eq!(value, value.clone());
    }
}
