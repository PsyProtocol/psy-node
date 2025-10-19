use parth_core::{crypto::hash::traits::MerkleHasher, felt::{QFelt64, QFeltSized, ToQFelts}, protocol::core_types::{Q256BitHash, QFHashBase}, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};

pub const PM_REWARD_COMMITMENT_SIZE: usize = 12;

#[pderive::serialize_copy_hash_ts]
#[derive(Default)]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "PMRewardCommitmentHash")]
#[repr(C)]
pub struct PPMRewardCommitment<Hash> {
    pub register_users_root: Hash,
    pub gutas_root: Hash,
    pub deploy_contracts_root: Hash,
}
impl<Hash: QPGenRandom> QPGenRandom for PPMRewardCommitment<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            register_users_root: Hash::qp_rand_gen(),
            gutas_root: Hash::qp_rand_gen(),
            deploy_contracts_root: Hash::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for PPMRewardCommitment<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32 * 3
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.register_users_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.gutas_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.deploy_contracts_root.into_owned_32bytes())?;

        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let register_users_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let gutas_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let deploy_contracts_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);

        Ok(Self {
            register_users_root,
            gutas_root,
            deploy_contracts_root,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PPMRewardCommitment,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PPMRewardCommitment<Hash> {}


impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PPMRewardCommitment<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}


impl<Hash: PartialEq> PPMRewardCommitment<Hash> {
    pub fn combine_with<H: MerkleHasher<Hash>>(&self, other: &Self) -> Self {
        let register_users_root = H::two_to_one(
            &self.register_users_root,
            &other.register_users_root
        );

        let gutas_root = H::two_to_one(
            &self.gutas_root,
            &other.gutas_root
        );
        let deploy_contracts_root = H::two_to_one(
            &self.deploy_contracts_root,
            &other.deploy_contracts_root
        );
        PPMRewardCommitment {
            register_users_root,
            gutas_root,
            deploy_contracts_root,
        }
    }
    

    pub fn get_commitment_hash<H: MerkleHasher<Hash>>(&self) -> Hash{
        let temp = H::two_to_one(
            &self.register_users_root,
            &self.gutas_root,
        );
        H::two_to_one(
            &temp,
            &self.deploy_contracts_root,
        )
    }
}

impl<Hash> QFeltSized for PPMRewardCommitment<Hash> {
    fn q_felt_size() -> usize {
        PM_REWARD_COMMITMENT_SIZE
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PPMRewardCommitment<Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(PM_REWARD_COMMITMENT_SIZE);
        result.extend_from_slice(&self.register_users_root.to_4_felts());
        result.extend_from_slice(&self.gutas_root.to_4_felts());
        result.extend_from_slice(&self.deploy_contracts_root.to_4_felts());
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != PM_REWARD_COMMITMENT_SIZE {
            panic!("Invalid number of elements for PPMRewardCommitment, expected {} got {}", PM_REWARD_COMMITMENT_SIZE, felts.len());
        }
        PPMRewardCommitment {
            register_users_root: Hash::from_4_felts_slice(&felts[0..4]),
            gutas_root: Hash::from_4_felts_slice(&felts[4..8]),
            deploy_contracts_root: Hash::from_4_felts_slice(&felts[8..12]),
        }
    }
}
#[cfg(test)]
mod test_psy_ser_pm_reward_commitment {
    use super::PPMRewardCommitment;
    use parth_core::utils::QPGenRandom;
    use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle};
    type PsySerTestTargetType = PPMRewardCommitment<parth_core::PHash>;
    #[test]
    fn test_simple_round_trip() -> anyhow::Result<()> {
        let value = PsySerTestTargetType::qp_rand_gen();
        let serialized = value.psy_ser_to_bytes_vec()?;
        let deserialized = PsySerTestTargetType::psy_ser_from_slice(&serialized)?;
        let deserialized_owned = PsySerTestTargetType::psy_ser_from_owned_bytes_vec(serialized.clone())?;
        assert!(value == deserialized, "Round trip serialization failed");
        assert!(value == deserialized_owned, "Round trip owned serialization failed");
        let serialized_owned = value.psy_ser_into_bytes_vec()?;
        assert_eq!(serialized, serialized_owned, "Owned and non-owned serialization differ");
        let fallback_serialized = value.fallback_psy_ser_to_bytes_vec()?;
        assert_eq!(serialized, fallback_serialized, "Fallback and non-fallback serialization differ");
        let fallback_deserialized = PsySerTestTargetType::fallback_psy_ser_from_slice(&fallback_serialized)?;
        assert!(value == fallback_deserialized, "Fallback round trip serialization failed");
        let fallback_deserialized_owned = PsySerTestTargetType::psy_ser_from_owned_bytes_vec(fallback_serialized.clone())?;
        assert!(value == fallback_deserialized_owned, "Fallback round trip owned serialization failed");
        Ok(())
    }

    #[test]
    fn fuzz_10000_round_trips() -> anyhow::Result<()> {
        for _ in 0..10000 {
            let value = PsySerTestTargetType::qp_rand_gen();
            let serialized = value.psy_ser_to_bytes_vec()?;
            let deserialized = PsySerTestTargetType::psy_ser_from_slice(&serialized)?;
            let deserialized_owned = PsySerTestTargetType::psy_ser_from_owned_bytes_vec(serialized.clone())?;
            assert!(value == deserialized, "Round trip serialization failed");
            assert!(value == deserialized_owned, "Round trip owned serialization failed");
            let serialized_owned = value.psy_ser_into_bytes_vec()?;
            assert_eq!(serialized, serialized_owned, "Owned and non-owned serialization differ");
            let fallback_serialized = value.fallback_psy_ser_to_bytes_vec()?;
            assert_eq!(serialized, fallback_serialized, "Fallback and non-fallback serialization differ");
            let fallback_deserialized = PsySerTestTargetType::fallback_psy_ser_from_slice(&fallback_serialized)?;
            assert!(value == fallback_deserialized, "Fallback round trip serialization failed");
            let fallback_deserialized_owned = PsySerTestTargetType::psy_ser_from_owned_bytes_vec(fallback_serialized.clone())?;
            assert!(value == fallback_deserialized_owned, "Fallback round trip owned serialization failed");
        }
        Ok(())
    }
    #[test]
    fn test_simple_vec_round_trip() -> anyhow::Result<()> {
        let values = PsySerTestTargetType::qp_rand_gen_vec(10);

        let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
        let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;
        assert!(values == deserialized, "Vector round trip serialization failed");
        Ok(())
    }
    #[test]
    fn fuzz_500_non_empty_vec_round_trips() -> anyhow::Result<()> {
        for _ in 0..500 {
            let count = (rand::random::<usize>() % 0xff) + 1;
            let values = PsySerTestTargetType::qp_rand_gen_vec(count);

            let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
            let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;
            assert!(values == deserialized, "Vector round trip serialization failed");
        }
        Ok(())
    }
     #[test]
    fn test_empty_vec_round_trip() -> anyhow::Result<()> {
        let values: Vec<PsySerTestTargetType> = vec![];
        let serialized = PsySerTestTargetType::psy_ser_serialize_vec_of_self_ref(&values, true);
        let deserialized = PsySerTestTargetType::psy_ser_deserialize_vec_of_self(&serialized, true)?;
        assert!(values == deserialized, "Empty vector round trip serialization failed");
        Ok(())
    }
}