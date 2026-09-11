use parth_core::{crypto::hash::traits::{FieldQHasher, PCircuitWitness, QFieldHashable}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}};
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{agg::AggStateTransitionWithStats, guta::header::GlobalUserTreeAggregatorHeader};




#[pderive::serialize_copy_f_hash]
pub struct QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    pub register_users_state_transition: AggStateTransitionWithStats<Hash>,
    pub deploy_contracts_state_transition: AggStateTransitionWithStats<Hash>,
    pub update_contracts_state_transition: AggStateTransitionWithStats<Hash>,
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
}
impl<F: QFelt64, Hash: QFHashBase<F>> QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {

        // the combined contract tree transition chains deploy then update:
        // start = deploy.start, end = update.end (deploy.end == update.start
        // is enforced by the part-1 circuit; for blocks without updates
        // update.start == update.end == deploy.end)
        let user_registration_deploy_contracts_start = Hasher::two_to_one(
            &self.register_users_state_transition.state_transition_start,
            &self.deploy_contracts_state_transition.state_transition_start,
        );
        let user_registration_deploy_contracts_end = Hasher::two_to_one(
            &self.register_users_state_transition.state_transition_end,
            &self.update_contracts_state_transition.state_transition_end,
        );
        let user_registration_deploy_contracts_combo = Hasher::two_to_one(
            &user_registration_deploy_contracts_start,
            &user_registration_deploy_contracts_end,
        );

        let guta_hash = self.guta_proof_header.qfhash::<Hasher>();
        let combo_without_stats = Hasher::two_to_one(&user_registration_deploy_contracts_combo, &guta_hash);
        let stats_hash = Hash::from_u64x4([
            self.deploy_contracts_state_transition.total_proofs_generated,
            self.register_users_state_transition.total_proofs_generated,
            self.guta_proof_header.total_aggregation_proofs_generated.to_u64_value(),
            0,
        ]);
        Hasher::two_to_one(&combo_without_stats, &stats_hash)
    }
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            register_users_state_transition: AggStateTransitionWithStats::qp_rand_gen(),
            deploy_contracts_state_transition: AggStateTransitionWithStats::qp_rand_gen(),
            update_contracts_state_transition: AggStateTransitionWithStats::qp_rand_gen(),
            guta_proof_header: GlobalUserTreeAggregatorHeader::qp_rand_gen(),
        }
    }
}




impl<F: QFelt64, Hash: QFHashBase<F>> PCircuitWitness<F, Hash>
    for QCAggUserRegistartionDeployContractsGUTAInput<F, Hash>
{
    fn get_expected_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        todo!("Implement get_expected_public_inputs_hash for QCAggUserRegistartionDeployContractsGUTAInput")
    }
}



impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = AggStateTransitionWithStats::<Hash>::FIXED_SIZE * 3
        + GlobalUserTreeAggregatorHeader::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
       Self::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.register_users_state_transition.pio_write_to_io(writer)?;
        self.deploy_contracts_state_transition.pio_write_to_io(writer)?;
        self.update_contracts_state_transition.pio_write_to_io(writer)?;
        self.guta_proof_header.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let register_users_state_transition = AggStateTransitionWithStats::pio_read_from_io(reader)?;
        let deploy_contracts_state_transition = AggStateTransitionWithStats::pio_read_from_io(reader)?;
        let update_contracts_state_transition = AggStateTransitionWithStats::pio_read_from_io(reader)?;
        let guta_proof_header = GlobalUserTreeAggregatorHeader::pio_read_from_io(reader)?;

        Ok(Self {
            register_users_state_transition,
            deploy_contracts_state_transition,
            update_contracts_state_transition,
            guta_proof_header,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    QCAggUserRegistartionDeployContractsGUTAInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    QCAggUserRegistartionDeployContractsGUTAInput,
    // Note the use of concrete types here
    {  parth_core::PF, parth_core::PHash },
    qc_agg_user_registration_deploy_contracts_guta_input_ser_tests
);

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{
        crypto::hash::traits::{FromU64x4, MerkleHasher, QFieldHashable},
        felt::{FromPrimitiveValuesFelt, ToU64Value},
        pgoldilocks::{PoseidonHasher, QHashOut},
        utils::QPGenRandom,
        PF,
    };

    type Hash = QHashOut<PF>;

    fn hash(seed: u64) -> Hash {
        Hash::from_u64x4([
            seed,
            seed.wrapping_mul(31),
            seed.wrapping_mul(7),
            seed.wrapping_mul(13),
        ])
    }

    fn transition_with(start: u64, end: u64, proofs: u64) -> AggStateTransitionWithStats<Hash> {
        AggStateTransitionWithStats {
            state_transition_start: hash(start),
            state_transition_end: hash(end),
            total_proofs_generated: proofs,
        }
    }

    fn controlled_input() -> QCAggUserRegistartionDeployContractsGUTAInput<PF, Hash> {
        let mut input = QCAggUserRegistartionDeployContractsGUTAInput::qp_rand_gen();
        input.register_users_state_transition = transition_with(1, 2, 3);
        input.deploy_contracts_state_transition = transition_with(4, 5, 6);
        input.update_contracts_state_transition = transition_with(7, 8, 9);
        input.guta_proof_header.total_aggregation_proofs_generated = PF::from_u64_value(11);
        input
    }

    #[test]
    fn public_inputs_hash_chains_transitions_guta_header_and_stats() {
        let input = controlled_input();

        let combined_start = PoseidonHasher::two_to_one(
            &input.register_users_state_transition.state_transition_start,
            &input.deploy_contracts_state_transition.state_transition_start,
        );
        let combined_end = PoseidonHasher::two_to_one(
            &input.register_users_state_transition.state_transition_end,
            &input.update_contracts_state_transition.state_transition_end,
        );
        let combined_transition = PoseidonHasher::two_to_one(&combined_start, &combined_end);
        let guta_hash = input.guta_proof_header.qfhash::<PoseidonHasher>();
        let combo_without_stats = PoseidonHasher::two_to_one(&combined_transition, &guta_hash);
        let stats_hash = Hash::from_u64x4([
            input.deploy_contracts_state_transition.total_proofs_generated,
            input.register_users_state_transition.total_proofs_generated,
            input.guta_proof_header.total_aggregation_proofs_generated.to_u64_value(),
            0,
        ]);
        let expected = PoseidonHasher::two_to_one(&combo_without_stats, &stats_hash);

        assert_eq!(input.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>(), expected);

        let mut more_proofs = controlled_input();
        more_proofs.register_users_state_transition.total_proofs_generated += 1;
        assert_ne!(
            more_proofs.get_public_inputs_hash_no_rewards_tag::<PoseidonHasher>(),
            expected
        );
    }

    #[test]
    fn fallback_serialization_round_trips_and_matches_declared_fixed_size() {
        let value = QCAggUserRegistartionDeployContractsGUTAInput::<PF, Hash>::qp_rand_gen();
        assert!(QCAggUserRegistartionDeployContractsGUTAInput::<PF, Hash>::IS_FIXED_SIZE);
        assert_eq!(
            value.fallback_pio_serialized_size(),
            QCAggUserRegistartionDeployContractsGUTAInput::<PF, Hash>::FIXED_SIZE
        );

        let bytes = value.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), value.fallback_pio_serialized_size());
        // The speedy-backed `pio_read_from_io` now reads unbuffered, so the
        // fallback reader no longer over-advances the shared cursor and the
        // full fallback round trip is deterministic.
        assert_eq!(
            QCAggUserRegistartionDeployContractsGUTAInput::<PF, Hash>::fallback_psy_ser_from_slice(&bytes).unwrap(),
            value
        );
    }
}
