use parth_core::{crypto::hash::traits::{FieldQHasher, PCircuitWitness, QFieldHashable}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}};
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{agg::AggStateTransitionWithStats, guta::{self, header::GlobalUserTreeAggregatorHeader}};




#[pderive::serialize_copy_f_hash]
pub struct QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    pub register_users_state_transition: AggStateTransitionWithStats<Hash>,
    pub deploy_contracts_state_transition: AggStateTransitionWithStats<Hash>,
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
}
/*



    pub fn get_combined_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let user_regsitration_deploy_contract_start = builder.hash_two_to_one::<H>(
            self.user_registration_tree_delta.state_transition_start,
            self.global_contract_tree_delta.state_transition_start,
        );
        let user_regsitration_deploy_contract_end = builder.hash_two_to_one::<H>(
            self.user_registration_tree_delta.state_transition_end,
            self.global_contract_tree_delta.state_transition_end,
        );
        let user_regsitration_deploy_contract_combo =
            builder.hash_two_to_one::<H>(user_regsitration_deploy_contract_start, user_regsitration_deploy_contract_end);

        let guta_hash = self.global_user_tree_delta.to_hash::<H, F, D>(builder);
        

        let combo_without_stats = builder.hash_two_to_one::<H>(user_regsitration_deploy_contract_combo, guta_hash);
        let stats_hash = HashOutTarget {
            elements: [
                self.combined_pm_jobs_completed.deploy_contracts_completed,
                self.combined_pm_jobs_completed.register_users_completed,
                self.combined_pm_jobs_completed.gutas_completed,
                builder.zero(),
            ]
        };
        builder.hash_two_to_one::<H>(combo_without_stats, stats_hash)
    }
    
*/
impl<F: QFelt64, Hash: QFHashBase<F>> QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {

        let user_registration_deploy_contracts_start = Hasher::two_to_one(
            &self.register_users_state_transition.state_transition_start,
            &self.deploy_contracts_state_transition.state_transition_start,
        );
        let user_registration_deploy_contracts_end = Hasher::two_to_one(
            &self.register_users_state_transition.state_transition_end,
            &self.deploy_contracts_state_transition.state_transition_end,
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
    const FIXED_SIZE: usize = AggStateTransitionWithStats::<Hash>::FIXED_SIZE * 2
        + GlobalUserTreeAggregatorHeader::<F, Hash>::FIXED_SIZE;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for QCAggUserRegistartionDeployContractsGUTAInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
       Self::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.register_users_state_transition.pio_write_to_io(writer)?;
        self.deploy_contracts_state_transition.pio_write_to_io(writer)?;
        self.guta_proof_header.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let register_users_state_transition = AggStateTransitionWithStats::pio_read_from_io(reader)?;
        let deploy_contracts_state_transition = AggStateTransitionWithStats::pio_read_from_io(reader)?;
        let guta_proof_header = GlobalUserTreeAggregatorHeader::pio_read_from_io(reader)?;

        Ok(Self {
            register_users_state_transition,
            deploy_contracts_state_transition,
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


pser::impl_psy_ser_basic_tests!(
    QCAggUserRegistartionDeployContractsGUTAInput,
    // Note the use of concrete types here
    {  parth_core::PF, parth_core::PHash },
    qc_agg_user_registration_deploy_contracts_guta_input_ser_tests
);
