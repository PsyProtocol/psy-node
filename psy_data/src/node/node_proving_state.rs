use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};

pub const PROVING_NODE_TYPE_REALM: u8 = 1;
pub const PROVING_NODE_TYPE_COORDINATOR: u8 = 2;

pub const PLAN_VARIANT_REALM_STANDARD: u8 = 1;
pub const PLAN_VARIANT_COORDINATOR_STANDARD: u8 = 1;


#[pderive::serialize_copy_bm]
#[repr(C)]
pub struct PsyNodeProvingState {
    pub realm_id: u64,
    pub realm_sub_id: u32,
    pub node_type: u8,
    pub plan_variant: u8,
    pub current_proving_level: u8,
    pub has_remaining_proving_jobs: u8,
    pub unique_pending_id: u64,
    pub last_committed_checkpoint_id: u64,
    pub guta_input_proofs: u64,
    pub total_guta_jobs: u64,
    pub new_user_registrations: u64,
    pub total_user_registration_jobs: u64,
    pub new_contracts_deployed: u64,
    pub total_deploy_contract_jobs: u64,
}

impl PsyNodeProvingState {
    pub fn new_standard_realm(
        realm_id: u64,
        realm_sub_id: u32,
        unique_pending_id: u64,
        last_committed_checkpoint_id: u64,
        guta_input_proofs: u64,
        total_guta_jobs: u64,
    ) -> Self {
        let has_remaining_proving_jobs = total_guta_jobs > 0;
        Self {
            realm_id,
            realm_sub_id,
            node_type: PROVING_NODE_TYPE_REALM,
            plan_variant: PLAN_VARIANT_REALM_STANDARD,
            has_remaining_proving_jobs: if has_remaining_proving_jobs { 1 } else { 0 },
            current_proving_level: 0,
            unique_pending_id,
            last_committed_checkpoint_id,
            total_guta_jobs,
            total_user_registration_jobs: 0,
            total_deploy_contract_jobs: 0,
            guta_input_proofs,
            new_user_registrations: 0,
            new_contracts_deployed: 0,
        }
    }
    pub fn new_standard_coordinator(
        realm_id: u64,
        realm_sub_id: u32,
        unique_pending_id: u64,
        last_committed_checkpoint_id: u64,
        guta_input_proofs: u64,
        total_guta_jobs: u64,
        new_user_registrations: u64,
        total_user_registration_jobs: u64,
        new_contracts_deployed: u64,
        total_deploy_contract_jobs: u64,
    ) -> Self {
        let has_remaining_proving_jobs = total_guta_jobs > 0 || new_user_registrations > 0 || new_contracts_deployed > 0;

        Self {
            realm_id,
            realm_sub_id,
            node_type: PROVING_NODE_TYPE_COORDINATOR,
            plan_variant: PLAN_VARIANT_COORDINATOR_STANDARD,
            current_proving_level: 0,
            has_remaining_proving_jobs: if has_remaining_proving_jobs { 1 } else { 0 },
            unique_pending_id,
            last_committed_checkpoint_id,
            guta_input_proofs,
            total_guta_jobs,
            new_user_registrations,
            total_user_registration_jobs,
            new_contracts_deployed,
            total_deploy_contract_jobs,
        }
    }
    pub fn inc_current_proving_level(&mut self) {
        self.current_proving_level = self.current_proving_level.wrapping_add(1);
    }
    pub fn set_current_proving_level(&mut self, level: u8) {
        self.current_proving_level = level;
    }
    pub fn finish(&mut self) {
        self.has_remaining_proving_jobs = 0;
    }
}

impl QPGenRandom for PsyNodeProvingState {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            realm_id: u64::qp_rand_gen(),
            realm_sub_id: u32::qp_rand_gen(),
            node_type: u8::qp_rand_gen(),   
            plan_variant: u8::qp_rand_gen(),
            current_proving_level: u8::qp_rand_gen(),
            has_remaining_proving_jobs: u8::qp_rand_gen()&1,
            unique_pending_id: u64::qp_rand_gen(),
            last_committed_checkpoint_id: u64::qp_rand_gen(),
            guta_input_proofs: u64::qp_rand_gen(),
            total_guta_jobs: u64::qp_rand_gen(),
            new_user_registrations: u64::qp_rand_gen(),
            total_user_registration_jobs: u64::qp_rand_gen(),
            new_contracts_deployed: u64::qp_rand_gen(),
            total_deploy_contract_jobs: u64::qp_rand_gen(),
        }
    }
}

impl PsyCanonicalSerializeMetadata for PsyNodeProvingState {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 80;
}

impl FallbackPsySerializeCanonical for PsyNodeProvingState {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.realm_id)?;
        writer.psy_write_u32(self.realm_sub_id)?;
        writer.psy_write_u8(self.node_type)?;
        writer.psy_write_u8(self.plan_variant)?;
        writer.psy_write_u8(self.current_proving_level)?;
        writer.psy_write_u8(self.has_remaining_proving_jobs)?;
        writer.psy_write_u64(self.unique_pending_id)?;
        writer.psy_write_u64(self.last_committed_checkpoint_id)?;
        writer.psy_write_u64(self.guta_input_proofs)?;
        writer.psy_write_u64(self.total_guta_jobs)?;
        writer.psy_write_u64(self.new_user_registrations)?;
        writer.psy_write_u64(self.total_user_registration_jobs)?;
        writer.psy_write_u64(self.new_contracts_deployed)?;
        writer.psy_write_u64(self.total_deploy_contract_jobs)?;

        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let realm_id = reader.psy_read_u64()?;
        let realm_sub_id = reader.psy_read_u32()?;
        let node_type = reader.psy_read_u8()?;
        let plan_variant = reader.psy_read_u8()?;
        let current_proving_level = reader.psy_read_u8()?;
        let has_remaining_proving_jobs = reader.psy_read_u8()?;
        let unique_pending_id = reader.psy_read_u64()?;
        let last_committed_checkpoint_id = reader.psy_read_u64()?;
        let guta_input_proofs = reader.psy_read_u64()?;
        let total_guta_jobs = reader.psy_read_u64()?;
        let new_user_registrations = reader.psy_read_u64()?;
        let total_user_registration_jobs = reader.psy_read_u64()?;
        let new_contracts_deployed = reader.psy_read_u64()?;
        let total_deploy_contract_jobs = reader.psy_read_u64()?;
        Ok(Self {
            realm_id,
            realm_sub_id,
            node_type,
            plan_variant,
            current_proving_level,
            has_remaining_proving_jobs,
            unique_pending_id,
            last_committed_checkpoint_id,
            guta_input_proofs,
            total_guta_jobs,
            new_user_registrations,
            total_user_registration_jobs,
            new_contracts_deployed,
            total_deploy_contract_jobs,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(PsyNodeProvingState);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyNodeProvingState {}

pser::impl_psy_ser_basic_tests_fallback!(PsyNodeProvingState, {}, psy_node_proving_state_tests);

#[cfg(test)]
mod behavior_tests {
    use super::*;

    #[test]
    fn realm_state_tracks_levels_and_completion() {
        let mut state = PsyNodeProvingState::new_standard_realm(1, 2, 3, 4, 5, 6);
        assert_eq!(state.node_type, PROVING_NODE_TYPE_REALM);
        assert_eq!(state.has_remaining_proving_jobs, 1);
        state.inc_current_proving_level();
        assert_eq!(state.current_proving_level, 1);
        state.set_current_proving_level(255);
        state.inc_current_proving_level();
        assert_eq!(state.current_proving_level, 0);
        state.finish();
        assert_eq!(state.has_remaining_proving_jobs, 0);
        assert_eq!(PsyNodeProvingState::new_standard_realm(1, 2, 3, 4, 0, 0).has_remaining_proving_jobs, 0);
    }

    #[test]
    fn coordinator_remaining_flag_considers_each_work_category() {
        let make = |guta, users, contracts| {
            PsyNodeProvingState::new_standard_coordinator(1, 2, 3, 4, 5, guta, users, 7, contracts, 8)
        };
        assert_eq!(make(0, 0, 0).has_remaining_proving_jobs, 0);
        assert_eq!(make(1, 0, 0).has_remaining_proving_jobs, 1);
        assert_eq!(make(0, 1, 0).has_remaining_proving_jobs, 1);
        assert_eq!(make(0, 0, 1).has_remaining_proving_jobs, 1);
        assert_eq!(make(0, 0, 1).node_type, PROVING_NODE_TYPE_COORDINATOR);
    }

    #[test]
    fn standard_realm_initializes_with_documented_defaults() {
        let state = PsyNodeProvingState::new_standard_realm(9, 8, 7, 6, 5, 4);
        assert_eq!(state.realm_id, 9);
        assert_eq!(state.realm_sub_id, 8);
        assert_eq!(state.unique_pending_id, 7);
        assert_eq!(state.last_committed_checkpoint_id, 6);
        assert_eq!(state.guta_input_proofs, 5);
        assert_eq!(state.total_guta_jobs, 4);
        assert_eq!(state.node_type, PROVING_NODE_TYPE_REALM);
        assert_eq!(state.plan_variant, PLAN_VARIANT_REALM_STANDARD);
        assert_eq!(state.current_proving_level, 0);
        assert_eq!(state.new_user_registrations, 0);
        assert_eq!(state.total_user_registration_jobs, 0);
        assert_eq!(state.new_contracts_deployed, 0);
        assert_eq!(state.total_deploy_contract_jobs, 0);
    }

    #[test]
    fn standard_coordinator_records_counters_verbatim() {
        let state = PsyNodeProvingState::new_standard_coordinator(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        assert_eq!(state.realm_id, 1);
        assert_eq!(state.realm_sub_id, 2);
        assert_eq!(state.unique_pending_id, 3);
        assert_eq!(state.last_committed_checkpoint_id, 4);
        assert_eq!(state.guta_input_proofs, 5);
        assert_eq!(state.total_guta_jobs, 6);
        assert_eq!(state.new_user_registrations, 7);
        assert_eq!(state.total_user_registration_jobs, 8);
        assert_eq!(state.new_contracts_deployed, 9);
        assert_eq!(state.total_deploy_contract_jobs, 10);
        assert_eq!(state.plan_variant, PLAN_VARIANT_COORDINATOR_STANDARD);
        assert_eq!(state.current_proving_level, 0);
    }
}
