//! Pure deterministic artifact factory for the branch-exact Realm Edge.
//!
//! This module owns no DB, queue, Redis, temp or proof-store handle. The
//! storage-owned ingress invokes it only after a durable claim winner exists,
//! and revalidates every returned byte before persistence.

use std::marker::PhantomData;

use parth_core::{
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QDBHashBase, QFHashBase, QFHasherU64},
};
use psy_data::proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput;
use psy_node_core::queue::{
    realm_user_update_artifact::{
        deterministic_qblob_context, RealmUserUpdateContractSlots,
        RealmUserUpdateSlotUpdate,
    },
    realm_user_update_claim::StoredRealmUserUpdateClaim,
    realm_user_update_ingress::{
        RealmUserUpdateArtifactFactory, RealmUserUpdateArtifactMaterial,
        RealmUserUpdateIngressError,
    },
};

use super::utils::end_cap::validate_end_cap_and_generate_node_data_for_edge;

#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicRealmUserUpdateArtifactFactory<F, Hash, Hasher> {
    _marker: PhantomData<fn() -> (F, Hash, Hasher)>,
}

impl<F, Hash, Hasher>
    DeterministicRealmUserUpdateArtifactFactory<F, Hash, Hasher>
{
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<F, Hash, Hasher> RealmUserUpdateArtifactFactory<F, Hash>
    for DeterministicRealmUserUpdateArtifactFactory<F, Hash, Hasher>
where
    F: QFelt64,
    Hash: Q256BitHash + QDBHashBase + QFHashBase<F>,
    Hasher: QFHasherU64<F, Hash> + Send + Sync,
{
    fn build(
        &self,
        claim: &StoredRealmUserUpdateClaim<Hash>,
        input: &SubmitUserEndCapNonProofInput<F, Hash>,
    ) -> Result<RealmUserUpdateArtifactMaterial, RealmUserUpdateIngressError> {
        let context = deterministic_qblob_context(claim)
            .map_err(|error| RealmUserUpdateIngressError::Artifact(error.to_string()))?;
        let contract_updates = validate_end_cap_and_generate_node_data_for_edge::<
            F,
            Hash,
            Hasher,
        >(&context, claim.user_id().get(), input)
        .map_err(|error| RealmUserUpdateIngressError::Artifact(error.to_string()))?;

        let slot_contracts = input
            .get_slot_updates()
            .map_err(|error| RealmUserUpdateIngressError::Artifact(error.to_string()))?
            .into_iter()
            .filter_map(|contract| {
                let updates = contract
                    .slot_updates
                    .into_iter()
                    .map(|slot| {
                        RealmUserUpdateSlotUpdate::new(
                            slot.slot,
                            slot.old_value.to_u64_value(),
                            slot.new_value.to_u64_value(),
                        )
                    })
                    .collect::<Vec<_>>();
                (!updates.is_empty()).then_some((contract.contract_id, updates))
            })
            .map(|(contract_id, updates)| {
                RealmUserUpdateContractSlots::try_new(contract_id, updates)
                    .map_err(|error| {
                        RealmUserUpdateIngressError::Artifact(error.to_string())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        RealmUserUpdateArtifactMaterial::try_new(
            contract_updates,
            slot_contracts,
        )
    }
}

#[cfg(test)]
mod tests {
    fn production_source() -> &'static str {
        include_str!("durable_user_update_artifact.rs")
            .split("#[derive(Clone, Copy, Debug, Default)]")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap()
    }

    #[test]
    fn factory_is_pure_and_uses_the_durable_winner_context() {
        let source = production_source();
        assert!(source.contains("deterministic_qblob_context(claim)"));
        assert!(source.contains("claim.user_id().get()"));
        assert!(source.contains(".get_slot_updates()"));
        for forbidden in [
            "new_at_now",
            "rand::",
            "SystemTime",
            "Session",
            "Redis",
            "Nats",
            "ProofStore",
            "TempDatabase",
            "RealmUserUpdatePublishPort",
        ] {
            assert!(
                !source.contains(forbidden),
                "pure artifact factory gained authority {forbidden}"
            );
        }
    }
}
