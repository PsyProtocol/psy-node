//! Genesis validator identity registry.
//!
//! Single source of truth for the validator identity of each
//! `(realm_id, realm_sub_id)` pair, built from `genesis.validators`
//! (`PsyGenesisBlockSetupData::validators`). The realm processor looks up its
//! own `(realm_id, realm_sub_id)` here to obtain the `GenesisValidator`
//! (validator_user_id + NodeId + BLS pubkey) it needs to configure the
//! `RealmGUTAPlanner` with `RealmFinalizeGUTAIdentity` for the
//! `RealmFinalizeGUTA` root job (circuit type 63).
//!
//! Do not invent a second identity table: this is the only mapping from realm
//! coordinates to genesis validator identity.

use std::collections::HashMap;

use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_data::genesis::genesis_block_setup::{PsyGenesisBlockSetupData, GenesisValidator};

/// Maps `(realm_id, realm_sub_id) -> GenesisValidator` from
/// `genesis.validators`.
pub type ValidatorRegistry = HashMap<(u32, u16), GenesisValidator>;

/// Build the registry from Genesis array order. Within each Realm, position
/// `index + 1` is the validator sub-id.
pub fn build_validator_registry_from_genesis<F, Hash>(
    genesis: &PsyGenesisBlockSetupData<F, Hash>,
) -> anyhow::Result<ValidatorRegistry> {
    let mut registry = ValidatorRegistry::with_capacity(genesis.validators.len());
    let mut realm_counts = HashMap::<u32, u16>::new();
    for validator in &genesis.validators {
        let realm_sub_id = realm_counts
            .entry(validator.realm_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        anyhow::ensure!(*realm_sub_id <= u8::MAX as u16, "realm {} has more than 255 validators", validator.realm_id);
        let key = (validator.realm_id, *realm_sub_id);
        anyhow::ensure!(
            registry.insert(key, *validator).is_none(),
            "duplicate genesis validator for realm {} sub_id {}",
            validator.realm_id,
            realm_sub_id,
        );
    }
    Ok(registry)
}

/// Returns true when `genesis.validators` is non-empty for at least one realm.
pub fn genesis_has_validators<F, Hash>(genesis: &PsyGenesisBlockSetupData<F, Hash>) -> bool {
    !genesis.validators.is_empty()
}

/// Ensures the realm has a genesis validator identity registered.
pub fn ensure_validator_identity(identity: &QRealmIdentifier, registry: &ValidatorRegistry) -> anyhow::Result<()> {
    anyhow::ensure!(
        registry.contains_key(&(identity.realm_id, identity.realm_sub_id)),
        "realm {} sub_id {} has no genesis validator",
        identity.realm_id,
        identity.realm_sub_id,
    );
    Ok(())
}

/// Looks up the Genesis validator for a Realm processor.
pub fn get_genesis_validator<'a>(
    identity: &QRealmIdentifier,
    registry: &'a ValidatorRegistry,
) -> anyhow::Result<&'a GenesisValidator> {
    registry
        .get(&(identity.realm_id, identity.realm_sub_id))
        .ok_or_else(|| anyhow::anyhow!("realm {} sub_id {} has no genesis validator", identity.realm_id, identity.realm_sub_id))
}

/// Looks up the genesis validator user id for a realm.
pub fn get_validator_user_id(identity: &QRealmIdentifier, registry: &ValidatorRegistry) -> anyhow::Result<u64> {
    Ok(get_genesis_validator(identity, registry)?.validator_user_id)
}

/// Ensures a configured realm beneficiary user id matches the genesis validator
/// user id for that realm (the validator is the realm beneficiary in the V1
/// finalize flow).
pub fn ensure_validator_beneficiary(
    identity: &QRealmIdentifier,
    configured_realm_user_id: u64,
    registry: &ValidatorRegistry,
) -> anyhow::Result<()> {
    match registry.get(&(identity.realm_id, identity.realm_sub_id)) {
        Some(validator) if validator.validator_user_id == configured_realm_user_id => Ok(()),
        Some(validator) => anyhow::bail!(
            "configured realm_user_id {} does not match genesis validator_user_id {} for realm {} sub_id {}",
            configured_realm_user_id,
            validator.validator_user_id,
            identity.realm_id,
            identity.realm_sub_id,
        ),
        None => anyhow::bail!(
            "realm {} sub_id {} has no genesis validator",
            identity.realm_id,
            identity.realm_sub_id,
        ),
    }
}

/// Validator sub-ids and BLS public keys for one Realm, derived from genesis.
pub fn realm_validators(
    realm_id: u32,
    registry: &ValidatorRegistry,
) -> anyhow::Result<(Vec<u16>, Vec<(u16, psy_data::p2p::BlsPublicKey)>)> {
    let mut validator_sub_ids: Vec<u16> = registry
        .iter()
        .filter_map(|(&(entry_realm, sub_id), _)| {
            if entry_realm == realm_id {
                Some(sub_id)
            } else {
                None
            }
        })
        .collect();
    validator_sub_ids.sort_unstable();
    validator_sub_ids.dedup();
    if validator_sub_ids.is_empty() {
        return Ok((validator_sub_ids, Vec::new()));
    }
    let mut keys = Vec::with_capacity(validator_sub_ids.len());
    for sub_id in &validator_sub_ids {
        let validator = registry
            .get(&(realm_id, *sub_id))
            .ok_or_else(|| anyhow::anyhow!("missing genesis validator for realm {realm_id} sub {sub_id}"))?;
        let key = psy_data::p2p::BlsPublicKey::from_bytes(&validator.bls_public_key)
            .map_err(|error| anyhow::anyhow!("invalid genesis BLS key for realm {realm_id} sub {sub_id}: {error}"))?;
        keys.push((*sub_id, key));
    }
    Ok((validator_sub_ids, keys))
}


#[cfg(test)]
mod tests {
    use super::*;

    fn validator(realm_id: u32, validator_user_id: u64) -> GenesisValidator {
        GenesisValidator {
            realm_id,
            validator_user_id,
            node_id: [0u8; 38],
            bls_public_key: [0u8; 48],
        }
    }

    #[test]
    fn rejects_unknown_realm() {
        let mut registry = ValidatorRegistry::new();
        registry.insert((3, 1), validator(3, 42));
        let known = QRealmIdentifier { realm_id: 3, realm_sub_id: 1 };
        let unknown = QRealmIdentifier { realm_id: 2, realm_sub_id: 1 };
        assert!(ensure_validator_identity(&known, &registry).is_ok());
        assert!(ensure_validator_identity(&unknown, &registry).is_err());
        assert_eq!(get_validator_user_id(&known, &registry).unwrap(), 42);
    }

    #[test]
    fn beneficiary_bound_to_genesis_user() {
        let mut registry = ValidatorRegistry::new();
        registry.insert((1, 1), validator(1, 16));
        let identity = QRealmIdentifier { realm_id: 1, realm_sub_id: 1 };
        assert!(ensure_validator_beneficiary(&identity, 16, &registry).is_ok());
        assert!(ensure_validator_beneficiary(&identity, 17, &registry).is_err());
    }
}