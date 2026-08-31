//! Genesis validator identity registry.
//!
//! Single source of truth for the validator identity of each
//! `(realm_id, realm_sub_id)` pair, built from `genesis.validators`
//! (`PsyGenesisBlockSetupData::validators`). The realm processor looks up its
//! own `(realm_id, realm_sub_id)` here to obtain the `ValidatorGenesisEntry`
//! (validator_user_id + NodeId + BLS pubkey) it needs to configure the
//! `RealmGUTAPlanner` with `RealmFinalizeGUTAIdentity` for the
//! `RealmFinalizeGUTA` root job (circuit type 63).
//!
//! Do not invent a second identity table: this is the only mapping from realm
//! coordinates to genesis validator identity.

use std::collections::HashMap;

use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_data::genesis::genesis_block_setup::{PsyGenesisBlockSetupData, ValidatorGenesisEntry};

/// Maps `(realm_id, realm_sub_id) -> ValidatorGenesisEntry` from
/// `genesis.validators`.
pub type ValidatorRegistry = HashMap<(u32, u16), ValidatorGenesisEntry>;

/// Build the registry from genesis. Rejects duplicate `(realm_id, realm_sub_id)`
/// entries (a realm may have at most one genesis validator identity).
pub fn build_validator_registry_from_genesis<F, Hash>(
    genesis: &PsyGenesisBlockSetupData<F, Hash>,
) -> anyhow::Result<ValidatorRegistry> {
    let mut registry = ValidatorRegistry::with_capacity(genesis.validators.len());
    for validator in &genesis.validators {
        let key = (validator.realm_id, validator.realm_sub_id);
        anyhow::ensure!(
            registry.insert(key, *validator).is_none(),
            "duplicate genesis validator for realm {} sub_id {}",
            validator.realm_id,
            validator.realm_sub_id,
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

/// Looks up the genesis validator entry for a realm.
pub fn get_validator_entry<'a>(
    identity: &QRealmIdentifier,
    registry: &'a ValidatorRegistry,
) -> anyhow::Result<&'a ValidatorGenesisEntry> {
    registry
        .get(&(identity.realm_id, identity.realm_sub_id))
        .ok_or_else(|| anyhow::anyhow!("realm {} sub_id {} has no genesis validator", identity.realm_id, identity.realm_sub_id))
}

/// Looks up the genesis validator user id for a realm.
pub fn get_validator_user_id(identity: &QRealmIdentifier, registry: &ValidatorRegistry) -> anyhow::Result<u64> {
    Ok(get_validator_entry(identity, registry)?.validator_user_id)
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
        Some(entry) if entry.validator_user_id == configured_realm_user_id => Ok(()),
        Some(entry) => anyhow::bail!(
            "configured realm_user_id {} does not match genesis validator_user_id {} for realm {} sub_id {}",
            configured_realm_user_id,
            entry.validator_user_id,
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
        let entry = registry
            .get(&(realm_id, *sub_id))
            .ok_or_else(|| anyhow::anyhow!("missing genesis validator for realm {realm_id} sub {sub_id}"))?;
        let key = psy_data::p2p::BlsPublicKey::from_bytes(&entry.bls_public_key)
            .map_err(|error| anyhow::anyhow!("invalid genesis BLS key for realm {realm_id} sub {sub_id}: {error}"))?;
        keys.push((*sub_id, key));
    }
    Ok((validator_sub_ids, keys))
}


#[cfg(test)]
mod tests {
    use super::*;

    fn entry(realm_id: u32, realm_sub_id: u16, validator_user_id: u64) -> ValidatorGenesisEntry {
        ValidatorGenesisEntry {
            realm_id,
            realm_sub_id,
            validator_user_id,
            node_id: [0u8; 38],
            bls_public_key: [0u8; 48],
        }
    }

    #[test]
    fn rejects_unknown_realm() {
        let mut registry = ValidatorRegistry::new();
        registry.insert((3, 0), entry(3, 0, 42));
        let known = QRealmIdentifier { realm_id: 3, realm_sub_id: 0 };
        let unknown = QRealmIdentifier { realm_id: 2, realm_sub_id: 0 };
        assert!(ensure_validator_identity(&known, &registry).is_ok());
        assert!(ensure_validator_identity(&unknown, &registry).is_err());
        assert_eq!(get_validator_user_id(&known, &registry).unwrap(), 42);
    }

    #[test]
    fn beneficiary_bound_to_genesis_user() {
        let mut registry = ValidatorRegistry::new();
        registry.insert((1, 0), entry(1, 0, 16));
        let identity = QRealmIdentifier { realm_id: 1, realm_sub_id: 0 };
        assert!(ensure_validator_beneficiary(&identity, 16, &registry).is_ok());
        assert!(ensure_validator_beneficiary(&identity, 17, &registry).is_err());
    }
}