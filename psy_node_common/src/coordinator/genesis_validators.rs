//! Genesis validator identity index.
//!
//! Maps each `(realm_id, realm_sub_id)` to its `GenesisValidator` from
//! `genesis.validators` (`PsyGenesisBlockSetupData::validators`). The realm
//! processor looks up its own coordinates here for
//! `RealmGUTAValidatorProofs` (circuit type 63).
//!
//! This is an in-memory index of genesis entries. The on-chain membership
//! structure is the validator tree (`validator_tree_root` / leaf proofs).

use std::collections::HashMap;

use psy_data::genesis::genesis_block_setup::{GenesisValidator, PsyGenesisBlockSetupData};

/// Maps `(realm_id, realm_sub_id) -> GenesisValidator` from `genesis.validators`.
pub type GenesisValidatorIndex = HashMap<(u32, u16), GenesisValidator>;

/// Build the index from Genesis array order. Within each Realm, position
/// `index + 1` is the validator sub-id.
pub fn index_from_genesis<F, Hash>(
    genesis: &PsyGenesisBlockSetupData<F, Hash>,
) -> anyhow::Result<GenesisValidatorIndex> {
    let mut index = GenesisValidatorIndex::with_capacity(genesis.validators.len());
    let mut realm_counts = HashMap::<u32, u16>::new();
    for validator in &genesis.validators {
        let realm_sub_id = realm_counts
            .entry(validator.realm_id)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        anyhow::ensure!(
            *realm_sub_id <= u8::MAX as u16,
            "realm {} has more than 255 validators",
            validator.realm_id
        );
        let key = (validator.realm_id, *realm_sub_id);
        anyhow::ensure!(
            index.insert(key, *validator).is_none(),
            "duplicate genesis validator for realm {} sub_id {}",
            validator.realm_id,
            realm_sub_id,
        );
    }
    Ok(index)
}
