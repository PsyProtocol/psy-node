use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    protocol::core_types::Q256BitHash,
};
use psy_data::p2p::{
    authenticate_validator_preimage, realm_validator_indexes, require_realm_validator_count,
    BlsPublicKey, ValidatorLeafPreimage,
};

use crate::psy_core_db::traits::full::{
    PsyNodeValidatorTreeDatabaseReader, PsyNodeValidatorTreeDatabaseWriter,
};

pub async fn load_realm_validators_from_tree<Hasher, Hash, Store>(
    store: &Store,
    checkpoint_id: u64,
    realm_id: u32,
    expected_root: &Hash,
) -> anyhow::Result<(Vec<u16>, Vec<(u16, BlsPublicKey)>, Vec<(u16, u64)>)>
where
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Q256BitHash,
    Store: PsyNodeValidatorTreeDatabaseReader<Hash> + Sync,
{
    let tree_root = store.validator_tree_get_root_hash(checkpoint_id).await?;
    anyhow::ensure!(
        &tree_root == expected_root,
        "validator tree root mismatch at checkpoint {checkpoint_id}"
    );

    let empty_leaf = Hasher::get_zero_hash(0);
    let mut validator_sub_ids = Vec::new();
    let mut keys = Vec::new();
    let mut user_ids = Vec::new();
    for (sub_id, leaf_index) in realm_validator_indexes(realm_id) {
        let leaf_hash = store
            .validator_tree_get_leaf_hash(checkpoint_id, leaf_index)
            .await?;
        if leaf_hash == empty_leaf {
            continue;
        }
        let preimage = store
            .validator_tree_get_leaf_preimage(checkpoint_id, leaf_index)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "validator leaf preimage missing at realm {realm_id} sub {sub_id} checkpoint {checkpoint_id}"
                )
            })?;
        anyhow::ensure!(
            preimage.realm_id == realm_id && preimage.realm_sub_id == sub_id,
            "validator preimage slot mismatch at realm {realm_id} sub {sub_id}"
        );
        let leaf = authenticate_validator_preimage(&preimage, &leaf_hash)?;
        validator_sub_ids.push(sub_id);
        keys.push((sub_id, leaf.bls_public_key));
        user_ids.push((sub_id, preimage.validator_user_id));
    }
    require_realm_validator_count(realm_id, validator_sub_ids.len())?;
    Ok((validator_sub_ids, keys, user_ids))
}

pub async fn write_validator_tree_genesis<Hash, Store>(
    store: &Store,
    nodes_ffs: &[u8],
    preimages: &[ValidatorLeafPreimage],
) -> anyhow::Result<()>
where
    Store: PsyNodeValidatorTreeDatabaseWriter<Hash> + Sync,
{
    if !nodes_ffs.is_empty() {
        store.validator_tree_set_nodes_ffs(0, nodes_ffs).await?;
    }
    for preimage in preimages {
        store
            .validator_tree_set_leaf_preimage(0, preimage.tree_index()?, preimage)
            .await?;
    }
    Ok(())
}
