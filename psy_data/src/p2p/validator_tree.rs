//! One checkpoint validator tree, two layers: realm then sub-id.
//!
//! The tree stores only leaf hashes. Full `ValidatorLeaf` preimages live in a
//! separate checkpointed record table. Leaf index is
//! `(realm_id << 8) | realm_sub_id`. A realm's validators are the non-empty
//! hashes at that realm's 256 known indexes.

use std::collections::HashSet;

use parth_common::merkle_leaf_serializer::zero_id::zero_id_merkle_tree_nodes_hash_map_from_leaves;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::hash::{
        fast_node_serializer::QMerkleStoreFastZeroNodeSerializer,
        merkle_node_nest::MerkleLeafNode,
    },
    protocol::core_types::Q256BitHash,
};
use serde_with::serde_as;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};

use crate::genesis::genesis_block_setup::ValidatorGenesisEntry;
use crate::guta::realm_finalize::{validator_tree_index, VALIDATOR_TREE_HEIGHT};

use super::bls::BlsPublicKey;
use super::limits::{MAX_VALIDATORS_PER_REALM, MIN_VALIDATORS_PER_REALM};
use super::node_id::NodeId;
use super::validator_leaf::ValidatorLeaf;

/// Maximum stored validator-tree preimages: one per 8-bit sub-id slot
/// across the 12-bit realm layer (`1 << VALIDATOR_TREE_HEIGHT`).
pub const MAX_VALIDATOR_TREE_PREIMAGES: usize = 1 << VALIDATOR_TREE_HEIGHT;
/// Upper bound for a height-20 zero-id node FFS payload.
pub const MAX_VALIDATOR_TREE_NODES_FFS_BYTES: usize = 1 << 22;

/// Checkpointed preimage for one validator-tree leaf.
///
/// The merkle tree stores `hash`; this record is the DOMAIN_VALIDATOR_LEAF
/// payload used to rebuild that hash and bind NodeId / BLS identity.
#[serde_as]
#[pderive::serialize_copy]
pub struct ValidatorLeafPreimage {
    pub chain_id: u32,
    pub realm_id: u32,
    pub realm_sub_id: u16,
    pub validator_user_id: u64,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub node_id: [u8; 38],
    #[serde_as(as = "serde_with::hex::Hex")]
    pub bls_public_key: [u8; 48],
}

impl psy_serialize::PsyCanonicalSerializeMetadata for ValidatorLeafPreimage {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 104;
}

impl psy_serialize::FallbackPsySerializeCanonical for ValidatorLeafPreimage {
    fn fallback_pio_serialized_size(&self) -> usize {
        104
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u32(self.chain_id)?;
        writer.psy_write_u32(self.realm_id)?;
        writer.psy_write_u16(self.realm_sub_id)?;
        writer.psy_write_u64(self.validator_user_id)?;
        writer.psy_write_bytes_fixed(&self.node_id)?;
        writer.psy_write_bytes_fixed(&self.bls_public_key)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        Ok(Self {
            chain_id: reader.psy_read_u32()?,
            realm_id: reader.psy_read_u32()?,
            realm_sub_id: reader.psy_read_u16()?,
            validator_user_id: reader.psy_read_u64()?,
            node_id: reader.psy_read_bytes_fixed()?,
            bls_public_key: reader.psy_read_bytes_fixed()?,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(ValidatorLeafPreimage);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl psy_serialize::AutoImplementFallbackPsySerializeCanonical for ValidatorLeafPreimage {}

#[cfg(feature = "rand_gen")]
impl parth_core::utils::QPGenRandom for ValidatorLeafPreimage {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            chain_id: u32::qp_rand_gen(),
            realm_id: u32::qp_rand_gen(),
            realm_sub_id: (u16::qp_rand_gen()) & 0xff,
            validator_user_id: u64::qp_rand_gen(),
            node_id: <[u8; 38]>::qp_rand_gen(),
            bls_public_key: <[u8; 48]>::qp_rand_gen(),
        }
    }
}

impl ValidatorLeafPreimage {
    pub fn from_genesis_entry(chain_id: u32, entry: &ValidatorGenesisEntry) -> anyhow::Result<Self> {
        if entry.realm_sub_id > u8::MAX as u16 {
            anyhow::bail!(
                "validator leaf realm {} sub_id {} exceeds 8-bit tree slot",
                entry.realm_id,
                entry.realm_sub_id
            );
        }
        let node_id = NodeId::from_raw(entry.node_id).map_err(|error| {
            anyhow::anyhow!(
                "invalid validator NodeId for realm {} sub {}: {error}",
                entry.realm_id,
                entry.realm_sub_id
            )
        })?;
        let bls_public_key = BlsPublicKey::from_bytes(&entry.bls_public_key).map_err(|error| {
            anyhow::anyhow!(
                "invalid validator BLS key for realm {} sub {}: {error}",
                entry.realm_id,
                entry.realm_sub_id
            )
        })?;
        Ok(Self {
            chain_id,
            realm_id: entry.realm_id,
            realm_sub_id: entry.realm_sub_id,
            validator_user_id: entry.validator_user_id,
            node_id: *node_id.as_raw(),
            bls_public_key: bls_public_key.to_bytes(),
        })
    }

    pub fn tree_index(&self) -> anyhow::Result<u64> {
        Ok(validator_tree_index(self.realm_id, self.realm_sub_id))
    }

    pub fn to_leaf(&self) -> anyhow::Result<ValidatorLeaf> {
        let node_id = NodeId::from_raw(self.node_id).map_err(|error| {
            anyhow::anyhow!(
                "invalid stored validator NodeId for realm {} sub {}: {error}",
                self.realm_id,
                self.realm_sub_id
            )
        })?;
        let bls_public_key = BlsPublicKey::from_bytes(&self.bls_public_key).map_err(|error| {
            anyhow::anyhow!(
                "invalid stored validator BLS key for realm {} sub {}: {error}",
                self.realm_id,
                self.realm_sub_id
            )
        })?;
        Ok(ValidatorLeaf::new(self.validator_user_id, node_id, bls_public_key))
    }

    pub fn leaf_hash(&self) -> anyhow::Result<[u8; 32]> {
        self.to_leaf()?.leaf_hash().map_err(|error| {
            anyhow::anyhow!(
                "validator leaf hash failed for realm {} sub {}: {error}",
                self.realm_id,
                self.realm_sub_id
            )
        })
    }
}

/// Genesis material for the single validator tree: root, URT-style node FFS,
/// and checkpointed preimages keyed by leaf index.
pub struct ValidatorTreeGenesis<Hash> {
    pub root: Hash,
    pub nodes_ffs: Vec<u8>,
    pub preimages: Vec<ValidatorLeafPreimage>,
}

/// Build the single height-20 tree and its preimages from genesis entries.
pub fn build_validator_tree_genesis<Hasher, Hash>(
    chain_id: u32,
    validators: &[ValidatorGenesisEntry],
) -> anyhow::Result<ValidatorTreeGenesis<Hash>>
where
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug + Q256BitHash,
{
    let mut preimages = Vec::with_capacity(validators.len());
    let mut leaves = Vec::with_capacity(validators.len());
    let mut indexes = HashSet::new();
    let mut user_ids = HashSet::new();
    let mut node_ids = HashSet::new();
    let mut bls_keys = HashSet::new();
    let mut per_realm: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();

    for entry in validators {
        let preimage = ValidatorLeafPreimage::from_genesis_entry(chain_id, entry)?;
        let index = preimage.tree_index()?;
        let hash = preimage.leaf_hash()?;
        anyhow::ensure!(
            indexes.insert(index),
            "duplicate validator tree index {} (realm {} sub {})",
            index,
            preimage.realm_id,
            preimage.realm_sub_id
        );
        anyhow::ensure!(
            user_ids.insert(preimage.validator_user_id),
            "duplicate validator_user_id {} at realm {} sub {}",
            preimage.validator_user_id,
            preimage.realm_id,
            preimage.realm_sub_id
        );
        anyhow::ensure!(
            node_ids.insert(preimage.node_id),
            "duplicate validator NodeId at realm {} sub {}",
            preimage.realm_id,
            preimage.realm_sub_id
        );
        anyhow::ensure!(
            bls_keys.insert(preimage.bls_public_key),
            "duplicate validator BLS key at realm {} sub {}",
            preimage.realm_id,
            preimage.realm_sub_id
        );
        let realm_count = per_realm.entry(preimage.realm_id).or_insert(0);
        *realm_count += 1;
        anyhow::ensure!(
            *realm_count <= MAX_VALIDATORS_PER_REALM,
            "realm {} has more than {MAX_VALIDATORS_PER_REALM} validator leaves",
            preimage.realm_id
        );
        leaves.push(MerkleLeafNode {
            index,
            value: Hash::from_owned_32bytes(hash),
        });
        preimages.push(preimage);
    }

    if leaves.is_empty() {
        return Ok(ValidatorTreeGenesis {
            root: empty_validator_tree_root::<Hasher, Hash>(),
            nodes_ffs: Vec::new(),
            preimages,
        });
    }

    let (root, nodes) = zero_id_merkle_tree_nodes_hash_map_from_leaves::<Hasher, Hash>(
        VALIDATOR_TREE_HEIGHT as u8,
        &leaves,
    );
    Ok(ValidatorTreeGenesis {
        root,
        nodes_ffs: QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_hash_map_to_vec(&nodes),
        preimages,
    })
}

/// Empty-tree root at [`VALIDATOR_TREE_HEIGHT`].
pub fn empty_validator_tree_root<Hasher, Hash>() -> Hash
where
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
{
    Hasher::get_zero_hash(VALIDATOR_TREE_HEIGHT)
}

/// Compute the checkpoint sixth root from genesis validator leaves.
pub fn validator_tree_root_from_genesis<Hasher, Hash>(
    chain_id: u32,
    validators: &[ValidatorGenesisEntry],
) -> anyhow::Result<Hash>
where
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug + Q256BitHash,
{
    Ok(build_validator_tree_genesis::<Hasher, Hash>(chain_id, validators)?.root)
}

/// Known indexes of one realm's 256-slot subtree.
pub fn realm_validator_indexes(realm_id: u32) -> impl Iterator<Item = (u16, u64)> {
    (0u16..=255).map(move |sub_id| (sub_id, validator_tree_index(realm_id, sub_id)))
}

/// Authenticate a stored preimage against a tree leaf hash.
pub fn authenticate_validator_preimage<Hash: Q256BitHash + PartialEq>(
    preimage: &ValidatorLeafPreimage,
    tree_leaf_hash: &Hash,
) -> anyhow::Result<ValidatorLeaf> {
    let leaf = preimage.to_leaf()?;
    let rebuilt = Hash::from_owned_32bytes(preimage.leaf_hash()?);
    anyhow::ensure!(
        &rebuilt == tree_leaf_hash,
        "validator preimage hash mismatch at realm {} sub {}",
        preimage.realm_id,
        preimage.realm_sub_id
    );
    Ok(leaf)
}

/// Require a realm's authenticated validator count to be in Phase 1 range.
pub fn require_realm_validator_count(realm_id: u32, n: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        (MIN_VALIDATORS_PER_REALM..=MAX_VALIDATORS_PER_REALM).contains(&n),
        "realm {realm_id} validator count {n} is outside {MIN_VALIDATORS_PER_REALM}..={MAX_VALIDATORS_PER_REALM}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p_identity::Keypair;
    use parth_core::{PHash, pgoldilocks::PoseidonHasher};

    use crate::p2p::bls::BlsSecretKey;

    fn sample_entry(realm_id: u32, realm_sub_id: u16, seed: u8) -> ValidatorGenesisEntry {
        for i in 0u8..32 {
            let mut bls_seed = [seed; 32];
            bls_seed[1] = i;
            let bls = BlsSecretKey::key_gen(&bls_seed).unwrap().public_key();
            let mut secret = [seed; 32];
            secret[2] = i;
            let node = NodeId::from_keypair(&Keypair::ed25519_from_bytes(&mut secret).unwrap()).unwrap();
            let entry = ValidatorGenesisEntry {
                realm_id,
                realm_sub_id,
                validator_user_id: ((realm_id as u64) << 20) | realm_sub_id as u64,
                node_id: *node.as_raw(),
                bls_public_key: bls.to_bytes(),
            };
            if ValidatorLeafPreimage::from_genesis_entry(1, &entry).is_ok() {
                return entry;
            }
        }
        panic!("failed to sample validator genesis entry");
    }

    #[test]
    fn empty_genesis_is_empty_tree_root() {
        let built = build_validator_tree_genesis::<PoseidonHasher, PHash>(1, &[]).unwrap();
        assert_eq!(built.root, PoseidonHasher::get_zero_hash(VALIDATOR_TREE_HEIGHT));
        assert!(built.nodes_ffs.is_empty());
        assert!(built.preimages.is_empty());
    }

    #[test]
    fn one_tree_two_layers_indexes_by_realm() {
        let entries = vec![
            sample_entry(0, 1, 11),
            sample_entry(0, 2, 12),
            sample_entry(1, 1, 21),
        ];
        let built = build_validator_tree_genesis::<PoseidonHasher, PHash>(1, &entries).unwrap();
        assert!(!built.nodes_ffs.is_empty());
        assert_eq!(built.preimages.len(), 3);
        assert_eq!(built.preimages[0].tree_index().unwrap(), (0u64 << 8) | 1);
        assert_eq!(built.preimages[2].tree_index().unwrap(), (1u64 << 8) | 1);
        let hash = built.preimages[0].leaf_hash().unwrap();
        let leaf_hash = PHash::from_owned_32bytes(hash);
        authenticate_validator_preimage(&built.preimages[0], &leaf_hash).unwrap();
        let realm0: Vec<u16> = built
            .preimages
            .iter()
            .filter(|preimage| preimage.realm_id == 0)
            .map(|preimage| preimage.realm_sub_id)
            .collect();
        assert_eq!(realm0, vec![1, 2]);
    }

    #[test]
    fn rejects_sub_id_over_255() {
        let err = ValidatorLeafPreimage::from_genesis_entry(
            1,
            &ValidatorGenesisEntry {
                realm_id: 0,
                realm_sub_id: 256,
                validator_user_id: 1,
                node_id: [0u8; 38],
                bls_public_key: [0u8; 48],
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds 8-bit"));
    }
}
