use parth_core::{
    crypto::hash::merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
    felt::{QFelt64, ToU64Value},
    protocol::core_types::{Q256BitHash, QFHashBase},
    utils::QPGenRandom,
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use super::IMTContractStateLeaf;

/// Membership proof: proves key K exists in the IMT with value V.
///
/// Contains the leaf preimage (key, value, next_key, next_index) and a standard
/// merkle proof that the leaf's hash is included in the tree at the given index.
#[pderive::serialize_clone_f_hash_ts]
#[ts(
    export,
    concrete(F = parth_core::PF, Hash = parth_core::PHash),
    rename = "IMTMembershipProof"
)]
pub struct IMTMembershipProof<F, Hash> {
    pub leaf: IMTContractStateLeaf<F, Hash>,
    pub merkle_proof: MerkleProofCore<Hash>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for IMTMembershipProof<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            leaf: IMTContractStateLeaf::qp_rand_gen(),
            merkle_proof: MerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata
    for IMTMembershipProof<F, Hash>
{
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical
    for IMTMembershipProof<F, Hash>
{
    fn fallback_pio_serialized_size(&self) -> usize {
        self.leaf.pio_serialized_size() + self.merkle_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.leaf.pio_write_to_io(writer)?;
        self.merkle_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let leaf = IMTContractStateLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let merkle_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        Ok(Self {
            leaf,
            merkle_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    IMTMembershipProof,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for IMTMembershipProof<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    IMTMembershipProof,
    { parth_core::PF, parth_core::PHash },
    imt_membership_proof_tests
);

/// Non-membership proof: proves key K does NOT exist in the IMT.
///
/// Contains the predecessor leaf (where predecessor.key < K < predecessor.next_key)
/// and a merkle proof that the predecessor leaf hash is included in the tree.
#[pderive::serialize_clone_f_hash_ts]
#[ts(
    export,
    concrete(F = parth_core::PF, Hash = parth_core::PHash),
    rename = "IMTNonMembershipProof"
)]
pub struct IMTNonMembershipProof<F, Hash> {
    pub predecessor_leaf: IMTContractStateLeaf<F, Hash>,
    pub merkle_proof: MerkleProofCore<Hash>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for IMTNonMembershipProof<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            predecessor_leaf: IMTContractStateLeaf::qp_rand_gen(),
            merkle_proof: MerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata
    for IMTNonMembershipProof<F, Hash>
{
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical
    for IMTNonMembershipProof<F, Hash>
{
    fn fallback_pio_serialized_size(&self) -> usize {
        self.predecessor_leaf.pio_serialized_size() + self.merkle_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.predecessor_leaf.pio_write_to_io(writer)?;
        self.merkle_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let predecessor_leaf = IMTContractStateLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let merkle_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        Ok(Self {
            predecessor_leaf,
            merkle_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    IMTNonMembershipProof,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for IMTNonMembershipProof<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    IMTNonMembershipProof,
    { parth_core::PF, parth_core::PHash },
    imt_non_membership_proof_tests
);

/// Result of a predecessor lookup for a given key.
///
/// Used by clients constructing transaction deltas: they need to know the
/// predecessor leaf to properly update the linked list pointers.
#[pderive::serialize_clone_f_hash_ts]
#[ts(
    export,
    concrete(F = parth_core::PF, Hash = parth_core::PHash),
    rename = "IMTPredecessorResult"
)]
pub struct IMTPredecessorResult<F, Hash> {
    pub predecessor_leaf_index: u64,
    pub predecessor_leaf: IMTContractStateLeaf<F, Hash>,
    pub predecessor_merkle_proof: MerkleProofCore<Hash>,
    pub next_append_index: u64,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for IMTPredecessorResult<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            predecessor_leaf_index: u64::qp_rand_gen(),
            predecessor_leaf: IMTContractStateLeaf::qp_rand_gen(),
            predecessor_merkle_proof: MerkleProofCore::qp_rand_gen(),
            next_append_index: u64::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata
    for IMTPredecessorResult<F, Hash>
{
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical
    for IMTPredecessorResult<F, Hash>
{
    fn fallback_pio_serialized_size(&self) -> usize {
        8 + self.predecessor_leaf.pio_serialized_size()
            + self.predecessor_merkle_proof.pio_serialized_size()
            + 8
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.predecessor_leaf_index)?;
        self.predecessor_leaf.pio_write_to_io(writer)?;
        self.predecessor_merkle_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.next_append_index)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let predecessor_leaf_index = reader.psy_read_u64()?;
        let predecessor_leaf = IMTContractStateLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let predecessor_merkle_proof = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let next_append_index = reader.psy_read_u64()?;
        Ok(Self {
            predecessor_leaf_index,
            predecessor_leaf,
            predecessor_merkle_proof,
            next_append_index,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    IMTPredecessorResult,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for IMTPredecessorResult<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    IMTPredecessorResult,
    { parth_core::PF, parth_core::PHash },
    imt_predecessor_result_tests
);

/// Encodes a 256-bit hash (4 Goldilocks field elements) into a comparison-compatible
/// byte representation for sorted storage in ScyllaDB.
///
/// ScyllaDB compares blobs byte-by-byte lexicographically. Native little-endian
/// does not match numerical ordering for multi-limb values. This encoding places
/// the most-significant limb first, with each limb in big-endian byte order.
///
/// Used only for key_to_leaf index table clustering columns.
pub fn encode_imt_key_for_sorting<F: QFelt64, Hash: QFHashBase<F>>(key: &Hash) -> [u8; 32] {
    let felts = key.to_4_felts();
    let mut bytes = [0u8; 32];
    // MSL first, each limb in big-endian
    bytes[0..8].copy_from_slice(&felts[3].to_u64_value().to_be_bytes());
    bytes[8..16].copy_from_slice(&felts[2].to_u64_value().to_be_bytes());
    bytes[16..24].copy_from_slice(&felts[1].to_u64_value().to_be_bytes());
    bytes[24..32].copy_from_slice(&felts[0].to_u64_value().to_be_bytes());
    bytes
}

/// Decodes a comparison-compatible encoded key back to a Hash.
pub fn decode_imt_key_from_sorting<F: QFelt64, Hash: QFHashBase<F>>(bytes: &[u8; 32]) -> Hash {
    let f3 = F::from_u64_value(u64::from_be_bytes(bytes[0..8].try_into().unwrap()));
    let f2 = F::from_u64_value(u64::from_be_bytes(bytes[8..16].try_into().unwrap()));
    let f1 = F::from_u64_value(u64::from_be_bytes(bytes[16..24].try_into().unwrap()));
    let f0 = F::from_u64_value(u64::from_be_bytes(bytes[24..32].try_into().unwrap()));
    Hash::from_4_felts_slice(&[f0, f1, f2, f3])
}

/// Compute the bucket index for a comparison-encoded key.
/// Bucket = first 2 bytes of the sort-encoded key → 65,536 buckets per contract.
/// Returns i16 (ScyllaDB SMALLINT compatible).
pub fn imt_key_bucket(encoded_key: &[u8; 32]) -> i16 {
    i16::from_be_bytes([encoded_key[0], encoded_key[1]])
}

/// Convert u16 bucket to i16 for database storage.
/// u16: 0 to 65535 → i16: -32768 to 32767
pub fn imt_key_bucket_to_i16(bucket: u16) -> i16 {
    (bucket as i32 - 32768) as i16
}

/// Convert i16 bucket from database to u16.
/// i16: -32768 to 32767 → u16: 0 to 65535
pub fn imt_key_bucket_from_i16(bucket: i16) -> u16 {
    (bucket as i32 + 32768) as u16
}

/// FFS entry for IMT leaf preimage data flowing through the pipeline (V1, deprecated).
///
/// Layout (153 bytes):
///   tree_id:      u64       (8 bytes)  -- user_id
///   tree_sub_id:  u64       (8 bytes)  -- contract_id
///   leaf_index:   u64       (8 bytes)  -- append position in tree
///   leaf_hash:    [u8; 32]  (32 bytes) -- computed hash of the leaf
///   leaf_key:     [u8; 32]  (32 bytes) -- the storage key
///   leaf_value:   [u8; 32]  (32 bytes) -- the storage value
///   next_key:     [u8; 32]  (32 bytes) -- successor key
///   is_new_key:   u8        (1 byte)   -- 1 if new insertion (needs key_index write), 0 if update
///
/// Note: next_index is NOT included in V1. Use V2 (161 bytes) which includes next_index explicitly.
pub const IMT_LEAF_FFS_ENTRY_SIZE: usize = 153;

pub fn serialize_imt_leaf_ffs_entry<Hash: Q256BitHash>(
    tree_id: u64,
    tree_sub_id: u64,
    leaf_index: u64,
    leaf_hash: &Hash,
    leaf_key: &Hash,
    leaf_value: &Hash,
    next_key: &Hash,
    _next_index: u64,
    is_new_key: bool,
) -> [u8; IMT_LEAF_FFS_ENTRY_SIZE] {
    let mut bytes = [0u8; IMT_LEAF_FFS_ENTRY_SIZE];
    bytes[0..8].copy_from_slice(&tree_id.to_le_bytes());
    bytes[8..16].copy_from_slice(&tree_sub_id.to_le_bytes());
    bytes[16..24].copy_from_slice(&leaf_index.to_le_bytes());
    bytes[24..56].copy_from_slice(&leaf_hash.into_owned_32bytes());
    bytes[56..88].copy_from_slice(&leaf_key.into_owned_32bytes());
    bytes[88..120].copy_from_slice(&leaf_value.into_owned_32bytes());
    bytes[120..152].copy_from_slice(&next_key.into_owned_32bytes());
    bytes[152] = if is_new_key { 1 } else { 0 };
    bytes
}

/// Extended FFS entry that includes next_index explicitly (161 bytes).
pub const IMT_LEAF_FFS_ENTRY_SIZE_V2: usize = 161;

pub fn serialize_imt_leaf_ffs_entry_v2<Hash: Q256BitHash>(
    tree_id: u64,
    tree_sub_id: u64,
    leaf_index: u64,
    leaf_hash: &Hash,
    leaf_key: &Hash,
    leaf_value: &Hash,
    next_key: &Hash,
    next_index: u64,
    is_new_key: bool,
) -> [u8; IMT_LEAF_FFS_ENTRY_SIZE_V2] {
    let mut bytes = [0u8; IMT_LEAF_FFS_ENTRY_SIZE_V2];
    bytes[0..8].copy_from_slice(&tree_id.to_le_bytes());
    bytes[8..16].copy_from_slice(&tree_sub_id.to_le_bytes());
    bytes[16..24].copy_from_slice(&leaf_index.to_le_bytes());
    bytes[24..56].copy_from_slice(&leaf_hash.into_owned_32bytes());
    bytes[56..88].copy_from_slice(&leaf_key.into_owned_32bytes());
    bytes[88..120].copy_from_slice(&leaf_value.into_owned_32bytes());
    bytes[120..152].copy_from_slice(&next_key.into_owned_32bytes());
    bytes[152..160].copy_from_slice(&next_index.to_le_bytes());
    bytes[160] = if is_new_key { 1 } else { 0 };
    bytes
}

pub fn deserialize_imt_leaf_ffs_entry_v2(
    data: &[u8],
) -> anyhow::Result<(u64, u64, u64, [u8; 32], [u8; 32], [u8; 32], [u8; 32], u64, bool)> {
    if data.len() != IMT_LEAF_FFS_ENTRY_SIZE_V2 {
        anyhow::bail!(
            "Invalid IMT leaf FFS entry size: expected {}, got {}",
            IMT_LEAF_FFS_ENTRY_SIZE_V2,
            data.len()
        );
    }
    let tree_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let tree_sub_id = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let leaf_index = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let leaf_hash: [u8; 32] = data[24..56].try_into().unwrap();
    let leaf_key: [u8; 32] = data[56..88].try_into().unwrap();
    let leaf_value: [u8; 32] = data[88..120].try_into().unwrap();
    let next_key: [u8; 32] = data[120..152].try_into().unwrap();
    let next_index = u64::from_le_bytes(data[152..160].try_into().unwrap());
    let is_new_key = data[160] != 0;
    Ok((
        tree_id, tree_sub_id, leaf_index, leaf_hash, leaf_key, leaf_value, next_key, next_index,
        is_new_key,
    ))
}

/// For IMT contracts, each state update is either an insert or an update.
/// This is used in the end cap submission and circuit verification.

// #[serde(
//     bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize + ts_rs::TS, for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize + ts_rs::TS"
// )]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    speedy::Readable,
    speedy::Writable
)]
#[serde(
    bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize,
             for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize"
)]
pub enum IMTContractStateUpdate<F, Hash> {
    /// Value update: key already exists, only value changes.
    /// Produces one delta merkle proof.
    Update {
        old_preimage: IMTContractStateLeaf<F, Hash>,
        new_preimage: IMTContractStateLeaf<F, Hash>,
        delta_proof: DeltaMerkleProofCore<Hash>,
    },
    /// Key insertion: new key added, predecessor pointers updated.
    /// Produces two delta merkle proofs applied sequentially.
    Insert {
        predecessor_old_preimage: IMTContractStateLeaf<F, Hash>,
        predecessor_new_preimage: IMTContractStateLeaf<F, Hash>,
        new_leaf_preimage: IMTContractStateLeaf<F, Hash>,
        predecessor_delta_proof: DeltaMerkleProofCore<Hash>,
        new_leaf_delta_proof: DeltaMerkleProofCore<Hash>,
    },
}

impl<F, Hash> IMTContractStateUpdate<F, Hash> {
    /// Get the old root before this update.
    pub fn old_root(&self) -> Hash
    where
        Hash: Copy,
    {
        match self {
            IMTContractStateUpdate::Update { delta_proof, .. } => delta_proof.old_root,
            IMTContractStateUpdate::Insert { predecessor_delta_proof, .. } => predecessor_delta_proof.old_root,
        }
    }

    /// Get the new root after this update.
    pub fn new_root(&self) -> Hash
    where
        Hash: Copy,
    {
        match self {
            IMTContractStateUpdate::Update { delta_proof, .. } => delta_proof.new_root,
            IMTContractStateUpdate::Insert { new_leaf_delta_proof, .. } => new_leaf_delta_proof.new_root,
        }
    }
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for IMTContractStateUpdate<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        // Simple approach: randomly choose Update or Insert
        if rand::random::<bool>() {
            IMTContractStateUpdate::Update {
                old_preimage: IMTContractStateLeaf::qp_rand_gen(),
                new_preimage: IMTContractStateLeaf::qp_rand_gen(),
                delta_proof: DeltaMerkleProofCore::qp_rand_gen(),
            }
        } else {
            IMTContractStateUpdate::Insert {
                predecessor_old_preimage: IMTContractStateLeaf::qp_rand_gen(),
                predecessor_new_preimage: IMTContractStateLeaf::qp_rand_gen(),
                new_leaf_preimage: IMTContractStateLeaf::qp_rand_gen(),
                predecessor_delta_proof: DeltaMerkleProofCore::qp_rand_gen(),
                new_leaf_delta_proof: DeltaMerkleProofCore::qp_rand_gen(),
            }
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for IMTContractStateUpdate<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for IMTContractStateUpdate<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        match self {
            IMTContractStateUpdate::Update {
                old_preimage,
                new_preimage,
                delta_proof,
            } => old_preimage.pio_serialized_size() + new_preimage.pio_serialized_size() + delta_proof.pio_serialized_size(),
            IMTContractStateUpdate::Insert {
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            } => {
                predecessor_old_preimage.pio_serialized_size()
                    + predecessor_new_preimage.pio_serialized_size()
                    + new_leaf_preimage.pio_serialized_size()
                    + predecessor_delta_proof.pio_serialized_size()
                    + new_leaf_delta_proof.pio_serialized_size()
            }
        }
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        match self {
            IMTContractStateUpdate::Update {
                old_preimage,
                new_preimage,
                delta_proof,
            } => {
                writer.psy_write_u8(0)?; // variant discriminant
                old_preimage.pio_write_to_io(writer)?;
                new_preimage.pio_write_to_io(writer)?;
                delta_proof.pio_write_to_io(writer)?;
            }
            IMTContractStateUpdate::Insert {
                predecessor_old_preimage,
                predecessor_new_preimage,
                new_leaf_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
            } => {
                writer.psy_write_u8(1)?; // variant discriminant
                predecessor_old_preimage.pio_write_to_io(writer)?;
                predecessor_new_preimage.pio_write_to_io(writer)?;
                new_leaf_preimage.pio_write_to_io(writer)?;
                predecessor_delta_proof.pio_write_to_io(writer)?;
                new_leaf_delta_proof.pio_write_to_io(writer)?;
            }
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let discriminant = reader.psy_read_u8()?;
        match discriminant {
            0 => {
                let old_preimage = IMTContractStateLeaf::<F, Hash>::pio_read_from_io(reader)?;
                let new_preimage = IMTContractStateLeaf::<F, Hash>::pio_read_from_io(reader)?;
                let delta_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
                Ok(IMTContractStateUpdate::Update {
                    old_preimage,
                    new_preimage,
                    delta_proof,
                })
            }
            1 => {
                let predecessor_old_preimage = IMTContractStateLeaf::<F, Hash>::pio_read_from_io(reader)?;
                let predecessor_new_preimage = IMTContractStateLeaf::<F, Hash>::pio_read_from_io(reader)?;
                let new_leaf_preimage = IMTContractStateLeaf::<F, Hash>::pio_read_from_io(reader)?;
                let predecessor_delta_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
                let new_leaf_delta_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
                Ok(IMTContractStateUpdate::Insert {
                    predecessor_old_preimage,
                    predecessor_new_preimage,
                    new_leaf_preimage,
                    predecessor_delta_proof,
                    new_leaf_delta_proof,
                })
            }
            _ => anyhow::bail!("Invalid discriminant for IMTContractStateUpdate"),
        }
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    IMTContractStateUpdate,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for IMTContractStateUpdate<F, Hash>
{
}

/// Contract state update history using Indexed Merkle Trees.
/// Replaces the positional `PsyContractStateUpdateHistory` for all contracts.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    speedy::Readable,
    speedy::Writable
)]
#[serde(
    bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize,
             for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize"
)]
pub struct IMTContractStateUpdateHistory<F, Hash> {
    /// Proof that updates the user's contract tree (maps contract_id -> state
    /// root)
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<Hash>,
    /// IMT contract state tree updates (insert or update operations)
    pub imt_updates: Vec<IMTContractStateUpdate<F, Hash>>,
}

impl<F, Hash> IMTContractStateUpdateHistory<F, Hash> {
    /// Calculate size hint for double_id nodes (IMT/CST updates).
    /// Each IMT update produces delta proofs that contribute to the CST nodes.
    pub fn get_double_id_nodes_size_hint(&self) -> usize {
        if self.imt_updates.is_empty() {
            0
        } else {
            let mut count = 0;
            for update in &self.imt_updates {
                match update {
                    IMTContractStateUpdate::Update { delta_proof, .. } => {
                        // Each update produces siblings.len() + 2 nodes (old leaf + new leaf +
                        // siblings)
                        count += delta_proof.siblings.len() + 2;
                    }
                    IMTContractStateUpdate::Insert {
                        predecessor_delta_proof,
                        new_leaf_delta_proof,
                        ..
                    } => {
                        // Insert produces two delta proofs: predecessor update + new leaf
                        count += predecessor_delta_proof.siblings.len() + 2;
                        count += new_leaf_delta_proof.siblings.len() + 2;
                    }
                }
            }
            count
        }
    }
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for IMTContractStateUpdateHistory<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            user_contract_tree_update_proof: DeltaMerkleProofCore::qp_rand_gen(),
            imt_updates: (0..rand::random::<u8>() as usize % 5)
                .map(|_| IMTContractStateUpdate::qp_rand_gen())
                .collect(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for IMTContractStateUpdateHistory<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for IMTContractStateUpdateHistory<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.user_contract_tree_update_proof.pio_serialized_size() + 4 + self.imt_updates.iter().map(|u| u.pio_serialized_size()).sum::<usize>()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.user_contract_tree_update_proof.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.imt_updates.len())?;
        for update in &self.imt_updates {
            update.pio_write_to_io(writer)?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let user_contract_tree_update_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let len = reader.psy_read_vec_length()?;
        let mut imt_updates = Vec::with_capacity(len);
        for _ in 0..len {
            imt_updates.push(IMTContractStateUpdate::<F, Hash>::pio_read_from_io(reader)?);
        }
        Ok(Self {
            user_contract_tree_update_proof,
            imt_updates,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    IMTContractStateUpdateHistory,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for IMTContractStateUpdateHistory<F, Hash>
{
}

#[cfg(test)]
mod imt_encoding_tests {
    use super::*;
    use parth_core::{PF, PHash};
    use parth_core::felt::{FromPrimitiveValuesFelt, ZeroableFelt};
    use parth_core::crypto::hash::traits::{FromU64x4, ZeroableHash};

    #[test]
    fn test_encode_decode_roundtrip_zero() {
        let key = PHash::get_zero_value();
        let encoded = encode_imt_key_for_sorting::<PF, PHash>(&key);
        let decoded = decode_imt_key_from_sorting::<PF, PHash>(&encoded);
        assert_eq!(key, decoded);
        assert_eq!(encoded, [0u8; 32]);
    }

    #[test]
    fn test_encode_decode_roundtrip_nonzero() {
        let key = PHash::from_u64x4([1, 2, 3, 4]);
        let encoded = encode_imt_key_for_sorting::<PF, PHash>(&key);
        let decoded = decode_imt_key_from_sorting::<PF, PHash>(&encoded);
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_encoding_preserves_ordering_msl() {
        // key_a has smaller MSL (felts[3]) than key_b
        let key_a = PHash::from_u64x4([100, 200, 300, 1]);
        let key_b = PHash::from_u64x4([100, 200, 300, 2]);
        let enc_a = encode_imt_key_for_sorting::<PF, PHash>(&key_a);
        let enc_b = encode_imt_key_for_sorting::<PF, PHash>(&key_b);
        assert!(enc_a < enc_b, "Higher MSL should produce larger encoded bytes");
    }

    #[test]
    fn test_encoding_preserves_ordering_lsl() {
        // Same MSL but different LSL
        let key_a = PHash::from_u64x4([1, 0, 0, 0]);
        let key_b = PHash::from_u64x4([2, 0, 0, 0]);
        let enc_a = encode_imt_key_for_sorting::<PF, PHash>(&key_a);
        let enc_b = encode_imt_key_for_sorting::<PF, PHash>(&key_b);
        assert!(enc_a < enc_b, "Higher LSL should produce larger encoded bytes when MSLs match");
    }

    #[test]
    fn test_encoding_msl_dominates() {
        // key_a has larger LSL but smaller MSL
        let key_a = PHash::from_u64x4([u64::MAX >> 1, u64::MAX >> 1, u64::MAX >> 1, 0]);
        let key_b = PHash::from_u64x4([0, 0, 0, 1]);
        let enc_a = encode_imt_key_for_sorting::<PF, PHash>(&key_a);
        let enc_b = encode_imt_key_for_sorting::<PF, PHash>(&key_b);
        assert!(enc_a < enc_b, "MSL should dominate comparison");
    }

    #[test]
    fn test_bucket_extraction() {
        // Bucket is from first 2 bytes of encoded key (MSL big-endian)
        let key = PHash::from_u64x4([0, 0, 0, 0x0102_0000_0000_0000]);
        let encoded = encode_imt_key_for_sorting::<PF, PHash>(&key);
        let bucket = imt_key_bucket(&encoded);
        assert_eq!(bucket, 0x0102i16);
    }

    #[test]
    fn test_bucket_zero_key() {
        let key = PHash::get_zero_value();
        let encoded = encode_imt_key_for_sorting::<PF, PHash>(&key);
        let bucket = imt_key_bucket(&encoded);
        assert_eq!(bucket, 0i16);
    }

    #[test]
    fn test_ffs_v2_roundtrip() {
        let tree_id = 42u64;
        let tree_sub_id = 7u64;
        let leaf_index = 100u64;
        let leaf_hash = PHash::from_u64x4([1, 2, 3, 4]);
        let leaf_key = PHash::from_u64x4([5, 6, 7, 8]);
        let leaf_value = PHash::from_u64x4([9, 10, 11, 12]);
        let next_key = PHash::from_u64x4([13, 14, 15, 16]);
        let next_index = 50u64;
        let is_new_key = true;

        let serialized = serialize_imt_leaf_ffs_entry_v2(
            tree_id, tree_sub_id, leaf_index,
            &leaf_hash, &leaf_key, &leaf_value, &next_key,
            next_index, is_new_key,
        );
        assert_eq!(serialized.len(), IMT_LEAF_FFS_ENTRY_SIZE_V2);

        let (r_tid, r_tsid, r_li, r_lh, r_lk, r_lv, r_nk, r_ni, r_ink) =
            deserialize_imt_leaf_ffs_entry_v2(&serialized).unwrap();
        assert_eq!(r_tid, tree_id);
        assert_eq!(r_tsid, tree_sub_id);
        assert_eq!(r_li, leaf_index);
        assert_eq!(r_lh, leaf_hash.into_owned_32bytes());
        assert_eq!(r_lk, leaf_key.into_owned_32bytes());
        assert_eq!(r_lv, leaf_value.into_owned_32bytes());
        assert_eq!(r_nk, next_key.into_owned_32bytes());
        assert_eq!(r_ni, next_index);
        assert_eq!(r_ink, is_new_key);
    }

    #[test]
    fn test_ffs_v2_is_new_key_false() {
        let zero_hash = PHash::get_zero_value();
        let serialized = serialize_imt_leaf_ffs_entry_v2(
            0, 0, 0, &zero_hash, &zero_hash, &zero_hash, &zero_hash, 0, false,
        );
        let (_, _, _, _, _, _, _, _, is_new_key) =
            deserialize_imt_leaf_ffs_entry_v2(&serialized).unwrap();
        assert!(!is_new_key);
    }

    #[test]
    fn test_ffs_v2_invalid_size() {
        let result = deserialize_imt_leaf_ffs_entry_v2(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ffs_v2_multiple_entries() {
        let zero_hash = PHash::get_zero_value();
        let entry1 = serialize_imt_leaf_ffs_entry_v2(
            1, 2, 0, &zero_hash, &zero_hash, &zero_hash, &zero_hash, 0, true,
        );
        let entry2 = serialize_imt_leaf_ffs_entry_v2(
            1, 2, 1, &zero_hash, &zero_hash, &zero_hash, &zero_hash, 0, false,
        );

        let mut data = Vec::new();
        data.extend_from_slice(&entry1);
        data.extend_from_slice(&entry2);

        assert_eq!(data.len(), 2 * IMT_LEAF_FFS_ENTRY_SIZE_V2);

        // Parse both entries
        let (tid1, _, li1, _, _, _, _, _, ink1) =
            deserialize_imt_leaf_ffs_entry_v2(&data[0..IMT_LEAF_FFS_ENTRY_SIZE_V2]).unwrap();
        let (tid2, _, li2, _, _, _, _, _, ink2) =
            deserialize_imt_leaf_ffs_entry_v2(&data[IMT_LEAF_FFS_ENTRY_SIZE_V2..]).unwrap();
        assert_eq!(tid1, 1);
        assert_eq!(li1, 0);
        assert!(ink1);
        assert_eq!(tid2, 1);
        assert_eq!(li2, 1);
        assert!(!ink2);
    }
}
