use std::hash::Hash;

use parth_core::crypto::hash::merkle_proof::{DeltaMerkleProofCore, compute_root_merkle_proof_generic};
use parth_core::crypto::hash::traits::{FieldQHasher, QFieldHashable};
use parth_core::felt::QFelt64;
use parth_core::protocol::core_types::Q256BitHash;
use parth_core::protocol::core_types::QFHashBase;
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState};

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointSyncInfoCompact")]
pub struct PQEDCheckpointSyncInfoCompact<F, Hash> {
    pub checkpoint_id: u64,
    pub coordinator_id: u64,
    pub coordinator_sub_id: u64,
    pub coordinator_unique_pending_id: u64,
    pub block_state: QEDL2BlockState,
    pub state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub checkpoint_leaf_hash: Hash,
    pub checkpoint_tree_root: Hash,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PQEDCheckpointSyncInfoCompact<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            checkpoint_id: u64::qp_rand_gen(),
            coordinator_id: u64::qp_rand_gen(),
            coordinator_sub_id: u64::qp_rand_gen(),
            coordinator_unique_pending_id: u64::qp_rand_gen(),
            block_state: QEDL2BlockState::qp_rand_gen(),
            state_roots: PQEDCheckpointGlobalStateRoots::qp_rand_gen(),
            checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            checkpoint_leaf_hash: Hash::qp_rand_gen(),
            checkpoint_tree_root: Hash::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PQEDCheckpointSyncInfoCompact<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 8*4 + QEDL2BlockState::FIXED_SIZE + PQEDCheckpointGlobalStateRoots::<Hash>::FIXED_SIZE + PQEDCheckpointLeaf::<F, Hash>::FIXED_SIZE + 32 + 32;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PQEDCheckpointSyncInfoCompact<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.checkpoint_id)?;
        writer.psy_write_u64(self.coordinator_id)?;
        writer.psy_write_u64(self.coordinator_sub_id)?;
        writer.psy_write_u64(self.coordinator_unique_pending_id)?;
        self.block_state.pio_write_to_io(writer)?;
        self.state_roots.pio_write_to_io(writer)?;
        self.checkpoint_leaf.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.checkpoint_leaf_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_id = reader.psy_read_u64()?;
        let coordinator_id = reader.psy_read_u64()?;
        let coordinator_sub_id = reader.psy_read_u64()?;
        let coordinator_unique_pending_id = reader.psy_read_u64()?;
        
        let block_state = QEDL2BlockState::pio_read_from_io(reader)?;
        let state_roots = PQEDCheckpointGlobalStateRoots::<Hash>::pio_read_from_io(reader)?;
        let checkpoint_leaf = PQEDCheckpointLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let checkpoint_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        Ok(Self {
            checkpoint_id,
            coordinator_id,
            coordinator_sub_id,
            coordinator_unique_pending_id,
            block_state,
            state_roots,
            checkpoint_leaf,
            checkpoint_leaf_hash,
            checkpoint_tree_root,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PQEDCheckpointSyncInfoCompact,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PQEDCheckpointSyncInfoCompact<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PQEDCheckpointSyncInfoCompact,
    { parth_core::PF, parth_core::PHash },
    pqed_checkpoint_sync_info_compact_tests
);


impl<F: QFelt64, Hash: QFHashBase<F>> PQEDCheckpointSyncInfoCompact<F, Hash> {


}
impl<F: QFelt64, Hash: QFHashBase<F>> PQEDCheckpointSyncInfoCompact<F, Hash> {

    pub fn ensure_valid<H: FieldQHasher<F, Hash>>(&self, checkpoint_tree_siblings: &[Hash]) -> anyhow::Result<()> {

        let global_chain_root = self.state_roots.qfhash::<H>();
        if global_chain_root != self.checkpoint_leaf.global_chain_root {
            anyhow::bail!("Invalid global chain root in checkpoint leaf");
        }
        


        let checkpoint_leaf_hash = self.checkpoint_leaf.qfhash::<H>();
        if checkpoint_leaf_hash != self.checkpoint_leaf_hash {
            anyhow::bail!("Invalid checkpoint leaf hash");
        }

        let checkpoint_tree_new_root = compute_root_merkle_proof_generic::<Hash, H>(checkpoint_leaf_hash, self.checkpoint_id, checkpoint_tree_siblings);
        if checkpoint_tree_new_root != self.checkpoint_tree_root {
            anyhow::bail!("Invalid checkpoint tree root");
        }
        Ok(())


    }
}


#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointCoreSyncInfo")]
pub struct PQEDCheckpointCoreSyncInfo<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub checkpoint_leaf_hash: Hash,
    pub l2_block_state: QEDL2BlockState,
    pub checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PQEDCheckpointCoreSyncInfo<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            checkpoint_tree_root: Hash::qp_rand_gen(),
            checkpoint_leaf_hash: Hash::qp_rand_gen(),
            l2_block_state: QEDL2BlockState::qp_rand_gen(),
            checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            state_roots: PQEDCheckpointGlobalStateRoots::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PQEDCheckpointCoreSyncInfo<F, Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 
        32 + // checkpoint_tree_root
        32 + // checkpoint_leaf_hash
        QEDL2BlockState::FIXED_SIZE +
        PQEDCheckpointLeaf::<F, Hash>::FIXED_SIZE +
        PQEDCheckpointGlobalStateRoots::<Hash>::FIXED_SIZE;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PQEDCheckpointCoreSyncInfo<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.checkpoint_leaf_hash.into_owned_32bytes())?;
        self.l2_block_state.pio_write_to_io(writer)?;
        self.checkpoint_leaf.pio_write_to_io(writer)?;
        self.state_roots.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let checkpoint_leaf_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let l2_block_state = QEDL2BlockState::pio_read_from_io(reader)?;
        let checkpoint_leaf = PQEDCheckpointLeaf::<F, Hash>::pio_read_from_io(reader)?;
        let state_roots = PQEDCheckpointGlobalStateRoots::<Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            checkpoint_tree_root,
            checkpoint_leaf_hash,
            l2_block_state,
            checkpoint_leaf,
            state_roots,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PQEDCheckpointCoreSyncInfo,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PQEDCheckpointCoreSyncInfo<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PQEDCheckpointCoreSyncInfo,
    { parth_core::PF, parth_core::PHash },
    pqed_checkpoint_core_sync_info_tests
);


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDCheckpointSyncInfo")]
pub struct PQEDCheckpointSyncInfo<F, Hash> {
    pub core: PQEDCheckpointCoreSyncInfo<F, Hash>,
    pub checkpoint_tree_update_proof: DeltaMerkleProofCore<Hash>,
    pub unique_pending_id: u64,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PQEDCheckpointSyncInfo<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            core: PQEDCheckpointCoreSyncInfo::qp_rand_gen(),
            checkpoint_tree_update_proof: DeltaMerkleProofCore::qp_rand_gen(),
            unique_pending_id: u64::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PQEDCheckpointSyncInfo<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PQEDCheckpointSyncInfo<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.core.pio_serialized_size() + 
        self.checkpoint_tree_update_proof.pio_serialized_size() + 
        8 // unique_pending_id
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.core.pio_write_to_io(writer)?;
        self.checkpoint_tree_update_proof.pio_write_to_io(writer)?;
        writer.psy_write_u64(self.unique_pending_id)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let core = PQEDCheckpointCoreSyncInfo::<F, Hash>::pio_read_from_io(reader)?;
        let checkpoint_tree_update_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let unique_pending_id = reader.psy_read_u64()?;

        Ok(Self {
            core,
            checkpoint_tree_update_proof,
            unique_pending_id,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PQEDCheckpointSyncInfo,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PQEDCheckpointSyncInfo<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PQEDCheckpointSyncInfo,
    { parth_core::PF, parth_core::PHash },
    pqed_checkpoint_sync_info_tests
);

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{pgoldilocks::{PoseidonHasher, QHashOut}, utils::QPGenRandom, PF};

    type Hash = QHashOut<PF>;

    #[test]
    fn compact_sync_validation_accepts_consistent_data_and_rejects_each_commitment() {
        let state_roots = PQEDCheckpointGlobalStateRoots::<Hash>::qp_rand_gen();
        let mut checkpoint_leaf = PQEDCheckpointLeaf::<PF, Hash>::qp_rand_gen();
        checkpoint_leaf.global_chain_root = state_roots.qfhash::<PoseidonHasher>();
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<PoseidonHasher>();
        let siblings = vec![Hash::qp_rand_gen(), Hash::qp_rand_gen()];
        let checkpoint_id = 3;
        let checkpoint_tree_root = compute_root_merkle_proof_generic::<Hash, PoseidonHasher>(checkpoint_leaf_hash, checkpoint_id, &siblings);
        let value = PQEDCheckpointSyncInfoCompact {
            checkpoint_id,
            coordinator_id: 1,
            coordinator_sub_id: 2,
            coordinator_unique_pending_id: 3,
            block_state: QEDL2BlockState::qp_rand_gen(),
            state_roots,
            checkpoint_leaf,
            checkpoint_leaf_hash,
            checkpoint_tree_root,
        };
        value.ensure_valid::<PoseidonHasher>(&siblings).unwrap();
        let mut invalid = value.clone();
        invalid.checkpoint_leaf.global_chain_root = Hash::qp_rand_gen();
        assert!(invalid.ensure_valid::<PoseidonHasher>(&siblings).is_err());
        invalid = value.clone();
        invalid.checkpoint_leaf_hash = Hash::qp_rand_gen();
        assert!(invalid.ensure_valid::<PoseidonHasher>(&siblings).is_err());
        invalid = value.clone();
        invalid.checkpoint_tree_root = Hash::qp_rand_gen();
        assert!(invalid.ensure_valid::<PoseidonHasher>(&siblings).is_err());
        invalid = value.clone();
        // a sibling path that does not derive the recorded root must also fail
        invalid.checkpoint_id += 1;
        assert!(invalid.ensure_valid::<PoseidonHasher>(&siblings).is_err());
    }

    #[test]
    fn ensure_valid_accepts_root_level_leaf_with_empty_sibling_path() {
        let state_roots = PQEDCheckpointGlobalStateRoots::<Hash>::qp_rand_gen();
        let mut checkpoint_leaf = PQEDCheckpointLeaf::<PF, Hash>::qp_rand_gen();
        checkpoint_leaf.global_chain_root = state_roots.qfhash::<PoseidonHasher>();
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<PoseidonHasher>();
        let value = PQEDCheckpointSyncInfoCompact {
            checkpoint_id: 0,
            coordinator_id: 0,
            coordinator_sub_id: 0,
            coordinator_unique_pending_id: 0,
            block_state: QEDL2BlockState::get_genesis_value(),
            state_roots,
            checkpoint_leaf,
            checkpoint_leaf_hash,
            // with no siblings the tree root is the leaf hash itself
            checkpoint_tree_root: checkpoint_leaf_hash,
        };
        value.ensure_valid::<PoseidonHasher>(&[]).unwrap();
    }

    #[test]
    fn compact_core_and_full_sync_info_fallback_round_trips() {
        use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

        // Regression test: the fallback read paths of these sync info types used
        // to be broken twice over — `fallback_pio_read_from_io` mixed manual
        // psy_io reads with children whose `pio_read_from_io` resolved to the
        // buffered speedy stream reader (which over-reads the shared cursor),
        // and PQEDCheckpointSyncInfoCompact parsed state_roots and
        // checkpoint_leaf in the opposite order to how they are written. Both
        // are fixed, so full fallback round trips are asserted below.
        let compact = PQEDCheckpointSyncInfoCompact::<PF, Hash>::qp_rand_gen();
        let compact_bytes = compact.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(compact_bytes.len(), <PQEDCheckpointSyncInfoCompact<PF, Hash> as PsyCanonicalSerializeMetadata>::FIXED_SIZE);
        assert_eq!(PQEDCheckpointSyncInfoCompact::<PF, Hash>::fallback_psy_ser_from_slice(&compact_bytes).unwrap(), compact);
        assert!(PQEDCheckpointSyncInfoCompact::<PF, Hash>::fallback_psy_ser_from_slice(&compact_bytes[..16]).is_err());
        let compact_canonical = compact.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(PQEDCheckpointSyncInfoCompact::psy_ser_from_slice(&compact_canonical).unwrap(), compact);

        let core = PQEDCheckpointCoreSyncInfo::<PF, Hash>::qp_rand_gen();
        let core_bytes = core.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(core_bytes.len(), <PQEDCheckpointCoreSyncInfo<PF, Hash> as PsyCanonicalSerializeMetadata>::FIXED_SIZE);
        assert_eq!(PQEDCheckpointCoreSyncInfo::<PF, Hash>::fallback_psy_ser_from_slice(&core_bytes).unwrap(), core);
        assert!(PQEDCheckpointCoreSyncInfo::<PF, Hash>::fallback_psy_ser_from_slice(&core_bytes[..16]).is_err());
        let core_canonical = core.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(PQEDCheckpointCoreSyncInfo::psy_ser_from_slice(&core_canonical).unwrap(), core);

        let full = PQEDCheckpointSyncInfo::<PF, Hash>::qp_rand_gen();
        let full_bytes = full.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(full_bytes.len(), full.fallback_pio_serialized_size());
        assert_eq!(PQEDCheckpointSyncInfo::<PF, Hash>::fallback_psy_ser_from_slice(&full_bytes).unwrap(), full);
        assert!(PQEDCheckpointSyncInfo::<PF, Hash>::fallback_psy_ser_from_slice(&full_bytes[..16]).is_err());
        let full_canonical = full.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(PQEDCheckpointSyncInfo::psy_ser_from_slice(&full_canonical).unwrap(), full);
    }

    #[test]
    fn sync_info_serde_round_trip() {
        let value = PQEDCheckpointSyncInfo::<PF, Hash>::qp_rand_gen();
        let json = serde_json::to_string(&value).unwrap();
        let restored = serde_json::from_str::<PQEDCheckpointSyncInfo<PF, Hash>>(&json).unwrap();
        assert_eq!(restored, value);
    }
}
