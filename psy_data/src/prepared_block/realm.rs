#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use parth_core::{QCoreProcCheckpointUniqueId, crypto::hash::{merkle_proof::MerkleProofCore, tag_tree::TagTreeMerkleProof}};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::v1::qdata::checkpoint_sync::PQEDCheckpointSyncInfoCompact;
use crate::protocol::canonical_chain::{CanonicalChainRef, CANONICAL_CHAIN_REF_V1_LEN};






#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct PsyPreparedRealmBlockStateUpdates<Hash> {
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub old_realm_root: Hash,
    pub new_realm_root: Hash,
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub update_user_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_state_tree_nodes_ffs: Vec<u8>,
    pub update_user_leaves_ffs: Vec<u8>,
    pub update_contract_state_imt_leaves_ffs: Vec<u8>,
}


#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for PsyPreparedRealmBlockStateUpdates<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            realm_id: u64::qp_rand_gen(),
            realm_sub_id: u64::qp_rand_gen(),
            unique_pending_id: u64::qp_rand_gen(),
            proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId::qp_rand_gen(),
            old_realm_root: Hash::qp_rand_gen(),
            new_realm_root: Hash::qp_rand_gen(),
            update_global_user_tree_nodes_ffs: QPGenRandom::qp_rand_gen_vec(32),
            update_user_contract_tree_nodes_ffs: QPGenRandom::qp_rand_gen_vec(32),
            update_contract_state_tree_nodes_ffs: QPGenRandom::qp_rand_gen_vec(32),
            update_user_leaves_ffs: QPGenRandom::qp_rand_gen_vec(32),
            update_contract_state_imt_leaves_ffs: QPGenRandom::qp_rand_gen_vec(32),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyPreparedRealmBlockStateUpdates<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyPreparedRealmBlockStateUpdates<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        let mut size = 0;
        size += 8; // realm_id
        size += 8; // realm_sub_id
        size += 8; // unique_pending_id
        size += 16; // proc_checkpoint_unique_id
        size += 32; // old_realm_root
        size += 32; // new_realm_root

        // Vec<u8> fields: 4 bytes for length + content length
        size += 4 + self.update_global_user_tree_nodes_ffs.len();
        size += 4 + self.update_user_contract_tree_nodes_ffs.len();
        size += 4 + self.update_contract_state_tree_nodes_ffs.len();
        size += 4 + self.update_user_leaves_ffs.len();
        size += 4 + self.update_contract_state_imt_leaves_ffs.len();
        size
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.realm_id)?;
        writer.psy_write_u64(self.realm_sub_id)?;
        writer.psy_write_u64(self.unique_pending_id)?;
        writer.psy_write_u128(self.proc_checkpoint_unique_id)?;

        writer.psy_write_bytes_fixed(&self.old_realm_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_realm_root.into_owned_32bytes())?;

        writer.psy_write_bytes_vec(&self.update_global_user_tree_nodes_ffs)?;
        writer.psy_write_bytes_vec(&self.update_user_contract_tree_nodes_ffs)?;
        writer.psy_write_bytes_vec(&self.update_contract_state_tree_nodes_ffs)?;
        writer.psy_write_bytes_vec(&self.update_user_leaves_ffs)?;
        writer.psy_write_bytes_vec(&self.update_contract_state_imt_leaves_ffs)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let realm_id = reader.psy_read_u64()?;
        let realm_sub_id = reader.psy_read_u64()?;
        let unique_pending_id = reader.psy_read_u64()?;
        let proc_checkpoint_unique_id = reader.psy_read_u128()?;

        let old_realm_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let new_realm_root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);

        let update_global_user_tree_nodes_ffs = reader.psy_read_bytes_vec()?;
        let update_user_contract_tree_nodes_ffs = reader.psy_read_bytes_vec()?;
        let update_contract_state_tree_nodes_ffs = reader.psy_read_bytes_vec()?;
        let update_user_leaves_ffs = reader.psy_read_bytes_vec()?;
        let update_contract_state_imt_leaves_ffs = reader.psy_read_bytes_vec()?;

        Ok(Self {
            realm_id,
            realm_sub_id,
            unique_pending_id,
            proc_checkpoint_unique_id,
            old_realm_root,
            new_realm_root,
            update_global_user_tree_nodes_ffs,
            update_user_contract_tree_nodes_ffs,
            update_contract_state_tree_nodes_ffs,
            update_user_leaves_ffs,
            update_contract_state_imt_leaves_ffs,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyPreparedRealmBlockStateUpdates,
    { Hash: Q256BitHash } => { Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyPreparedRealmBlockStateUpdates<Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyPreparedRealmBlockStateUpdates,
    { parth_core::PHash },
    psy_prepared_realm_block_state_updates_tests
);



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<F, Hash> {
    pub prepared_updates: PsyPreparedRealmBlockStateUpdates<Hash>,
    pub coordinator_update: PsyRealmCoordinatorUpdate<F, Hash>,
}





#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            prepared_updates: PsyPreparedRealmBlockStateUpdates::qp_rand_gen(),
            coordinator_update: PsyRealmCoordinatorUpdate::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.prepared_updates.pio_serialized_size() +
        self.coordinator_update.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.prepared_updates.pio_write_to_io(writer)?;
        self.coordinator_update.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let prepared_updates = PsyPreparedRealmBlockStateUpdates::<Hash>::pio_read_from_io(reader)?;
        let coordinator_update = PsyRealmCoordinatorUpdate::<F, Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            prepared_updates,
            coordinator_update,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate,
    { parth_core::PF, parth_core::PHash },
    psy_prepared_realm_block_state_updates_with_coordinator_update_tests
);






#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyRealmCoordinatorUpdate<F, Hash> {
    // Exact Coordinator branch identity for `checkpoint_sync_info.checkpoint_id`.
    // This is the proof public-input hash, not the checkpoint-tree root/leaf.
    #[ts(type = "{ network_id: number, chain_epoch: bigint, checkpoint: { checkpoint_id: bigint, checkpoint_hash: QHashOut } }")]
    pub canonical_chain_ref: CanonicalChainRef<Hash>,
    pub checkpoint_sync_info: PQEDCheckpointSyncInfoCompact<F, Hash>,
    pub merkle_proof_to_realm_root: MerkleProofCore<Hash>,
    pub reward_tree_top_proof: TagTreeMerkleProof<Hash>,
}





#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyRealmCoordinatorUpdate<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        let checkpoint_sync_info = PQEDCheckpointSyncInfoCompact::qp_rand_gen();
        Self {
            canonical_chain_ref: CanonicalChainRef::new(
                crate::protocol::canonical_chain::NetworkId::try_from_chain_id(0)
                    .expect("local devnet is a supported network"),
                crate::protocol::canonical_chain::ChainEpoch::new(0),
                crate::protocol::canonical_chain::CheckpointRef::new(
                    crate::protocol::canonical_chain::CheckpointId::new(
                        checkpoint_sync_info.checkpoint_id,
                    ),
                    crate::protocol::canonical_chain::CheckpointHash::from_last_chain_hash(
                        Hash::qp_rand_gen(),
                    ),
                ),
            ),
            checkpoint_sync_info,
            merkle_proof_to_realm_root: MerkleProofCore::qp_rand_gen(),
            reward_tree_top_proof: TagTreeMerkleProof::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyRealmCoordinatorUpdate<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyRealmCoordinatorUpdate<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        CANONICAL_CHAIN_REF_V1_LEN +
        self.checkpoint_sync_info.pio_serialized_size() +
        self.merkle_proof_to_realm_root.pio_serialized_size() +
        self.reward_tree_top_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.canonical_chain_ref.to_canonical_bytes())?;
        self.checkpoint_sync_info.pio_write_to_io(writer)?;
        self.merkle_proof_to_realm_root.pio_write_to_io(writer)?;
        self.reward_tree_top_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let canonical_chain_ref_bytes: [u8; CANONICAL_CHAIN_REF_V1_LEN] =
            reader.psy_read_bytes_fixed()?;
        let canonical_chain_ref =
            CanonicalChainRef::from_canonical_bytes(&canonical_chain_ref_bytes)?;
        let checkpoint_sync_info = PQEDCheckpointSyncInfoCompact::<F, Hash>::pio_read_from_io(reader)?;
        let merkle_proof_to_realm_root = MerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let reward_tree_top_proof = TagTreeMerkleProof::<Hash>::pio_read_from_io(reader)?;

        Ok(Self {
            canonical_chain_ref,
            checkpoint_sync_info,
            merkle_proof_to_realm_root,
            reward_tree_top_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyRealmCoordinatorUpdate,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyRealmCoordinatorUpdate<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyRealmCoordinatorUpdate,
    { parth_core::PF, parth_core::PHash },
    psy_realm_coordinator_update_tests
);
