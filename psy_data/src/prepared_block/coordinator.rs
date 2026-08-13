use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleHasher},
    QCoreProcCheckpointUniqueId,
    felt::QFelt64,
    protocol::core_types::Q256BitHash,
};
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{
    FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata,
    PsyIOReadWrite,
};

use crate::{
    prepared_block::common::PsyCoordinatorPendingCheckpointBase,
    protocol::{
        checkpoint_transition_hash::{CheckpointStateHashTransition, CheckpointStateTransitionPublicInputs},
        verifiable_checkpoint_transition::PsyVerifiableCheckpointTransition,
    },
    v1::qdata::contract::ContractCodeDefinitionWithContractId,
};

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyPreparedCoordinatorBlockStateUpdates<F, Hash> {
    pub coordinator_id: u64,
    pub checkpoint_id: u64,
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub old_base: PsyCoordinatorPendingCheckpointBase<F, Hash>,
    pub new_base: PsyCoordinatorPendingCheckpointBase<F, Hash>,

    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,

    pub update_user_registration_tree_nodes_ffs: Vec<u8>,
    pub new_user_public_keys_ffs: Vec<u8>,
    pub new_public_key_hash_to_user_id_rows_ffs: Vec<u8>,

    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub new_realm_guta_reward_tree_node_keys_ffs: Vec<u8>,

    pub checkpoint_tree_update_proof: DeltaMerkleProofCore<Hash>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom
    for PsyPreparedCoordinatorBlockStateUpdates<F, Hash>
{
    fn qp_rand_gen() -> Self {
        Self {
            coordinator_id: QPGenRandom::qp_rand_gen(),
            checkpoint_id: QPGenRandom::qp_rand_gen(),
            unique_pending_id: QPGenRandom::qp_rand_gen(),
            proc_checkpoint_unique_id: QPGenRandom::qp_rand_gen(),
            old_base: QPGenRandom::qp_rand_gen(),
            new_base: QPGenRandom::qp_rand_gen(),
            update_global_contract_tree_nodes_ffs: QPGenRandom::qp_rand_gen_vec(32),
            update_contract_function_tree_nodes_ffs: QPGenRandom::qp_rand_gen_vec(32),
            new_contract_leaves_ffs: QPGenRandom::qp_rand_gen_vec(32),
            new_contract_code_definitions: QPGenRandom::qp_rand_gen_vec(4),
            update_user_registration_tree_nodes_ffs: QPGenRandom::qp_rand_gen_vec(32),
            new_user_public_keys_ffs: QPGenRandom::qp_rand_gen_vec(32),
            new_public_key_hash_to_user_id_rows_ffs: QPGenRandom::qp_rand_gen_vec(32),
            update_global_user_tree_nodes_ffs: QPGenRandom::qp_rand_gen_vec(32),
            new_realm_guta_reward_tree_node_keys_ffs: QPGenRandom::qp_rand_gen_vec(32),
            checkpoint_tree_update_proof: QPGenRandom::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata
    for PsyPreparedCoordinatorBlockStateUpdates<F, Hash>
{
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical
    for PsyPreparedCoordinatorBlockStateUpdates<F, Hash>
{
    fn fallback_pio_serialized_size(&self) -> usize {
        8 + 8 + 8 + 16
            + self.old_base.pio_serialized_size()
            + self.new_base.pio_serialized_size()
            + 4 + self.update_global_contract_tree_nodes_ffs.len()
            + 4 + self.update_contract_function_tree_nodes_ffs.len()
            + 4 + self.new_contract_leaves_ffs.len()
            + 4 + self
                .new_contract_code_definitions
                .iter()
                .map(PsyIOReadWrite::pio_serialized_size)
                .sum::<usize>()
            + 4 + self.update_user_registration_tree_nodes_ffs.len()
            + 4 + self.new_user_public_keys_ffs.len()
            + 4 + self.new_public_key_hash_to_user_id_rows_ffs.len()
            + 4 + self.update_global_user_tree_nodes_ffs.len()
            + 4 + self.new_realm_guta_reward_tree_node_keys_ffs.len()
            + self.checkpoint_tree_update_proof.pio_serialized_size()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(
        &self,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        writer.psy_write_u64(self.coordinator_id)?;
        writer.psy_write_u64(self.checkpoint_id)?;
        writer.psy_write_u64(self.unique_pending_id)?;
        writer.psy_write_u128(self.proc_checkpoint_unique_id)?;
        self.old_base.pio_write_to_io(writer)?;
        self.new_base.pio_write_to_io(writer)?;
        writer.psy_write_bytes_vec(&self.update_global_contract_tree_nodes_ffs)?;
        writer.psy_write_bytes_vec(&self.update_contract_function_tree_nodes_ffs)?;
        writer.psy_write_bytes_vec(&self.new_contract_leaves_ffs)?;
        writer.psy_write_vec_length(self.new_contract_code_definitions.len())?;
        for definition in &self.new_contract_code_definitions {
            definition.pio_write_to_io(writer)?;
        }
        writer.psy_write_bytes_vec(&self.update_user_registration_tree_nodes_ffs)?;
        writer.psy_write_bytes_vec(&self.new_user_public_keys_ffs)?;
        writer.psy_write_bytes_vec(&self.new_public_key_hash_to_user_id_rows_ffs)?;
        writer.psy_write_bytes_vec(&self.update_global_user_tree_nodes_ffs)?;
        writer.psy_write_bytes_vec(&self.new_realm_guta_reward_tree_node_keys_ffs)?;
        self.checkpoint_tree_update_proof.pio_write_to_io(writer)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(
        reader: &mut R,
    ) -> anyhow::Result<Self> {
        let coordinator_id = reader.psy_read_u64()?;
        let checkpoint_id = reader.psy_read_u64()?;
        let unique_pending_id = reader.psy_read_u64()?;
        let proc_checkpoint_unique_id = reader.psy_read_u128()?;
        let old_base = PsyCoordinatorPendingCheckpointBase::pio_read_from_io(reader)?;
        let new_base = PsyCoordinatorPendingCheckpointBase::pio_read_from_io(reader)?;
        let update_global_contract_tree_nodes_ffs = reader.psy_read_bytes_vec()?;
        let update_contract_function_tree_nodes_ffs = reader.psy_read_bytes_vec()?;
        let new_contract_leaves_ffs = reader.psy_read_bytes_vec()?;
        let definition_count = reader.psy_read_vec_length()?;
        if definition_count > 1_048_576 {
            anyhow::bail!(
                "Coordinator prepared update has too many contract definitions: {}",
                definition_count
            );
        }
        let mut new_contract_code_definitions = Vec::with_capacity(definition_count);
        for _ in 0..definition_count {
            new_contract_code_definitions.push(
                ContractCodeDefinitionWithContractId::pio_read_from_io(reader)?,
            );
        }
        let update_user_registration_tree_nodes_ffs = reader.psy_read_bytes_vec()?;
        let new_user_public_keys_ffs = reader.psy_read_bytes_vec()?;
        let new_public_key_hash_to_user_id_rows_ffs = reader.psy_read_bytes_vec()?;
        let update_global_user_tree_nodes_ffs = reader.psy_read_bytes_vec()?;
        let new_realm_guta_reward_tree_node_keys_ffs = reader.psy_read_bytes_vec()?;
        let checkpoint_tree_update_proof = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        Ok(Self {
            coordinator_id,
            checkpoint_id,
            unique_pending_id,
            proc_checkpoint_unique_id,
            old_base,
            new_base,
            update_global_contract_tree_nodes_ffs,
            update_contract_function_tree_nodes_ffs,
            new_contract_leaves_ffs,
            new_contract_code_definitions,
            update_user_registration_tree_nodes_ffs,
            new_user_public_keys_ffs,
            new_public_key_hash_to_user_id_rows_ffs,
            update_global_user_tree_nodes_ffs,
            new_realm_guta_reward_tree_node_keys_ffs,
            checkpoint_tree_update_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyPreparedCoordinatorBlockStateUpdates,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash>
    psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyPreparedCoordinatorBlockStateUpdates<F, Hash>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyPreparedCoordinatorBlockStateUpdates,
    { parth_core::PF, parth_core::PHash },
    psy_prepared_coordinator_block_state_updates_tests
);

impl<F: Copy + PartialEq, Hash: Copy + PartialEq> PsyPreparedCoordinatorBlockStateUpdates<F, Hash> {
    pub fn get_public_inputs_verifiable_state_transition(
        &self,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> PsyVerifiableCheckpointTransition<F, Hash> {
        PsyVerifiableCheckpointTransition {
            state_transition: CheckpointStateTransitionPublicInputs {
                checkpoint_transition: CheckpointStateHashTransition {
                    old_checkpoint_tree_root: self.old_base.checkpoint_tree_root,
                    new_checkpoint_tree_root: self.new_base.checkpoint_tree_root,
                    old_checkpoint_leaf_hash: self.old_base.checkpoint_leaf_hash,
                    new_checkpoint_leaf_hash: self.new_base.checkpoint_leaf_hash,
                },
                genesis_checkpoint_state_transition_hash,
                checkpoint_state_transition_circuit_fingerprint,
            },
            checkpoint_leaf: self.new_base.checkpoint_leaf,
        }
    }
    pub fn get_checkpoint_state_transition_hash<Hasher: MerkleHasher<Hash>>(
        &self,
    ) -> Hash {
        CheckpointStateHashTransition {
            old_checkpoint_tree_root: self.old_base.checkpoint_tree_root,
            new_checkpoint_tree_root: self.new_base.checkpoint_tree_root,
            old_checkpoint_leaf_hash: self.old_base.checkpoint_leaf_hash,
            new_checkpoint_leaf_hash: self.new_base.checkpoint_leaf_hash,
        }
        .get_hash::<Hasher>()
    }
    pub fn get_checkpoint_transition_public_inputs_hash<Hasher: MerkleHasher<Hash>>(
        &self,
        genesis_checkpoint_state_transition_hash: Hash,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> Hash {
        CheckpointStateTransitionPublicInputs {
            checkpoint_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: self.old_base.checkpoint_tree_root,
                new_checkpoint_tree_root: self.new_base.checkpoint_tree_root,
                old_checkpoint_leaf_hash: self.old_base.checkpoint_leaf_hash,
                new_checkpoint_leaf_hash: self.new_base.checkpoint_leaf_hash,
            },
            genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint,
        }
        .get_public_inputs_hash_no_rewards_tag::<Hasher>()
    }
}
