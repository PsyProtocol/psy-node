#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{
    crypto::hash::merkle_proof::DeltaMerkleProofCore,
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{
    proof_input::guta::SubmitUserEndCapNonProofCoreInput,
    v1::qdata::{
        contract::{IMTContractStateUpdate, PSimpleContractHeightCache, PsyContractSlotUpdates, PsySlotUpdate},
        user::PQEDUserLeaf,
    },
};

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize
)]
#[cfg_attr(all(feature = "serialize_speedy", target_endian = "little"), derive(speedy::Readable, speedy::Writable))]
#[serde(
    bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize,
             for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize"
)]
pub enum ContractStateUpdate<F, Hash> {
    Positional {
        delta_proof: DeltaMerkleProofCore<Hash>,
    },
    IMT {
        update: IMTContractStateUpdate<F, Hash>,
    },
}

impl<F: QFelt64, Hash: Q256BitHash> ContractStateUpdate<F, Hash> {
    pub fn old_root(&self) -> Hash {
        match self {
            ContractStateUpdate::Positional { delta_proof } => delta_proof.old_root,
            ContractStateUpdate::IMT { update } => update.old_root(),
        }
    }

    pub fn new_root(&self) -> Hash {
        match self {
            ContractStateUpdate::Positional { delta_proof } => delta_proof.new_root,
            ContractStateUpdate::IMT { update } => update.new_root(),
        }
    }

    pub fn get_double_id_nodes_size_hint(&self) -> usize {
        match self {
            ContractStateUpdate::Positional { delta_proof } => delta_proof.siblings.len() + 2,
            ContractStateUpdate::IMT { update } => match update {
                IMTContractStateUpdate::Update { delta_proof, .. } => delta_proof.siblings.len() + 2,
                IMTContractStateUpdate::Insert {
                    predecessor_delta_proof,
                    new_leaf_delta_proof,
                    ..
                } => predecessor_delta_proof.siblings.len() + 2 + new_leaf_delta_proof.siblings.len() + 2,
            },
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for ContractStateUpdate<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for ContractStateUpdate<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        match self {
            ContractStateUpdate::Positional { delta_proof } => 1 + delta_proof.pio_serialized_size(),
            ContractStateUpdate::IMT { update } => 1 + update.pio_serialized_size(),
        }
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        match self {
            ContractStateUpdate::Positional { delta_proof } => {
                writer.psy_write_u8(0)?;
                delta_proof.pio_write_to_io(writer)?;
            }
            ContractStateUpdate::IMT { update } => {
                writer.psy_write_u8(1)?;
                update.pio_write_to_io(writer)?;
            }
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let variant = reader.psy_read_u8()?;
        match variant {
            0 => Ok(ContractStateUpdate::Positional {
                delta_proof: DeltaMerkleProofCore::pio_read_from_io(reader)?,
            }),
            1 => Ok(ContractStateUpdate::IMT {
                update: IMTContractStateUpdate::pio_read_from_io(reader)?,
            }),
            _ => anyhow::bail!("invalid ContractStateUpdate variant: {}", variant),
        }
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    ContractStateUpdate,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for ContractStateUpdate<F, Hash> {}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize
)]
#[cfg_attr(all(feature = "serialize_speedy", target_endian = "little"), derive(speedy::Readable, speedy::Writable))]
#[serde(
    bound = "for<'de2> F: serde::Deserialize<'de2> + serde::Serialize,
             for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize"
)]
pub struct ContractStateUpdateHistory<F, Hash> {
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<Hash>,
    pub updates: Vec<ContractStateUpdate<F, Hash>>,
}

impl<F: QFelt64, Hash: Q256BitHash> ContractStateUpdateHistory<F, Hash> {
    pub fn get_double_id_nodes_size_hint(&self) -> usize {
        self.updates.iter().map(|u| u.get_double_id_nodes_size_hint()).sum()
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for ContractStateUpdateHistory<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for ContractStateUpdateHistory<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.user_contract_tree_update_proof.pio_serialized_size() + 4 + self.updates.iter().map(|u| u.pio_serialized_size()).sum::<usize>()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.user_contract_tree_update_proof.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.updates.len())?;
        for update in &self.updates {
            update.pio_write_to_io(writer)?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let user_contract_tree_update_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let updates_len = reader.psy_read_vec_length()?;
        let mut updates = Vec::with_capacity(updates_len);
        for _ in 0..updates_len {
            updates.push(ContractStateUpdate::pio_read_from_io(reader)?);
        }
        Ok(Self {
            user_contract_tree_update_proof,
            updates,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    ContractStateUpdateHistory,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for ContractStateUpdateHistory<F, Hash> {}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct SubmitUserEndCapNonProofInput<F, Hash> {
    pub core: SubmitUserEndCapNonProofCoreInput<F, Hash>,
    #[ts(skip)]
    pub contract_state_updates: Vec<ContractStateUpdateHistory<F, Hash>>,
    #[serde(default)]
    pub events: Vec<PsyUserEventRecord<F>>,
}
#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for SubmitUserEndCapNonProofInput<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            core: SubmitUserEndCapNonProofCoreInput::qp_rand_gen(),
            contract_state_updates: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for SubmitUserEndCapNonProofInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for SubmitUserEndCapNonProofInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.core.pio_serialized_size()
            + 4
            + self.contract_state_updates.iter().map(|u| u.pio_serialized_size()).sum::<usize>()
            + 4
            + self.events.iter().map(|e| e.pio_serialized_size()).sum::<usize>()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.core.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.contract_state_updates.len())?;
        for update in &self.contract_state_updates {
            update.pio_write_to_io(writer)?;
        }
        writer.psy_write_vec_length(self.events.len())?;
        for event in &self.events {
            event.pio_write_to_io(writer)?;
        }

        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let core = SubmitUserEndCapNonProofCoreInput::pio_read_from_io(reader)?;
        let updates_len = reader.psy_read_vec_length()?;
        let mut contract_state_updates = Vec::with_capacity(updates_len);
        for _ in 0..updates_len {
            contract_state_updates.push(ContractStateUpdateHistory::pio_read_from_io(reader)?);
        }
        let events_len = reader.psy_read_vec_length()?;
        let mut events = Vec::with_capacity(events_len);
        for _ in 0..events_len {
            events.push(PsyUserEventRecord::pio_read_from_io(reader)?);
        }
        Ok(Self {
            core,
            contract_state_updates,
            events,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    SubmitUserEndCapNonProofInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for SubmitUserEndCapNonProofInput<F, Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    SubmitUserEndCapNonProofInput,
    { parth_core::PF, parth_core::PHash },
    submit_user_end_cap_non_proof_input_ser_tests
);

impl<F: QFelt64, Hash: Q256BitHash + QFHashBase<F> + std::fmt::Debug> SubmitUserEndCapNonProofInput<F, Hash> {
    pub fn ensure_simple_self_consistent<Hasher: FieldQHasher<F, Hash>, C: PSimpleContractHeightCache<Hash>>(
        &self,
        old_user_leaf: &PQEDUserLeaf<F, Hash>,
        proof_public_inputs_hash: Hash,
        contract_helper: &C,
        global_user_tree_height: u8,
        contract_tree_height: usize,
    ) -> anyhow::Result<()> {
        if self.core.checkpoint_id != self.core.new_user_leaf.last_checkpoint_id {
            anyhow::bail!(
                "invalid checkpoint id, left: {}, right: {}",
                self.core.checkpoint_id,
                self.core.new_user_leaf.last_checkpoint_id
            );
        }
        if self.core.new_user_leaf.user_id != self.core.state_transition.user_id {
            anyhow::bail!(
                "inconsistent user id, left: {}, right: {}",
                self.core.new_user_leaf.user_id,
                self.core.state_transition.user_id
            );
        }

        let expected_proof_public_inputs_hash = self.core.get_proof_public_inputs_hash::<Hasher>(global_user_tree_height);
        if proof_public_inputs_hash != expected_proof_public_inputs_hash {
            anyhow::bail!(
                "invalid public inputs/state transition, left: {:?}, right: {:?}",
                proof_public_inputs_hash,
                expected_proof_public_inputs_hash
            );
        }
        let old_leaf_hash = old_user_leaf.qfhash::<Hasher>();
        if !old_user_leaf.is_first_transaction_old_user_leaf() && old_leaf_hash != self.core.state_transition.start_user_leaf_hash {
            anyhow::bail!("invalid old_user_leaf");
        }
        if old_user_leaf.last_checkpoint_id.to_u64_value() != 0
            && old_user_leaf.last_checkpoint_id.to_u64_value() >= self.core.checkpoint_id.to_u64_value()
        {
            anyhow::bail!(
                "old_user_leaf last_checkpoint_id {} is not less than end cap checkpoint_id {}",
                old_user_leaf.last_checkpoint_id.to_u64_value(),
                self.core.checkpoint_id
            );
        }

        let computed_leaf_hash = self.core.new_user_leaf.qfhash::<Hasher>();
        if computed_leaf_hash != self.core.state_transition.end_user_leaf_hash {
            anyhow::bail!("invalid new_user_leaf");
        }
        if self.contract_state_updates.is_empty() {
            anyhow::bail!("contract_state_updates cannot be empty");
        }

        for i in 1..self.contract_state_updates.len() {
            if self.contract_state_updates[i - 1].user_contract_tree_update_proof.new_root
                != self.contract_state_updates[i].user_contract_tree_update_proof.old_root
            {
                anyhow::bail!(
                    "contract_state_updates are not consistent at index {}, left: {:?}, right: {:?}",
                    i,
                    self.contract_state_updates[i - 1].user_contract_tree_update_proof.new_root,
                    self.contract_state_updates[i].user_contract_tree_update_proof.old_root
                );
            }
        }
        let csu_old_root = self.contract_state_updates.first().as_ref().unwrap().user_contract_tree_update_proof.old_root;
        if csu_old_root != old_user_leaf.user_state_tree_root {
            anyhow::bail!(
                "user_state_tree_root does not match the first old root, left: {:?}, right: {:?}",
                csu_old_root,
                old_user_leaf.user_state_tree_root
            );
        }
        let csu_last_new_root = self.contract_state_updates.last().as_ref().unwrap().user_contract_tree_update_proof.new_root;
        if csu_last_new_root != self.core.new_user_leaf.user_state_tree_root {
            anyhow::bail!(
                "user_state_tree_root does not match the last new root, left: {:?}, right: {:?}",
                csu_last_new_root,
                self.core.new_user_leaf.user_state_tree_root
            );
        }

        for csu in self.contract_state_updates.iter() {
            if csu.updates.is_empty() {
                anyhow::bail!("mixed contract updates cannot be empty");
            }
            let cid = csu.user_contract_tree_update_proof.index as u32;
            let expected_height = contract_helper.get_contract_height(cid)? as usize;
            let first_old = csu.updates.first().unwrap().old_root();
            let last_new = csu.updates.last().unwrap().new_root();
            if first_old != csu.user_contract_tree_update_proof.old_value {
                // Fresh contract leaf in UCT is zero, but CST root should be the tree-height zero root.
                if csu.user_contract_tree_update_proof.old_value != Hash::get_zero_value()
                    || first_old != contract_helper.get_contract_zero_hash(cid)?
                {
                    anyhow::bail!("first update old_root does not match user contract tree old_value");
                }
            }
            if last_new != csu.user_contract_tree_update_proof.new_value {
                anyhow::bail!("last update new_root does not match user contract tree new_value");
            }
            for j in 1..csu.updates.len() {
                if csu.updates[j - 1].new_root() != csu.updates[j].old_root() {
                    anyhow::bail!("mixed updates root chain broken at {}", j);
                }
            }
            for update in csu.updates.iter() {
                match update {
                    ContractStateUpdate::Positional { delta_proof } => {
                        if delta_proof.siblings.len() != expected_height {
                            anyhow::bail!("positional proof height mismatch");
                        }
                    }
                    ContractStateUpdate::IMT { update } => match update {
                        IMTContractStateUpdate::Update { delta_proof, .. } => {
                            if delta_proof.siblings.len() != expected_height {
                                anyhow::bail!("imt update proof height mismatch");
                            }
                        }
                        IMTContractStateUpdate::Insert {
                            predecessor_delta_proof,
                            new_leaf_delta_proof,
                            ..
                        } => {
                            if predecessor_delta_proof.siblings.len() != expected_height
                                || new_leaf_delta_proof.siblings.len() != expected_height
                            {
                                anyhow::bail!("imt insert proof height mismatch");
                            }
                        }
                    },
                }
            }
        }

        Ok(())
    }
    pub fn get_needed_contract_zero_hashes(&self) -> Vec<(u64, usize)> {
        self.contract_state_updates
            .iter()
            .filter_map(|x| {
                let first = x.updates.first()?;
                if x.user_contract_tree_update_proof.old_value != Hash::get_zero_value() {
                    return None;
                }
                let h = match first {
                    ContractStateUpdate::Positional { delta_proof } => delta_proof.siblings.len(),
                    ContractStateUpdate::IMT { update } => match update {
                        IMTContractStateUpdate::Update { delta_proof, .. } => delta_proof.siblings.len(),
                        IMTContractStateUpdate::Insert {
                            predecessor_delta_proof,
                            ..
                        } => predecessor_delta_proof.siblings.len(),
                    },
                };
                Some((x.user_contract_tree_update_proof.index, h))
            })
            .collect()
    }
    pub fn single_id_nodes_size_hint_in_nodes_modified(&self, contract_tree_height: usize) -> usize {
        self.contract_state_updates.len() * (1 + contract_tree_height) + 1
    }
    pub fn double_id_nodes_size_hint_in_nodes_modified(&self) -> usize {
        self.contract_state_updates
            .iter()
            .map(|csu| csu.get_double_id_nodes_size_hint())
            .sum()
    }

    pub fn get_slot_updates(&self) -> anyhow::Result<Vec<PsyContractSlotUpdates<F>>>
    where
        Hash: QFHashBase<F>,
    {
        let contract_updates = self
            .contract_state_updates
            .iter()
            .map(|contract_update| {
                let slot_updates = contract_update
                    .updates
                    .iter()
                    .flat_map(|update| match update {
                        ContractStateUpdate::Positional { delta_proof } => {
                            delta_proof_to_slot_updates::<F, Hash>(delta_proof)
                        }
                        ContractStateUpdate::IMT { update } => match update {
                            IMTContractStateUpdate::Update { delta_proof, .. } => {
                                delta_proof_to_slot_updates::<F, Hash>(delta_proof)
                            }
                            IMTContractStateUpdate::Insert {
                                predecessor_delta_proof,
                                new_leaf_delta_proof,
                                ..
                            } => {
                                // An insert touches two leaves: the predecessor
                                // (its next_key/next_index pointers change) and the
                                // newly appended leaf. Each carries its own delta proof
                                // against the contract state tree, so both are emitted.
                                let mut updates = delta_proof_to_slot_updates::<F, Hash>(
                                    predecessor_delta_proof,
                                );
                                updates.extend(delta_proof_to_slot_updates::<F, Hash>(
                                    new_leaf_delta_proof,
                                ));
                                updates
                            }
                        },
                    })
                    .collect::<Vec<_>>();

                PsyContractSlotUpdates {
                    contract_id: contract_update.user_contract_tree_update_proof.index as u32,
                    slot_updates,
                }
            })
            .filter(|contract_update| !contract_update.slot_updates.is_empty())
            .collect();

        Ok(contract_updates)
    }
    /*
    pub fn verify_and_generate_cst_updates<H: FieldQHasher<F, Hash>>(&self, checkpoint_id: u64, old_user_state_tree_root: Hash) -> anyhow::Result<CSTUserUpdate<Hash>> {

        if self.contract_state_updates.len() == 0 {
            anyhow::bail!("contract_state_updates cannot be empty");
        }


        if self.contract_state_updates[0].user_contract_tree_update_proof.old_root != old_user_state_tree_root {

            anyhow::bail!("old_user_state_tree_root does not match the first old root ({:?}, {:?})",self.contract_state_updates[0].user_contract_tree_update_proof.old_root,old_user_state_tree_root);
        }
        let mut injestor = CSTUserUpdateStore::<Hash>::new();

        for csu in self.contract_state_updates.iter() {
            csu.verify_generate_cst_delta::<H>(&mut injestor)?;
        }

        let upd = injestor.into_updates(checkpoint_id, self.core.state_transition.user_id.to_canonical_u64());



        Ok(upd)
    }
    */
}

/// Decompose a contract state tree delta proof into felt-level slot updates.
///
/// Each leaf in the contract state tree occupies 4 storage slots (one per felt of
/// its 256-bit hash value); only the felts that actually change are emitted. This
/// is shared by positional updates and IMT updates, since an IMT leaf is stored in
/// the contract state tree as its leaf hash at `delta_proof.index` — the exact same
/// layout a positional value uses.
fn delta_proof_to_slot_updates<F, Hash>(
    delta_proof: &DeltaMerkleProofCore<Hash>,
) -> Vec<PsySlotUpdate<F>>
where
    F: QFelt64,
    Hash: QFHashBase<F>,
{
    let old_elements = delta_proof.old_value.to_4_felts();
    let new_elements = delta_proof.new_value.to_4_felts();
    old_elements
        .iter()
        .zip(new_elements.iter())
        .enumerate()
        .filter(|(_, (old, new))| old != new)
        .map(|(offset, (old, new))| PsySlotUpdate {
            slot: delta_proof.index * 4 + offset as u64,
            old_value: *old,
            new_value: *new,
        })
        .collect()
}

#[pderive::serialize_clone_f_ts]
#[ts(export, concrete(F = parth_core::PF))]
pub struct PsyUserEventRecord<F> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub contract_id: F,
    pub method_id: F,
    pub event_index: F,
    pub data: Vec<F>,
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom> QPGenRandom for PsyUserEventRecord<F> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            checkpoint_id: F::qp_rand_gen(),
            user_id: F::qp_rand_gen(),
            contract_id: F::qp_rand_gen(),
            method_id: F::qp_rand_gen(),
            event_index: F::qp_rand_gen(),
            data: QPGenRandom::qp_rand_gen_vec(rand::random::<u8>() as usize % 10 + 1),
        }
    }
}

impl<F: QFelt64> PsyCanonicalSerializeMetadata for PsyUserEventRecord<F> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64> FallbackPsySerializeCanonical for PsyUserEventRecord<F> {
    fn fallback_pio_serialized_size(&self) -> usize {
        // 5 u64 fields (40 bytes) + vec_length u32 (4 bytes) + data.len() u64s
        5 * 8 + 4 + self.data.len() * 8
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.checkpoint_id.to_u64_value())?;
        writer.psy_write_u64(self.user_id.to_u64_value())?;
        writer.psy_write_u64(self.contract_id.to_u64_value())?;
        writer.psy_write_u64(self.method_id.to_u64_value())?;
        writer.psy_write_u64(self.event_index.to_u64_value())?;
        writer.psy_write_vec_length(self.data.len())?;
        for data in &self.data {
            writer.psy_write_u64(data.to_u64_value())?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_id = F::from_u64_value(reader.psy_read_u64()?);
        let user_id = F::from_u64_value(reader.psy_read_u64()?);
        let contract_id = F::from_u64_value(reader.psy_read_u64()?);
        let method_id = F::from_u64_value(reader.psy_read_u64()?);
        let event_index = F::from_u64_value(reader.psy_read_u64()?);
        let data_len = reader.psy_read_vec_length()?;
        let mut data = Vec::with_capacity(data_len);
        for _ in 0..data_len {
            data.push(F::from_u64_value(reader.psy_read_u64()?));
        }
        Ok(Self {
            checkpoint_id,
            user_id,
            contract_id,
            method_id,
            event_index,
            data,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyUserEventRecord,
    { F: QFelt64 } => { F }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyUserEventRecord<F> {}

#[cfg(test)]
pub mod gen_fake_data {
    use parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
        felt::QFelt64,
        protocol::core_types::{Q256BitHash, QFHashBase, QFHasherU64},
        utils::QPGenRandom,
    };

    use crate::{
        guta::stats::GUTAStats,
        proof_input::guta::{
            end_cap_input::{ContractStateUpdate, ContractStateUpdateHistory, SubmitUserEndCapNonProofInput},
            SubmitUserEndCapNonProofCoreInput,
        },
        v1::qdata::{
            contract::PSimpleContractHeightCache,
            user::PQEDUserLeaf,
            user_end_cap_result::PUPSEndCapResultCompact,
        },
    };

    /// test-only stand-in for DashMapContractHeightCache so tests build
    /// without the node feature (and its dashmap dependency)
    #[derive(Default)]
    pub struct TestContractHeightCache<Hash> {
        mapping: std::sync::Mutex<std::collections::HashMap<u32, (u8, Hash)>>,
    }

    impl<Hash> TestContractHeightCache<Hash> {
        pub fn new() -> Self {
            Self { mapping: std::sync::Mutex::new(std::collections::HashMap::new()) }
        }
    }

    impl<Hash: Clone> PSimpleContractHeightCache<Hash> for TestContractHeightCache<Hash> {
        fn add_contract(&self, contract_id: u32, height: u8, zero_hash: Hash) {
            self.mapping.lock().unwrap().insert(contract_id, (height, zero_hash));
        }
        fn get_contract_height(&self, contract_id: u32) -> anyhow::Result<u8> {
            match self.mapping.lock().unwrap().get(&contract_id) {
                Some(x) => Ok(x.0),
                None => anyhow::bail!("contract {} not loaded", contract_id),
            }
        }
        fn get_contract_zero_hash(&self, contract_id: u32) -> anyhow::Result<Hash> {
            match self.mapping.lock().unwrap().get(&contract_id) {
                Some(x) => Ok(x.1.clone()),
                None => anyhow::bail!("contract {} not loaded", contract_id),
            }
        }
    }

    pub fn gen_fake_valid_submit_user_end_cap_non_proof_input<F, Hash, Hasher>(
        global_user_tree_height: u8,
        contract_tree_height: u8,
    ) -> (
        PQEDUserLeaf<F, Hash>,
        SubmitUserEndCapNonProofInput<F, Hash>,
        TestContractHeightCache<Hash>,
    )
    where
        F: QFelt64,
        Hash: Q256BitHash + QFHashBase<F> + QPGenRandom,
        Hasher: QFHasherU64<F, Hash> + MerkleZeroHasher<Hash>,
    {
        let mut user_contract_tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(contract_tree_height);
        let contract_helper = TestContractHeightCache::new();

        let mut contract_trees = (0..5)
            .map(|i| {
                let contract_state_tree_height = 24 + i as u8;
                let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(contract_state_tree_height);
                let max_leaf_id = 1u64 << contract_state_tree_height;
                contract_helper.add_contract(i as u32, contract_state_tree_height, tree.get_root());

                for _ in 0..1000 {
                    let rand_leaf_id = rand::random::<u64>() % max_leaf_id;
                    tree.set_leaf(rand_leaf_id, Hash::qp_rand_gen());
                }
                user_contract_tree.set_leaf(i as u64, tree.get_root());
                tree
            })
            .collect::<Vec<_>>();
        let old_user_contract_tree_root = user_contract_tree.get_root();
        let user_id = 42u64;
        let user_id_f = F::from_owned_u64(user_id);
        let old_checkpoint_id = 7u64;
        let old_checkpoint_id_f = F::from_owned_u64(old_checkpoint_id);

        let new_checkpoint_id = old_checkpoint_id + 1000;
        let new_checkpoint_id_f = F::from_owned_u64(new_checkpoint_id);

        let public_key = Hash::qp_rand_gen();
        let balance = F::from_owned_u64(1_000_000);
        let old_nonce = F::from_owned_u64(55);
        let event_index = F::from_owned_u64(1234);

        let old_user_leaf = PQEDUserLeaf {
            user_id: user_id_f,
            last_checkpoint_id: old_checkpoint_id_f,
            user_state_tree_root: old_user_contract_tree_root,
            public_key,
            balance,
            nonce: old_nonce,
            event_index,
        };
        let start_user_leaf_hash = old_user_leaf.qfhash::<Hasher>();

        let mut contract_state_updates = vec![];
        contract_trees.iter_mut().enumerate().for_each(|(i, ctree)| {
            let leaf_count = ctree.get_max_leaf_index() + 1;
            let contract_state_tree_updates = (0..50)
                .map(|_| {
                    let rand_leaf_id = rand::random::<u64>() % leaf_count;
                    ctree.set_leaf(rand_leaf_id, Hash::qp_rand_gen())
                })
                .collect::<Vec<_>>();
            let end_root = ctree.get_root();
            let user_contract_tree_update_proof = user_contract_tree.set_leaf(i as u64, end_root);
            contract_state_updates.push(ContractStateUpdateHistory {
                user_contract_tree_update_proof,
                updates: contract_state_tree_updates
                    .into_iter()
                    .map(|delta_proof| ContractStateUpdate::Positional { delta_proof })
                    .collect(),
            });
        });

        let new_user_contract_tree_root = user_contract_tree.get_root();
        let new_user_leaf = PQEDUserLeaf {
            user_id: user_id_f,
            last_checkpoint_id: new_checkpoint_id_f,
            user_state_tree_root: new_user_contract_tree_root,
            public_key,
            balance,
            nonce: F::from_owned_u64(56),
            event_index: F::from_owned_u64(1235),
        };
        let end_user_leaf_hash = new_user_leaf.qfhash::<Hasher>();

        let new_checkpoint_tree_root = Hash::qp_rand_gen();
        let state_transition = PUPSEndCapResultCompact {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash: new_checkpoint_tree_root,
            user_id: user_id_f,
        };

        let guta_stats = GUTAStats {
            guta_fees_collected: F::from_owned_u64(1000 * 50 * contract_trees.len() as u64),
            da_fees_collected: F::from_owned_u64(1000),
            user_ops_processed: F::from_owned_u64(1),
            total_transactions: F::from_owned_u64(contract_trees.len() as u64),
            slots_modified: F::from_owned_u64(50 * contract_trees.len() as u64),
        };

        let core = SubmitUserEndCapNonProofCoreInput {
            checkpoint_id: new_checkpoint_id_f,
            state_transition,
            new_user_leaf,
            stats: guta_stats,
        };

        let input = SubmitUserEndCapNonProofInput {
            core,
            contract_state_updates,
            events: vec![],
        };

        let public_inputs_hash = input.core.get_proof_public_inputs_hash::<Hasher>(global_user_tree_height);
        input
            .ensure_simple_self_consistent::<Hasher, _>(
                &old_user_leaf,
                public_inputs_hash,
                &contract_helper,
                global_user_tree_height,
                contract_tree_height as usize,
            )
            .unwrap();
        assert!(input
            .ensure_simple_self_consistent::<Hasher, _>(
                &old_user_leaf,
                public_inputs_hash,
                &contract_helper,
                global_user_tree_height,
                contract_tree_height as usize
            )
            .is_ok());

        (old_user_leaf, input, contract_helper)
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::{
            merkle_proof::DeltaMerkleProofCore,
            traits::{FromU64x4, HashTo4Felts, QFieldHashable, ZeroableHash},
        },
        felt::ToU64Value,
        pgoldilocks::PoseidonHasher,
        utils::QPGenRandom,
        PF, PHash,
    };
    use psy_io::Cursor;
    use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseSingle};

    use super::{PsyUserEventRecord, SubmitUserEndCapNonProofInput};
    use crate::{
        proof_input::guta::{
            end_cap_input::{gen_fake_data::gen_fake_valid_submit_user_end_cap_non_proof_input, ContractStateUpdate, ContractStateUpdateHistory},
            SubmitUserEndCapNonProofCoreInput,
        },
        v1::qdata::contract::{IMTContractStateLeaf, IMTContractStateUpdate, PSimpleContractHeightCache},
    };

    fn delta(old: u64, new: u64, siblings: usize) -> DeltaMerkleProofCore<PHash> {
        let hash = |value| PHash::from_u64x4([value, 0, 0, 0]);
        DeltaMerkleProofCore {
            old_root: hash(old),
            old_value: PHash::get_zero_value(),
            new_root: hash(new),
            new_value: PHash::get_zero_value(),
            index: 0,
            siblings: vec![PHash::get_zero_value(); siblings],
        }
    }

    #[test]
    fn generate_simple_input() {
        type Hash = PHash;
        type F = parth_core::PF;
        type Hasher = PoseidonHasher;
        let (old_user_leaf, input, contract_helper) = gen_fake_valid_submit_user_end_cap_non_proof_input::<F, Hash, Hasher>(32, 30);

        let proof_public_inputs_hash = input.core.get_proof_public_inputs_hash::<Hasher>(32);

        assert!(input
            .ensure_simple_self_consistent::<Hasher, _>(&old_user_leaf, proof_public_inputs_hash, &contract_helper, 32, 30)
            .is_ok());
    }

    #[test]
    fn contract_update_variants_expose_roots_and_node_hints() {
        let positional = ContractStateUpdate::<PF, PHash>::Positional {
            delta_proof: delta(1, 2, 3),
        };
        let leaf = IMTContractStateLeaf::<PF, PHash>::default();
        let imt = ContractStateUpdate::IMT {
            update: IMTContractStateUpdate::Update {
                old_preimage: leaf.clone(),
                new_preimage: leaf,
                delta_proof: delta(3, 4, 2),
            },
        };
        assert_eq!(positional.old_root(), PHash::from_u64x4([1, 0, 0, 0]));
        assert_eq!(positional.new_root(), PHash::from_u64x4([2, 0, 0, 0]));
        assert_eq!(positional.get_double_id_nodes_size_hint(), 5);
        assert_eq!(imt.old_root(), PHash::from_u64x4([3, 0, 0, 0]));
        assert_eq!(imt.new_root(), PHash::from_u64x4([4, 0, 0, 0]));
        assert_eq!(imt.get_double_id_nodes_size_hint(), 4);

        let history = ContractStateUpdateHistory {
            user_contract_tree_update_proof: delta(0, 0, 0),
            updates: vec![positional, imt],
        };
        assert_eq!(history.get_double_id_nodes_size_hint(), 9);
    }

    #[test]
    fn imt_insert_variant_exposes_roots_and_node_hints() {
        let insert = ContractStateUpdate::<PF, PHash>::IMT {
            update: IMTContractStateUpdate::Insert {
                predecessor_old_preimage: IMTContractStateLeaf::default(),
                predecessor_new_preimage: IMTContractStateLeaf::default(),
                new_leaf_preimage: IMTContractStateLeaf::default(),
                predecessor_delta_proof: delta(10, 11, 2),
                new_leaf_delta_proof: delta(20, 21, 3),
            },
        };
        assert_eq!(insert.old_root(), PHash::from_u64x4([10, 0, 0, 0]));
        assert_eq!(insert.new_root(), PHash::from_u64x4([21, 0, 0, 0]));
        // predecessor siblings (2) + 2 + new leaf siblings (3) + 2
        assert_eq!(insert.get_double_id_nodes_size_hint(), 9);

        let history = ContractStateUpdateHistory {
            user_contract_tree_update_proof: delta(0, 0, 0),
            updates: vec![insert],
        };
        assert_eq!(history.get_double_id_nodes_size_hint(), 9);
    }

    fn assert_ensure_err(result: anyhow::Result<()>, needle: &str) {
        let err = result.unwrap_err();
        assert!(err.to_string().contains(needle), "unexpected error: {}", err);
    }

    fn positional_parts(update: &ContractStateUpdate<PF, PHash>) -> (PHash, PHash, u64, Vec<PHash>) {
        match update {
            ContractStateUpdate::Positional { delta_proof } => {
                (delta_proof.old_root, delta_proof.new_root, delta_proof.index, delta_proof.siblings.clone())
            }
            _ => panic!("expected positional update"),
        }
    }

    #[test]
    fn ensure_rejects_core_state_mismatches() {
        let (old_user_leaf, input, contract_helper) =
            gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);
        let hash = input.core.get_proof_public_inputs_hash::<PoseidonHasher>(32);
        assert!(input
            .ensure_simple_self_consistent::<PoseidonHasher, _>(&old_user_leaf, hash, &contract_helper, 32, 30)
            .is_ok());

        // checkpoint id no longer matches the new leaf's last_checkpoint_id
        let mut bad = input.clone();
        bad.core.checkpoint_id = PF::from_owned_u64(6);
        assert_ensure_err(
            bad.ensure_simple_self_consistent::<PoseidonHasher, _>(&old_user_leaf, hash, &contract_helper, 32, 30),
            "invalid checkpoint id",
        );

        // new leaf user id no longer matches the state transition user id
        let mut bad = input.clone();
        bad.core.new_user_leaf.user_id = PF::from_owned_u64(43);
        assert_ensure_err(
            bad.ensure_simple_self_consistent::<PoseidonHasher, _>(&old_user_leaf, hash, &contract_helper, 32, 30),
            "inconsistent user id",
        );

        // wrong public inputs hash supplied by the caller
        assert_ensure_err(
            input.ensure_simple_self_consistent::<PoseidonHasher, _>(
                &old_user_leaf,
                PHash::from_u64x4([1, 2, 3, 4]),
                &contract_helper,
                32,
                30,
            ),
            "invalid public inputs/state transition",
        );

        // old leaf hash no longer matches the recorded start hash
        let mut stale_leaf = old_user_leaf.clone();
        stale_leaf.balance = PF::from_owned_u64(2);
        assert_ensure_err(
            input.ensure_simple_self_consistent::<PoseidonHasher, _>(&stale_leaf, hash, &contract_helper, 32, 30),
            "invalid old_user_leaf",
        );

        // new leaf hash no longer matches the recorded end hash
        let mut bad = input.clone();
        bad.core.new_user_leaf.nonce = PF::from_owned_u64(999);
        assert_ensure_err(
            bad.ensure_simple_self_consistent::<PoseidonHasher, _>(&old_user_leaf, hash, &contract_helper, 32, 30),
            "invalid new_user_leaf",
        );
    }

    #[test]
    fn ensure_rejects_stale_old_leaf_checkpoint() {
        let (old_user_leaf, input, contract_helper) =
            gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);

        // Equal checkpoint ids trip the "not strictly less" rule; the start hash and
        // the public inputs hash are recomputed so the earlier checks pass.
        let mut stale_leaf = old_user_leaf.clone();
        stale_leaf.last_checkpoint_id = input.core.checkpoint_id;
        let mut bad = input.clone();
        bad.core.state_transition.start_user_leaf_hash = stale_leaf.qfhash::<PoseidonHasher>();
        let stale_hash = bad.core.get_proof_public_inputs_hash::<PoseidonHasher>(32);
        assert_ensure_err(
            bad.ensure_simple_self_consistent::<PoseidonHasher, _>(&stale_leaf, stale_hash, &contract_helper, 32, 30),
            "is not less than end cap checkpoint_id",
        );
    }

    #[test]
    fn ensure_rejects_empty_and_inconsistent_contract_update_histories() {
        let (old_user_leaf, input, contract_helper) =
            gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);
        let hash = input.core.get_proof_public_inputs_hash::<PoseidonHasher>(32);
        let ensure = |input: &SubmitUserEndCapNonProofInput<PF, PHash>| {
            input.ensure_simple_self_consistent::<PoseidonHasher, _>(&old_user_leaf, hash, &contract_helper, 32, 30)
        };

        let mut bad = input.clone();
        bad.contract_state_updates = vec![];
        assert_ensure_err(ensure(&bad), "contract_state_updates cannot be empty");

        let mut bad = input.clone();
        bad.contract_state_updates[1].user_contract_tree_update_proof.old_root = PHash::from_u64x4([7, 7, 7, 7]);
        assert_ensure_err(ensure(&bad), "contract_state_updates are not consistent at index 1");

        let mut bad = input.clone();
        bad.contract_state_updates[0].user_contract_tree_update_proof.old_root = PHash::from_u64x4([8, 8, 8, 8]);
        assert_ensure_err(ensure(&bad), "user_state_tree_root does not match the first old root");

        let mut bad = input.clone();
        let last = bad.contract_state_updates.len() - 1;
        bad.contract_state_updates[last].user_contract_tree_update_proof.new_root = PHash::from_u64x4([9, 9, 9, 9]);
        assert_ensure_err(ensure(&bad), "user_state_tree_root does not match the last new root");

        let mut bad = input.clone();
        bad.contract_state_updates[2].updates = vec![];
        assert_ensure_err(ensure(&bad), "mixed contract updates cannot be empty");
    }

    #[test]
    fn ensure_rejects_broken_update_chains_within_history() {
        let (old_user_leaf, input, contract_helper) =
            gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);
        let hash = input.core.get_proof_public_inputs_hash::<PoseidonHasher>(32);
        let ensure = |input: &SubmitUserEndCapNonProofInput<PF, PHash>| {
            input.ensure_simple_self_consistent::<PoseidonHasher, _>(&old_user_leaf, hash, &contract_helper, 32, 30)
        };

        let mut bad = input.clone();
        if let ContractStateUpdate::Positional { delta_proof } = &mut bad.contract_state_updates[1].updates[0] {
            delta_proof.old_root = PHash::from_u64x4([1, 1, 1, 1]);
        }
        assert_ensure_err(ensure(&bad), "first update old_root does not match user contract tree old_value");

        let mut bad = input.clone();
        let update_count = bad.contract_state_updates[1].updates.len();
        if let ContractStateUpdate::Positional { delta_proof } = &mut bad.contract_state_updates[1].updates[update_count - 1] {
            delta_proof.new_root = PHash::from_u64x4([2, 2, 2, 2]);
        }
        assert_ensure_err(ensure(&bad), "last update new_root does not match user contract tree new_value");

        let mut bad = input.clone();
        if let ContractStateUpdate::Positional { delta_proof } = &mut bad.contract_state_updates[1].updates[25] {
            delta_proof.old_root = PHash::from_u64x4([3, 3, 3, 3]);
        }
        assert_ensure_err(ensure(&bad), "mixed updates root chain broken at 25");
    }

    #[test]
    fn ensure_rejects_proof_height_mismatches() {
        let (old_user_leaf, input, contract_helper) =
            gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);
        let hash = input.core.get_proof_public_inputs_hash::<PoseidonHasher>(32);
        let ensure = |input: &SubmitUserEndCapNonProofInput<PF, PHash>| {
            input.ensure_simple_self_consistent::<PoseidonHasher, _>(&old_user_leaf, hash, &contract_helper, 32, 30)
        };

        // positional update carrying one sibling too many
        let mut bad = input.clone();
        if let ContractStateUpdate::Positional { delta_proof } = &mut bad.contract_state_updates[1].updates[10] {
            delta_proof.siblings.push(PHash::get_zero_value());
        }
        assert_ensure_err(ensure(&bad), "positional proof height mismatch");

        // IMT update whose delta proof is one level too deep, roots preserved so the chain stays intact
        let (old_root, new_root, index, siblings) = positional_parts(&input.contract_state_updates[1].updates[12]);
        let mut wrong_siblings = siblings.clone();
        wrong_siblings.push(PHash::get_zero_value());
        let mut bad = input.clone();
        bad.contract_state_updates[1].updates[12] = ContractStateUpdate::IMT {
            update: IMTContractStateUpdate::Update {
                old_preimage: IMTContractStateLeaf::default(),
                new_preimage: IMTContractStateLeaf::default(),
                delta_proof: DeltaMerkleProofCore {
                    old_root,
                    old_value: PHash::get_zero_value(),
                    new_root,
                    new_value: PHash::get_zero_value(),
                    index,
                    siblings: wrong_siblings,
                },
            },
        };
        assert_ensure_err(ensure(&bad), "imt update proof height mismatch");

        // IMT insert with a correct predecessor proof but an oversized new leaf proof
        let (old_root, new_root, index, siblings) = positional_parts(&input.contract_state_updates[1].updates[14]);
        let mut wrong_siblings = siblings.clone();
        wrong_siblings.push(PHash::get_zero_value());
        let mut bad = input.clone();
        bad.contract_state_updates[1].updates[14] = ContractStateUpdate::IMT {
            update: IMTContractStateUpdate::Insert {
                predecessor_old_preimage: IMTContractStateLeaf::default(),
                predecessor_new_preimage: IMTContractStateLeaf::default(),
                new_leaf_preimage: IMTContractStateLeaf::default(),
                predecessor_delta_proof: DeltaMerkleProofCore {
                    old_root,
                    old_value: PHash::get_zero_value(),
                    new_root,
                    new_value: PHash::get_zero_value(),
                    index,
                    siblings,
                },
                new_leaf_delta_proof: DeltaMerkleProofCore {
                    old_root: new_root,
                    old_value: PHash::get_zero_value(),
                    new_root,
                    new_value: PHash::get_zero_value(),
                    index,
                    siblings: wrong_siblings,
                },
            },
        };
        assert_ensure_err(ensure(&bad), "imt insert proof height mismatch");

        // IMT insert whose predecessor proof itself has the wrong height
        let (old_root, new_root, index, siblings) = positional_parts(&input.contract_state_updates[1].updates[16]);
        let mut wrong_siblings = siblings.clone();
        wrong_siblings.push(PHash::get_zero_value());
        let mut bad = input.clone();
        bad.contract_state_updates[1].updates[16] = ContractStateUpdate::IMT {
            update: IMTContractStateUpdate::Insert {
                predecessor_old_preimage: IMTContractStateLeaf::default(),
                predecessor_new_preimage: IMTContractStateLeaf::default(),
                new_leaf_preimage: IMTContractStateLeaf::default(),
                predecessor_delta_proof: DeltaMerkleProofCore {
                    old_root,
                    old_value: PHash::get_zero_value(),
                    new_root,
                    new_value: PHash::get_zero_value(),
                    index,
                    siblings: wrong_siblings,
                },
                new_leaf_delta_proof: DeltaMerkleProofCore {
                    old_root: new_root,
                    old_value: PHash::get_zero_value(),
                    new_root,
                    new_value: PHash::get_zero_value(),
                    index,
                    siblings,
                },
            },
        };
        assert_ensure_err(ensure(&bad), "imt insert proof height mismatch");
    }

    #[test]
    fn ensure_accepts_fresh_contract_leaf_with_zero_old_value() {
        let (old_user_leaf, input, contract_helper) =
            gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);
        let hash = input.core.get_proof_public_inputs_hash::<PoseidonHasher>(32);
        assert!(input.get_needed_contract_zero_hashes().is_empty());

        // Turn contract 0 into a freshly-added contract: the user contract tree old
        // value is zero and the first update starts from the contract zero root.
        let mut fresh = input.clone();
        fresh.contract_state_updates[0].user_contract_tree_update_proof.old_value = PHash::get_zero_value();
        let contract_zero_hash = contract_helper.get_contract_zero_hash(0).unwrap();
        if let ContractStateUpdate::Positional { delta_proof } = &mut fresh.contract_state_updates[0].updates[0] {
            delta_proof.old_root = contract_zero_hash;
        }
        assert!(fresh
            .ensure_simple_self_consistent::<PoseidonHasher, _>(&old_user_leaf, hash, &contract_helper, 32, 30)
            .is_ok());
        assert_eq!(fresh.get_needed_contract_zero_hashes(), vec![(0, 24)]);
    }

    #[test]
    fn get_needed_contract_zero_hashes_covers_all_first_update_variants() {
        let (_, input, _) = gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);
        let mut probe = input.clone();

        // IMT update as first update: height taken from its delta proof siblings.
        let (old_root, new_root, index, _) = positional_parts(&input.contract_state_updates[1].updates[0]);
        probe.contract_state_updates[1].user_contract_tree_update_proof.old_value = PHash::get_zero_value();
        probe.contract_state_updates[1].updates[0] = ContractStateUpdate::IMT {
            update: IMTContractStateUpdate::Update {
                old_preimage: IMTContractStateLeaf::default(),
                new_preimage: IMTContractStateLeaf::default(),
                delta_proof: DeltaMerkleProofCore {
                    old_root,
                    old_value: PHash::get_zero_value(),
                    new_root,
                    new_value: PHash::get_zero_value(),
                    index,
                    siblings: vec![PHash::get_zero_value(); 7],
                },
            },
        };

        // IMT insert as first update: height taken from the predecessor delta proof.
        let (old_root, new_root, index, _) = positional_parts(&input.contract_state_updates[2].updates[0]);
        probe.contract_state_updates[2].user_contract_tree_update_proof.old_value = PHash::get_zero_value();
        probe.contract_state_updates[2].updates[0] = ContractStateUpdate::IMT {
            update: IMTContractStateUpdate::Insert {
                predecessor_old_preimage: IMTContractStateLeaf::default(),
                predecessor_new_preimage: IMTContractStateLeaf::default(),
                new_leaf_preimage: IMTContractStateLeaf::default(),
                predecessor_delta_proof: DeltaMerkleProofCore {
                    old_root,
                    old_value: PHash::get_zero_value(),
                    new_root,
                    new_value: PHash::get_zero_value(),
                    index,
                    siblings: vec![PHash::get_zero_value(); 9],
                },
                new_leaf_delta_proof: DeltaMerkleProofCore {
                    old_root: new_root,
                    old_value: PHash::get_zero_value(),
                    new_root,
                    new_value: PHash::get_zero_value(),
                    index,
                    siblings: vec![PHash::get_zero_value(); 3],
                },
            },
        };

        // A history with zero old value but no updates is skipped, and a history
        // with a non-zero old value (contract 4) is skipped as well.
        probe.contract_state_updates[3].user_contract_tree_update_proof.old_value = PHash::get_zero_value();
        probe.contract_state_updates[3].updates = vec![];

        assert_eq!(probe.get_needed_contract_zero_hashes(), vec![(1, 7), (2, 9)]);
    }

    #[test]
    fn size_hints_track_contract_update_structure() {
        let (_, input, _) = gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);

        assert_eq!(input.single_id_nodes_size_hint_in_nodes_modified(30), 5 * (1 + 30) + 1);

        // Every history holds 50 positional updates over a tree of height 24 + i.
        for (i, history) in input.contract_state_updates.iter().enumerate() {
            assert_eq!(history.get_double_id_nodes_size_hint(), 50 * (24 + i + 2));
        }
        assert_eq!(input.double_id_nodes_size_hint_in_nodes_modified(), 50 * (26 + 27 + 28 + 29 + 30));
    }

    fn slot_delta(old: [u64; 4], new: [u64; 4], index: u64) -> DeltaMerkleProofCore<PHash> {
        DeltaMerkleProofCore {
            old_root: PHash::get_zero_value(),
            old_value: PHash::from_u64x4(old),
            new_root: PHash::get_zero_value(),
            new_value: PHash::from_u64x4(new),
            index,
            siblings: vec![PHash::get_zero_value(); 3],
        }
    }

    #[test]
    fn get_slot_updates_decomposes_delta_proofs_into_changed_felts() -> anyhow::Result<()> {
        let history = |contract_id: u64, updates: Vec<ContractStateUpdate<PF, PHash>>| ContractStateUpdateHistory {
            user_contract_tree_update_proof: DeltaMerkleProofCore {
                old_root: PHash::get_zero_value(),
                old_value: PHash::get_zero_value(),
                new_root: PHash::get_zero_value(),
                new_value: PHash::get_zero_value(),
                index: contract_id,
                siblings: vec![],
            },
            updates,
        };
        let leaf = IMTContractStateLeaf::default();

        // Only the last felt changes: one slot update at index * 4 + 3.
        let positional = ContractStateUpdate::Positional {
            delta_proof: slot_delta([1, 2, 3, 4], [1, 2, 3, 9], 7),
        };
        // Only the first felt changes: one slot update at index * 4 + 0.
        let imt_update = ContractStateUpdate::IMT {
            update: IMTContractStateUpdate::Update {
                old_preimage: leaf.clone(),
                new_preimage: leaf.clone(),
                delta_proof: slot_delta([5, 5, 5, 5], [6, 5, 5, 5], 2),
            },
        };
        // An insert emits the predecessor proof followed by the new leaf proof.
        let imt_insert = ContractStateUpdate::IMT {
            update: IMTContractStateUpdate::Insert {
                predecessor_old_preimage: leaf.clone(),
                predecessor_new_preimage: leaf.clone(),
                new_leaf_preimage: leaf,
                predecessor_delta_proof: slot_delta([7, 7, 7, 7], [7, 7, 8, 7], 9),
                new_leaf_delta_proof: slot_delta([0, 0, 0, 0], [0, 3, 0, 0], 5),
            },
        };
        // No felt changes: the whole contract is filtered out of the result.
        let unchanged = ContractStateUpdate::Positional {
            delta_proof: slot_delta([1, 1, 1, 1], [1, 1, 1, 1], 4),
        };

        let input = SubmitUserEndCapNonProofInput {
            core: SubmitUserEndCapNonProofCoreInput::qp_rand_gen(),
            contract_state_updates: vec![
                history(11, vec![positional]),
                history(22, vec![imt_update, imt_insert]),
                history(33, vec![unchanged]),
            ],
            events: vec![],
        };

        let updates = input.get_slot_updates()?;
        assert_eq!(updates.len(), 2);

        assert_eq!(updates[0].contract_id, 11);
        assert_eq!(updates[0].slot_updates.len(), 1);
        assert_eq!(updates[0].slot_updates[0].slot, 7 * 4 + 3);
        assert_eq!(updates[0].slot_updates[0].old_value, PHash::from_u64x4([1, 2, 3, 4]).to_4_felts()[3]);
        assert_eq!(updates[0].slot_updates[0].new_value, PHash::from_u64x4([1, 2, 3, 9]).to_4_felts()[3]);

        assert_eq!(updates[1].contract_id, 22);
        assert_eq!(updates[1].slot_updates.len(), 3);
        assert_eq!(updates[1].slot_updates[0].slot, 2 * 4 + 0);
        assert_eq!(updates[1].slot_updates[1].slot, 9 * 4 + 2);
        assert_eq!(updates[1].slot_updates[2].slot, 5 * 4 + 1);
        Ok(())
    }

    #[test]
    fn random_gen_submit_input_starts_with_empty_updates_and_events() {
        let input = SubmitUserEndCapNonProofInput::<PF, PHash>::qp_rand_gen();
        assert!(input.contract_state_updates.is_empty());
        assert!(input.events.is_empty());
    }

    #[test]
    fn psy_user_event_record_random_gen_round_trips() -> anyhow::Result<()> {
        let record = PsyUserEventRecord::<PF>::qp_rand_gen();
        assert!(!record.data.is_empty());

        let bytes = record.fallback_psy_ser_to_bytes_vec()?;
        assert_eq!(bytes.len(), record.fallback_pio_serialized_size());
        assert_eq!(PsyUserEventRecord::<PF>::fallback_psy_ser_from_slice(&bytes)?, record);
        Ok(())
    }

    #[test]
    fn contract_state_update_fallback_round_trips_all_variants() -> anyhow::Result<()> {
        let leaf = IMTContractStateLeaf::default();
        let variants: Vec<ContractStateUpdate<PF, PHash>> = vec![
            ContractStateUpdate::Positional { delta_proof: delta(1, 2, 3) },
            ContractStateUpdate::IMT {
                update: IMTContractStateUpdate::Update {
                    old_preimage: leaf.clone(),
                    new_preimage: leaf.clone(),
                    delta_proof: delta(3, 4, 2),
                },
            },
            ContractStateUpdate::IMT {
                update: IMTContractStateUpdate::Insert {
                    predecessor_old_preimage: leaf.clone(),
                    predecessor_new_preimage: leaf.clone(),
                    new_leaf_preimage: leaf,
                    predecessor_delta_proof: delta(5, 6, 2),
                    new_leaf_delta_proof: delta(6, 7, 3),
                },
            },
        ];
        for variant in variants {
            let bytes = variant.fallback_psy_ser_to_bytes_vec()?;
            assert_eq!(bytes.len(), variant.fallback_pio_serialized_size());
            assert_eq!(ContractStateUpdate::<PF, PHash>::fallback_psy_ser_from_slice(&bytes)?, variant);
        }
        Ok(())
    }

    #[test]
    fn contract_state_update_rejects_unknown_variant_tag() {
        let mut reader = Cursor::new(vec![2u8]);
        assert!(ContractStateUpdate::<PF, PHash>::fallback_pio_read_from_io(&mut reader).is_err());
    }

    #[test]
    fn contract_state_update_history_serialization_round_trip() -> anyhow::Result<()> {
        let leaf = IMTContractStateLeaf::default();
        let history = ContractStateUpdateHistory {
            user_contract_tree_update_proof: delta(0, 9, 4),
            updates: vec![
                ContractStateUpdate::Positional { delta_proof: delta(9, 1, 3) },
                ContractStateUpdate::IMT {
                    update: IMTContractStateUpdate::Update {
                        old_preimage: leaf.clone(),
                        new_preimage: leaf.clone(),
                        delta_proof: delta(1, 2, 4),
                    },
                },
                ContractStateUpdate::IMT {
                    update: IMTContractStateUpdate::Insert {
                        predecessor_old_preimage: leaf.clone(),
                        predecessor_new_preimage: leaf.clone(),
                        new_leaf_preimage: leaf,
                        predecessor_delta_proof: delta(2, 3, 2),
                        new_leaf_delta_proof: delta(3, 4, 2),
                    },
                },
            ],
        };

        // Fallback write side emits exactly the declared size.
        // (The fallback *read* path cannot round-trip non-empty histories under the
        // `serialize_speedy` feature: the speedy nested delta-proof read buffers
        // past the object and desynchronizes the shared cursor.)
        let bytes = history.fallback_psy_ser_to_bytes_vec()?;
        assert_eq!(bytes.len(), history.fallback_pio_serialized_size());

        // The canonical serializer round-trips the nested structure intact.
        let canonical = psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle::psy_ser_to_bytes_vec(&history)?;
        assert_eq!(
            ContractStateUpdateHistory::<PF, PHash>::psy_ser_from_slice(&canonical)?,
            history
        );
        Ok(())
    }

    #[test]
    fn submit_input_serialization_round_trips_updates_and_events() -> anyhow::Result<()> {
        let (_, mut input, _) = gen_fake_valid_submit_user_end_cap_non_proof_input::<PF, PHash, PoseidonHasher>(32, 30);
        input.events = vec![PsyUserEventRecord::qp_rand_gen(), PsyUserEventRecord::qp_rand_gen()];

        // Fallback write side emits exactly the declared size. (The fallback *read*
        // path cannot consume non-empty contract update histories under the
        // `serialize_speedy` feature: the speedy nested delta-proof read buffers
        // past the object and desynchronizes the shared cursor.)
        let bytes = input.fallback_psy_ser_to_bytes_vec()?;
        assert_eq!(bytes.len(), input.fallback_pio_serialized_size());

        // The canonical serializer round-trips the full nested structure intact.
        let canonical = psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle::psy_ser_to_bytes_vec(&input)?;
        assert_eq!(SubmitUserEndCapNonProofInput::<PF, PHash>::psy_ser_from_slice(&canonical)?, input);
        Ok(())
    }

    #[test]
    fn submit_input_with_event_records_serializes_consistently() -> anyhow::Result<()> {
        // Even with no contract update histories, the fallback *read* path cannot
        // round-trip under the `serialize_speedy` feature: the core input's speedy
        // buffered read consumes the trailing vec-length bytes of the shared
        // cursor, so the following manual length read always fails. Only the
        // write side and the canonical serializer are asserted here.
        let mut input = SubmitUserEndCapNonProofInput::<PF, PHash>::qp_rand_gen();
        input.events = vec![PsyUserEventRecord::qp_rand_gen()];

        let bytes = input.fallback_psy_ser_to_bytes_vec()?;
        assert_eq!(bytes.len(), input.fallback_pio_serialized_size());

        let canonical = psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle::psy_ser_to_bytes_vec(&input)?;
        assert_eq!(SubmitUserEndCapNonProofInput::<PF, PHash>::psy_ser_from_slice(&canonical)?, input);
        Ok(())
    }
}
