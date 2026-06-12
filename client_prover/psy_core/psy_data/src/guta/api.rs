use std::collections::HashMap;

use kvq::traits::KVQSerializable;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::RichField,
    plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use psy_client_common::{data::qhashout::QHashOut, job::id::QProvingJobDataID};
use psy_crypto::hash::{
    merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
    traits::{hasher::FieldQHasher, qhashable::QFieldHashable},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;

use super::{end_cap_input::SubmitUserEndCapNonProofInput, stats::GUTAStats};
use crate::{
    dpn::event::PsyUserEventRecord,
    qblock::cmds::deploy_contract::{PsyContractSlotUpdates, PsySlotUpdate},
    qdata::{imt_proof::IMTContractStateUpdate, ups_end_cap_result::UPSEndCapResultCompact, user::PsyUserLeaf},
    qstore::uct_merkle_nodes::{CSTUserUpdate, CSTUserUpdateStore},
};

#[derive(Clone, Debug)]
pub struct SimpleContractHeightCache<F: RichField> {
    mapping: HashMap<u64, (u8, QHashOut<F>)>,
}

impl<F: RichField> SimpleContractHeightCache<F> {
    pub fn new() -> Self {
        Self { mapping: HashMap::new() }
    }
    pub fn add_contract(&mut self, contract_id: u64, height: u8, zero_hash: QHashOut<F>) {
        self.mapping.insert(contract_id, (height, zero_hash));
    }
    pub fn get_contract_height(&self, contract_id: u64) -> anyhow::Result<u8> {
        match self.mapping.get(&contract_id) {
            Some(x) => Ok(x.0),
            None => anyhow::bail!("contract {} not loaded", contract_id),
        }
    }
    pub fn get_contract_zero_hash(&self, contract_id: u64) -> anyhow::Result<QHashOut<F>> {
        match self.mapping.get(&contract_id) {
            Some(x) => Ok(x.1),
            None => anyhow::bail!("contract {} not loaded", contract_id),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct PsyContractStateUpdateHistory<F: RichField> {
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<QHashOut<F>>,
    #[serde(
        rename = "updates",
        serialize_with = "serialize_contract_state_updates",
        deserialize_with = "deserialize_contract_state_updates"
    )]
    pub contract_state_tree_updates: Vec<ContractStateUpdate<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub enum ContractStateUpdate<F: RichField> {
    Positional { delta_proof: DeltaMerkleProofCore<QHashOut<F>> },
    IMT { update: IMTContractStateUpdate<F> },
}

fn serialize_contract_state_updates<F, S>(updates: &Vec<ContractStateUpdate<F>>, serializer: S) -> Result<S::Ok, S::Error>
where
    F: RichField,
    S: Serializer,
{
    updates.serialize(serializer)
}

fn deserialize_contract_state_updates<'de, F, D>(deserializer: D) -> Result<Vec<ContractStateUpdate<F>>, D::Error>
where
    F: RichField,
    D: Deserializer<'de>,
{
    Vec::<ContractStateUpdate<F>>::deserialize(deserializer)
}

impl<F: RichField> PsyContractStateUpdateHistory<F> {
    pub fn ensure_basic_consistency(&self, contract_helper: &SimpleContractHeightCache<F>) -> anyhow::Result<()> {
        if self.contract_state_tree_updates.len() == 0 {
            anyhow::bail!("contract_state_tree_updates cannot be empty")
        }
        let first_old_root = match &self.contract_state_tree_updates[0] {
            ContractStateUpdate::Positional { delta_proof } => delta_proof.old_root,
            ContractStateUpdate::IMT { update } => update.old_root(),
        };
        if first_old_root != self.user_contract_tree_update_proof.old_value
            && (self.user_contract_tree_update_proof.old_value != QHashOut::ZERO
                || first_old_root != contract_helper.get_contract_zero_hash(self.user_contract_tree_update_proof.index)?)
        {
            anyhow::bail!("first state update old root does not match UCT old value");
        }
        let last_new_root = match self.contract_state_tree_updates.last().as_ref().unwrap() {
            ContractStateUpdate::Positional { delta_proof } => delta_proof.new_root,
            ContractStateUpdate::IMT { update } => update.new_root(),
        };
        if last_new_root != self.user_contract_tree_update_proof.new_value {
            anyhow::bail!("last state update new root does not match UCT new value");
        }

        for i in 1..self.contract_state_tree_updates.len() {
            let prev_new_root = match &self.contract_state_tree_updates[i - 1] {
                ContractStateUpdate::Positional { delta_proof } => delta_proof.new_root,
                ContractStateUpdate::IMT { update } => update.new_root(),
            };
            let curr_old_root = match &self.contract_state_tree_updates[i] {
                ContractStateUpdate::Positional { delta_proof } => delta_proof.old_root,
                ContractStateUpdate::IMT { update } => update.old_root(),
            };
            if curr_old_root != prev_new_root {
                anyhow::bail!("invalid state update transition proof: current old_root != last new_root");
            }
        }

        let expected_height = contract_helper.get_contract_height(self.user_contract_tree_update_proof.index)? as usize;
        for update in self.contract_state_tree_updates.iter() {
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
                        if predecessor_delta_proof.siblings.len() != expected_height || new_leaf_delta_proof.siblings.len() != expected_height {
                            anyhow::bail!("imt insert proof height mismatch");
                        }
                    }
                },
            }
        }

        Ok(())
    }
    pub fn verify_generate_cst_delta<H: FieldQHasher<F>>(&self, injestor: &mut CSTUserUpdateStore<QHashOut<F>>) -> anyhow::Result<()> {
        injestor.verify_injest_uct_delta_merkle_proof::<H>(&self.user_contract_tree_update_proof)?;

        let contract_id = self.user_contract_tree_update_proof.index as u32;

        for p in self.contract_state_tree_updates.iter() {
            match p {
                ContractStateUpdate::Positional { delta_proof } => {
                    injestor.verify_injest_delta_merkle_proof::<H>(contract_id, delta_proof)?;
                }
                ContractStateUpdate::IMT { update } => match update {
                    IMTContractStateUpdate::Update { delta_proof, .. } => {
                        injestor.verify_injest_delta_merkle_proof::<H>(contract_id, delta_proof)?;
                    }
                    IMTContractStateUpdate::Insert {
                        predecessor_delta_proof,
                        new_leaf_delta_proof,
                        ..
                    } => {
                        injestor.verify_injest_delta_merkle_proof::<H>(contract_id, predecessor_delta_proof)?;
                        injestor.verify_injest_delta_merkle_proof::<H>(contract_id, new_leaf_delta_proof)?;
                    }
                },
            }
        }

        Ok(())
    }

    pub fn get_slot_updates(&self) -> anyhow::Result<PsyContractSlotUpdates<F>> {
        let slot_updates = self
            .contract_state_tree_updates
            .iter()
            .flat_map(|update| match update {
                ContractStateUpdate::Positional { delta_proof: update } => {
                    let old_elements = &update.old_value.0.elements;
                    let new_elements = &update.new_value.0.elements;
                    old_elements
                        .iter()
                        .zip(new_elements.iter())
                        .enumerate()
                        .filter(|(_, (old, new))| old != new)
                        .map(|(offset, (old, new))| PsySlotUpdate {
                            slot: update.index * 4 + offset as u64,
                            old_value: *old,
                            new_value: *new,
                        })
                        .collect::<Vec<_>>()
                }
                ContractStateUpdate::IMT { .. } => Vec::new(),
            })
            .collect::<Vec<_>>();
        let contract_id = self.user_contract_tree_update_proof.index as u32;
        let contract_update = PsyContractSlotUpdates { contract_id, slot_updates };
        Ok(contract_update)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct UserEndCapNonProofCoreInputQueueItem<F: RichField> {
    pub input: SubmitUserEndCapNonProofCoreInput<F>,
    pub checkpoint_tree_proof: MerkleProofCore<QHashOut<F>>,
    pub cst_user_update: CSTUserUpdate<QHashOut<F>>,
    pub events: Vec<PsyUserEventRecord<F>>,
    pub proof_id: QProvingJobDataID,
    pub checkpoint_id: u64,
    pub channel_id: u64,
}

// impl<F: RichField> UserEndCapNonProofCoreInputQueueItem<F> {
//     pub fn get_verify_end_cap_simple_input(&self) ->
// VerifyEndCapSimpleStandardInput<F> {         VerifyEndCapSimpleStandardInput
// {             guta_stats: self.input.stats,
//             checkpoint_root:
// self.input.state_transition.checkpoint_tree_root_hash,
// checkpoint_historical_merkle_proof: self.checkpoint_tree_proof.clone(),
//         }
//     }
// }

// impl<F: RichField> DrainQueueMetadataTagged for
// UserEndCapNonProofCoreInputQueueItem<F> {     fn get_dq_metadata(&self) ->
// DrainQueueMetadata {         DrainQueueMetadata {
//             channel_id: self.channel_id,
//             checkpoint_id: self.checkpoint_id,
//             item_id: self.input.new_user_leaf.user_id.to_canonical_u64(),
//         }
//     }
// }
impl<F: RichField> KVQSerializable for UserEndCapNonProofCoreInputQueueItem<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct SubmitUserEndCapNonProofCoreInput<F: RichField> {
    pub checkpoint_id: F,
    pub stats: GUTAStats<F>,
    pub state_transition: UPSEndCapResultCompact<F>,
    pub new_user_leaf: PsyUserLeaf<F>,
}
impl<F: RichField> SubmitUserEndCapNonProofCoreInput<F> {
    pub fn get_proof_public_inputs_hash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_two_to_one(self.state_transition.qfhash::<H>(), self.stats.qfhash::<H>())
    }
}

impl<F: RichField> KVQSerializable for SubmitUserEndCapNonProofCoreInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct SubmitUserEndCapProofAPIInput<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub input: SubmitUserEndCapNonProofInput<F>,
    pub proof: ProofWithPublicInputs<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> KVQSerializable for SubmitUserEndCapProofAPIInput<F, C, D> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct SubmitUserEndCapProofIDAPIInput<F: RichField> {
    pub input: SubmitUserEndCapNonProofInput<F>,
    pub proof_id: QProvingJobDataID,
}

impl<F: RichField> KVQSerializable for SubmitUserEndCapProofIDAPIInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GUTARealmCheckpointResult<F: RichField> {
    pub checkpoint_id: u64,
    pub guta_stats: GUTAStats<F>,
    pub top_line_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub checkpoint_tree_root: QHashOut<F>,
    pub proof_id: QProvingJobDataID,
}
impl<F: RichField> KVQSerializable for GUTARealmCheckpointResult<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct SubmitGUTARealmResultAPINoProofInput<F: RichField> {
    pub realm_id: u64,
    pub checkpoint_id: u64,
    pub guta_stats: GUTAStats<F>,
    pub top_line_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub checkpoint_tree_root: QHashOut<F>,
    pub proof_id: QProvingJobDataID,
}
impl<F: RichField> KVQSerializable for SubmitGUTARealmResultAPINoProofInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct SubmitGUTARealmResultAPIQueueItem<F: RichField> {
    pub realm_id: u64,
    pub guta_channel_id: u64,
    pub checkpoint_id: u64,
    pub guta_stats: GUTAStats<F>,
    pub top_line_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub checkpoint_tree_root: QHashOut<F>,
    pub proof_id: QProvingJobDataID,
}
impl<F: RichField> KVQSerializable for SubmitGUTARealmResultAPIQueueItem<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> SubmitGUTARealmResultAPINoProofInput<F> {
    pub fn to_queue_item(self, guta_channel_id: u64, _realm_root_level: u32) -> SubmitGUTARealmResultAPIQueueItem<F> {
        SubmitGUTARealmResultAPIQueueItem {
            realm_id: self.realm_id,
            guta_channel_id: guta_channel_id,
            checkpoint_id: self.checkpoint_id,
            guta_stats: self.guta_stats,
            top_line_proof: self.top_line_proof,
            checkpoint_tree_root: self.checkpoint_tree_root,
            proof_id: self.proof_id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct SubmitGUTARealmResultAPIWithProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub input: SubmitGUTARealmResultAPINoProofInput<F>,
    pub proof: ProofWithPublicInputs<F, C, D>,
}
impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> KVQSerializable for SubmitGUTARealmResultAPIWithProof<F, C, D> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
