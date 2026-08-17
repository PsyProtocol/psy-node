use plonky2::{
    field::types::PrimeField64,
    hash::hash_types::{HashOut, RichField},
};
use psy_client_common::{data::qhashout::QHashOut, traits::to_qfelts::ToQFelts};
use psy_client_data::{
    config::store_config::{PsyFelt, PsyHasher},
    dpn::{
        cfc_context_input::{DapenCFCUserTransactionEndContext, DapenCFCUserTransactionInputContext},
        event::PsyUserEventRecord,
        proving_session::DPNProvingSessionSimpleMethodCall,
    },
    qdata::imt_contract_state::compare_qhashout_keys,
    qstore::{
        controllers::proving_session::{
            PsyEventsStore, PsyLocalProvingSessionStore, PsyReadLocalProvingSessionStore, PsyReadLocalProvingSessionStoreMut,
        },
        imm::{
            cmd::{
                QSRCmdGetCheckpointLeafData, QSRCmdGetContractLeafData, QSRMerkleCmd, QSRMerkleCmdGetCheckpointTreeMerkleProof,
                QSRMerkleCmdGetContractTreeMerkleProof, QSRMerkleCmdGetUserContractStateTreeMerkleProof, QSRMerkleCmdGetUserContractTreeMerkleProof,
            },
            cmd_processor::{
                DPNCheckpointGlobalStateRootsWitness, DPNCheckpointLeafStatsWitness, DPNClearEntireTreeWitness, DPNContractLeafWitness,
                DPNIMTContainsOtherUserWitness, DPNIMTContainsWitness, DPNIMTOtherUserReadWitness, DPNIMTReadWitness,
                DPNIMTSelfUserExternalReadWitness, DPNIMTSetWitness, DPNInvokeDeferredMethodCallWitness,
                DPNReadOtherUserContractStateLeafMerkleProof, DPNStateCmdWitness, PsyReadCommandProcessorSync, PsyReadCommandProcessorSyncMut,
            },
        },
    },
    traits::qdatastore::qmetadata::QMetaDataStoreReaderSync,
};
use psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64;
use psy_crypto::hash::{
    merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
    traits::{
        hasher::{FieldQHasher, MerkleZeroHasherWithMarkedLeaf},
        qhashable::QFieldHashable,
    },
    utils::safe_hash_fixed_length,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::cfc_input::DapenContractFunctionCircuitInput;
use crate::dpn::{
    ops::{
        op_types::{decode_indexed_op_id, DPNBuiltInDataType, DPNOpType},
        state_cmd::{data::DPNStateCmd, types::DPNStateCmdCore},
    },
    vm::{
        def::DPNFunctionCircuitDefinition,
        exec::{DPNTransactionEntry, SimpleDPNExecutor},
    },
};
fn mp_to_dmp<H: PartialEq + Copy>(mp: MerkleProofCore<H>) -> DeltaMerkleProofCore<H> {
    DeltaMerkleProofCore {
        old_root: mp.root,
        old_value: mp.value,
        new_root: mp.root,
        new_value: mp.value,
        index: mp.index,
        siblings: mp.siblings,
    }
}

fn imt_slot_base_from_subslot_base(base_offset: u64) -> u64 {
    base_offset.div_ceil(4)
}

fn validate_imt_leaf_index(leaf_index: u64, state_slot_base: u64, capacity: u64) -> anyhow::Result<u64> {
    let min_absolute = state_slot_base
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("IMT absolute min overflow: base={}", state_slot_base))?;
    let max_absolute = state_slot_base
        .checked_add(capacity)
        .ok_or_else(|| anyhow::anyhow!("IMT absolute max overflow: base={}, capacity={}", state_slot_base, capacity))?;
    if leaf_index >= min_absolute && leaf_index <= max_absolute {
        return Ok(leaf_index);
    }
    anyhow::bail!(
        "IMT leaf_index {} is out of absolute slot range [{}..={}] (base={}, capacity={})",
        leaf_index,
        min_absolute,
        max_absolute,
        state_slot_base,
        capacity
    )
}

fn validate_imt_predecessor_leaf_index(leaf_index: u64, state_slot_base: u64, capacity: u64) -> anyhow::Result<u64> {
    // Predecessor may legally be the sentinel slot at `state_slot_base`.
    if leaf_index == state_slot_base {
        return Ok(leaf_index);
    }
    validate_imt_leaf_index(leaf_index, state_slot_base, capacity)
}

fn validate_imt_next_append_index(next_append_index: u64, state_slot_base: u64, capacity: u64) -> anyhow::Result<u64> {
    if next_append_index == 0 {
        return state_slot_base
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("IMT first append slot overflow: base={}", state_slot_base));
    }
    validate_imt_leaf_index(next_append_index, state_slot_base, capacity)
}

fn validate_imt_preimage<F: RichField + PrimeField64>(
    leaf: psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf<F>,
    state_slot_base: u64,
    capacity: u64,
) -> anyhow::Result<psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf<F>> {
    let next_index = leaf.next_index.to_canonical_u64();
    if next_index != 0 {
        validate_imt_leaf_index(next_index, state_slot_base, capacity)?;
    }
    Ok(leaf)
}

fn is_imt_key_not_found_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("Key not found in IMT") || msg.contains("key not found in IMT")
}

fn is_imt_predecessor_not_found_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("No predecessor found")
}

fn validate_contract_state_tree_height(height: u64) -> anyhow::Result<u8> {
    const MAX_SUPPORTED_HEIGHT: u64 = 32;
    if height == 0 || height > MAX_SUPPORTED_HEIGHT {
        anyhow::bail!(
            "contract_state_tree_height {} is outside supported range 1..={}",
            height,
            MAX_SUPPORTED_HEIGHT
        );
    }
    Ok(height as u8)
}

fn validate_imt_slot_index(slot_index: u64, state_slot_base: u64, capacity: u64) -> anyhow::Result<u64> {
    let min_index = state_slot_base
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("IMT leaf min index overflow: base={}", state_slot_base))?;
    let max_absolute = state_slot_base
        .checked_add(capacity)
        .ok_or_else(|| anyhow::anyhow!("IMT absolute index bound overflow: base={}, capacity={}", state_slot_base, capacity))?;
    if slot_index < min_index || slot_index > max_absolute {
        anyhow::bail!("IMT slot index {} is out of range [{}..={}]", slot_index, min_index, max_absolute);
    }
    Ok(slot_index)
}

fn is_valid_imt_non_membership_predecessor<F: RichField>(
    predecessor_leaf: &psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf<F>,
    key: &QHashOut<F>,
) -> bool {
    let predecessor_lt_key = compare_qhashout_keys::<F>(&predecessor_leaf.key, key).is_lt();
    let key_lt_predecessor_next = predecessor_leaf.next_key == QHashOut::ZERO || compare_qhashout_keys::<F>(key, &predecessor_leaf.next_key).is_lt();
    predecessor_lt_key && key_lt_predecessor_next
}

fn imt_leaf_matches_key<F: RichField>(leaf: &psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf<F>, key: &QHashOut<F>) -> bool {
    leaf.key == *key
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub trait PsyCmdInputWitnessResolver<F: RichField + PrimeField64, H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F> + Send> {
    async fn resolve_vec(&mut self, state_cmd: &DPNStateCmd<u64>) -> anyhow::Result<PsyCmdWithInputAndWitness<F>>;
}
//(sub_slot_length-2)%4
/*
const SLOT_MASK_TABLE: [[u8; 4]; 7] = [
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [1, 0, 0, 0],
    [1, 1, 0, 0],
    [1, 1, 1, 0],
    [1, 1, 1, 1],
];

fn get_slot_mask(length: u64, sub_slot_index: u64) -> [u8; 4] {
    let length_minus_2 = length - 2;

    let length_minus_2_low_bits = length_minus_2 & 0b11;
    let sub_slot_index_low_bits = sub_slot_index & 0b11;

    SLOT_MASK_TABLE[(length_minus_2_low_bits + sub_slot_index_low_bits) as usize]
}
*/

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<
        F: RichField + PrimeField64,
        H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F> + Send,
        R: PsyReadCommandProcessorSync<F> + psy_client_data::qstore::imm::cmd_processor::QUserIdManager + QMetaDataStoreReaderSync<F> + Send + Sync,
    > PsyCmdInputWitnessResolver<F, H> for PsyLocalProvingSessionStore<F, R, H>
{
    async fn resolve_vec(&mut self, state_cmd: &DPNStateCmd<u64>) -> anyhow::Result<PsyCmdWithInputAndWitness<F>> {
        tracing::debug!("Resolving state command: {:#?}", state_cmd);
        let current_contract_id = self.get_current_contract_id();
        match state_cmd {
            DPNStateCmd::SetContractStateSlotHash(c) => {
                if c.condition == 0 {
                    let mp = self
                        .get_contract_state_slot(current_contract_id, F::from_noncanonical_u64(c.slot_index))
                        .await?;
                    let dmp = mp_to_dmp(mp);
                    let result = dmp.new_value.0.elements.to_vec();
                    let witness = DPNStateCmdWitness::DeltaMerkleProof(dmp);

                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness,
                        result,
                    })
                } else {
                    let dmp = self
                        .set_contract_state_slot(
                            current_contract_id,
                            F::from_canonical_u64(c.slot_index),
                            QHashOut::from_values(c.value[0], c.value[1], c.value[2], c.value[3]),
                        )
                        .await?;
                    let result = dmp.new_value.0.elements.to_vec();
                    let witness = DPNStateCmdWitness::DeltaMerkleProof(dmp);
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness,
                        result,
                    })
                }
            }
            DPNStateCmd::SetContractStateSlotSingle(c) => {
                let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                let n = (c.sub_slot_index & 0b11) as usize;
                let mp = self.get_contract_state_slot(current_contract_id, slot_index).await?;

                let cur = mp.value.0.elements;
                if c.condition == 0 {
                    let dmp = mp_to_dmp(mp);
                    let result = vec![cur[n], cur[n]];
                    let witness = DPNStateCmdWitness::DeltaMerkleProof(dmp);
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness,
                        result,
                    })
                } else {
                    let mut new_elements = cur.clone();
                    new_elements[n] = F::from_canonical_u64(c.value);

                    let dmp = self
                        .set_contract_state_slot(current_contract_id, slot_index, QHashOut(HashOut { elements: new_elements }))
                        .await?;
                    let result = vec![cur[n], F::from_canonical_u64(c.value)];
                    let witness = DPNStateCmdWitness::DeltaMerkleProof(dmp);
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness,
                        result,
                    })
                }
            }
            DPNStateCmd::SetContractStateSlotRange(c) => {
                if c.condition == 0 {
                    let r = self
                        .resolve_vec(&DPNStateCmd::get_self_user_current_contract_state_slot_range(
                            c.sub_slot_index,
                            c.value.len() as u32,
                        ))
                        .await?;
                    match r.witness {
                        DPNStateCmdWitness::MerkleProofArray(vec) => {
                            let dmp = vec.iter().map(|x| mp_to_dmp(x.clone())).collect::<Vec<_>>();
                            let result = c.value.iter().map(|x| F::from_canonical_u64(*x)).collect::<Vec<F>>();
                            let witness = DPNStateCmdWitness::DeltaMerkleProofArray(dmp);
                            return Ok(PsyCmdWithInputAndWitness {
                                state_cmd: state_cmd.clone(),
                                witness,
                                result,
                            });
                        }
                        _ => panic!("invalid response type witness for get contract state range"),
                    }
                }
                let value_len = c.value.len();
                if value_len == 1 {
                    let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                    let n = (c.sub_slot_index & 0b11) as usize;
                    let cur = self.get_contract_state_slot(current_contract_id, slot_index).await?.value.0.elements;
                    let mut new_elements = cur.clone();
                    new_elements[n] = F::from_canonical_u64(c.value[0]);

                    let dmp = self
                        .set_contract_state_slot(current_contract_id, slot_index, QHashOut(HashOut { elements: new_elements }))
                        .await?;
                    let result = vec![F::from_canonical_u64(c.value[0])];
                    let witness = DPNStateCmdWitness::DeltaMerkleProofArray(vec![dmp]);
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness,
                        result,
                    })
                } else if value_len < 6 {
                    // two merkle proofs

                    let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                    let n = (c.sub_slot_index & 0b11) as usize;
                    let mut proof_0_elements = self.get_contract_state_slot(current_contract_id, slot_index).await?.value.0.elements;
                    let mut proof_1_elements = self
                        .get_contract_state_slot(current_contract_id, slot_index + F::ONE)
                        .await?
                        .value
                        .0
                        .elements;
                    for (i, v) in c.value.iter().enumerate() {
                        let r_ind = n + i;
                        if r_ind < 4 {
                            proof_0_elements[r_ind] = F::from_canonical_u64(*v);
                        } else {
                            proof_1_elements[r_ind - 4] = F::from_canonical_u64(*v);
                        }
                    }
                    let delta_proof_0 = self
                        .set_contract_state_slot(current_contract_id, slot_index, QHashOut(HashOut { elements: proof_0_elements }))
                        .await?;
                    let delta_proof_1 = self
                        .set_contract_state_slot(current_contract_id, slot_index + F::ONE, QHashOut(HashOut { elements: proof_1_elements }))
                        .await?;
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness: DPNStateCmdWitness::DeltaMerkleProofArray(vec![delta_proof_0, delta_proof_1]),
                        result: c.value.iter().map(|x| F::from_noncanonical_u64(*x)).collect(),
                    })
                } else {
                    let start_slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                    let n_proofs = ((value_len + 6) / 4) as u64;
                    let sub_slot_index_mod_4 = c.sub_slot_index % 4;
                    let len_minus_2_mod_4 = (value_len - 2) % 4;
                    //let start_slot = c.sub_slot_index / 4;
                    let mut dmps = Vec::with_capacity(n_proofs as usize);
                    let result = c.value.iter().map(|i| F::from_noncanonical_u64(*i)).collect::<Vec<_>>();

                    let slot_mask_type = sub_slot_index_mod_4 as usize + len_minus_2_mod_4;

                    // handle the first proof special case
                    let main_body_proofs_index_offset = (4 - sub_slot_index_mod_4) as usize;
                    let first_proof_set_elements = if sub_slot_index_mod_4 == 0 {
                        [result[0], result[1], result[2], result[3]]
                    } else {
                        let first_proof_existing_value = self
                            .get_contract_state_slot(current_contract_id, start_slot_index)
                            .await?
                            .value
                            .0
                            .elements;
                        if sub_slot_index_mod_4 == 1 {
                            [first_proof_existing_value[0], result[0], result[1], result[2]]
                        } else if sub_slot_index_mod_4 == 2 {
                            [first_proof_existing_value[0], first_proof_existing_value[1], result[0], result[1]]
                        } else {
                            // }else if sub_slot_index_mod_4 == 3 {
                            [
                                first_proof_existing_value[0],
                                first_proof_existing_value[1],
                                first_proof_existing_value[2],
                                result[0],
                            ]
                        }
                    };
                    let dmp = self
                        .set_contract_state_slot(
                            current_contract_id,
                            start_slot_index,
                            QHashOut(HashOut {
                                elements: first_proof_set_elements,
                            }),
                        )
                        .await?;
                    dmps.push(dmp);

                    // we don't need to get the old values for main body proofs
                    for i in 1..(n_proofs - 1) {
                        let current_value_index = main_body_proofs_index_offset + (i - 1) as usize * 4;

                        let set_value = QHashOut(HashOut {
                            elements: [
                                result[current_value_index],
                                result[current_value_index + 1],
                                result[current_value_index + 2],
                                result[current_value_index + 3],
                            ],
                        });

                        let dmp = self
                            .set_contract_state_slot(current_contract_id, start_slot_index + F::from_canonical_u64(i), set_value)
                            .await?;
                        dmps.push(dmp);
                    }

                    // handle the last proof special case
                    /*

                    const SLOT_MASK_TABLE: [[u8; 4]; 7] = [
                        [0, 0, 0, 0], // type 0
                        [0, 0, 0, 0], // type 1
                        [0, 0, 0, 0], // type 2
                        [1, 0, 0, 0], // type 3
                        [1, 1, 0, 0], // type 4
                        [1, 1, 1, 0], // type 5
                        [1, 1, 1, 1], // type 6
                    ];

                    */

                    let last_proof_value_index = main_body_proofs_index_offset + (n_proofs as usize - 2) * 4;
                    let last_proof_slot_index = start_slot_index + F::from_canonical_u64(n_proofs - 1);
                    if slot_mask_type == 6 {
                        // if mask type is 6, we don't need to check the old value
                        // type 6 => [1, 1, 1, 1],

                        let set_value = QHashOut(HashOut {
                            elements: [
                                result[last_proof_value_index],
                                result[last_proof_value_index + 1],
                                result[last_proof_value_index + 2],
                                result[last_proof_value_index + 3],
                            ],
                        });

                        let dmp = self
                            .set_contract_state_slot(current_contract_id, last_proof_slot_index, set_value)
                            .await?;
                        dmps.push(dmp);
                    } else if slot_mask_type < 3 {
                        let last_proof_existing_mp = self.get_contract_state_slot(current_contract_id, last_proof_slot_index).await?;
                        // type 0, 1, 2 => [0, 0, 0, 0]
                        // if slot mask type is < 3, then we are done and can just trasform the existing
                        // mp into a delta merkle proof
                        dmps.push(last_proof_existing_mp.to_delta_merkle_proof_inplace());
                    } else {
                        // handle types 3, 4, 5
                        // get the previous value of this slot
                        let last_proof_existing_value = self
                            .get_contract_state_slot(current_contract_id, last_proof_slot_index)
                            .await?
                            .value
                            .0
                            .elements;

                        let new_set_value = if slot_mask_type == 3 {
                            // type 3 => [1, 0, 0, 0]
                            [
                                result[last_proof_value_index],
                                last_proof_existing_value[1],
                                last_proof_existing_value[2],
                                last_proof_existing_value[3],
                            ]
                        } else if slot_mask_type == 4 {
                            [
                                result[last_proof_value_index],
                                result[last_proof_value_index + 1],
                                last_proof_existing_value[2],
                                last_proof_existing_value[3],
                            ]
                        } else {
                            // if slot_mask_type == 5 {
                            [
                                result[last_proof_value_index],
                                result[last_proof_value_index + 1],
                                result[last_proof_value_index + 2],
                                last_proof_existing_value[3],
                            ]
                        };
                        let dmp = self
                            .set_contract_state_slot(current_contract_id, last_proof_slot_index, QHashOut(HashOut { elements: new_set_value }))
                            .await?;
                        dmps.push(dmp);
                    }

                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result,
                        witness: DPNStateCmdWitness::DeltaMerkleProofArray(dmps),
                    })
                    /*
                    let base_offset = c.sub_slot_index % 4u64;
                    let end_sub_index = (c.value.len() as u64) + c.sub_slot_index;
                    let end_offset = end_sub_index % 4u64;
                    let slot_index = c.sub_slot_index / 4u64;
                    let pre_pad_left = base_offset as usize;
                    let post_pad_right = 4 - (end_offset as usize);
                    let end_slot_index = end_sub_index / 4u64;
                    let left_values = self
                        .get_contract_state_slot(
                            current_contract_id,
                            F::from_canonical_u64(slot_index),
                        )?
                        .value
                        .0
                        .elements;
                    let right_values = self
                        .get_contract_state_slot(
                            current_contract_id,
                            F::from_canonical_u64(end_slot_index),
                        )?
                        .value
                        .0
                        .elements;
                    let finished_values = vec![
                        left_values[0..pre_pad_left].to_vec(),
                        c.value
                            .to_vec()
                            .iter()
                            .map(|x| F::from_noncanonical_u64(*x))
                            .collect::<Vec<F>>(),
                        right_values[post_pad_right..].to_vec(),
                    ]
                    .concat();
                    let r = finished_values
                        .chunks_exact(4)
                        .enumerate()
                        .map(|(i, x)| {
                            self.set_contract_state_slot(
                                current_contract_id,
                                F::from_canonical_u64((i as u64) + slot_index),
                                QHashOut(HashOut {
                                    elements: [x[0], x[1], x[2], x[3]],
                                }),
                            )
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;

                    let witness = DPNStateCmdWitness::DeltaMerkleProofArray(r);
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness,
                        result: c
                            .value
                            .iter()
                            .map(|x| F::from_noncanonical_u64(*x))
                            .collect::<Vec<F>>(),
                    })*/
                }
            }
            DPNStateCmd::InvokeExternalContractFunctionSync(_c) => todo!(),
            DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(c) => {
                let witness = self
                    .get_contract_state_slot(current_contract_id, F::from_canonical_u64(c.slot_index))
                    .await?;
                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: witness.value.0.elements.to_vec(),
                    witness: DPNStateCmdWitness::MerkleProof(witness),
                })
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(c) => {
                let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                let slot_offset = c.sub_slot_index % 4u64;
                let witness = self.get_contract_state_slot(current_contract_id, slot_index).await?;
                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: vec![witness.value.0.elements[slot_offset as usize]],
                    witness: DPNStateCmdWitness::MerkleProof(witness),
                })
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotRange(c) => {
                if c.length == 1 {
                    // one merkle proof
                    let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                    let n = (c.sub_slot_index & 0b11) as usize;
                    let cur = self.get_contract_state_slot(current_contract_id, slot_index).await?;
                    let el = cur.value.0.elements[n];
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result: vec![el],
                        witness: DPNStateCmdWitness::MerkleProofArray(vec![cur]),
                    })
                } else if c.length < 6 {
                    // two merkle proofs

                    let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                    let n = (c.sub_slot_index & 0b11) as usize;
                    let proof_0 = self.get_contract_state_slot(current_contract_id, slot_index).await?;
                    let proof_1 = self.get_contract_state_slot(current_contract_id, slot_index + F::ONE).await?;

                    let elements = [proof_0.value.0.elements, proof_1.value.0.elements].concat();

                    let result = elements[n..(n + c.length as usize)].to_vec();
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result,
                        witness: DPNStateCmdWitness::MerkleProofArray(vec![proof_0, proof_1]),
                    })
                } else {
                    // max proofs needed = floor((c.length+6)/4)
                    /*
                        The first leaf can always be:
                            if sub_slot_index%4 == 0: 1, 1, 1, 1
                            if sub_slot_index%4 == 1: 0, 1, 1, 1
                            if sub_slot_index%4 == 2: 0, 0, 1, 1
                            if sub_slot_index%4 == 3: 0, 0, 0, 1

                    The last leaf takes on the pattern (where 1 means we modify the element and 0 means we keep it the same):
                        if (length-2)%4 == 0 {
                            if sub_slot_index%4 == 0: 0, 0, 0, 0
                            if sub_slot_index%4 == 1: 0, 0, 0, 0
                            if sub_slot_index%4 == 2: 0, 0, 0, 0
                            if sub_slot_index%4 == 3: 1, 0, 0, 0
                        }
                        ======================================

                        if (length-2)%4 == 1 {
                            if sub_slot_index%4 == 0: 0, 0, 0, 0
                            if sub_slot_index%4 == 1: 0, 0, 0, 0
                            if sub_slot_index%4 == 2: 1, 0, 0, 0
                            if sub_slot_index%4 == 3: 1, 1, 0, 0
                        }
                        ======================================

                        if (length-2)%4 == 2 {
                            if sub_slot_index%4 == 0: 0, 0, 0, 0
                            if sub_slot_index%4 == 1: 1, 0, 0, 0
                            if sub_slot_index%4 == 2: 1, 1, 0, 0
                            if sub_slot_index%4 == 3: 1, 1, 1, 0
                        }
                        ======================================

                        if (length-2)%4 == 3 {
                            if sub_slot_index%4 == 0: 1, 0, 0, 0
                            if sub_slot_index%4 == 1: 1, 1, 0, 0
                            if sub_slot_index%4 == 2: 1, 1, 1, 0
                            if sub_slot_index%4 == 3: 1, 1, 1, 1
                        }
                        ======================================
                     */

                    let n_proofs = ((c.length + 6) / 4) as u64;
                    let sub_slot_index_mod_4 = c.sub_slot_index % 4;
                    let start_slot = c.sub_slot_index / 4;
                    let mut mps = Vec::with_capacity(n_proofs as usize);
                    let mut result = Vec::<F>::with_capacity(c.length as usize);

                    let len_minus_2_mod_4 = (c.length - 2) % 4;

                    for i in 0..n_proofs {
                        let mp = self
                            .get_contract_state_slot(current_contract_id, F::from_canonical_u64(start_slot + i))
                            .await?;
                        if i == 0 {
                            if sub_slot_index_mod_4 == 0 {
                                result.push(mp.value.0.elements[0]);
                                result.push(mp.value.0.elements[1]);
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 1 {
                                result.push(mp.value.0.elements[1]);
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 2 {
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 3 {
                                result.push(mp.value.0.elements[3]);
                            }
                        } else if i == (n_proofs - 1) {
                            let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                            /*

                                const SLOT_MASK_TABLE: [[u8; 4]; 7] = [
                                    [0, 0, 0, 0],
                                    [0, 0, 0, 0],
                                    [0, 0, 0, 0],
                                    [1, 0, 0, 0],
                                    [1, 1, 0, 0],
                                    [1, 1, 1, 0],
                                    [1, 1, 1, 1],
                                ];
                            */
                            if slot_mask_type >= 3 {
                                result.push(mp.value.0.elements[0]);
                            }
                            if slot_mask_type >= 4 {
                                result.push(mp.value.0.elements[1]);
                            }
                            if slot_mask_type >= 5 {
                                result.push(mp.value.0.elements[2]);
                            }
                            if slot_mask_type >= 6 {
                                result.push(mp.value.0.elements[3]);
                            }
                        } else {
                            result.extend_from_slice(&mp.value.0.elements);
                        }
                        mps.push(mp);
                    }

                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result,
                        witness: DPNStateCmdWitness::MerkleProofArray(mps),
                    })

                    /*
                    let base_offset = c.sub_slot_index % 4u64;
                    let end_sub_index = (c.length as u64) + c.sub_slot_index;
                    let end_offset = end_sub_index % 4u64;
                    let slot_index = c.sub_slot_index / 4u64;
                    //let pre_pad_left = base_offset as usize;
                    //let post_pad_right = 4-(end_offset as usize);
                    let end_slot_index = end_sub_index / 4u64;
                    let mut mps = Vec::<MerkleProofCore<QHashOut<F>>>::new();
                    let mut result = Vec::<F>::with_capacity(c.length as usize);
                    for i in slot_index..end_slot_index {
                        let mp = self.get_contract_state_slot(
                            current_contract_id,
                            F::from_canonical_u64(i),
                        )?;
                        if base_offset != 0 && i == slot_index {
                            result
                                .extend_from_slice(&mp.value.0.elements[(base_offset as usize)..]);
                        }
                        mps.push(mp);
                    }
                    if end_offset != 0 {
                        let mp = self.get_contract_state_slot(
                            current_contract_id,
                            F::from_canonical_u64(end_slot_index),
                        )?;
                        result.extend_from_slice(&mp.value.0.elements[..(end_offset as usize)]);
                        mps.push(mp);
                    }
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result,
                        witness: DPNStateCmdWitness::MerkleProofArray(mps),
                    })
                    */
                }
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotHash(c) => {
                let contract_id = F::from_noncanonical_u64(c.contract_id);

                let uct_witness_upper = self.get_self_user_contract_tree_leaf(contract_id).await?;

                let state_slot_witness_lower = self.get_contract_state_slot(contract_id, F::from_canonical_u64(c.slot_index)).await?;
                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: state_slot_witness_lower.value.0.elements.to_vec(),
                    witness: DPNStateCmdWitness::MerkleProofArray(vec![uct_witness_upper, state_slot_witness_lower]),
                })
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotSingle(c) => {
                let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                let slot_offset = c.sub_slot_index % 4u64;
                let contract_id = F::from_noncanonical_u64(c.contract_id);

                let uct_witness_upper = self.get_self_user_contract_tree_leaf(contract_id).await?;
                let state_slot_witness_lower = self.get_contract_state_slot(contract_id, slot_index).await?;

                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: vec![state_slot_witness_lower.value.0.elements[slot_offset as usize]],
                    witness: DPNStateCmdWitness::MerkleProofArray(vec![uct_witness_upper, state_slot_witness_lower]),
                })
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotRange(c) => {
                let contract_id = F::from_noncanonical_u64(c.contract_id);

                let uct_witness_upper = self.get_self_user_contract_tree_leaf(contract_id).await?;

                if c.length == 1 {
                    let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                    let n = (c.sub_slot_index & 0b11) as usize;
                    let cur = self.get_contract_state_slot(contract_id, slot_index).await?;
                    let el = cur.value.0.elements[n];
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result: vec![el],
                        witness: DPNStateCmdWitness::MerkleProofArray(vec![uct_witness_upper, cur]),
                    })
                } else if c.length < 6 {
                    // two merkle proofs

                    let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                    let n = (c.sub_slot_index & 0b11) as usize;
                    let proof_0 = self.get_contract_state_slot(contract_id, slot_index).await?;
                    let proof_1 = self.get_contract_state_slot(contract_id, slot_index + F::ONE).await?;

                    let elements = [proof_0.value.0.elements, proof_1.value.0.elements].concat();

                    let result = elements[n..(n + c.length as usize)].to_vec();
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result,
                        witness: DPNStateCmdWitness::MerkleProofArray(vec![uct_witness_upper, proof_0, proof_1]),
                    })
                } else {
                    let n_proofs = ((c.length + 6) / 4) as u64;
                    let sub_slot_index_mod_4 = c.sub_slot_index % 4;
                    let start_slot = c.sub_slot_index / 4;
                    let mut mps = Vec::with_capacity(n_proofs as usize + 1);
                    let mut result = Vec::<F>::with_capacity(c.length as usize);
                    mps.push(uct_witness_upper);

                    let len_minus_2_mod_4 = (c.length - 2) % 4;

                    for i in 0..n_proofs {
                        let mp = self.get_contract_state_slot(contract_id, F::from_canonical_u64(start_slot + i)).await?;
                        if i == 0 {
                            if sub_slot_index_mod_4 == 0 {
                                result.push(mp.value.0.elements[0]);
                                result.push(mp.value.0.elements[1]);
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 1 {
                                result.push(mp.value.0.elements[1]);
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 2 {
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 3 {
                                result.push(mp.value.0.elements[3]);
                            }
                        } else if i == (n_proofs - 1) {
                            let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                            if slot_mask_type >= 3 {
                                result.push(mp.value.0.elements[0]);
                            }
                            if slot_mask_type >= 4 {
                                result.push(mp.value.0.elements[1]);
                            }
                            if slot_mask_type >= 5 {
                                result.push(mp.value.0.elements[2]);
                            }
                            if slot_mask_type >= 6 {
                                result.push(mp.value.0.elements[3]);
                            }
                        } else {
                            result.extend_from_slice(&mp.value.0.elements);
                        }
                        mps.push(mp);
                    }

                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result,
                        witness: DPNStateCmdWitness::MerkleProofArray(mps),
                    })
                }
            }
            DPNStateCmd::GetOtherUserContractStateSlotHash(c) => {
                let user_id = F::from_noncanonical_u64(c.user_id);

                let user_leaf_witness = self.get_external_user_leaf_proof(user_id).await?;
                let contract_state_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractTreeMerkleProof(
                        QSRMerkleCmdGetUserContractTreeMerkleProof {
                            checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                            user_id: c.user_id,
                            contract_id: c.contract_id as u32,
                        },
                    ))
                    .await?;

                let state_slot_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                        QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                            checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                            user_id: c.user_id,
                            contract_id: c.contract_id as u32,
                            height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                            leaf_id: c.slot_index,
                        },
                    ))
                    .await?;
                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: state_slot_proof.value.0.elements.to_vec(),
                    witness: DPNStateCmdWitness::ReadOtherUserContractState(DPNReadOtherUserContractStateLeafMerkleProof {
                        user_leaf_witness,
                        contract_state_proof,
                        state_slot_proofs: vec![state_slot_proof],
                    }),
                })
            }
            DPNStateCmd::GetOtherUserContractStateSlotSingle(c) => {
                let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                let slot_offset = c.sub_slot_index % 4u64;
                let user_id = F::from_noncanonical_u64(c.user_id);

                let user_leaf_witness = self.get_external_user_leaf_proof(user_id).await?;
                let contract_state_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractTreeMerkleProof(
                        QSRMerkleCmdGetUserContractTreeMerkleProof {
                            checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                            user_id: c.user_id,
                            contract_id: c.contract_id as u32,
                        },
                    ))
                    .await?;

                let state_slot_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                        QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                            checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                            user_id: c.user_id,
                            contract_id: c.contract_id as u32,
                            height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                            leaf_id: slot_index.to_canonical_u64(),
                        },
                    ))
                    .await?;
                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: vec![state_slot_proof.value.0.elements[slot_offset as usize]],
                    witness: DPNStateCmdWitness::ReadOtherUserContractState(DPNReadOtherUserContractStateLeafMerkleProof {
                        user_leaf_witness,
                        contract_state_proof,
                        state_slot_proofs: vec![state_slot_proof],
                    }),
                })
            }
            DPNStateCmd::GetOtherUserContractStateSlotRange(c) => {
                let user_id = F::from_noncanonical_u64(c.user_id);

                let user_leaf_witness = self.get_external_user_leaf_proof(user_id).await?;
                let contract_state_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractTreeMerkleProof(
                        QSRMerkleCmdGetUserContractTreeMerkleProof {
                            checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                            user_id: c.user_id,
                            contract_id: c.contract_id as u32,
                        },
                    ))
                    .await?;

                if c.length == 1 {
                    //let slot_index = F::from_canonical_u64(c.sub_slot_index / 4u64);
                    //let n = (c.sub_slot_index & 0b11) as usize;

                    let state_slot_proof = self
                        .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                            QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                                checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                                user_id: c.user_id,
                                contract_id: c.contract_id as u32,
                                height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                                leaf_id: c.sub_slot_index / 4u64,
                            },
                        ))
                        .await?;
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result: state_slot_proof.value.0.elements.to_vec(),
                        witness: DPNStateCmdWitness::ReadOtherUserContractState(DPNReadOtherUserContractStateLeafMerkleProof {
                            user_leaf_witness,
                            contract_state_proof,
                            state_slot_proofs: vec![state_slot_proof],
                        }),
                    })
                } else if c.length < 6 {
                    // two merkle proofs

                    let slot_index = c.sub_slot_index / 4u64;
                    let n = (c.sub_slot_index & 0b11) as usize;
                    let proof_0 = self
                        .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                            QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                                checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                                user_id: c.user_id,
                                contract_id: c.contract_id as u32,
                                height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                                leaf_id: slot_index,
                            },
                        ))
                        .await?;
                    let proof_1 = self
                        .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                            QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                                checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                                user_id: c.user_id,
                                contract_id: c.contract_id as u32,
                                height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                                leaf_id: slot_index + 1,
                            },
                        ))
                        .await?;

                    let elements = [proof_0.value.0.elements, proof_1.value.0.elements].concat();

                    let result = elements[n..(n + c.length as usize)].to_vec();

                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result,
                        witness: DPNStateCmdWitness::ReadOtherUserContractState(DPNReadOtherUserContractStateLeafMerkleProof {
                            user_leaf_witness,
                            contract_state_proof,
                            state_slot_proofs: vec![proof_0, proof_1],
                        }),
                    })
                } else {
                    let n_proofs = ((c.length + 6) / 4) as u64;
                    let sub_slot_index_mod_4 = c.sub_slot_index % 4;
                    let start_slot = c.sub_slot_index / 4;
                    let mut mps = Vec::with_capacity(n_proofs as usize + 1);
                    let mut result = Vec::<F>::with_capacity(c.length as usize);

                    let len_minus_2_mod_4 = (c.length - 2) % 4;

                    for i in 0..n_proofs {
                        let mp = self
                            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                                QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                                    checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                                    user_id: c.user_id,
                                    contract_id: c.contract_id as u32,
                                    height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                                    leaf_id: start_slot + i,
                                },
                            ))
                            .await?;
                        if i == 0 {
                            if sub_slot_index_mod_4 == 0 {
                                result.push(mp.value.0.elements[0]);
                                result.push(mp.value.0.elements[1]);
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 1 {
                                result.push(mp.value.0.elements[1]);
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 2 {
                                result.push(mp.value.0.elements[2]);
                                result.push(mp.value.0.elements[3]);
                            } else if sub_slot_index_mod_4 == 3 {
                                result.push(mp.value.0.elements[3]);
                            }
                        } else if i == (n_proofs - 1) {
                            let slot_mask_type = (len_minus_2_mod_4 as usize) + sub_slot_index_mod_4 as usize;
                            if slot_mask_type >= 3 {
                                result.push(mp.value.0.elements[0]);
                            }
                            if slot_mask_type >= 4 {
                                result.push(mp.value.0.elements[1]);
                            }
                            if slot_mask_type >= 5 {
                                result.push(mp.value.0.elements[2]);
                            }
                            if slot_mask_type >= 6 {
                                result.push(mp.value.0.elements[3]);
                            }
                        } else {
                            result.extend_from_slice(&mp.value.0.elements);
                        }
                        mps.push(mp);
                    }

                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result,
                        witness: DPNStateCmdWitness::ReadOtherUserContractState(DPNReadOtherUserContractStateLeafMerkleProof {
                            user_leaf_witness,
                            contract_state_proof,
                            state_slot_proofs: mps,
                        }),
                    })
                }
            }
            DPNStateCmd::InvokeExternalContractFunctionDeferred(c) => {
                let call_data = DPNProvingSessionSimpleMethodCall {
                    caller_contract_id: current_contract_id,
                    contract_id: F::from_canonical_u64(c.contract_id),
                    method_id: F::from_canonical_u64(c.method_id),
                    inputs: c.input_args.iter().map(|x| F::from_canonical_u64(*x)).collect::<Vec<F>>(),
                };
                if c.condition == 0 {
                    let insertion_proof_placeholder = mp_to_dmp(self.get_latest_deferred_tx_leaf()?);
                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result: call_data
                            .qfhash::<<Self as PsyReadLocalProvingSessionStoreMut<F>>::Hasher>()
                            .0
                            .elements
                            .to_vec(),
                        witness: DPNStateCmdWitness::InvokeExternalContractFunctionDeferred(DPNInvokeDeferredMethodCallWitness {
                            call_data,
                            insertion_proof: insertion_proof_placeholder,
                        }),
                    })
                } else {
                    let insertion_proof = self.add_deferred_tx_to_debt(call_data.clone())?;
                    let call_hash = call_data.qfhash::<<Self as PsyReadLocalProvingSessionStoreMut<F>>::Hasher>();
                    tracing::debug!(
                        "deferred_witness insertion_proof old_root={} new_root={} old_value={} new_value={} call_hash={}",
                        insertion_proof.old_root,
                        insertion_proof.new_root,
                        insertion_proof.old_value,
                        insertion_proof.new_value,
                        call_hash
                    );

                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result: call_hash.0.elements.to_vec(),
                        witness: DPNStateCmdWitness::InvokeExternalContractFunctionDeferred(DPNInvokeDeferredMethodCallWitness {
                            call_data,
                            insertion_proof,
                        }),
                    })
                }
            }
            DPNStateCmd::GetContractLeaf(c) => {
                let contract_leaf = self
                    .resolve_get_contract_leaf_mut(&QSRCmdGetContractLeafData { contract_id: c.contract_id })
                    .await?;

                let contract_tree_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetContractTreeMerkleProof(QSRMerkleCmdGetContractTreeMerkleProof {
                        checkpoint_id: self.get_current_start_checkpoint_id_u64(),
                        contract_id: c.contract_id as u32,
                    }))
                    .await?;

                let result = contract_leaf.to_qfelts();

                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result,
                    witness: DPNStateCmdWitness::ContractLeaf(DPNContractLeafWitness {
                        contract_leaf,
                        contract_tree_proof,
                    }),
                })
            }
            DPNStateCmd::GetCheckpointLeafStats(c) => {
                let requested_checkpoint_id = c.checkpoint_id;
                let checkpoint_leaf_cmd = QSRCmdGetCheckpointLeafData {
                    checkpoint_id: requested_checkpoint_id,
                };
                let checkpoint_leaf = self.resolve_get_checkpoint_leaf_mut(&checkpoint_leaf_cmd).await?;

                let state_roots = self.get_checkpoint_state_roots(requested_checkpoint_id).await?;

                let current_checkpoint_id = self.get_current_start_checkpoint_id_u64();
                let historical_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetCheckpointTreeMerkleProof(QSRMerkleCmdGetCheckpointTreeMerkleProof {
                        checkpoint_id: current_checkpoint_id,
                        leaf_checkpoint_id: requested_checkpoint_id,
                    }))
                    .await?;

                let mut result = Vec::new();
                result.extend_from_slice(&checkpoint_leaf.stats.to_qfelts());

                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result,
                    witness: DPNStateCmdWitness::CheckpointLeafStats(DPNCheckpointLeafStatsWitness {
                        checkpoint_leaf_stats: checkpoint_leaf.stats,
                        checkpoint_state_roots: state_roots,
                        checkpoint_historical_proof: historical_proof,
                    }),
                })
            }
            DPNStateCmd::GetGlobalStateRoots(c) => {
                let requested_checkpoint_id = c.checkpoint_id;
                let checkpoint_leaf_cmd = QSRCmdGetCheckpointLeafData {
                    checkpoint_id: requested_checkpoint_id,
                };
                let checkpoint_leaf = self.resolve_get_checkpoint_leaf_mut(&checkpoint_leaf_cmd).await?;

                let state_roots = self.get_checkpoint_state_roots(requested_checkpoint_id).await?;

                let current_checkpoint_id = self.get_current_start_checkpoint_id_u64();
                let historical_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetCheckpointTreeMerkleProof(QSRMerkleCmdGetCheckpointTreeMerkleProof {
                        checkpoint_id: current_checkpoint_id,
                        leaf_checkpoint_id: requested_checkpoint_id,
                    }))
                    .await?;

                let result = state_roots.to_qfelts();

                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result,
                    witness: DPNStateCmdWitness::CheckpointGlobalStateRoots(DPNCheckpointGlobalStateRootsWitness {
                        checkpoint_state_roots: state_roots,
                        checkpoint_leaf_stats: checkpoint_leaf.stats,
                        checkpoint_historical_proof: historical_proof,
                    }),
                })
            }
            DPNStateCmd::ClearEntireTree(c) => {
                let current_contract_id = self.get_current_contract_id();

                let contract_leaf = self
                    .resolve_get_contract_leaf_mut(&QSRCmdGetContractLeafData {
                        contract_id: current_contract_id.to_canonical_u64(),
                    })
                    .await?;

                let state_tree_height = contract_leaf.state_tree_height.to_canonical_u64();
                let zero_hash = <Self as PsyReadLocalProvingSessionStoreMut<F>>::Hasher::get_zero_hash(state_tree_height as usize);

                if c.condition == 0 {
                    let current_state_root = self.get_contract_state_slot(current_contract_id, F::ZERO).await?.root;

                    return Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result: current_state_root
                            .0
                            .elements
                            .iter()
                            .map(|x| F::from_noncanonical_u64(x.to_canonical_u64()))
                            .collect(),
                        witness: DPNStateCmdWitness::ClearEntireTree(DPNClearEntireTreeWitness {
                            state_tree_height,
                            zero_hash,
                        }),
                    });
                } else {
                    self.notify_clear_entire_tree(current_contract_id.to_canonical_u64()).await?;

                    let zero_hash_felts: Vec<F> = zero_hash
                        .0
                        .elements
                        .iter()
                        .map(|x| F::from_noncanonical_u64(x.to_canonical_u64()))
                        .collect();

                    Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        result: zero_hash_felts,
                        witness: DPNStateCmdWitness::ClearEntireTree(DPNClearEntireTreeWitness {
                            state_tree_height,
                            zero_hash,
                        }),
                    })
                }
            }

            DPNStateCmd::SetIMTContractStateValue(c) => {
                let key_hash = QHashOut::from_values(c.key[0], c.key[1], c.key[2], c.key[3]);
                let new_value = QHashOut::from_values(c.value[0], c.value[1], c.value[2], c.value[3]);
                let state_slot_base = imt_slot_base_from_subslot_base(c.base_offset);
                let capacity = c.capacity;
                let checkpoint_id = self.get_current_start_checkpoint_id_u64();
                let user_id = self.get_current_user_id_64();
                let contract_id_u32 = current_contract_id.to_canonical_u64() as u32;

                if c.condition == 0 {
                    let noop_slot_index = state_slot_base
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("IMT noop slot overflow: base={}", state_slot_base))?;
                    let noop_state_slot_index = F::from_canonical_u64(noop_slot_index);
                    let leaf_preimage_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                        checkpoint_id,
                        user_id,
                        contract_id: contract_id_u32,
                        leaf_index: noop_slot_index,
                    };
                    let noop_mp = self.get_contract_state_slot(current_contract_id, noop_state_slot_index).await?;
                    let noop_dmp = mp_to_dmp(noop_mp);
                    let mut result = Vec::with_capacity(8);
                    result.extend_from_slice(&noop_dmp.old_value.0.elements);
                    result.extend_from_slice(&noop_dmp.new_value.0.elements);

                    let noop_leaf = self
                        .resolve_contract_state_imt_get_leaf_preimage_mut(&leaf_preimage_lookup)
                        .await
                        .unwrap_or_default();
                    let witness = DPNStateCmdWitness::IMTSet(DPNIMTSetWitness {
                        delta_merkle_proofs: vec![noop_dmp.clone(), noop_dmp],
                        is_insert: false,
                        insert_has_predecessor: false,
                        old_leaf: noop_leaf.clone(),
                        new_leaf: noop_leaf.clone(),
                        predecessor_old_leaf: noop_leaf.clone(),
                        predecessor_new_leaf: noop_leaf,
                    });

                    return Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness,
                        result,
                    });
                }

                let leaf_index_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey {
                    key: c.key,
                    checkpoint_id,
                    user_id,
                    contract_id: contract_id_u32,
                    state_slot_base,
                    capacity,
                };
                let next_append_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetNextAppendIndex {
                    user_id,
                    contract_id: contract_id_u32,
                    state_slot_base,
                    capacity,
                };
                let (is_insert, leaf_slot_index) = match self.resolve_contract_state_imt_get_leaf_index_for_key_mut(&leaf_index_lookup).await {
                    Ok(existing_leaf_index) => {
                        let normalized_leaf_index = validate_imt_leaf_index(existing_leaf_index, state_slot_base, capacity)?;
                        let existing_leaf_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                            checkpoint_id,
                            user_id,
                            contract_id: contract_id_u32,
                            leaf_index: normalized_leaf_index,
                        };
                        let existing_leaf = self
                            .resolve_contract_state_imt_get_leaf_preimage_mut(&existing_leaf_lookup)
                            .await
                            .and_then(|leaf| validate_imt_preimage(leaf, state_slot_base, capacity))?;

                        if imt_leaf_matches_key(&existing_leaf, &key_hash) {
                            (false, normalized_leaf_index)
                        } else {
                            let next_append_index = self.resolve_contract_state_imt_get_next_append_index_mut(&next_append_lookup).await?;
                            tracing::warn!(
                                contract_id = current_contract_id.to_canonical_u64(),
                                normalized_leaf_index,
                                requested_key = %key_hash,
                                returned_leaf_key = %existing_leaf.key,
                                "IMT key lookup returned non-matching leaf; treating as insert"
                            );
                            (true, validate_imt_next_append_index(next_append_index, state_slot_base, capacity)?)
                        }
                    }
                    Err(err) if is_imt_key_not_found_error(&err) => {
                        let next_append_index = self.resolve_contract_state_imt_get_next_append_index_mut(&next_append_lookup).await?;
                        (true, validate_imt_next_append_index(next_append_index, state_slot_base, capacity)?)
                    }
                    Err(err) => return Err(err),
                };
                tracing::info!(
                    contract_id = current_contract_id.to_canonical_u64(),
                    base_offset = c.base_offset,
                    state_slot_base,
                    is_insert,
                    leaf_slot_index,
                    predecessor_lookup_key = %key_hash,
                    "IMT set resolved slot mapping"
                );
                let state_slot_index = F::from_canonical_u64(leaf_slot_index);
                let leaf_preimage_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                    checkpoint_id,
                    user_id,
                    contract_id: contract_id_u32,
                    leaf_index: leaf_slot_index,
                };
                let old_slot_mp = self.get_contract_state_slot(current_contract_id, state_slot_index).await?;

                let old_leaf_result = self
                    .resolve_contract_state_imt_get_leaf_preimage_mut(&leaf_preimage_lookup)
                    .await
                    .and_then(|leaf| validate_imt_preimage(leaf, state_slot_base, capacity));
                if !is_insert {
                    let old_leaf = match old_leaf_result {
                        Ok(existing_leaf) => existing_leaf,
                        Err(_) => {
                            anyhow::bail!("IMT update expects existing leaf preimage for slot index {}", leaf_slot_index)
                        }
                    };
                    let new_preimage = psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf {
                        key: old_leaf.key,
                        value: new_value,
                        next_key: old_leaf.next_key,
                        next_index: old_leaf.next_index,
                    };
                    let dmp = self
                        .set_contract_state_imt_update(
                            current_contract_id,
                            leaf_slot_index,
                            state_slot_index,
                            old_leaf.key,
                            old_leaf,
                            new_preimage,
                        )
                        .await?;
                    let delta_merkle_proofs = vec![dmp, old_slot_mp.to_delta_merkle_proof()];
                    let mut result = old_leaf.value.0.elements.to_vec();
                    result.extend_from_slice(&new_preimage.value.0.elements);
                    let predecessor_leaf = psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default();
                    let witness = DPNStateCmdWitness::IMTSet(DPNIMTSetWitness {
                        delta_merkle_proofs,
                        is_insert: false,
                        insert_has_predecessor: false,
                        old_leaf,
                        new_leaf: new_preimage,
                        predecessor_old_leaf: predecessor_leaf,
                        predecessor_new_leaf: predecessor_leaf,
                    });
                    return Ok(PsyCmdWithInputAndWitness {
                        state_cmd: state_cmd.clone(),
                        witness,
                        result,
                    });
                }

                if old_slot_mp.value != QHashOut::ZERO {
                    anyhow::bail!(
                        "IMT insert target slot is not empty: contract_id={}, slot={}, base={}, capacity={}; next_append_index/local mapping may be stale",
                        current_contract_id.to_canonical_u64(),
                        leaf_slot_index,
                        state_slot_base,
                        capacity
                    );
                }

                let old_leaf = old_leaf_result.unwrap_or_default();
                let predecessor_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdFindPredecessor {
                    key: c.key,
                    checkpoint_id,
                    user_id,
                    contract_id: contract_id_u32,
                    state_slot_base,
                    capacity,
                };
                let (insert_has_predecessor, predecessor_leaf_slot_index, predecessor_old_leaf) =
                    match self.resolve_contract_state_imt_find_predecessor_mut(&predecessor_lookup).await {
                        Ok((leaf_index, leaf)) => (
                            true,
                            validate_imt_predecessor_leaf_index(leaf_index, state_slot_base, capacity)?,
                            validate_imt_preimage(leaf, state_slot_base, capacity)?,
                        ),
                        Err(err) if is_imt_predecessor_not_found_error(&err) => {
                            // No predecessor found — the sentinel (base slot) is the predecessor.
                            // Read the actual sentinel preimage; it may have non-zero next pointers
                            // from previous inserts.  Falls back to default (all zeros) if the
                            // sentinel has never been written.
                            let sentinel_preimage_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                                checkpoint_id,
                                user_id,
                                contract_id: contract_id_u32,
                                leaf_index: state_slot_base,
                            };
                            let sentinel = self
                                .resolve_contract_state_imt_get_leaf_preimage_mut(&sentinel_preimage_lookup)
                                .await
                                .unwrap_or_default();
                            (false, state_slot_base, validate_imt_preimage(sentinel, state_slot_base, capacity)?)
                        }
                        Err(err) => return Err(err),
                    };

                let new_preimage = psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf {
                    key: key_hash,
                    value: new_value,
                    next_key: predecessor_old_leaf.next_key,
                    next_index: predecessor_old_leaf.next_index,
                };
                let predecessor_new_leaf = psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf {
                    key: predecessor_old_leaf.key,
                    value: predecessor_old_leaf.value,
                    next_key: key_hash,
                    next_index: F::from_canonical_u64(leaf_slot_index),
                };
                let predecessor_old_leaf_hash = predecessor_old_leaf.qfhash::<H>();
                let predecessor_new_leaf_hash = predecessor_new_leaf.qfhash::<H>();
                let new_preimage_hash = new_preimage.qfhash::<H>();
                let (pre_dmp, insert_dmp) = self
                    .set_contract_state_imt_insert(
                        current_contract_id,
                        predecessor_leaf_slot_index,
                        F::from_canonical_u64(predecessor_leaf_slot_index),
                        predecessor_old_leaf.clone(),
                        predecessor_new_leaf.clone(),
                        leaf_slot_index,
                        state_slot_index,
                        new_preimage.clone(),
                    )
                    .await?;
                let delta_merkle_proofs = vec![pre_dmp, insert_dmp];
                let mut result = old_leaf.value.0.elements.to_vec();
                result.extend_from_slice(&new_preimage.value.0.elements);
                let witness = DPNStateCmdWitness::IMTSet(DPNIMTSetWitness {
                    delta_merkle_proofs,
                    is_insert: true,
                    insert_has_predecessor,
                    old_leaf,
                    new_leaf: new_preimage,
                    predecessor_old_leaf,
                    predecessor_new_leaf,
                });
                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    witness,
                    result,
                })
            }
            DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(c) => {
                let state_slot_base = imt_slot_base_from_subslot_base(c.base_offset);
                let capacity = c.capacity;
                let checkpoint_id = self.get_current_start_checkpoint_id_u64();
                let user_id = self.get_current_user_id_64();
                let contract_id_u32 = current_contract_id.to_canonical_u64() as u32;

                let leaf_index_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey {
                    key: c.key,
                    checkpoint_id,
                    user_id,
                    contract_id: contract_id_u32,
                    state_slot_base,
                    capacity,
                };
                let leaf_slot_index = match self.resolve_contract_state_imt_get_leaf_index_for_key_mut(&leaf_index_lookup).await {
                    Ok(idx) => validate_imt_leaf_index(idx, state_slot_base, capacity)?,
                    Err(err) => return Err(err),
                };
                let state_slot_index = F::from_canonical_u64(leaf_slot_index);

                let merkle_witness = self.get_contract_state_slot(current_contract_id, state_slot_index).await?;

                let leaf_preimage_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                    checkpoint_id,
                    user_id,
                    contract_id: contract_id_u32,
                    leaf_index: leaf_slot_index,
                };
                let leaf_preimage = validate_imt_preimage(
                    self.resolve_contract_state_imt_get_leaf_preimage_mut(&leaf_preimage_lookup).await?,
                    state_slot_base,
                    capacity,
                )?;

                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: leaf_preimage.value.0.elements.to_vec(),
                    witness: DPNStateCmdWitness::IMTRead(DPNIMTReadWitness {
                        leaf_preimage,
                        merkle_proof: merkle_witness,
                    }),
                })
            }
            DPNStateCmd::GetSelfUserExternalIMTContractStateValue(c) => {
                let state_slot_base = imt_slot_base_from_subslot_base(c.base_offset);
                let capacity = c.capacity;
                let checkpoint_id = self.get_current_start_checkpoint_id_u64();
                let user_id = self.get_current_user_id_64();
                let external_contract_id_u32 = c.contract_id as u32;
                let external_contract_id_f = F::from_noncanonical_u64(c.contract_id);

                let leaf_index_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey {
                    key: c.key,
                    checkpoint_id,
                    user_id,
                    contract_id: external_contract_id_u32,
                    state_slot_base,
                    capacity,
                };
                let leaf_slot_index = validate_imt_leaf_index(
                    self.resolve_contract_state_imt_get_leaf_index_for_key_mut(&leaf_index_lookup).await?,
                    state_slot_base,
                    capacity,
                )?;
                let state_slot_index = F::from_canonical_u64(leaf_slot_index);

                let uct_merkle_witness = self.get_self_user_contract_tree_leaf(external_contract_id_f).await?;
                let state_slot_merkle_witness = self.get_contract_state_slot(external_contract_id_f, state_slot_index).await?;

                let leaf_preimage_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                    checkpoint_id,
                    user_id,
                    contract_id: external_contract_id_u32,
                    leaf_index: leaf_slot_index,
                };
                let leaf_preimage = validate_imt_preimage(
                    self.resolve_contract_state_imt_get_leaf_preimage_mut(&leaf_preimage_lookup).await?,
                    state_slot_base,
                    capacity,
                )?;

                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: leaf_preimage.value.0.elements.to_vec(),
                    witness: DPNStateCmdWitness::IMTSelfUserExternalRead(DPNIMTSelfUserExternalReadWitness {
                        contract_tree_proof: uct_merkle_witness,
                        state_slot_proof: state_slot_merkle_witness,
                        leaf_preimage,
                    }),
                })
            }
            DPNStateCmd::GetOtherUserIMTContractStateValue(c) => {
                let state_slot_base = imt_slot_base_from_subslot_base(c.base_offset);
                let capacity = c.capacity;
                let checkpoint_id = self.get_current_start_checkpoint_id_u64();
                let other_user_id_f = F::from_noncanonical_u64(c.user_id);
                let other_contract_id_u32 = c.contract_id as u32;

                let leaf_index_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey {
                    key: c.key,
                    checkpoint_id,
                    user_id: c.user_id,
                    contract_id: other_contract_id_u32,
                    state_slot_base,
                    capacity,
                };
                let leaf_slot_index = validate_imt_leaf_index(
                    self.resolve_contract_state_imt_get_leaf_index_for_key_mut(&leaf_index_lookup).await?,
                    state_slot_base,
                    capacity,
                )?;
                let state_slot_index = F::from_canonical_u64(leaf_slot_index);

                let user_leaf_witness = self.get_external_user_leaf_proof(other_user_id_f).await?;
                let contract_tree_merkle_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractTreeMerkleProof(
                        QSRMerkleCmdGetUserContractTreeMerkleProof {
                            checkpoint_id,
                            user_id: c.user_id,
                            contract_id: other_contract_id_u32,
                        },
                    ))
                    .await?;

                let state_slot_merkle_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                        QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                            checkpoint_id,
                            user_id: c.user_id,
                            contract_id: other_contract_id_u32,
                            height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                            leaf_id: state_slot_index.to_canonical_u64(),
                        },
                    ))
                    .await?;
                let leaf_preimage_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                    checkpoint_id,
                    user_id: c.user_id,
                    contract_id: other_contract_id_u32,
                    leaf_index: leaf_slot_index,
                };
                let leaf_preimage = validate_imt_preimage(
                    self.resolve_contract_state_imt_get_leaf_preimage_mut(&leaf_preimage_lookup).await?,
                    state_slot_base,
                    capacity,
                )?;
                Ok(PsyCmdWithInputAndWitness {
                    state_cmd: state_cmd.clone(),
                    result: leaf_preimage.value.0.elements.to_vec(),
                    witness: DPNStateCmdWitness::IMTOtherUserRead(DPNIMTOtherUserReadWitness {
                        user_leaf_witness,
                        contract_state_proof: contract_tree_merkle_proof,
                        state_slot_proof: state_slot_merkle_proof,
                        leaf_preimage,
                    }),
                })
            }
            DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(c) => {
                let key_hash = QHashOut::from_values(c.key[0], c.key[1], c.key[2], c.key[3]);
                let checkpoint_id = self.get_current_start_checkpoint_id_u64();
                let user_id = self.get_current_user_id_64();
                let contract_id_u32 = self.get_current_contract_id().to_canonical_u64() as u32;
                let state_slot_base = imt_slot_base_from_subslot_base(c.base_offset);
                let capacity = c.capacity;
                tracing::info!(
                    contract_id = contract_id_u32,
                    base_offset = c.base_offset,
                    state_slot_base,
                    capacity,
                    key = %key_hash,
                    "IMT contains lookup params"
                );
                let leaf_index_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey {
                    key: c.key,
                    checkpoint_id,
                    user_id,
                    contract_id: contract_id_u32,
                    state_slot_base,
                    capacity,
                };
                let predecessor_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdFindPredecessor {
                    key: c.key,
                    checkpoint_id,
                    user_id,
                    contract_id: contract_id_u32,
                    state_slot_base,
                    capacity,
                };

                match self.resolve_contract_state_imt_get_leaf_index_for_key_mut(&leaf_index_lookup).await {
                    Ok(found_index) => {
                        let leaf_index = validate_imt_leaf_index(found_index, state_slot_base, capacity)?;
                        let leaf_preimage_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                            checkpoint_id,
                            user_id,
                            contract_id: contract_id_u32,
                            leaf_index,
                        };
                        let membership_leaf = self
                            .resolve_contract_state_imt_get_leaf_preimage_mut(&leaf_preimage_lookup)
                            .await
                            .and_then(|leaf| validate_imt_preimage(leaf, state_slot_base, capacity))?;
                        if !imt_leaf_matches_key(&membership_leaf, &key_hash) {
                            tracing::warn!(
                                contract_id = current_contract_id.to_canonical_u64(),
                                leaf_index,
                                requested_key = %key_hash,
                                returned_leaf_key = %membership_leaf.key,
                                "IMT contains lookup returned non-matching leaf; treating as non-membership"
                            );
                            let (witness_slot_index, witness_leaf) =
                                match self.resolve_contract_state_imt_find_predecessor_mut(&predecessor_lookup).await {
                                    Ok((predecessor_leaf_index, predecessor_leaf)) => {
                                        let predecessor_min = state_slot_base;
                                        let predecessor_max = state_slot_base + capacity;
                                        if predecessor_leaf_index < predecessor_min || predecessor_leaf_index > predecessor_max {
                                            tracing::warn!(
                                                contract_id = current_contract_id.to_canonical_u64(),
                                                predecessor_leaf_index,
                                                state_slot_base,
                                                capacity,
                                                "IMT predecessor index is outside requested IMT range; falling back to sentinel"
                                            );
                                            (
                                                state_slot_base,
                                                psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default(),
                                            )
                                        } else {
                                            let predecessor_leaf = validate_imt_preimage(predecessor_leaf, state_slot_base, capacity)?;
                                            anyhow::ensure!(
                                                is_valid_imt_non_membership_predecessor::<F>(&predecessor_leaf, &key_hash),
                                                "invalid IMT non-membership predecessor witness"
                                            );
                                            (
                                                validate_imt_predecessor_leaf_index(predecessor_leaf_index, state_slot_base, capacity)?,
                                                predecessor_leaf,
                                            )
                                        }
                                    }
                                    Err(pred_err) if is_imt_predecessor_not_found_error(&pred_err) => (
                                        state_slot_base,
                                        psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default(),
                                    ),
                                    Err(pred_err) => return Err(pred_err),
                                };

                            let merkle_proof = self
                                .get_contract_state_slot(current_contract_id, F::from_canonical_u64(witness_slot_index))
                                .await?;

                            return Ok(PsyCmdWithInputAndWitness {
                                state_cmd: state_cmd.clone(),
                                result: vec![F::ZERO],
                                witness: DPNStateCmdWitness::IMTContains(DPNIMTContainsWitness {
                                    exists: false,
                                    leaf_preimage: witness_leaf,
                                    merkle_proof,
                                }),
                            });
                        }
                        let merkle_proof = self
                            .get_contract_state_slot(current_contract_id, F::from_canonical_u64(leaf_index))
                            .await?;

                        Ok(PsyCmdWithInputAndWitness {
                            state_cmd: state_cmd.clone(),
                            result: vec![F::ONE],
                            witness: DPNStateCmdWitness::IMTContains(DPNIMTContainsWitness {
                                exists: true,
                                leaf_preimage: membership_leaf,
                                merkle_proof,
                            }),
                        })
                    }
                    Err(err) if is_imt_key_not_found_error(&err) => {
                        let (witness_slot_index, witness_leaf) = match self.resolve_contract_state_imt_find_predecessor_mut(&predecessor_lookup).await
                        {
                            Ok((predecessor_leaf_index, predecessor_leaf)) => {
                                let predecessor_min = state_slot_base;
                                let predecessor_max = state_slot_base + capacity;
                                if predecessor_leaf_index < predecessor_min || predecessor_leaf_index > predecessor_max {
                                    tracing::warn!(
                                        contract_id = current_contract_id.to_canonical_u64(),
                                        predecessor_leaf_index,
                                        state_slot_base,
                                        capacity,
                                        "IMT predecessor index is outside requested IMT range; falling back to sentinel"
                                    );
                                    (
                                        state_slot_base,
                                        psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default(),
                                    )
                                } else {
                                    let predecessor_leaf = validate_imt_preimage(predecessor_leaf, state_slot_base, capacity)?;
                                    anyhow::ensure!(
                                        is_valid_imt_non_membership_predecessor::<F>(&predecessor_leaf, &key_hash),
                                        "invalid IMT non-membership predecessor witness"
                                    );
                                    (
                                        validate_imt_predecessor_leaf_index(predecessor_leaf_index, state_slot_base, capacity)?,
                                        predecessor_leaf,
                                    )
                                }
                            }
                            Err(pred_err) if is_imt_predecessor_not_found_error(&pred_err) => (
                                state_slot_base,
                                psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default(),
                            ),
                            Err(pred_err) => return Err(pred_err),
                        };

                        let merkle_proof = self
                            .get_contract_state_slot(current_contract_id, F::from_canonical_u64(witness_slot_index))
                            .await?;

                        Ok(PsyCmdWithInputAndWitness {
                            state_cmd: state_cmd.clone(),
                            result: vec![F::ZERO],
                            witness: DPNStateCmdWitness::IMTContains(DPNIMTContainsWitness {
                                exists: false,
                                leaf_preimage: witness_leaf,
                                merkle_proof,
                            }),
                        })
                    }
                    Err(err) => Err(err),
                }
            }
            DPNStateCmd::ContainsOtherUserIMTContractStateValue(c) => {
                let key_hash = QHashOut::from_values(c.key[0], c.key[1], c.key[2], c.key[3]);
                let checkpoint_id = self.get_current_start_checkpoint_id_u64();
                let other_user_id_f = F::from_noncanonical_u64(c.user_id);
                let other_contract_id_u32 = c.contract_id as u32;
                let state_slot_base = imt_slot_base_from_subslot_base(c.base_offset);
                let capacity = c.capacity;

                tracing::info!(
                    other_user_id = c.user_id,
                    contract_id = other_contract_id_u32,
                    base_offset = c.base_offset,
                    state_slot_base,
                    capacity,
                    key = %key_hash,
                    "IMT contains (other user) lookup params"
                );

                let leaf_index_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafIndexForKey {
                    key: c.key,
                    checkpoint_id,
                    user_id: c.user_id,
                    contract_id: other_contract_id_u32,
                    state_slot_base,
                    capacity,
                };
                let predecessor_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdFindPredecessor {
                    key: c.key,
                    checkpoint_id,
                    user_id: c.user_id,
                    contract_id: other_contract_id_u32,
                    state_slot_base,
                    capacity,
                };

                let user_leaf_witness = self.get_external_user_leaf_proof(other_user_id_f).await?;
                let contract_tree_merkle_proof = self
                    .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractTreeMerkleProof(
                        QSRMerkleCmdGetUserContractTreeMerkleProof {
                            checkpoint_id,
                            user_id: c.user_id,
                            contract_id: other_contract_id_u32,
                        },
                    ))
                    .await?;

                match self.resolve_contract_state_imt_get_leaf_index_for_key_mut(&leaf_index_lookup).await {
                    Ok(found_index) => {
                        let leaf_index = validate_imt_leaf_index(found_index, state_slot_base, capacity)?;
                        let leaf_preimage_lookup = psy_client_data::qstore::imm::cmd::QSRIMTCmdGetLeafPreimage {
                            checkpoint_id,
                            user_id: c.user_id,
                            contract_id: other_contract_id_u32,
                            leaf_index,
                        };
                        let membership_leaf = self
                            .resolve_contract_state_imt_get_leaf_preimage_mut(&leaf_preimage_lookup)
                            .await
                            .and_then(|leaf| validate_imt_preimage(leaf, state_slot_base, capacity))?;
                        if !imt_leaf_matches_key(&membership_leaf, &key_hash) {
                            tracing::warn!(
                                other_user_id = c.user_id,
                                contract_id = other_contract_id_u32,
                                leaf_index,
                                requested_key = %key_hash,
                                returned_leaf_key = %membership_leaf.key,
                                "IMT contains (other user) lookup returned non-matching leaf; treating as non-membership"
                            );
                            let (witness_slot_index, witness_leaf) =
                                match self.resolve_contract_state_imt_find_predecessor_mut(&predecessor_lookup).await {
                                    Ok((predecessor_leaf_index, predecessor_leaf)) => {
                                        let predecessor_min = state_slot_base;
                                        let predecessor_max = state_slot_base + capacity;
                                        if predecessor_leaf_index < predecessor_min || predecessor_leaf_index > predecessor_max {
                                            tracing::warn!(
                                                other_user_id = c.user_id,
                                                contract_id = other_contract_id_u32,
                                                predecessor_leaf_index,
                                                state_slot_base,
                                                capacity,
                                                "IMT predecessor index is outside requested IMT range; falling back to sentinel"
                                            );
                                            (
                                                state_slot_base,
                                                psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default(),
                                            )
                                        } else {
                                            let predecessor_leaf = validate_imt_preimage(predecessor_leaf, state_slot_base, capacity)?;
                                            anyhow::ensure!(
                                                is_valid_imt_non_membership_predecessor::<F>(&predecessor_leaf, &key_hash),
                                                "invalid IMT non-membership predecessor witness"
                                            );
                                            (
                                                validate_imt_predecessor_leaf_index(predecessor_leaf_index, state_slot_base, capacity)?,
                                                predecessor_leaf,
                                            )
                                        }
                                    }
                                    Err(pred_err) if is_imt_predecessor_not_found_error(&pred_err) => (
                                        state_slot_base,
                                        psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default(),
                                    ),
                                    Err(pred_err) => return Err(pred_err),
                                };

                            let state_slot_merkle_proof = self
                                .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                                    QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                                        checkpoint_id,
                                        user_id: c.user_id,
                                        contract_id: other_contract_id_u32,
                                        height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                                        leaf_id: witness_slot_index,
                                    },
                                ))
                                .await?;

                            return Ok(PsyCmdWithInputAndWitness {
                                state_cmd: state_cmd.clone(),
                                result: vec![F::ZERO],
                                witness: DPNStateCmdWitness::IMTContainsOtherUser(DPNIMTContainsOtherUserWitness {
                                    exists: false,
                                    user_leaf_witness,
                                    contract_state_proof: contract_tree_merkle_proof,
                                    state_slot_proof: state_slot_merkle_proof,
                                    leaf_preimage: witness_leaf,
                                }),
                            });
                        }
                        let state_slot_merkle_proof = self
                            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                                QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                                    checkpoint_id,
                                    user_id: c.user_id,
                                    contract_id: other_contract_id_u32,
                                    height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                                    leaf_id: leaf_index,
                                },
                            ))
                            .await?;

                        Ok(PsyCmdWithInputAndWitness {
                            state_cmd: state_cmd.clone(),
                            result: vec![F::ONE],
                            witness: DPNStateCmdWitness::IMTContainsOtherUser(DPNIMTContainsOtherUserWitness {
                                exists: true,
                                user_leaf_witness,
                                contract_state_proof: contract_tree_merkle_proof,
                                state_slot_proof: state_slot_merkle_proof,
                                leaf_preimage: membership_leaf,
                            }),
                        })
                    }
                    Err(err) if is_imt_key_not_found_error(&err) => {
                        let (witness_slot_index, witness_leaf) = match self.resolve_contract_state_imt_find_predecessor_mut(&predecessor_lookup).await
                        {
                            Ok((predecessor_leaf_index, predecessor_leaf)) => {
                                let predecessor_min = state_slot_base;
                                let predecessor_max = state_slot_base + capacity;
                                if predecessor_leaf_index < predecessor_min || predecessor_leaf_index > predecessor_max {
                                    tracing::warn!(
                                        other_user_id = c.user_id,
                                        contract_id = other_contract_id_u32,
                                        predecessor_leaf_index,
                                        state_slot_base,
                                        capacity,
                                        "IMT predecessor index is outside requested IMT range; falling back to sentinel"
                                    );
                                    (
                                        state_slot_base,
                                        psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default(),
                                    )
                                } else {
                                    let predecessor_leaf = validate_imt_preimage(predecessor_leaf, state_slot_base, capacity)?;
                                    anyhow::ensure!(
                                        is_valid_imt_non_membership_predecessor::<F>(&predecessor_leaf, &key_hash),
                                        "invalid IMT non-membership predecessor witness"
                                    );
                                    (
                                        validate_imt_predecessor_leaf_index(predecessor_leaf_index, state_slot_base, capacity)?,
                                        predecessor_leaf,
                                    )
                                }
                            }
                            Err(pred_err) if is_imt_predecessor_not_found_error(&pred_err) => (
                                state_slot_base,
                                psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf::default(),
                            ),
                            Err(pred_err) => return Err(pred_err),
                        };

                        let state_slot_merkle_proof = self
                            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserContractStateTreeMerkleProof(
                                QSRMerkleCmdGetUserContractStateTreeMerkleProof {
                                    checkpoint_id,
                                    user_id: c.user_id,
                                    contract_id: other_contract_id_u32,
                                    height: validate_contract_state_tree_height(c.contract_state_tree_height)?,
                                    leaf_id: witness_slot_index,
                                },
                            ))
                            .await?;

                        Ok(PsyCmdWithInputAndWitness {
                            state_cmd: state_cmd.clone(),
                            result: vec![F::ZERO],
                            witness: DPNStateCmdWitness::IMTContainsOtherUser(DPNIMTContainsOtherUserWitness {
                                exists: false,
                                user_leaf_witness,
                                contract_state_proof: contract_tree_merkle_proof,
                                state_slot_proof: state_slot_merkle_proof,
                                leaf_preimage: witness_leaf,
                            }),
                        })
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = PsyFelt))]
pub struct PsyCmdWithInputAndWitness<F: RichField> {
    pub state_cmd: DPNStateCmd<u64>,
    pub witness: DPNStateCmdWitness<F>,
    pub result: Vec<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyEvalSessionResult<F: RichField> {
    pub cmd_witnesses: Vec<PsyCmdWithInputAndWitness<F>>,
}

impl<F: RichField> PsyEvalSessionResult<F> {
    pub fn new() -> Self {
        Self { cmd_witnesses: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::imt_slot_base_from_subslot_base;

    #[test]
    fn test_imt_slot_base_from_subslot_base_rounds_up_to_slot_boundary() {
        assert_eq!(imt_slot_base_from_subslot_base(0), 0);
        assert_eq!(imt_slot_base_from_subslot_base(1), 1);
        assert_eq!(imt_slot_base_from_subslot_base(2), 1);
        assert_eq!(imt_slot_base_from_subslot_base(3), 1);
        assert_eq!(imt_slot_base_from_subslot_base(4), 1);
        assert_eq!(imt_slot_base_from_subslot_base(5), 2);
        assert_eq!(imt_slot_base_from_subslot_base(130), 33);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<F: RichField + PrimeField64> PsyEvalSessionResult<F> {
    pub async fn process_state_cmd<S>(&mut self, executor: &mut SimpleDPNExecutor<F>, sesh: &mut S, cmd: &DPNStateCmd<u64>) -> anyhow::Result<()>
    where
        S: PsyReadLocalProvingSessionStore<F>
            + PsyEventsStore<F>
            + PsyReadLocalProvingSessionStoreMut<F>
            + PsyCmdInputWitnessResolver<F, <S as PsyReadLocalProvingSessionStoreMut<F>>::Hasher>,
    {
        let real_inputs = cmd
            .get_inputs()
            .iter()
            .map(|x| {
                let (t, _index) = decode_indexed_op_id(*x);
                match t {
                    DPNBuiltInDataType::Target => executor.resolve_target(*x).to_canonical_u64(),
                    DPNBuiltInDataType::Bool => {
                        if executor.resolve_bool(*x) {
                            1
                        } else {
                            0
                        }
                    }
                    DPNBuiltInDataType::U32Target => executor.resolve_u32(*x) as u64,
                    DPNBuiltInDataType::Unknown => {
                        panic!("state cmd input contains Unknown typed op id: {}", x)
                    }
                    DPNBuiltInDataType::HashOut
                    | DPNBuiltInDataType::HashOut160
                    | DPNBuiltInDataType::TargetArray
                    | DPNBuiltInDataType::BoolArray
                    | DPNBuiltInDataType::U32TargetArray => {
                        panic!("state cmd input expects scalar, got {:?} for op id {}", t, x)
                    }
                }
            })
            .collect::<Vec<u64>>();
        let new_cmd = cmd.convert_to_u64(&real_inputs);
        tracing::debug!("process_state_cmd original={:?} real_inputs={:?} new_cmd={:?}", cmd, real_inputs, new_cmd);

        let r = sesh.resolve_vec(&new_cmd).await?;
        tracing::debug!("process_state_cmd resolved result={:?}", r.result);
        self.cmd_witnesses.push(r);
        Ok(())
    }

    pub async fn exec_deferred_contract_call<S>(
        self,
        sesh: &mut S,
        contract_id: F,
        caller_contract_id: F,
        fn_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<DapenContractFunctionCircuitInput<F>>
    where
        S: PsyReadLocalProvingSessionStore<F>
            + PsyEventsStore<F>
            + PsyReadLocalProvingSessionStoreMut<F>
            + PsyCmdInputWitnessResolver<F, <S as PsyReadLocalProvingSessionStoreMut<F>>::Hasher>,
    {
        if fn_def.circuit_inputs.len() != inputs.len() {
            return Err(anyhow::anyhow!(
                "Contract {} method {} expect {} number of inputs, but got {}",
                contract_id.to_canonical_u64(),
                fn_def.name,
                fn_def.circuit_inputs.len(),
                inputs.len()
            ));
        }
        sesh.init_transaction(DPNProvingSessionSimpleMethodCall {
            caller_contract_id,
            contract_id,
            method_id: F::from_canonical_u32(fn_def.method_id),
            inputs: inputs.clone(),
        })
        .await?;
        self.eval_session(fn_def, sesh, inputs).await
    }

    pub async fn exec_deferred_contract_call_local<S>(
        self,
        sesh: &mut S,
        caller_contract_id: F,
        fn_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<DapenContractFunctionCircuitInput<F>>
    where
        S: PsyReadLocalProvingSessionStore<F>
            + PsyEventsStore<F>
            + PsyReadLocalProvingSessionStoreMut<F>
            + PsyCmdInputWitnessResolver<F, <S as PsyReadLocalProvingSessionStoreMut<F>>::Hasher>,
    {
        self.exec_deferred_contract_call(
            sesh,
            F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64),
            caller_contract_id,
            fn_def,
            inputs,
        )
        .await
    }

    pub async fn exec_contract_call<S>(
        self,
        sesh: &mut S,
        contract_id: F,
        fn_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<DapenContractFunctionCircuitInput<F>>
    where
        S: PsyReadLocalProvingSessionStore<F>
            + PsyEventsStore<F>
            + PsyReadLocalProvingSessionStoreMut<F>
            + PsyCmdInputWitnessResolver<F, <S as PsyReadLocalProvingSessionStoreMut<F>>::Hasher>,
    {
        self.exec_deferred_contract_call(sesh, contract_id, F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64), fn_def, inputs)
            .await
    }

    async fn eval_session<S>(
        mut self,
        fn_def: &DPNFunctionCircuitDefinition,
        sesh: &mut S,
        inputs: Vec<F>,
    ) -> anyhow::Result<DapenContractFunctionCircuitInput<F>>
    where
        S: PsyReadLocalProvingSessionStore<F>
            + PsyEventsStore<F>
            + PsyReadLocalProvingSessionStoreMut<F>
            + PsyCmdInputWitnessResolver<F, <S as PsyReadLocalProvingSessionStoreMut<F>>::Hasher>,
    {
        fn_def.validate_state_command_resolution_semantics()?;
        let start_session_ctx = sesh.get_fresh_start_ctx_for_user(sesh.get_current_user_id()).await?;
        let mut call_data_ctx = sesh
            .get_call_start_data(sesh.get_current_contract_id(), F::from_canonical_u32(fn_def.method_id), &inputs)
            .await?;

        let inputs_clone = inputs.clone();
        let mut executor = SimpleDPNExecutor::<F>::new_with_contract_ctx(
            inputs,
            sesh.get_current_user_id(),
            sesh.get_current_contract_id(),
            sesh.get_current_caller_contract_id(),
            sesh.get_current_start_checkpoint_id(),
            sesh.get_nonce(),
            start_session_ctx.start_session_user_leaf.public_key.0.elements,
            sesh.get_q_recursion_proof_tree_root().0.elements,
        );
        let previous_transactions = sesh.get_previous_transaction_log();
        let transaction_infos = previous_transactions
            .iter()
            .map(|call| psy_client_data::dpn::sd_key::SDKeyTransactionInfo::from(call.to_compact::<S::Hasher>()))
            .collect::<Vec<_>>();
        let transaction_inputs = previous_transactions.iter().map(|call| call.inputs.clone()).collect::<Vec<_>>();
        let mut transaction_stack_hash = QHashOut::default();
        let transaction_log = previous_transactions
            .iter()
            .map(|call| {
                let compact = call.to_compact::<S::Hasher>();
                transaction_stack_hash = S::Hasher::q_two_to_one(transaction_stack_hash, compact.qfhash::<S::Hasher>());
                DPNTransactionEntry {
                    contract_id: call.contract_id,
                    caller_contract_id: call.caller_contract_id,
                    method_id: call.method_id,
                    inputs_length: compact.inputs_length,
                    inputs_hash: compact.inputs_hash.0.elements,
                    inputs: call.inputs.clone(),
                }
            })
            .collect();
        executor.set_transaction_context(transaction_log, transaction_stack_hash.0.elements);
        let state_cmd_len = fn_def.state_command_resolution_indices.len();
        let mut next_state_cmd_id = 0;
        let mut next_state_cmd_index = if state_cmd_len == 0 {
            fn_def.definitions.len() + 10
        } else {
            fn_def.state_command_resolution_indices[0]
        };
        for (i, def) in fn_def.definitions.iter().enumerate() {
            while i >= next_state_cmd_index && next_state_cmd_id < state_cmd_len {
                self.process_state_cmd(&mut executor, sesh, &fn_def.state_commands[next_state_cmd_id])
                    .await?;
                next_state_cmd_id += 1;
                if next_state_cmd_id >= state_cmd_len {
                    next_state_cmd_index = fn_def.definitions.len() + 10;
                } else {
                    next_state_cmd_index = fn_def.state_command_resolution_indices[next_state_cmd_id];
                }
            }
            if def.op_type.eq(&DPNOpType::GetStateCommandResultSingle) {
                let ind = def.inputs[0] as usize;
                executor.push_external_target(def.index, self.cmd_witnesses[ind].result[0]);
            } else if def.op_type.eq(&DPNOpType::GetStateCommandResultArray) {
                let ind = def.inputs[0] as usize;
                executor.push_external_target_array(def.index, self.cmd_witnesses[ind].result.clone());
            } else if def.op_type.eq(&DPNOpType::GetStateCommandResultHash) {
                let ind = def.inputs[0] as usize;
                executor.push_external_hash(
                    def.index,
                    [
                        self.cmd_witnesses[ind].result[0],
                        self.cmd_witnesses[ind].result[1],
                        self.cmd_witnesses[ind].result[2],
                        self.cmd_witnesses[ind].result[3],
                    ],
                );
            } else {
                executor.process_var_def(&def);
            }
        }
        while next_state_cmd_id < state_cmd_len {
            self.process_state_cmd(&mut executor, sesh, &fn_def.state_commands[next_state_cmd_id])
                .await?;
            next_state_cmd_id += 1;
        }
        for assertion in fn_def.assertions.iter() {
            let left = executor.resolve_target(assertion.left).to_canonical_u64();
            let right = executor.resolve_target(assertion.right).to_canonical_u64();
            tracing::trace!("ASSERTION: msg={} left={} right={}", assertion.message, left, right);
            if left != right {
                if assertion.message.contains("proof tree root mismatch") {
                    tracing::error!("ASSERTION FAILED: proof tree root mismatch — cmp_field={} expected_field={}", left, right,);
                }
                anyhow::bail!("assertion failed: {} (left: {}, right: {})", assertion.message, left, right);
            }
        }

        let mut events = Vec::new();
        let start_event_index = sesh.get_event_index();
        for event in fn_def.events.iter() {
            let condition = executor.resolve_target(event.condition);
            if condition == F::ZERO {
                // Condition is false — skip this event, event index stays unchanged
                continue;
            }
            let event_record = PsyUserEventRecord {
                checkpoint_id: executor.resolve_target(event.checkpoint_id),
                user_id: executor.resolve_target(event.user_id),
                contract_id: executor.resolve_target(event.contract_id),
                method_id: F::from_canonical_u32(fn_def.method_id),
                event_index: start_event_index + F::from_noncanonical_u64(events.len() as u64),
                data: event.data.iter().map(|x| executor.resolve_target(*x)).collect::<Vec<F>>(),
            };
            events.push(event_record);
        }

        let total_events_emitted = F::from_noncanonical_u64(events.len() as u64);
        sesh.write_events(events.clone());

        let outputs = fn_def.circuit_outputs.iter().map(|x| executor.resolve_target(*x)).collect::<Vec<F>>();
        let end_contract_state_tree_root = if let Some(tracker) = sesh
            .get_local_state_tracker()
            .contracts
            .get(&sesh.get_current_contract_id().to_canonical_u64())
        {
            tracker.end_state_root
        } else {
            sesh.get_contract_state_slot(sesh.get_current_contract_id(), F::ZERO).await?.root
        };
        let mut end_ctx = DapenCFCUserTransactionEndContext {
            end_contract_state_tree_root,
            end_deferred_tx_debt_tree_root: sesh.get_latest_deferred_tx_leaf()?.root,
            outputs_hash: safe_hash_fixed_length::<<S as PsyReadLocalProvingSessionStoreMut<F>>::Hasher, F>(&outputs),
            outputs_length: F::from_noncanonical_u64(outputs.len() as u64),
            total_events_emitted,
            total_balance_spent: F::from_noncanonical_u64(0),
        };

        // Root-consistency fix for deferred commands:
        // If this tx enqueued deferred children, align the tx input context roots
        // with the actual insertion proof roots captured in the command witness.
        let deferred_witnesses = self
            .cmd_witnesses
            .iter()
            .filter_map(|w| match &w.witness {
                DPNStateCmdWitness::InvokeExternalContractFunctionDeferred(dw) => Some(dw),
                _ => None,
            })
            .collect::<Vec<&DPNInvokeDeferredMethodCallWitness<F>>>();
        if let (Some(first), Some(last)) = (deferred_witnesses.first(), deferred_witnesses.last()) {
            if call_data_ctx.start_deferred_tx_debt_tree_root != first.insertion_proof.old_root {
                tracing::warn!(
                    "adjusting start_deferred_tx_debt_tree_root from {} to {} to match deferred insertion proof",
                    call_data_ctx.start_deferred_tx_debt_tree_root,
                    first.insertion_proof.old_root
                );
                call_data_ctx.start_deferred_tx_debt_tree_root = first.insertion_proof.old_root;
            }
            if end_ctx.end_deferred_tx_debt_tree_root != last.insertion_proof.new_root {
                tracing::warn!(
                    "adjusting end_deferred_tx_debt_tree_root from {} to {} to match deferred insertion proof",
                    end_ctx.end_deferred_tx_debt_tree_root,
                    last.insertion_proof.new_root
                );
                end_ctx.end_deferred_tx_debt_tree_root = last.insertion_proof.new_root;
            }
        }

        let input_ctx = DapenCFCUserTransactionInputContext {
            proving_session_start_ctx: start_session_ctx,
            transaction_call_start_ctx: call_data_ctx,
            transaction_end_ctx: end_ctx,
        };

        sesh.finalize_transaction().await?;

        Ok(DapenContractFunctionCircuitInput {
            inputs: inputs_clone,
            outputs,
            events,
            cmd_witnesses: self.cmd_witnesses,
            session_proof_tree_root: sesh.get_q_recursion_proof_tree_root(),
            tx_input_ctx: input_ctx,
            transaction_infos,
            transaction_inputs,
            transaction_stack_hash,
        })
    }
}
