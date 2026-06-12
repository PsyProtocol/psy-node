use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::{data::qhashout::QHashOut, traits::to_qfelts::ToQFelts};
use psy_config::network_constants::{DEFAULT_CALLER_CONTRACT_ID_U64, DEFERRED_CALL_MAGIC, SIGN_SIMPLE_TRANSACTION_MAGIC};
use psy_crypto::hash::{
    merkle::core::DeltaMerkleProofCore,
    traits::{hasher::FieldQHasher, qhashable::QFieldHashable},
    utils::safe_hash_fixed_length,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::qdata::{
    checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
    user::PsyUserLeaf,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct DPNProvingSessionCheckpointState<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub checkpoint_hash: QHashOut<F>,
    pub checkpoint_id: F,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub last_global_tree_state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub session_start_user_leaf: PsyUserLeaf<F>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNProvingSessionCompactMethodCall<F: RichField> {
    pub caller_contract_id: F,
    pub contract_id: F,
    pub method_id: F,
    pub inputs_length: F,
    pub inputs_hash: QHashOut<F>,
}
impl<F: RichField> DPNProvingSessionCompactMethodCall<F> {
    pub fn new_from_inputs<H: FieldQHasher<F>>(caller_contract_id: F, contract_id: F, method_id: F, inputs: &[F]) -> Self {
        let inputs_length = F::from_canonical_u64(inputs.len() as u64);
        let inputs_hash = safe_hash_fixed_length::<H, F>(inputs);

        Self {
            caller_contract_id,
            contract_id,
            method_id,
            inputs_length,
            inputs_hash,
        }
    }
}

impl<F: RichField> KVQSerializable for DPNProvingSessionCompactMethodCall<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> ToQFelts<F> for DPNProvingSessionCompactMethodCall<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![
            self.caller_contract_id,
            self.contract_id,
            self.method_id,
            self.inputs_length,
            self.inputs_hash.0.elements[0],
            self.inputs_hash.0.elements[1],
            self.inputs_hash.0.elements[2],
            self.inputs_hash.0.elements[3],
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 8 {
            panic!(
                "Invalid number of elements for DPNProvingSessionCompactMethodCall, expected 8, got {}",
                felts.len()
            );
        }

        Self {
            caller_contract_id: felts[0],
            contract_id: felts[1],
            method_id: felts[2],
            inputs_length: felts[3],
            inputs_hash: QHashOut::from_felt_slice(&felts[4..]),
        }
    }
}

impl<F: RichField> QFieldHashable<F> for DPNProvingSessionCompactMethodCall<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let magic_felt = F::from_noncanonical_u64(DEFERRED_CALL_MAGIC);

        /*
          we need to be able to verify:
            - the contract being called
            - the method called
            - the length of the inputs
            - the hash of the inputs
        */

        H::q_hash_many(&[
            magic_felt,
            self.caller_contract_id,
            self.contract_id,
            self.method_id,
            self.inputs_length,
            self.inputs_hash.0.elements[0],
            self.inputs_hash.0.elements[1],
            self.inputs_hash.0.elements[2],
            self.inputs_hash.0.elements[3],
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct DPNProvingSessionSimpleMethodCall<F: RichField> {
    pub caller_contract_id: F,
    pub contract_id: F,
    pub method_id: F,
    pub inputs: Vec<F>,
}
impl<F: RichField> DPNProvingSessionSimpleMethodCall<F> {
    pub fn new(contract_id: F, method_id: F, inputs: Vec<F>) -> Self {
        Self {
            caller_contract_id: F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64),
            contract_id,
            method_id,
            inputs,
        }
    }
    pub fn to_compact<H: FieldQHasher<F>>(&self) -> DPNProvingSessionCompactMethodCall<F> {
        DPNProvingSessionCompactMethodCall::new_from_inputs::<H>(self.caller_contract_id, self.contract_id, self.method_id, &self.inputs)
    }
}
impl<F: RichField> Default for DPNProvingSessionSimpleMethodCall<F> {
    fn default() -> Self {
        Self {
            caller_contract_id: F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64),
            contract_id: F::ZERO,
            method_id: F::ZERO,
            inputs: Vec::new(),
        }
    }
}
impl<F: RichField> KVQSerializable for DPNProvingSessionSimpleMethodCall<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> ToQFelts<F> for DPNProvingSessionSimpleMethodCall<F> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut felts = Vec::with_capacity(3 + self.inputs.len());
        felts.push(self.caller_contract_id);
        felts.push(self.contract_id);
        felts.push(self.method_id);
        felts.extend_from_slice(&self.inputs);
        felts
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() < 3 {
            panic!("Invalid number of elements for DPNProvingSessionSimpleMethodCall");
        }
        Self {
            caller_contract_id: felts[0],
            contract_id: felts[1],
            method_id: felts[2],
            inputs: felts[3..].to_vec(),
        }
    }
}

impl<F: RichField> QFieldHashable<F> for DPNProvingSessionSimpleMethodCall<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        DPNProvingSessionCompactMethodCall::new_from_inputs::<H>(self.caller_contract_id, self.contract_id, self.method_id, &self.inputs)
            .qfhash::<H>()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct DPNProvingSessionSignableCompactMethodCall<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub call_data: DPNProvingSessionCompactMethodCall<F>,
}

impl<F: RichField> KVQSerializable for DPNProvingSessionSignableCompactMethodCall<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> ToQFelts<F> for DPNProvingSessionSignableCompactMethodCall<F> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut felts = Vec::with_capacity(10);
        felts.push(self.checkpoint_id);
        felts.push(self.user_id);
        felts.extend_from_slice(&self.call_data.to_qfelts());
        felts
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 10 {
            panic!(
                "Invalid number of elements for DPNProvingSessionSignableCompactMethodCall: expected 10, got {}",
                felts.len()
            );
        }
        Self {
            checkpoint_id: felts[0],
            user_id: felts[1],
            call_data: DPNProvingSessionCompactMethodCall::from_qfelts(&felts[2..]),
        }
    }
}

impl<F: RichField> QFieldHashable<F> for DPNProvingSessionSignableCompactMethodCall<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        let call_data_hash = self.call_data.qfhash::<H>();

        H::q_hash_many(&[
            F::from_noncanonical_u64(SIGN_SIMPLE_TRANSACTION_MAGIC),
            self.checkpoint_id,
            self.user_id,
            F::from_noncanonical_u64(SIGN_SIMPLE_TRANSACTION_MAGIC),
            call_data_hash.0.elements[0],
            call_data_hash.0.elements[1],
            call_data_hash.0.elements[2],
            call_data_hash.0.elements[3],
        ])
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct DPNProvingSessionSignableMethodCall<F: RichField> {
    pub checkpoint_id: F,
    pub user_id: F,
    pub call_data: DPNProvingSessionSimpleMethodCall<F>,
}

impl<F: RichField> DPNProvingSessionSignableMethodCall<F> {
    pub fn new(user_id: F, checkpoint_id: F, call_data: DPNProvingSessionSimpleMethodCall<F>) -> Self {
        Self {
            checkpoint_id,
            user_id,
            call_data,
        }
    }
    pub fn to_compact<H: FieldQHasher<F>>(&self) -> DPNProvingSessionSignableCompactMethodCall<F> {
        let call_data_compact = self.call_data.to_compact::<H>();
        DPNProvingSessionSignableCompactMethodCall {
            checkpoint_id: self.checkpoint_id,
            user_id: self.user_id,
            call_data: call_data_compact,
        }
    }
}

impl<F: RichField> KVQSerializable for DPNProvingSessionSignableMethodCall<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> ToQFelts<F> for DPNProvingSessionSignableMethodCall<F> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut felts = Vec::with_capacity(10);
        felts.push(self.checkpoint_id);
        felts.push(self.user_id);
        felts.extend_from_slice(&self.call_data.to_qfelts());
        felts
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() < 5 {
            panic!(
                "Invalid number of elements for DPNProvingSessionSignableMethodCall: expected >= 5, got {}",
                felts.len()
            );
        }
        Self {
            checkpoint_id: felts[0],
            user_id: felts[1],
            call_data: DPNProvingSessionSimpleMethodCall::from_qfelts(&felts[2..]),
        }
    }
}

impl<F: RichField> QFieldHashable<F> for DPNProvingSessionSignableMethodCall<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        self.to_compact::<H>().qfhash::<H>()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct DPNProvingSessionCallStack<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub checkpoint_hash: QHashOut<F>,
    pub checkpoint_id: F,
    pub checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub last_global_tree_state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub session_start_user_leaf: PsyUserLeaf<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> TX: Deserialize<'de2>")]
pub struct DPNTransactionDebtItem<TX: QFieldHashable<F> + Serialize, F: RichField> {
    pub call_data: TX,
    pub tree_index: u64,
    pub hash: QHashOut<F>,
    pub insertion_proof: DeltaMerkleProofCore<QHashOut<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PsyLocalTransactionRecord<F: RichField> {
    pub start_checkpoint: F,
    pub write_checkpoint: F,
    pub call_data: DPNProvingSessionSignableMethodCall<F>,

    // state info
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<QHashOut<F>>,

    // external call info
    pub added_deferred_tx_items: Vec<DPNTransactionDebtItem<DPNProvingSessionSimpleMethodCall<F>, F>>,
}

impl<F: RichField> PsyLocalTransactionRecord<F> {
    pub fn new_base(
        start_checkpoint: F,
        write_checkpoint: F,
        call_data: DPNProvingSessionSignableMethodCall<F>,
        _start_contract_state_tree_root: QHashOut<F>,
    ) -> Self {
        Self {
            start_checkpoint,
            write_checkpoint,
            call_data,
            user_contract_tree_update_proof: Default::default(),
            added_deferred_tx_items: Vec::new(),
        }
    }
    pub fn add_deferred_tx_item(&mut self, item: DPNTransactionDebtItem<DPNProvingSessionSimpleMethodCall<F>, F>) {
        self.added_deferred_tx_items.push(item);
    }
    pub fn set_uct_proof(&mut self, user_contract_tree_update_proof: DeltaMerkleProofCore<QHashOut<F>>) {
        self.user_contract_tree_update_proof = user_contract_tree_update_proof;
    }
}
