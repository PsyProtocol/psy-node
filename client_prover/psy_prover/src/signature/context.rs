use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_vm::ups::{sd_key::SDKeyDpnCircuitWitnessInput, signature::SDKeyPlonky2CircuitWitnessInput};

#[derive(Debug)]
pub enum SdKeySignInput {
    Dpn(SDKeyDpnCircuitWitnessInput),
    Plonky2(SDKeyPlonky2CircuitWitnessInput),
}

#[derive(Debug)]
pub struct SignContext {
    pub fingerprint: QHashOut<GoldilocksField>,
    pub contract_id: Option<u64>,
    pub sign_inputs: Vec<u64>,
    pub sd_key_signature_input: Option<SdKeySignInput>,
    pub checkpoint_id: Option<u64>,
    pub user_id: Option<u64>,
    pub contract_state_tree_root: Option<QHashOut<GoldilocksField>>,
    pub checkpoint_tree_root: Option<QHashOut<GoldilocksField>>,
}

impl SignContext {
    pub fn new(fingerprint: QHashOut<GoldilocksField>) -> Self {
        Self {
            fingerprint,
            contract_id: None,
            sign_inputs: Vec::new(),
            sd_key_signature_input: None,
            checkpoint_id: None,
            user_id: None,
            contract_state_tree_root: None,
            checkpoint_tree_root: None,
        }
    }

    pub fn with_sd_key_input(
        mut self,
        input: SdKeySignInput,
        checkpoint_id: u64,
        user_id: u64,
        contract_state_tree_root: QHashOut<GoldilocksField>,
        checkpoint_tree_root: QHashOut<GoldilocksField>,
    ) -> Self {
        self.sd_key_signature_input = Some(input);
        self.checkpoint_id = Some(checkpoint_id);
        self.user_id = Some(user_id);
        self.contract_state_tree_root = Some(contract_state_tree_root);
        self.checkpoint_tree_root = Some(checkpoint_tree_root);
        self
    }

    pub fn with_contract_id(mut self, contract_id: Option<u64>) -> Self {
        self.contract_id = contract_id;
        self
    }

    pub fn with_sign_inputs(mut self, inputs: Vec<u64>) -> Self {
        self.sign_inputs = inputs;
        self
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
