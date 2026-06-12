use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_provider::request::DPNSoftwareDefinedSignatureInput;
use psy_vm::ups::sdk_key::SDKKeyCircuitWitnessInput;
use psy_vm::ups::signature::Plonky2SoftwareDefinedSignatureInput;

#[derive(Debug)]
pub struct SignContext {
    pub fingerprint: QHashOut<GoldilocksField>,
    pub contract_id: Option<u64>,
    pub sign_inputs: Vec<u64>,
    pub psy_signature_input: Option<DPNSoftwareDefinedSignatureInput>,
    pub plonky2_signature_input: Option<Plonky2SoftwareDefinedSignatureInput>,
    pub sdk_key_signature_input: Option<SDKKeyCircuitWitnessInput>,
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
            psy_signature_input: None,
            plonky2_signature_input: None,
            sdk_key_signature_input: None,
            checkpoint_id: None,
            user_id: None,
            contract_state_tree_root: None,
            checkpoint_tree_root: None,
        }
    }

    pub fn with_contract_id(mut self, contract_id: Option<u64>) -> Self {
        self.contract_id = contract_id;
        self
    }

    pub fn with_sign_inputs(mut self, inputs: Vec<u64>) -> Self {
        self.sign_inputs = inputs;
        self
    }

    pub fn with_psy_signature_input(
        mut self,
        signature_input: DPNSoftwareDefinedSignatureInput,
        checkpoint_id: u64,
        user_id: u64,
        contract_state_tree_root: QHashOut<GoldilocksField>,
        checkpoint_tree_root: QHashOut<GoldilocksField>,
    ) -> Self {
        self.psy_signature_input = Some(signature_input);
        self.checkpoint_id = Some(checkpoint_id);
        self.user_id = Some(user_id);
        self.contract_state_tree_root = Some(contract_state_tree_root);
        self.checkpoint_tree_root = Some(checkpoint_tree_root);
        self
    }

    pub fn with_plonky2_signature_input(
        mut self,
        signature_input: Plonky2SoftwareDefinedSignatureInput,
        checkpoint_id: u64,
        user_id: u64,
        contract_state_tree_root: QHashOut<GoldilocksField>,
        checkpoint_tree_root: QHashOut<GoldilocksField>,
    ) -> Self {
        self.plonky2_signature_input = Some(signature_input);
        self.checkpoint_id = Some(checkpoint_id);
        self.user_id = Some(user_id);
        self.contract_state_tree_root = Some(contract_state_tree_root);
        self.checkpoint_tree_root = Some(checkpoint_tree_root);
        self
    }

    pub fn with_sdk_key_signature_input(
        mut self,
        signature_input: SDKKeyCircuitWitnessInput,
        checkpoint_id: u64,
        user_id: u64,
        contract_state_tree_root: QHashOut<GoldilocksField>,
        checkpoint_tree_root: QHashOut<GoldilocksField>,
    ) -> Self {
        self.sdk_key_signature_input = Some(signature_input);
        self.checkpoint_id = Some(checkpoint_id);
        self.user_id = Some(user_id);
        self.contract_state_tree_root = Some(contract_state_tree_root);
        self.checkpoint_tree_root = Some(checkpoint_tree_root);
        self
    }
}
