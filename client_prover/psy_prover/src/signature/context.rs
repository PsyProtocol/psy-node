use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_provider::request::DPNSoftwareDefinedSignatureInput;
use psy_vm::ups::{sd_key::SDKeyCircuitWitnessInput, signature::Plonky2SoftwareDefinedSignatureInput};

#[derive(Debug)]
pub struct SignContext {
    pub fingerprint: QHashOut<GoldilocksField>,
    pub contract_id: Option<u64>,
    pub sign_inputs: Vec<u64>,
    pub psy_signature_input: Option<DPNSoftwareDefinedSignatureInput>,
    pub plonky2_signature_input: Option<Plonky2SoftwareDefinedSignatureInput>,
    pub sd_key_signature_input: Option<SDKeyCircuitWitnessInput>,
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
            sd_key_signature_input: None,
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

    pub fn with_sd_key_signature_input(
        mut self,
        signature_input: SDKeyCircuitWitnessInput,
        checkpoint_id: u64,
        user_id: u64,
        contract_state_tree_root: QHashOut<GoldilocksField>,
        checkpoint_tree_root: QHashOut<GoldilocksField>,
    ) -> Self {
        self.sd_key_signature_input = Some(signature_input);
        self.checkpoint_id = Some(checkpoint_id);
        self.user_id = Some(user_id);
        self.contract_state_tree_root = Some(contract_state_tree_root);
        self.checkpoint_tree_root = Some(checkpoint_tree_root);
        self
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use plonky2::{field::types::Field, hash::hash_types::HashOut};

    use super::*;

    fn hash(values: [u64; 4]) -> QHashOut<GoldilocksField> {
        QHashOut(HashOut {
            elements: values.map(GoldilocksField::from_canonical_u64),
        })
    }

    #[test]
    fn new_context_has_only_the_fingerprint() {
        let fingerprint = hash([1, 2, 3, 4]);
        let context = SignContext::new(fingerprint);

        assert_eq!(context.fingerprint, fingerprint);
        assert_eq!(context.contract_id, None);
        assert!(context.sign_inputs.is_empty());
        assert!(context.psy_signature_input.is_none());
        assert!(context.plonky2_signature_input.is_none());
        assert!(context.sd_key_signature_input.is_none());
        assert_eq!(context.checkpoint_id, None);
        assert_eq!(context.user_id, None);
        assert_eq!(context.contract_state_tree_root, None);
        assert_eq!(context.checkpoint_tree_root, None);
    }

    #[test]
    fn basic_builder_methods_preserve_existing_context() {
        let fingerprint = hash([5, 6, 7, 8]);
        let context = SignContext::new(fingerprint)
            .with_contract_id(Some(42))
            .with_sign_inputs(vec![10, 20, 30]);

        assert_eq!(context.fingerprint, fingerprint);
        assert_eq!(context.contract_id, Some(42));
        assert_eq!(context.sign_inputs, vec![10, 20, 30]);
    }

    #[test]
    fn psy_signature_input_builder_populates_session_fields() {
        let fingerprint = hash([9, 10, 11, 12]);
        let state_root = hash([13, 14, 15, 16]);
        let checkpoint_root = hash([17, 18, 19, 20]);
        let signature_input = DPNSoftwareDefinedSignatureInput {
            cfc_input: Default::default(),
        };

        let context = SignContext::new(fingerprint).with_psy_signature_input(signature_input, 7, 8, state_root, checkpoint_root);

        assert!(context.psy_signature_input.is_some());
        assert!(context.plonky2_signature_input.is_none());
        assert!(context.sd_key_signature_input.is_none());
        assert_eq!(context.checkpoint_id, Some(7));
        assert_eq!(context.user_id, Some(8));
        assert_eq!(context.contract_state_tree_root, Some(state_root));
        assert_eq!(context.checkpoint_tree_root, Some(checkpoint_root));
    }

    #[test]
    fn plonky2_signature_input_builder_populates_session_fields() {
        let signature_input = Plonky2SoftwareDefinedSignatureInput {
            state_reader_results: psy_vm::ups::state_reader::StateReaderResults {
                state: Default::default(),
                state_cmds: Vec::new(),
                merkel_proofs: Vec::new(),
            },
            circuit_inputs: Vec::new(),
        };

        let context =
            SignContext::new(hash([1, 1, 1, 1])).with_plonky2_signature_input(signature_input, 70, 80, hash([2, 2, 2, 2]), hash([3, 3, 3, 3]));

        assert!(context.plonky2_signature_input.is_some());
        assert!(context.psy_signature_input.is_none());
        assert!(context.sd_key_signature_input.is_none());
        assert_eq!(context.checkpoint_id, Some(70));
        assert_eq!(context.user_id, Some(80));
        assert_eq!(context.contract_state_tree_root, Some(hash([2, 2, 2, 2])));
        assert_eq!(context.checkpoint_tree_root, Some(hash([3, 3, 3, 3])));
    }

    #[test]
    fn sd_key_signature_input_builder_populates_session_fields() {
        let signature_input = SDKeyCircuitWitnessInput {
            circuit_inputs: Vec::new(),
            transaction_infos: Vec::new(),
            tx_stack_hash: QHashOut::ZERO,
            tx_count: GoldilocksField::ZERO,
            state_reader_results: None,
            secp256k1_slots: Vec::new(),
            checkpoint_id: GoldilocksField::ZERO,
            user_id: GoldilocksField::ZERO,
        };

        let context =
            SignContext::new(hash([4, 4, 4, 4])).with_sd_key_signature_input(signature_input, 700, 800, hash([5, 5, 5, 5]), hash([6, 6, 6, 6]));

        assert!(context.sd_key_signature_input.is_some());
        assert!(context.psy_signature_input.is_none());
        assert!(context.plonky2_signature_input.is_none());
        assert_eq!(context.checkpoint_id, Some(700));
        assert_eq!(context.user_id, Some(800));
        assert_eq!(context.contract_state_tree_root, Some(hash([5, 5, 5, 5])));
        assert_eq!(context.checkpoint_tree_root, Some(hash([6, 6, 6, 6])));
    }
}
