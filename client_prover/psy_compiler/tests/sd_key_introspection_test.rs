use psy_client_data::dpn::sd_key::{SDKEY_MAX_CALLDATA_WORDS, MAX_INTROSPECTABLE_TRANSACTIONS};
use psy_compiler::{compile_sd_key, compile_sd_key_for_contract};
use psy_vm::dpn::ops::op_types::DPNOpType;

const CALLDATA_SOURCE: &str = r#"
    #[contract]
    pub struct TestKey {}

    #[contract_implementation]
    impl TestKey {
        #[contract_method]
        pub fn authorize(&mut self, ctx: &ChainContext, sd: &SDKeyContext) {
            let count = sd.num_transactions;
            let stack_hash = sd.transaction_stack_hash;
            let contract_id = sd.tx[1].contract_id;
            let caller_contract_id = sd.tx[1].caller_contract_id;
            let method_id = sd.tx[1].method_id;
            let inputs_length = sd.tx[1].inputs_length;
            let inputs_hash = sd.tx[1].inputs_hash;
            require(count >= 2, "not enough transactions");
            require(contract_id == 11, "unexpected contract");
            require(caller_contract_id == 12, "unexpected caller");
            require(method_id == 13, "unexpected method");
            require(inputs_length >= 3, "short calldata");
            require(stack_hash[0] == stack_hash[0], "invalid stack hash");
            require(inputs_hash[0] == inputs_hash[0], "invalid inputs hash");
            require(sd.tx[1].inputs[2] == 7, "unexpected calldata");
        }
    }
"#;

const STATE_READER_SOURCE: &str = r#"
    #[contract]
    pub struct TestKey {
        pub limit: Felt,
    }

    #[contract_implementation]
    impl TestKey {
        #[contract_method]
        pub fn authorize(&mut self, ctx: &ChainContext, sd: &SDKeyContext) {
            require(self.limit > 0, "limit disabled");
        }
    }
"#;

#[test]
fn calldata_word_access_uses_transaction_opcode() {
    let output = compile_sd_key(CALLDATA_SOURCE).expect("calldata introspection should compile");
    assert_eq!(output.config.num_introspectable_transactions, 2);
    for expected in [
        DPNOpType::GetTransactionCount,
        DPNOpType::GetTransactionStackHash,
        DPNOpType::GetTransactionContractId,
        DPNOpType::GetTransactionCallerContractId,
        DPNOpType::GetTransactionMethodId,
        DPNOpType::GetTransactionInputLength,
        DPNOpType::GetTransactionInputsHash,
        DPNOpType::GetTransactionInputWord,
    ] {
        assert!(output.circuit_def.definitions.iter().any(|definition| definition.op_type == expected), "missing {expected}");
    }
}

#[test]
fn transaction_and_calldata_limits_match_protocol_constants() {
    let tx_source = CALLDATA_SOURCE.replace("tx[1]", &format!("tx[{}]", MAX_INTROSPECTABLE_TRANSACTIONS));
    let tx_error = compile_sd_key(&tx_source).unwrap_err().to_string();
    assert!(tx_error.contains("exceeds maximum allowed introspectable transactions"));

    let word_source = CALLDATA_SOURCE.replace("inputs[2]", &format!("inputs[{}]", SDKEY_MAX_CALLDATA_WORDS));
    let word_error = compile_sd_key(&word_source).unwrap_err().to_string();
    assert!(word_error.contains("exceeds maximum allowed words"));
}

#[test]
fn state_reading_requires_and_preserves_contract_id() {
    let error = compile_sd_key(STATE_READER_SOURCE).unwrap_err().to_string();
    assert!(error.contains("no contract_id was supplied"));

    let output = compile_sd_key_for_contract(STATE_READER_SOURCE, 42).expect("contract-aware compilation should succeed");
    assert!(output.config.can_read_state);
    assert_eq!(output.config.contract_id, 42);
}
