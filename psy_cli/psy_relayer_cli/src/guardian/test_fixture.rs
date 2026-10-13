use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::args::ContractCallData;
use psy_prover::trace::{GeneratedTxTraceJson, SessionAnchor, TraceMeta, TxFinalization, TxTrace, UpsStartWitness};

use guardian_common::protocol::{GuardianOperation, GuardianSignRequest, Hash4, Hex, JsonText, BRIDGE_USER_ID};

pub(crate) fn codec_request_fixture() -> GuardianSignRequest {
    let trace = TxTrace {
        meta: TraceMeta { network_magic: 90101, user_id: BRIDGE_USER_ID, public_key: Hash4::ZERO },
        anchor: SessionAnchor { start_checkpoint_id: 0, checkpoint_leaf: Default::default(), global_state_roots: Default::default(), ups_step_circuit_whitelist_root: Hash4::ZERO },
        ups_start_witness: UpsStartWitness { ups_header: Default::default(), state_roots: Default::default(), checkpoint_tree_proof: Default::default(), user_tree_proof: Default::default(), user_registration_tree_proof: None, proof: None },
        contract_codes: vec![], steps: vec![],
        finalization: TxFinalization { submit_end_cap_input: Default::default(), nonce: GoldilocksField(1), tx_hash: Hash4::ZERO, software_defined_call: Default::default(), sig_hash: Hash4::ZERO },
    };
    let generated = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(ContractCallData::new(vec![])).unwrap()).unwrap();
    GuardianSignRequest { schema_version: 1, authorization_version: 1, network_magic: 90101, genesis_hash: Hex([1; 32]), user_id: BRIDGE_USER_ID, session_nonce: 1, operation: GuardianOperation::Bootstrap, trace_json: JsonText::from_value(&generated).unwrap(), deposit_anchors: vec![], withdrawal_records: vec![] }
}
