use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::args::ContractCallData;
use psy_client_data::qdata::contract::PsyContractLeaf;
use psy_prover::trace::{GeneratedTxTraceJson, SessionAnchor, TraceMeta, TxFinalization, TxTrace, UpsStartWitness};
use psy_vm::ups::multisig::{MultisigAccount, StoredMultisigPolicy, MULTISIG_POLICY_CONTRACT_ID};

use guardian_common::protocol::{ApprovedContract, ApprovedMethod, GuardianAuthorization, GuardianOperation, GuardianSignRequest, Hash4, Hex, JsonText, BRIDGE_USER_ID};

/// Canonical minimal seven-field authorization; the request fixture below embeds its digest and
/// derived account public key so every consumer (relayer db, daemon, verifier) shares one identity.
pub(crate) fn codec_authorization_fixture() -> GuardianAuthorization {
    let members = [Hash4::from_values(1, 0, 0, 0), Hash4::from_values(2, 0, 0, 0), Hash4::from_values(3, 0, 0, 0)];
    let account = MultisigAccount { contract_id: MULTISIG_POLICY_CONTRACT_ID, initial_policy: StoredMultisigPolicy { header: Hash4::from_values(1, 2, 3, 0), members }.policy().unwrap() };
    GuardianAuthorization {
        genesis_hash: Hex([1; 32]),
        bridge_relayer_signing_policy: JsonText::from_value(&account).unwrap(),
        multisig_fingerprint: Hash4::from_values(9, 8, 7, 6),
        endcap_verifier_fingerprint: Hash4::from_values(1, 1, 1, 1),
        max_fee: 100,
        approved_contracts: vec![ApprovedContract {
            contract_id: 3,
            contract_leaf_json: JsonText::from_value(&PsyContractLeaf::<GoldilocksField>::default()).unwrap(),
            withdrawal_layout: None,
            methods: vec![ApprovedMethod { name: "first".into(), method_id: 1, input_felt_count: 0 }, ApprovedMethod { name: "second".into(), method_id: 2, input_felt_count: 0 }],
        }],
        chains: vec![],
    }
}

pub(crate) fn codec_request_fixture() -> GuardianSignRequest {
    let authorization = codec_authorization_fixture();
    let trace = TxTrace {
        meta: TraceMeta { network_magic: 90101, user_id: BRIDGE_USER_ID, public_key: authorization.account_public_key().unwrap() },
        anchor: SessionAnchor { start_checkpoint_id: 0, checkpoint_leaf: Default::default(), global_state_roots: Default::default(), ups_step_circuit_whitelist_root: Hash4::ZERO },
        ups_start_witness: UpsStartWitness { ups_header: Default::default(), state_roots: Default::default(), checkpoint_tree_proof: Default::default(), user_tree_proof: Default::default(), user_registration_tree_proof: None, proof: None },
        contract_codes: vec![], steps: vec![],
        finalization: TxFinalization { submit_end_cap_input: Default::default(), nonce: GoldilocksField(1), tx_hash: Hash4::ZERO, software_defined_call: Default::default(), sig_hash: Hash4::ZERO },
    };
    let generated = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(ContractCallData::new(vec![])).unwrap()).unwrap();
    GuardianSignRequest { schema_version: 1, authorization_sha256: authorization.digest().unwrap(), network_magic: 90101, genesis_hash: Hex([1; 32]), user_id: BRIDGE_USER_ID, session_nonce: 1, operation: GuardianOperation::Bootstrap, trace_json: JsonText::from_value(&generated).unwrap(), deposit_anchors: vec![], withdrawal_records: vec![] }
}
