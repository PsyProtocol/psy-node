use guardian_common::protocol::{ChainEndpoint, GuardianConfig, GuardianOperation, GuardianSignRequest, Hash4, Hex, JsonText, BRIDGE_USER_ID};
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::args::ContractCallData;
use psy_prover::trace::{GeneratedTxTraceJson, SessionAnchor, TraceMeta, TxFinalization, TxTrace, UpsStartWitness};

/// Network the verifier tests share. Members are the three distinct nonzero
/// commitments the protocol account derives. Chain id and bridge are the
/// configured L1 identity.
pub(crate) fn codec_network() -> psy_config::NetworkConfigGoldilocks {
    serde_json::from_value(serde_json::json!({
        "magic": "0x1337CF514544CF69",
        "users_per_realm": 1,
        "global_user_tree_height": 1,
        "realm_user_tree_height": 1,
        "group_realm_height": 1,
        "realm_configs": [],
        "p2p": { "checkpoints_per_epoch": 1 },
        "coordinator_configs": [],
        "prove_proxy_url": [],
        "faucet_rpc_url": [],
        "nostr_relay_url": "ws://127.0.0.1:1",
        "native_currency": "PSY",
        "native_currency_decimal": 6,
        "native_currency_name": "Psy",
        "fees": { "register_user_fee": 1, "deploy_contract_fee": 1, "guta_fee": 1, "da_fee": 1 },
        "guardian_initial_member_hashes": [Hash4::from_values(1, 0, 0, 0), Hash4::from_values(2, 0, 0, 0), Hash4::from_values(3, 0, 0, 0)],
    })).expect("codec network")
}

pub(crate) fn codec_guardian_config() -> GuardianConfig {
    GuardianConfig { network: codec_network(), guardian_root: "guardians-root".into(), endpoints: [String::new(), String::new(), String::new()], history_url: String::new(), l1_chains: vec![ChainEndpoint { chain_index: 0, chain_id: alloy_primitives::U256::from(1u8), bridge: Hex([0x11; 20]), deployment_block: 0, rpc_url: "http://127.0.0.1:8545".into() }] }
}

pub(crate) fn codec_request_fixture() -> GuardianSignRequest {
    let config = codec_guardian_config();
    let trace = TxTrace {
        meta: TraceMeta { network_magic: config.network_magic().unwrap(), user_id: BRIDGE_USER_ID, public_key: config.account_public_key().unwrap() },
        anchor: SessionAnchor { start_checkpoint_id: 0, checkpoint_leaf: Default::default(), global_state_roots: Default::default(), ups_step_circuit_whitelist_root: Hash4::ZERO },
        ups_start_witness: UpsStartWitness { ups_header: Default::default(), state_roots: Default::default(), checkpoint_tree_proof: Default::default(), user_tree_proof: Default::default(), user_registration_tree_proof: None, proof: None },
        contract_codes: vec![], steps: vec![],
        finalization: TxFinalization { submit_end_cap_input: Default::default(), nonce: GoldilocksField(1), tx_hash: Hash4::ZERO, software_defined_call: Default::default(), sig_hash: Hash4::ZERO },
    };
    let generated = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(ContractCallData::new(vec![])).unwrap()).unwrap();
    GuardianSignRequest { schema_version: 2, network_magic: trace.meta.network_magic, user_id: BRIDGE_USER_ID, session_nonce: 1, operation: GuardianOperation::Bootstrap, trace_json: JsonText::from_value(&generated).unwrap(), deposit_anchors: vec![], withdrawal_records: vec![] }
}
