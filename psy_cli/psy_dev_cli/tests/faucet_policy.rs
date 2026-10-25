use clap::Parser;
use psy_dev_cli::subcommand::generate_genesis::GenerateGenesisDataArgs;

#[test]
fn faucet_policy_defaults_limit_calls_and_bind_transfer_caller() {
    let args = GenerateGenesisDataArgs::try_parse_from(["generate-genesis-data", "--relayer-multisig-account", "account.json", "--governance-multisig-account", "governance.json", "--multisig-policy-artifact", "policy.json"]).unwrap();
    assert_eq!((args.sd_key_min_tx_count, args.sd_key_max_tx_count), (1, 64));
    assert!(args.sd_key_fingerprint.is_empty());
    let (_, config) = psy_vm::ups::sd_key::build_allow_caller_and_method_policy_range(
        &args.sd_key_allowed_caller_contract_ids,
        &args.sd_key_allowed_contract_ids,
        &args.sd_key_allowed_method_ids,
        args.sd_key_min_tx_count,
        args.sd_key_max_tx_count,
    ).unwrap();
    let calls = config.transaction_count_policy.unwrap().allowed_calls;
    let transfer = calls.iter().find(|call| call.contract_id == 0 && call.method_id == 2789897329).unwrap();
    assert_eq!(transfer.caller_contract_id, Some(args.faucet_contract_id));
    assert_ne!(transfer.caller_contract_id, Some(psy_config::network_constants::DEFAULT_CALLER_CONTRACT_ID_U64));
}
