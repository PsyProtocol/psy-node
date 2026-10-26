use parth_core::{
    data::queue::queue_key::PCoreQueueItemBase,
    felt::ToU64Value,
    pgoldilocks::PoseidonHasher,
    PHash, PF,
};
use psy_data::v1::qdata::contract::{
    ContractCodeDefinition, ContractFunctionCodeDefinition, PQBCDeployContract,
    PQBCDeployContractV2, PQBCUpdateContract, PsyDeployContractQueueItemV2,
    PsyUpdateContractQueueItem, STATE_LAYOUT_VERSION,
};

type DeployItem = PsyDeployContractQueueItemV2<PF, PHash>;
type UpdateItem = PsyUpdateContractQueueItem<PF, PHash>;

fn hash(value: u64) -> PHash {
    PHash::from_values(value, value + 1, value + 2, value + 3)
}

fn code_definition() -> ContractCodeDefinition {
    ContractCodeDefinition {
        state_tree_height: 4,
        functions: vec![ContractFunctionCodeDefinition {
            method_id: 7,
            num_inputs: 1,
            num_outputs: 1,
            vm_type: 0,
            code: vec![1, 2, 3],
        }],
    }
}

#[test]
fn deploy_command_survives_queue_boundary() -> anyhow::Result<()> {
    let command = PQBCDeployContractV2 {
        deploy_contract: PQBCDeployContract::new(
            42,
            code_definition(),
            vec![hash(10), hash(20)],
            hash(30),
        ),
        layout_protocol_version: STATE_LAYOUT_VERSION,
        state_layout_root: hash(40),
        state_layout_field_count: 2,
        state_layout_slot_count: 4,
        canonical_layout_verifier_fingerprint: hash(50),
        canonical_layout_proof: vec![1, 2, 3],
    };
    command.validate_shape()?;
    let rooted = command.deploy_contract.clone().into_with_whitelist_root::<PoseidonHasher>(2)?;

    let item = DeployItem::new_from_layout_endpoint::<PoseidonHasher>(
        command.deploy_contract.deployer,
        command.deploy_contract.code_definition.state_tree_height,
        command.deploy_contract.function_whitelist.clone(),
        command.deploy_contract.code_root,
        2,
        command.layout_protocol_version,
        command.state_layout_root,
        command.state_layout_field_count,
        command.state_layout_slot_count,
        command.canonical_layout_verifier_fingerprint,
        command.canonical_layout_proof.clone(),
    )?;
    let bytes = item.encode_queue_item_vec()?;
    assert!(DeployItem::is_queue_item(&bytes));
    let decoded = DeployItem::decode_queue_item_ref(&bytes)?;
    assert_eq!(decoded, item);
    assert_eq!(decoded.contract_leaf.deployer.to_u64_value(), 42);
    assert_eq!(decoded.contract_leaf.function_tree_root, rooted.function_whitelist_root);
    assert_eq!(decoded.contract_leaf.code_root, command.deploy_contract.code_root);
    assert_eq!(decoded.contract_leaf.state_layout_root, command.state_layout_root);
    assert_eq!(decoded.contract_leaf.state_layout_field_count.to_u64_value(), 2);
    assert_eq!(decoded.contract_leaf.state_layout_slot_count.to_u64_value(), 4);
    assert_eq!(decoded.function_leaves, command.deploy_contract.function_whitelist);
    assert_eq!(decoded.canonical_layout_proof, command.canonical_layout_proof);

    let mut wrong_version = bytes.clone();
    wrong_version[4] = 0;
    assert!(DeployItem::decode_queue_item_ref(&wrong_version).is_err());
    let mut invalid = decoded;
    invalid.canonical_layout_proof.clear();
    assert!(invalid.encode_queue_item_vec().is_err());
    Ok(())
}

#[test]
fn update_command_survives_queue_boundary() -> anyhow::Result<()> {
    let command = PQBCUpdateContract {
        contract_id: 9,
        deployer: 42,
        code_definition: code_definition(),
        function_whitelist: vec![hash(10), hash(20)],
        code_root: hash(30),
        layout_protocol_version: STATE_LAYOUT_VERSION,
        state_layout_root: hash(40),
        state_layout_field_count: 2,
        state_layout_slot_count: 4,
        canonical_layout_verifier_fingerprint: hash(50),
        canonical_layout_proof: vec![4, 5, 6],
    };
    command.validate_shape()?;
    let rooted = command.clone().into_with_whitelist_root::<PoseidonHasher>(2)?;
    let item = UpdateItem::new_from_leaves_and_deployer::<PoseidonHasher>(
        command.contract_id,
        command.deployer,
        command.code_definition.state_tree_height,
        command.state_layout_root,
        command.state_layout_field_count,
        command.state_layout_slot_count,
        command.layout_protocol_version,
        command.canonical_layout_verifier_fingerprint,
        command.canonical_layout_proof.clone(),
        command.function_whitelist.clone(),
        command.code_root,
        2,
    )?;
    let bytes = item.encode_queue_item_vec()?;
    let decoded = UpdateItem::decode_queue_item_ref(&bytes)?;
    assert_eq!(decoded, item);
    assert_eq!(decoded.contract_id, command.contract_id);
    assert_eq!(decoded.contract_leaf.deployer.to_u64_value(), command.deployer);
    assert_eq!(decoded.contract_leaf.function_tree_root, rooted.function_whitelist_root);
    assert_eq!(decoded.contract_leaf.code_root, command.code_root);
    assert_eq!(decoded.contract_leaf.state_layout_root, command.state_layout_root);
    assert_eq!(decoded.contract_leaf.state_layout_field_count.to_u64_value(), 2);
    assert_eq!(decoded.contract_leaf.state_layout_slot_count.to_u64_value(), 4);
    assert_eq!(decoded.function_leaves, command.function_whitelist);
    assert_eq!(decoded.canonical_layout_proof, command.canonical_layout_proof);

    let mut invalid = decoded;
    invalid.contract_id = 0;
    assert!(invalid.encode_queue_item_vec().is_err());
    Ok(())
}
