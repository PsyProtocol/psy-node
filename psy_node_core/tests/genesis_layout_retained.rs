//! Replay an explicit public Genesis artifact through the production builder.
//! This test uses only APIs present at 5d38eefc; copy this file alone for the
//! baseline run. It neither generates keys nor opens a database or network.

use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    felt::ToU64Value,
    pgoldilocks::PoseidonHasher,
    protocol::core_types::QNetworkTreeConstants,
    PF, PHash,
};
use psy_core::{
    constants::chain_id::PsyChainNetworkType,
    network_config::PsyNetworkPsyPublicTestnetConstants,
    user_id::get_user_id_from_user_registration_id,
};
use psy_data::{
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    p2p::empty_validator_tree_root,
    v1::qdata::contract::{PQEDContractLeafV2, CONTRACT_LEAF_SERIALIZED_SIZE},
    v1::qdata::{ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF, user::PQEDUserLeaf},
};
use psy_node_core::genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder;
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate};

#[test]
#[ignore = "requires an explicitly selected public Genesis artifact"]
fn retained_genesis_token_layout_must_be_nonempty() {
    let path = std::env::var_os("PSY_LAYOUT_GENESIS_FIXTURE")
        .expect("set PSY_LAYOUT_GENESIS_FIXTURE to the hash-verified public Genesis");
    let file = std::fs::File::open(path).expect("open public Genesis fixture");
    let genesis: PsyGenesisBlockSetupData<PF, PHash> =
        serde_json::from_reader(std::io::BufReader::new(file))
            .expect("decode public Genesis with production DTO");
    assert_eq!(genesis.contracts.len(), 6, "expected the six-contract incident cohort");
    for id in [0, 4] {
        assert_eq!(genesis.contracts[id].code_definition.state_tree_height, 32);
        assert_eq!(genesis.contracts[id].code_definition.functions.len(), 10);
        assert_eq!(genesis.contracts[id].function_whitelist.len(), 20);
    }
    let mut builder = GenesisDatabaseDataBuilder::new(
        genesis.deposit_tree_root,
        genesis.withdrawal_tree_root,
        genesis.checkpoint_stats.clone(),
    );
    builder.setup_contracts::<PoseidonHasher, PsyNetworkPsyPublicTestnetConstants>(
        &genesis, true,
    ).expect("build real contract leaves from the selected Genesis");
    let row_size = 8 + CONTRACT_LEAF_SERIALIZED_SIZE;
    assert_eq!(builder.contract_leaves_ffs.len(), 6 * row_size);
    let mut observed = Vec::new();
    for row in builder.contract_leaves_ffs.chunks_exact(row_size) {
        let id = u64::from_le_bytes(row[..8].try_into().unwrap());
        if id == 0 || id == 4 {
            let leaf = PQEDContractLeafV2::<PF, PHash>::psy_ser_from_slice(&row[8..])
                .expect("decode production contract FFS leaf");
            observed.push((id, leaf.state_layout_root,
                leaf.state_layout_field_count.to_u64_value(),
                leaf.state_layout_slot_count.to_u64_value()));
        }
    }
    assert_eq!(observed.len(), 2, "both real token leaves must be present");
    // Only public contract metadata is emitted; never print users or keys.
    eprintln!("token layout metadata (id, root, fields, slots): {observed:?}");
    assert!(observed.iter().all(|(_, root, fields, slots)|
        *root != PHash::default() && *fields > 0 && *slots >= *fields),
        "Genesis token0/4 use storage but runtime leaves lack nonempty canonical layout commitments");

    type N = PsyNetworkPsyPublicTestnetConstants;
    assert_eq!(genesis.users.len(), 107);
    assert_eq!(genesis.validators.len(), 6);
    assert!(builder.setup_users::<PoseidonHasher, N>(&genesis, None, true, true).unwrap().is_none());
    let chain_id = PsyChainNetworkType::PsyPublicTestnet.get_chain_id();
    builder.setup_validators::<PoseidonHasher>(&genesis, chain_id, N::REALM_GLOBAL_USER_TREE_HEIGHT).unwrap();
    assert_eq!(builder.total_users_registered, 107);
    assert_eq!(builder.user_leaves_ffs.len(), 107 * PSY_OBJECT_FFS_SIZE_USER_LEAF);
    for (registration, row) in builder.user_leaves_ffs.chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF).enumerate() {
        let leaf = PQEDUserLeaf::<PF, PHash>::fx_tpl_psy_ser_from_slice(row).unwrap();
        let user_id = get_user_id_from_user_registration_id(registration as u64,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, N::REALM_GLOBAL_USER_TREE_HEIGHT, N::GROUP_REALM_HEIGHT);
        assert_eq!(leaf.user_id.to_u64_value(), user_id);
        assert!(leaf.public_key == genesis.users[registration].public_key_info.to_hash::<PoseidonHasher>());
        assert_eq!(leaf.nonce.to_u64_value(), 0);
        if registration == 2 { assert_eq!(user_id, 524288); }
    }
    assert_eq!(builder.validator_leaf_preimages.len(), 6);
    let mut positions = [0u16; 2];
    let expected_users = [[0, 262144, 786432], [1048576, 1572864, 1310720]];
    for (member, source) in builder.validator_leaf_preimages.iter().zip(&genesis.validators) {
        assert!(member.realm_id < 2);
        let realm = member.realm_id as usize;
        positions[realm] += 1;
        assert_eq!((member.chain_id, member.realm_sub_id), (chain_id, positions[realm]));
        assert_eq!((member.realm_id, member.validator_user_id), (source.realm_id, source.validator_user_id));
        assert_eq!(member.validator_user_id, expected_users[realm][usize::from(member.realm_sub_id - 1)]);
        assert!(member.node_id == source.node_id && member.bls_public_key == source.bls_public_key);
    }
    assert_eq!(positions, [3, 3]);
    for (root, empty) in [
        (builder.global_contract_tree_root, PoseidonHasher::get_zero_hash(N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE)),
        (builder.global_user_tree_root, PoseidonHasher::get_zero_hash(N::GLOBAL_USER_TREE_HEIGHT_USIZE)),
        (builder.user_registration_tree_root, PoseidonHasher::get_zero_hash(N::GLOBAL_USER_TREE_HEIGHT_USIZE)),
        (builder.validator_tree_root, empty_validator_tree_root::<PoseidonHasher, PHash>()),
    ] {
        assert!(root != PHash::default() && root != empty);
    }
    assert!(!builder.global_user_tree_nodes_ffs.is_empty()
        && !builder.user_registration_tree_nodes_ffs.is_empty() && !builder.validator_tree_nodes_ffs.is_empty());
    let base = builder.get_coordinator_pending_checkpoint_base::<PoseidonHasher>(N::CHECKPOINT_TREE_HEIGHT);
    assert_eq!((base.block_state.checkpoint_id, base.block_state.next_user_id, base.block_state.next_contract_id), (0, 107, 6));
    assert_eq!((base.block_state.next_add_withdrawal_id, base.block_state.next_process_withdrawal_id,
        base.block_state.next_deposit_id, base.block_state.total_deposits_claimed_epoch, base.block_state.end_balance), (0, 0, 0, 0, 0));
    assert_eq!(base.checkpoint_leaf.global_state_roots, builder.get_checkpoint_state_roots::<PoseidonHasher>());
    assert!(base.checkpoint_leaf_hash != PHash::default() && base.checkpoint_tree_root != PHash::default());
    eprintln!("Coordinator Genesis: users=107 validators=6 checkpoint=0 root={:?}", base.checkpoint_tree_root);
}
