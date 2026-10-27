//! Replay an explicit public Genesis artifact through the production builder.
//! This test uses only APIs present at 5d38eefc; copy this file alone for the
//! baseline run. It neither generates keys nor opens a database or network.

use parth_core::{
    felt::ToU64Value,
    pgoldilocks::PoseidonHasher,
    PF, PHash,
};
use psy_core::network_config::PsyNetworkPsyPublicTestnetConstants;
use psy_data::{
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    v1::qdata::contract::{PQEDContractLeafV2, CONTRACT_LEAF_SERIALIZED_SIZE},
};
use psy_node_core::genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

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
}
