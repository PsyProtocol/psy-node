use std::sync::Arc;

use parth_core::{
    pgoldilocks::{PoseidonHasher, QHashOut},
    protocol::core_types::{QNetworkTreeConstants, QNetworkTypesConfigHelper},
};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use psy_core::{constants::chain_id::PsyChainNetworkType, job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore;
use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};
use psy_plonky2_circuits::{circuit_library::get_plonky2_circuit_library_and_prover_for_network, protocol_types::ZKTypesPlonky2GoldilocksPoseidon};

type Network = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type Hash = QHashOut<F>;
type Hasher = PoseidonHasher;

const NETWORK: PsyChainNetworkType = PsyChainNetworkType::LocalDevnet;


type ExBiDirectionalMappingTableIdentifier = InMemoryTableIdentifier;
type ExBiDirectionalU64U128MappingTableIdentifier = InMemoryTableIdentifier;
type ExU64TableIdentifier = InMemoryTableIdentifier;
type ExU64CounterTableIdentifier = InMemoryTableIdentifier;
type ExSingleIdTableIdentifier = InMemoryTableIdentifier;
type ExDoubleIdTableIdentifier = InMemoryTableIdentifier;
type ExKivTableIdentifier = InMemoryTableIdentifier;
type ExSingleIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExDoubleIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExZeroIdMerkleTableIdentifier = InMemoryTableIdentifier;
type ExTagTreeTableIdentifier = InMemoryTableIdentifier;
type ExHashToManyIdsTableIdentifier = InMemoryTableIdentifier;
type ExImtLeafTableIdentifier = InMemoryTableIdentifier;
type ExImtKeyIndexTableIdentifier = InMemoryTableIdentifier;
type ExImtNextAppendIndexTableIdentifier = InMemoryTableIdentifier;

type InMemoryTestStore = InMemoryCoreStore<Hash, Hasher>;
type PsyDBStore = PsyUnifiedCoreDatabaseStore<
        Network,
        ExBiDirectionalMappingTableIdentifier,
        ExBiDirectionalU64U128MappingTableIdentifier,
        ExU64TableIdentifier,
        ExU64CounterTableIdentifier,
        ExSingleIdTableIdentifier,
        ExDoubleIdTableIdentifier,
        ExKivTableIdentifier,
        ExSingleIdMerkleTableIdentifier,
        ExDoubleIdMerkleTableIdentifier,
        ExZeroIdMerkleTableIdentifier,
        ExTagTreeTableIdentifier,
        ExHashToManyIdsTableIdentifier,
        ExImtLeafTableIdentifier,
        ExImtKeyIndexTableIdentifier,
        ExImtNextAppendIndexTableIdentifier,
        InMemoryTestStore,
    >;



fn get_psy_db(store: Arc<InMemoryTestStore>) -> PsyDBStore {
    
        let keyspace = format!("psy_v3_mem_test_ex1_{}", rand::random::<u64>());
        let checkpoint_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_leaf_table"));
        let checkpoint_root_to_checkpoint_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(
            &keyspace,
            "checkpoint_root_to_checkpoint_id_table",
        ));
        let checkpoint_leaf_to_checkpoint_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(
            &keyspace,
            "checkpoint_leaf_to_checkpoint_id_table",
        ));
        let l2_block_state_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "l2_block_state_table"));
        let checkpoint_id_to_realm_root_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_id_to_realm_root_table"));
        let latest_info_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "latest_info_table"));
        let checkpointed_object_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpointed_object_table"));
        let checkpoint_state_roots_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_state_roots_table"));
        let user_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "user_leaf_table"));
        let user_public_key_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "user_public_key_table"));
        let u64_singleton_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "u64_singleton_table"));
        let u64_counter_singleton_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "u64_counter_singleton_table"));
        let contract_state_tree_height_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_state_tree_height_table"));
        let checkpoint_id_to_pending_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_id_to_pending_id_table"));
        let pending_id_to_checkpoint_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "pending_id_to_checkpoint_id_table"));
        let pending_id_to_pending_proc_id_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(
            &keyspace,
            "pending_id_to_pending_proc_id_table",
        ));
        let realm_rewards_tree_node_key_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "realm_rewards_tree_node_key_table"));
        // mappings
        let public_key_hash_to_user_ids_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "public_key_hash_to_user_ids_table"));
        // start trees
        let global_user_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_user_tree_table", Network::GLOBAL_USER_TREE_HEIGHT));
        let user_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "user_contract_tree_table", Network::GLOBAL_CONTRACT_TREE_HEIGHT));
        let contract_state_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_state_tree_table"));
        let global_checkpoint_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_checkpoint_tree_table", Network::CHECKPOINT_TREE_HEIGHT));
        // start reward tree table
        let guta_reward_tag_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "guta_reward_tag_tree_table"));
        // added tables for completeness
        let user_registration_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "user_registration_tree_table", Network::GLOBAL_USER_TREE_HEIGHT));
        let validator_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "validator_tree_table", psy_data::guta::realm_finalize::VALIDATOR_TREE_HEIGHT as u8));
        let global_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(&keyspace, "global_contract_tree_table", Network::GLOBAL_CONTRACT_TREE_HEIGHT));
        let contract_function_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_function_tree_table"));
        let contract_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_leaf_table"));
        let contract_code_definition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_code_definition_table"));
        let checkpoint_zk_proof_and_transition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "checkpoint_zk_proof_and_transition_table"));

        let imt_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "imt_leaf_table"));
        let imt_key_index_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "imt_key_index_table"));
        let imt_next_append_index_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "imt_next_append_index_table"));

        let psy_db = PsyUnifiedCoreDatabaseStore::new(
            store.clone(),
            checkpoint_leaf_table,
            checkpoint_root_to_checkpoint_id_table,
            checkpoint_leaf_to_checkpoint_id_table,
            l2_block_state_table,
            checkpoint_id_to_realm_root_table,
            latest_info_table,
            checkpointed_object_table,
            checkpoint_state_roots_table,
            user_leaf_table,
            user_public_key_table,
            u64_singleton_table,
            u64_counter_singleton_table,
            contract_state_tree_height_table,
            checkpoint_id_to_pending_id_table,
            pending_id_to_checkpoint_id_table,
            pending_id_to_pending_proc_id_table,
            realm_rewards_tree_node_key_table,
            // mappings
            public_key_hash_to_user_ids_table,
            // start trees
            global_user_tree_table,
            user_contract_tree_table,
            contract_state_tree_table,
            global_checkpoint_tree_table,
            // start reward tree table
            guta_reward_tag_tree_table,
            // added tables for completeness
            user_registration_tree_table,
            validator_tree_table,
            global_contract_tree_table,
            contract_function_tree_table,
            contract_leaf_table,
            contract_code_definition_table,
            checkpoint_zk_proof_and_transition_table,
            imt_leaf_table,
            imt_key_index_table,
            imt_next_append_index_table,
        );
        psy_db

}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cf_utils::logging::setup_logging()?;

    let (_gcv, _coordinator_circuits) = get_plonky2_circuit_library_and_prover_for_network::<C, D>(NETWORK)?;

    let psy_db = get_psy_db(Arc::new(InMemoryTestStore::new()));


    let _checkpoint_id = psy_db.get_latest_checkpoint_id().await?;

    
    




    



    Ok(())

}
