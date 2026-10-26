use std::sync::Arc;

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::pgoldilocks::PoseidonHasher;

use parth_core::protocol::core_types::{QNetworkHashTypes, QNetworkTreeCircuitSpecificConstants, QNetworkTreeConstants};
use psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore;
use psy_node_store_memory::cbs_store::{InMemoryCoreStore, InMemoryTableIdentifier};
use psy_node_store_memory::temp_store::InMemoryTempStore;

pub type Hasher = PoseidonHasher;
pub type Hash = parth_core::PHash;
pub type F = parth_core::PF;
pub type RecTree = SimpleMemoryMerkleRecorderStore<Hasher, Hash>;

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, ZeroableHash},
        felt::{FromPrimitiveValuesFelt, ToU64Value},
        protocol::core_types::QNetworkTreeConstants,
        utils::QPGenRandom,
    };
    use parth_core::QJobIdBase;
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use psy_io::tokio::TokioLikeFileSystem;
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_temp_db::QTempDBProofWitnessReader,
    };
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    use crate::guta_planner::realm_guta_planner::RealmGUTAPlanner;

    use super::{F, Hash, Hasher, PsyRGPNetworkConfig};
    use super::super::test_env::{basic_validate_job_results_singlet_case, RGPContractUpdate, RGPJobInfo, RGPTestChainState, RGPTestResultValidator};

    type N = PsyRGPNetworkConfig;
    type RecTree = super::RecTree;

    async fn test_chain_with_two_users_and_one_contract() -> anyhow::Result<(RGPTestChainState, u64, u64)> {
        let mut chain_state = RGPTestChainState::create_for_tests().await?;
        let user_a = chain_state.register_new_random_user().await?;
        let user_b = chain_state.register_new_random_user().await?;
        chain_state.add_new_contract(12).await?;
        Ok((chain_state, user_a, user_b))
    }

    fn one_contract_update() -> Vec<RGPContractUpdate> {
        vec![RGPContractUpdate {
            contract_id: 0,
            leaves: vec![(0, Hash::qp_rand_gen()), (1, Hash::qp_rand_gen())],
        }]
    }

    #[tokio::test]
    async fn single_user_checkpoint_produces_single_end_cap_root() -> anyhow::Result<()> {
        let (mut chain_state, user_a, _user_b) = test_chain_with_two_users_and_one_contract().await?;
        let result = chain_state
            .process_checkpoint(&[], &[(user_a, one_contract_update())], true)
            .await?
            .ok_or_else(|| anyhow::anyhow!("expected a gatherer output for a single user"))?;

        let job_levels = &result.job_ids;
        assert_eq!(job_levels.len(), 1);
        assert_eq!(job_levels[0].len(), 1);
        let root_job = &job_levels[0][0];
        assert_eq!(root_job.job_id.circuit_type, ProvingJobCircuitType::GUTASingleEndCap);

        // the single dependency is the user's end cap job
        let end_cap_job_id = QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            user_a,
            N::GLOBAL_USER_TREE_HEIGHT,
            chain_state.unique_pending_id,
        )?;
        assert_eq!(root_job.metadata.dependencies, vec![end_cap_job_id.clone()]);
        basic_validate_job_results_singlet_case(&[end_cap_job_id.clone()], job_levels)?;

        assert_eq!(result.db_output.total_users_updated, 1);
        assert_eq!(result.db_output.total_proofs_generated, 1);
        assert_ne!(result.db_output.old_realm_root, result.db_output.new_realm_root);

        // the stored witness round trips and its realm sub-tree transition verifies
        let witness_bytes = chain_state
            .temp_db
            .get_tdb_proof_witness_bytes(&chain_state.realm_identifier, chain_state.unique_pending_id, root_job.job_id.clone())
            .await?;
        let job_info = RGPJobInfo::new_from_metadata_and_raw_witness(root_job, &witness_bytes)?;
        let validator = RGPTestResultValidator::new(
            chain_state.guta_circuit_whitelist,
            result.db_output.clone(),
            vec![vec![job_info]],
            vec![end_cap_job_id],
        )?;
        let _ = validator;
        Ok(())
    }

    #[tokio::test]
    async fn future_checkpoint_end_caps_are_deferred_and_processed_later() -> anyhow::Result<()> {
        let (mut chain_state, user_a, user_b) = test_chain_with_two_users_and_one_contract().await?;
        chain_state.unique_pending_id += 1;
        let unique_pending_id = chain_state.unique_pending_id;
        // both users update against checkpoint 1 while the realm planner is still at checkpoint 0
        chain_state.checkpoint_id += 1;
        let item_a = chain_state.run_ups_for_user(user_a, &one_contract_update()).await?;
        let item_b = chain_state.run_ups_for_user(user_b, &one_contract_update()).await?;

        let realm_tree_height = N::REALM_GLOBAL_USER_TREE_HEIGHT;
        let mut realm_tree = RecTree::new(realm_tree_height);
        let backup_file_system = SimpleMockMemoryFileSystem::new();
        let backup_file_path = "backups/future_end_caps_test".to_string();
        let mut backup_file = backup_file_system.file_like_fs_create(&backup_file_path).await?;

        let start_realm_root = realm_tree.get_root();
        let new_planner = |checkpoint_root: Hash, checkpoint_id: u64| {
            RealmGUTAPlanner::<F, Hash>::new(
                chain_state.chain_id,
                chain_state.realm_identifier,
                checkpoint_root,
                checkpoint_id,
                unique_pending_id,
                start_realm_root,
                realm_tree_height,
                N::GLOBAL_USER_TREE_HEIGHT,
                chain_state.guta_circuit_whitelist,
            )
        };

        let mut planner = new_planner(chain_state.checkpoint_tree_root, 0);
        let added_a = planner
            .add_end_cap_job(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                &item_a.psy_ser_to_bytes_vec()?,
                item_a.clone(),
            )
            .await?;
        assert_eq!(added_a, 0, "future checkpoint items must not be processed");
        assert_eq!(planner.future_pending_end_cap_jobs.len(), 1);
        assert_eq!(planner.total_end_caps_processed, 0);

        let added_b = planner
            .add_end_cap_job(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                &item_b.psy_ser_to_bytes_vec()?,
                item_b.clone(),
            )
            .await?;
        assert_eq!(added_b, 0);
        assert_eq!(planner.future_pending_end_cap_jobs.len(), 2);

        // while the planner stays at checkpoint 0 the future jobs keep being re-deferred
        let deferred_jobs: Vec<_> = planner.future_pending_end_cap_jobs.drain(..).collect();
        assert_eq!(deferred_jobs.len(), 2);
        let still_deferred = planner
            .add_future_end_cap_jobs(&chain_state.checkpoint_tree, &mut realm_tree, &mut backup_file, chain_state.temp_db.clone(), deferred_jobs)
            .await?;
        assert_eq!(still_deferred, 0);
        assert_eq!(planner.future_pending_end_cap_jobs.len(), 2);

        // once the realm advances to checkpoint 1 the deferred jobs are processed and paired
        chain_state.checkpoint_tree.append_leaf(1, Hash::qp_rand_gen())?;
        let checkpoint_1_root = chain_state.checkpoint_tree.get_root();
        let mut advanced_planner = new_planner(checkpoint_1_root, 1);
        let processed = advanced_planner
            .add_future_end_cap_jobs(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                planner.future_pending_end_cap_jobs.drain(..).collect(),
            )
            .await?;
        assert_eq!(processed, 2);
        assert_eq!(advanced_planner.total_end_caps_processed, 2);
        assert!(advanced_planner.end_cap_straggler.is_none());
        assert_eq!(advanced_planner.planned_jobs[0].len(), 1);
        assert_eq!(
            advanced_planner.planned_jobs[0][0].job_id.circuit_type,
            ProvingJobCircuitType::GUTATwoEndCap
        );

        let result = advanced_planner
            .finalize_with_reward_ids(&chain_state.checkpoint_tree, &mut realm_tree, chain_state.temp_db.clone(), 0, 0)
            .await?
            .ok_or_else(|| anyhow::anyhow!("expected a planner output for the processed future end caps"))?;
        assert_eq!(result.db_output.total_users_updated, 2);
        assert_eq!(result.db_output.total_proofs_generated, 1);
        assert_eq!(result.job_ids.len(), 1);
        let root_job = &result.job_ids[0][0];
        assert_eq!(root_job.job_id.circuit_type, ProvingJobCircuitType::GUTATwoEndCap);
        assert_eq!(root_job.metadata.dependencies, vec![item_a.job_id.clone(), item_b.job_id.clone()]);

        // the two-end-cap witness round trips through the temp db
        let witness_bytes = chain_state
            .temp_db
            .get_tdb_proof_witness_bytes(&chain_state.realm_identifier, unique_pending_id, root_job.job_id.clone())
            .await?;
        let job_info = RGPJobInfo::new_from_metadata_and_raw_witness(root_job, &witness_bytes)?;
        RGPTestResultValidator::new(
            chain_state.guta_circuit_whitelist,
            result.db_output.clone(),
            vec![vec![job_info]],
            vec![item_a.job_id.clone(), item_b.job_id.clone()],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn future_end_cap_without_contract_updates_is_dropped() -> anyhow::Result<()> {
        let (mut chain_state, user_a, user_b) = test_chain_with_two_users_and_one_contract().await?;
        chain_state.unique_pending_id += 1;
        // only user a runs an update, so user b has no contract updates in the temp db
        let item_a = chain_state.run_ups_for_user(user_a, &one_contract_update()).await?;

        let realm_tree_height = N::REALM_GLOBAL_USER_TREE_HEIGHT;
        let mut realm_tree = RecTree::new(realm_tree_height);
        let backup_file_system = SimpleMockMemoryFileSystem::new();
        let mut backup_file = backup_file_system.file_like_fs_create("backups/future_missing_updates").await?;
        let mut planner = RealmGUTAPlanner::<F, Hash>::new(
            chain_state.chain_id,
            chain_state.realm_identifier,
            chain_state.checkpoint_tree_root,
            0,
            chain_state.unique_pending_id,
            realm_tree.get_root(),
            realm_tree_height,
            N::GLOBAL_USER_TREE_HEIGHT,
            chain_state.guta_circuit_whitelist,
        );

        // item for user b pointing at a future checkpoint, but no contract updates exist for b
        let mut future_b = item_a.clone();
        future_b.new_user_leaf.user_id = F::from_u64_value(user_b);
        future_b.new_user_leaf.last_checkpoint_id = F::from_u64_value(planner.current_checkpoint_id + 1);
        let added = planner
            .add_end_cap_job(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                &future_b.psy_ser_to_bytes_vec()?,
                future_b,
            )
            .await?;
        assert_eq!(added, 0);
        assert!(
            planner.future_pending_end_cap_jobs.is_empty(),
            "a future end cap without contract updates must be dropped, not queued"
        );
        assert_eq!(planner.total_end_caps_processed, 0);
        Ok(())
    }

    #[tokio::test]
    async fn add_end_cap_job_skips_invalid_queue_items() -> anyhow::Result<()> {
        let (mut chain_state, user_a, user_b) = test_chain_with_two_users_and_one_contract().await?;
        chain_state.unique_pending_id += 1;
        let item_a = chain_state.run_ups_for_user(user_a, &one_contract_update()).await?;

        let realm_tree_height = N::REALM_GLOBAL_USER_TREE_HEIGHT;
        let mut realm_tree = RecTree::new(realm_tree_height);
        let backup_file_system = SimpleMockMemoryFileSystem::new();
        let mut backup_file = backup_file_system.file_like_fs_create("backups/skips_test").await?;
        let mut planner = RealmGUTAPlanner::<F, Hash>::new(
            chain_state.chain_id,
            chain_state.realm_identifier,
            chain_state.checkpoint_tree_root,
            chain_state.checkpoint_id,
            chain_state.unique_pending_id,
            realm_tree.get_root(),
            realm_tree_height,
            N::GLOBAL_USER_TREE_HEIGHT,
            chain_state.guta_circuit_whitelist,
        );
        let min_user_id = planner.realm_user_min_id;
        let max_user_id = planner.realm_user_max_id;

        // out-of-bounds user id: skipped before any tree access
        let mut out_of_bounds = item_a.clone();
        out_of_bounds.new_user_leaf.user_id = F::from_u64_value(max_user_id + 1);
        let added = planner
            .add_end_cap_job(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                &out_of_bounds.psy_ser_to_bytes_vec()?,
                out_of_bounds,
            )
            .await?;
        assert_eq!(added, 0);
        assert_eq!(planner.total_end_caps_processed, 0);

        // stale old leaf hash against a non-zero tree leaf: skipped without any mutation
        realm_tree.set_leaf(user_a - min_user_id, Hash::from_values(9, 9, 9, 9));
        let mut stale = item_a.clone();
        stale.old_user_leaf_hash = Hash::from_values(1, 2, 3, 4);
        let added = planner
            .add_end_cap_job(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                &stale.psy_ser_to_bytes_vec()?,
                stale,
            )
            .await?;
        assert_eq!(added, 0);
        assert_eq!(planner.total_end_caps_processed, 0);
        assert_eq!(realm_tree.get_leaf_value(user_a - min_user_id), Hash::from_values(9, 9, 9, 9));

        // zero tree leaf is initialized from the queue item's old hash, then the missing
        // contract updates for user b cause a skip
        let mut for_user_b = item_a.clone();
        for_user_b.new_user_leaf.user_id = F::from_u64_value(user_b);
        for_user_b.old_user_leaf_hash = Hash::from_values(5, 6, 7, 8);
        let added = planner
            .add_end_cap_job(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                &for_user_b.psy_ser_to_bytes_vec()?,
                for_user_b,
            )
            .await?;
        assert_eq!(added, 0);
        assert_eq!(planner.total_end_caps_processed, 0);
        assert_eq!(realm_tree.get_leaf_value(user_b - min_user_id), Hash::from_values(5, 6, 7, 8));

        // a consistent item without contract updates is skipped too
        let mut no_updates = item_a.clone();
        no_updates.new_user_leaf.user_id = F::from_u64_value(user_b);
        no_updates.old_user_leaf_hash = Hash::get_zero_value();
        let added = planner
            .add_end_cap_job(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                &no_updates.psy_ser_to_bytes_vec()?,
                no_updates,
            )
            .await?;
        assert_eq!(added, 0);

        // the valid item for user a still processes after its tree leaf is restored
        realm_tree.set_leaf(user_a - min_user_id, Hash::get_zero_value());
        let added = planner
            .add_end_cap_job(
                &chain_state.checkpoint_tree,
                &mut realm_tree,
                &mut backup_file,
                chain_state.temp_db.clone(),
                &item_a.psy_ser_to_bytes_vec()?,
                item_a.clone(),
            )
            .await?;
        assert_eq!(added, 1);
        assert_eq!(planner.total_end_caps_processed, 1);
        assert!(planner.end_cap_straggler.is_some());
        assert!(planner.user_leaf_updates_ffs.len() > 0);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PsyRGPNetworkConfig {}

impl QNetworkTreeCircuitSpecificConstants for PsyRGPNetworkConfig {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize = 32;
    const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize = 64;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize = 8;
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize = 4;
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;

    const DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4: [u64; 4] = [3896366420105793420, 17410332186442776169, 7329967984378645716, 6310665049578686403];

    const END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4: [u64; 4] = [1412692327731855940, 17963365021580141687, 10532510199226356508, 3943799806037696098];
}

impl QNetworkTreeConstants for PsyRGPNetworkConfig {
    const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
    const CHECKPOINT_TREE_HEIGHT: u8 = Self::CHECKPOINT_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 32;
    const GLOBAL_USER_TREE_HEIGHT: u8 = Self::GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = Self::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE as u8;

    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = Self::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE as u8;

    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 12;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 20;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = Self::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

    const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize = 32;
    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = Self::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE as u8;

    const GROUP_REALM_HEIGHT: u8 = 1;

    const MAX_USERS: u64 = 1 << Self::GLOBAL_USER_TREE_HEIGHT;

    const MAX_REALMS: u32 = 1 << Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT;

    const MAX_USERS_PER_REALM: u32 = 1 << Self::REALM_GLOBAL_USER_TREE_HEIGHT;
}

type InMemoryTestStore = InMemoryCoreStore<Hash, Hasher>;

impl QNetworkHashTypes for PsyRGPNetworkConfig {
    type QHash = Hash;

    type HasherBase = Hasher;

    type F = F;
}
pub type TempStore = InMemoryTempStore;

pub type PsyRGPTestDatabase = PsyUnifiedCoreDatabaseStore<
    PsyRGPNetworkConfig,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryTableIdentifier,
    InMemoryCoreStore<Hash, Hasher>,
>;

pub async fn create_rgp_test_db() -> anyhow::Result<PsyRGPTestDatabase> {
    let store = Arc::new(InMemoryTestStore::new());
    setup_rgp_test_db(store).await
}
pub async fn setup_rgp_test_db(store: Arc<InMemoryTestStore>) -> anyhow::Result<PsyRGPTestDatabase> {
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
    let global_user_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "global_user_tree_table",
        PsyRGPNetworkConfig::GLOBAL_USER_TREE_HEIGHT,
    ));
    let user_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "user_contract_tree_table",
        PsyRGPNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT,
    ));
    let contract_state_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_state_tree_table"));
    let global_checkpoint_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "global_checkpoint_tree_table",
        PsyRGPNetworkConfig::CHECKPOINT_TREE_HEIGHT,
    ));
    // start reward tree table
    let guta_reward_tag_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "guta_reward_tag_tree_table"));
    // added tables for completeness
    let user_registration_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "user_registration_tree_table",
        PsyRGPNetworkConfig::GLOBAL_USER_TREE_HEIGHT,
    ));
    let global_contract_tree_table = Arc::new(InMemoryTableIdentifier::new_treee_with_keyspace(
        &keyspace,
        "global_contract_tree_table",
        PsyRGPNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT,
    ));
    let contract_function_tree_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_function_tree_table"));
    let contract_leaf_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_leaf_table"));
    let contract_code_definition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(&keyspace, "contract_code_definition_table"));
    let checkpoint_zk_proof_and_transition_table = Arc::new(InMemoryTableIdentifier::new_with_keyspace(
        &keyspace,
        "checkpoint_zk_proof_and_transition_table",
    ));

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
        global_contract_tree_table,
        contract_function_tree_table,
        contract_leaf_table,
        contract_code_definition_table,
        checkpoint_zk_proof_and_transition_table,
        imt_leaf_table,
        imt_key_index_table,
        imt_next_append_index_table,
    );
    Ok(psy_db)
}
