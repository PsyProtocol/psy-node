use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    node::coordinator_processor::{CoordinatorProcessorIdState, CoordinatorProcessorLastCommittedState},
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
};
use psy_io::tokio::TokioLikeFileSystem;

use crate::{
    backup::output::coordinator_output_builder::CoordinatorOutputBuilder,
    coordinator::processor::gatherers::{
        coordinator_guta_update_gatherer::{
            get_new_coordinator_guta_update_gatherer_backup_file_path, read_coordinator_guta_update_gatherer_backup_file,
        },
        deploy_contract_gatherer::{get_new_deploy_contract_gatherer_backup_file_path, read_deploy_contract_gatherer_backup_file_path},
        register_user_gatherer::{get_new_register_user_gatherer_backup_file_path, read_register_user_gatherer_backup_file_path},
        update_contract_gatherer::{get_new_update_contract_gatherer_backup_file_path, read_update_contract_gatherer_backup_file_path},
    },
};

pub async fn generate_coordinator_output_from_backups<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    file_system: &FileSystem,
    deploy_contract_gatherer_backup_directory: &str,
    update_contract_gatherer_backup_directory: &str,
    register_user_gatherer_backup_directory: &str,
    guta_gatherer_backup_directory: &str,
    coordinator_ids: &CoordinatorProcessorIdState,
    last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
    reward_tree_root: N::QHash,
    append_checkpoint_tree_siblings: Vec<N::QHash>,
    global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    global_contract_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    user_registration_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
) -> anyhow::Result<PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>> {
    let guta_gatherer_backup_file_path = get_new_coordinator_guta_update_gatherer_backup_file_path(
        guta_gatherer_backup_directory,
        coordinator_ids.realm_id_u64,
        coordinator_ids.realm_sub_id_u64,
        coordinator_ids.unique_pending_id,
    );

    let guta_gatherer_result = read_coordinator_guta_update_gatherer_backup_file::<N::HasherBase, N::QHash, N::F, FileSystem>(
        file_system,
        &guta_gatherer_backup_file_path.to_string_lossy(),
        global_user_tree,
    )
    .await?;

    let register_users_gatherer_backup_file_path = get_new_register_user_gatherer_backup_file_path(
        register_user_gatherer_backup_directory,
        coordinator_ids.realm_id_u64,
        coordinator_ids.realm_sub_id_u64,
        coordinator_ids.unique_pending_id,
    );

    let register_user_gatherer_result = read_register_user_gatherer_backup_file_path::<N::HasherBase, N::QHash, FileSystem>(
        file_system,
        &register_users_gatherer_backup_file_path,
        user_registration_tree,
    )
    .await?;

    let deploy_contract_gatherer_backup_file_path = get_new_deploy_contract_gatherer_backup_file_path(
        deploy_contract_gatherer_backup_directory,
        coordinator_ids.realm_id_u64,
        coordinator_ids.realm_sub_id_u64,
        coordinator_ids.unique_pending_id,
    );
    let deploy_contract_gatherer_result = read_deploy_contract_gatherer_backup_file_path::<N::HasherBase, N::QHash, N::F, FileSystem>(
        file_system,
        &deploy_contract_gatherer_backup_file_path,
        1 << N::CONTRACT_FUNCTION_TREE_HEIGHT,
        global_contract_tree,
    )
    .await?;

    let update_contract_gatherer_backup_file_path = get_new_update_contract_gatherer_backup_file_path(
        update_contract_gatherer_backup_directory,
        coordinator_ids.realm_id_u64,
        coordinator_ids.realm_sub_id_u64,
        coordinator_ids.unique_pending_id,
    );
    let update_contract_gatherer_result = read_update_contract_gatherer_backup_file_path::<N::HasherBase, N::QHash, N::F, FileSystem>(
        file_system,
        &update_contract_gatherer_backup_file_path,
        1 << N::CONTRACT_FUNCTION_TREE_HEIGHT,
        global_contract_tree,
    )
    .await?;

    let block_time = register_user_gatherer_result.block_time;

    let final_output = CoordinatorOutputBuilder::<N>::get_output_for_backup(
        coordinator_ids,
        last_committed,
        reward_tree_root,
        guta_gatherer_result,
        register_user_gatherer_result,
        deploy_contract_gatherer_result,
        update_contract_gatherer_result,
        append_checkpoint_tree_siblings,
        block_time,
    )?;
    Ok(final_output)
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::{MerkleHasher, MerkleZeroHasher},
        node::realm_identifier::QRealmIdentifier,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{QNetworkTreeConstants, Q256BitHash},
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_data::{
        node::coordinator_processor::{CoordinatorProcessorIdState, CoordinatorProcessorLastCommittedState},
        protocol::checkpoint_transition_hash::CheckpointStateHashTransition,
        v1::qdata::checkpoint::{
            PQEDCheckpointGlobalStateRoots,
            PQEDCheckpointLeaf,
            PQEDCheckpointLeafStats,
            QEDL2BlockState,
        },
    };
    use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;

    use crate::coordinator::processor::gatherers::{
        coordinator_guta_update_gatherer::{
            get_new_coordinator_guta_update_gatherer_backup_file_path,
            COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32,
        },
        deploy_contract_gatherer::{get_new_deploy_contract_gatherer_backup_file_path, DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32},
        register_user_gatherer::{get_new_register_user_gatherer_backup_file_path, REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32},
        update_contract_gatherer::{get_new_update_contract_gatherer_backup_file_path, UPDATE_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32},
    };
    use crate::test_common::TestNetworkConfig;

    use super::*;

    type Hasher = PoseidonHasher;
    type Hash = PHash;
    type Fs = SimpleMockMemoryFileSystem;
    type N = TestNetworkConfig;

    const REALM_ID: u64 = 1;
    const REALM_SUB_ID: u64 = 2;
    const PENDING_ID: u64 = 100;
    const BLOCK_TIME: u64 = 1_700_000_000;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    fn h(i: u64) -> Hash {
        PHash::from_values(i * 32 + 1, 0xAAAA_1_111, 0x2222_BBBB, i + 5)
    }

    fn coordinator_ids(checkpoint_id: u64) -> CoordinatorProcessorIdState {
        CoordinatorProcessorIdState {
            realm_identifier: QRealmIdentifier { realm_id: REALM_ID as u32, realm_sub_id: REALM_SUB_ID as u16 },
            realm_id_u64: REALM_ID,
            realm_sub_id_u64: REALM_SUB_ID,
            checkpoint_id,
            next_checkpoint_id: checkpoint_id + 1,
            unique_pending_id: PENDING_ID,
            proc_checkpoint_unique_id: 200,
            gathering_unique_pending_id: 300,
            gathering_proc_checkpoint_unique_id: 400,
        }
    }

    fn last_committed_state() -> CoordinatorProcessorLastCommittedState<PF, PHash> {
        CoordinatorProcessorLastCommittedState {
            l2_state: QEDL2BlockState {
                checkpoint_id: 0,
                next_add_withdrawal_id: 3,
                next_process_withdrawal_id: 5,
                next_deposit_id: 7,
                total_deposits_claimed_epoch: 9,
                next_user_id: 0,
                end_balance: 13,
                next_contract_id: 15,
            },
            checkpoint_leaf_stats: PQEDCheckpointLeafStats::qp_rand_gen(),
            checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            checkpoint_state_roots: PQEDCheckpointGlobalStateRoots::qp_rand_gen(),
            checkpoint_state_transition: CheckpointStateHashTransition {
                old_checkpoint_tree_root: h(1),
                new_checkpoint_tree_root: h(2),
                old_checkpoint_leaf_hash: h(3),
                new_checkpoint_leaf_hash: h(4),
            },
            checkpoint_root: h(5),
            checkpoint_leaf_hash: h(6),
            last_chain_hash: h(7),
        }
    }

    fn write_backup(fs: &Fs, path: String, bytes: Vec<u8>) {
        fs.files.insert(path, bytes);
    }

    /// GUTA backup with zero queue items: magic + start_root + random seed.
    fn guta_backup_bytes(start_root: Hash) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
        bytes.extend_from_slice(&start_root.into_owned_32bytes());
        bytes.extend_from_slice(&h(60).into_owned_32bytes());
        bytes
    }

    /// register backup: magic + start_next_user_id + start_root + N*64-byte
    /// public keys + total_jobs + block_time.
    fn register_backup_bytes(start_next_user_id: u64, start_root: Hash, public_keys: &[[u8; 64]], total_jobs: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
        bytes.extend_from_slice(&start_next_user_id.to_le_bytes());
        bytes.extend_from_slice(&start_root.into_owned_32bytes());
        for key in public_keys {
            bytes.extend_from_slice(&key[..]);
        }
        bytes.extend_from_slice(&total_jobs.to_le_bytes());
        bytes.extend_from_slice(&BLOCK_TIME.to_le_bytes());
        bytes
    }

    /// deploy backup with zero contracts: magic + start_next_contract_id +
    /// start_root + num(0) + total_jobs.
    fn deploy_backup_bytes(start_next_contract_id: u64, start_root: Hash, total_jobs: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32.to_le_bytes());
        bytes.extend_from_slice(&start_next_contract_id.to_le_bytes());
        bytes.extend_from_slice(&start_root.into_owned_32bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&total_jobs.to_le_bytes());
        bytes
    }

    /// update backup with zero updates: magic + start_root + num(0) + total_jobs.
    fn update_backup_bytes(start_root: Hash, total_jobs: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&UPDATE_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
        bytes.extend_from_slice(&start_root.into_owned_32bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&total_jobs.to_le_bytes());
        bytes
    }

    fn pubkey(i: usize) -> [u8; 64] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&h(i as u64).into_owned_32bytes());
        key[32..].copy_from_slice(&h(i as u64 + 1).into_owned_32bytes());
        key
    }

    /// Mirrors the register gatherer's private `hash_two_from_slice`.
    fn hash_two(key: &[u8; 64]) -> Hash {
        let left = PHash::from_owned_32bytes(key[0..32].try_into().expect("32 bytes"));
        let right = PHash::from_owned_32bytes(key[32..64].try_into().expect("32 bytes"));
        PoseidonHasher::two_to_one(&left, &right)
    }

    struct BackupSet {
        fs: Fs,
        ids: CoordinatorProcessorIdState,
        last_committed: CoordinatorProcessorLastCommittedState<PF, PHash>,
        user_registration_tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        global_user_tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        global_contract_tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    }

    /// Writes a consistent set of four gatherer backups with two registered
    /// users and no contract activity against fresh in-memory trees.
    fn backup_set(checkpoint_id: u64) -> BackupSet {
        let fs = Fs::new();
        let ids = coordinator_ids(checkpoint_id);
        let user_registration_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(N::GLOBAL_USER_TREE_HEIGHT);
        let mut global_user_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(N::GLOBAL_USER_TREE_HEIGHT);
        global_user_tree.set_effective_height(N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);
        let global_contract_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(N::GLOBAL_CONTRACT_TREE_HEIGHT);

        let guta_path = get_new_coordinator_guta_update_gatherer_backup_file_path("guta", REALM_ID, REALM_SUB_ID, PENDING_ID);
        write_backup(&fs, guta_path.to_string_lossy().to_string(), guta_backup_bytes(global_user_tree.get_root()));

        let register_path = get_new_register_user_gatherer_backup_file_path("register", REALM_ID, REALM_SUB_ID, PENDING_ID);
        let register_start_root = user_registration_tree.get_historical_pivot_leaf(0).root;
        write_backup(
            &fs,
            register_path,
            register_backup_bytes(0, register_start_root, &[pubkey(0), pubkey(2)], 2),
        );

        let deploy_path = get_new_deploy_contract_gatherer_backup_file_path("deploy", REALM_ID, REALM_SUB_ID, PENDING_ID);
        let deploy_start_root = global_contract_tree.get_historical_pivot_leaf(0).root;
        write_backup(&fs, deploy_path, deploy_backup_bytes(0, deploy_start_root, 0));

        let update_path = get_new_update_contract_gatherer_backup_file_path("update", REALM_ID, REALM_SUB_ID, PENDING_ID);
        write_backup(&fs, update_path, update_backup_bytes(global_contract_tree.get_root(), 0));

        BackupSet {
            fs,
            ids,
            last_committed: last_committed_state(),
            user_registration_tree,
            global_user_tree,
            global_contract_tree,
        }
    }

    async fn generate(set: BackupSet) -> anyhow::Result<PsyPreparedCoordinatorBlockStateUpdates<PF, PHash>> {
        let BackupSet { fs, ids, last_committed, mut user_registration_tree, mut global_user_tree, mut global_contract_tree } = set;
        generate_coordinator_output_from_backups::<N, Fs>(
            &fs,
            "deploy",
            "update",
            "register",
            "guta",
            &ids,
            &last_committed,
            h(50),
            vec![],
            &mut global_user_tree,
            &mut global_contract_tree,
            &mut user_registration_tree,
        )
        .await
    }

    #[tokio::test]
    async fn regenerates_block_output_from_consistent_backups() -> anyhow::Result<()> {
        let set = backup_set(3);
        let output = generate(set).await?;

        // the output targets the next checkpoint after the coordinator ids
        assert_eq!(output.checkpoint_id, 4);
        // two registered users moved the next user id forward
        assert_eq!(output.new_base.block_state.next_user_id, 2);
        // no contract activity: the final contract root is the empty tree root
        assert_eq!(
            output.new_base.checkpoint_leaf.global_state_roots.contract_tree_root,
            zh(N::GLOBAL_CONTRACT_TREE_HEIGHT as usize)
        );
        assert_eq!(output.old_base.checkpoint_tree_root, h(5));
        Ok(())
    }

    #[tokio::test]
    async fn register_backup_replays_users_into_the_registration_tree() -> anyhow::Result<()> {
        let set = backup_set(0);
        let BackupSet { fs, ids, last_committed, mut user_registration_tree, mut global_user_tree, mut global_contract_tree } = set;
        generate_coordinator_output_from_backups::<N, Fs>(
            &fs,
            "deploy",
            "update",
            "register",
            "guta",
            &ids,
            &last_committed,
            h(50),
            vec![],
            &mut global_user_tree,
            &mut global_contract_tree,
            &mut user_registration_tree,
        )
        .await?;

        assert_eq!(user_registration_tree.get_leaf_value(0), hash_two(&pubkey(0)));
        assert_eq!(user_registration_tree.get_leaf_value(1), hash_two(&pubkey(2)));
        assert_eq!(user_registration_tree.get_leaf_value(2), zh(0));
        // the guta gatherer had no items: the global user tree is untouched
        assert_eq!(global_user_tree.get_root(), zh(N::GLOBAL_USER_TREE_HEIGHT as usize));
        assert_eq!(global_user_tree.get_effective_height(), N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);
        // no deploys or updates touched the contract tree
        assert_eq!(global_contract_tree.get_leaf_value(0), zh(0));
        Ok(())
    }

    #[tokio::test]
    async fn fails_when_guta_backup_start_root_does_not_match_tree() -> anyhow::Result<()> {
        let set = backup_set(3);
        let guta_path =
            get_new_coordinator_guta_update_gatherer_backup_file_path("guta", REALM_ID, REALM_SUB_ID, PENDING_ID).to_string_lossy().to_string();
        set.fs.files.insert(guta_path, guta_backup_bytes(h(99)));
        let err = generate(set).await.err().expect("a mismatching guta start root must fail");
        assert!(err.to_string().contains("does not match tree root"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn fails_when_guta_backup_file_is_missing() -> anyhow::Result<()> {
        let set = backup_set(3);
        let guta_path =
            get_new_coordinator_guta_update_gatherer_backup_file_path("guta", REALM_ID, REALM_SUB_ID, PENDING_ID).to_string_lossy().to_string();
        let patched = set;
        patched.fs.files.remove(&guta_path);
        let err = generate(patched).await.err().expect("a missing guta backup file must fail");
        assert!(err.to_string().to_lowercase().contains("not found"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn fails_when_register_backup_block_time_is_out_of_range() -> anyhow::Result<()> {
        let set = backup_set(3);
        let register_path = get_new_register_user_gatherer_backup_file_path("register", REALM_ID, REALM_SUB_ID, PENDING_ID);
        let register_start_root = set.user_registration_tree.get_historical_pivot_leaf(0).root;
        // block time 0 is rejected by the reader
        let mut bytes = register_backup_bytes(0, register_start_root, &[pubkey(0)], 1);
        let len = bytes.len();
        bytes[len - 8..].copy_from_slice(&0u64.to_le_bytes());
        set.fs.files.insert(register_path, bytes);
        let err = generate(set).await.err().expect("block_time 0 must fail");
        assert!(err.to_string().contains("block_time"), "unexpected error: {err}");
        Ok(())
    }
}
