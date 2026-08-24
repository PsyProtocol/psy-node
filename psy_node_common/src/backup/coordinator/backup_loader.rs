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
