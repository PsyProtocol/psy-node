use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{node::realm_processor::RealmProcessorCoreState, prepared_block::realm::PsyPreparedRealmBlockStateUpdates};
use psy_io::tokio::TokioLikeFileSystem;

use crate::realm::processor::gatherers::realm_end_cap_gatherer::{
    get_new_realm_end_cap_gatherer_backup_file_path, read_realm_end_cap_gatherer_backup_file,
};

pub async fn generate_realm_output_from_backups<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    file_system: &FileSystem,
    guta_gatherer_backup_directory: &str,
    state: &RealmProcessorCoreState<N::QHash>,
    restore_unique_pending_id: Option<u64>,
    global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
) -> anyhow::Result<PsyPreparedRealmBlockStateUpdates<N::QHash>> {
    let pending_id = restore_unique_pending_id.unwrap_or(state.processing_unique_pending_id);
    let guta_gatherer_backup_file_path = get_new_realm_end_cap_gatherer_backup_file_path(
        guta_gatherer_backup_directory,
        state.realm_id_u64,
        state.realm_sub_id_u64,
        pending_id,
    );
    let path_str = guta_gatherer_backup_file_path.to_string_lossy();
    tracing::info!(
        "Loading realm backup for recovery: path={}, realm_id={}, realm_sub_id={}, pending_id={}",
        path_str,
        state.realm_id_u64,
        state.realm_sub_id_u64,
        pending_id
    );

    let guta_gatherer_result = read_realm_end_cap_gatherer_backup_file::<N::HasherBase, N::QHash, N::F, FileSystem>(
        file_system,
        &path_str,
        global_user_tree,
        state.realm_id_u64,
        N::REALM_GLOBAL_USER_TREE_HEIGHT,
        N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
        false,
    )
    .await?;

    let updates = PsyPreparedRealmBlockStateUpdates {
        realm_id: state.realm_id_u64,
        realm_sub_id: state.realm_sub_id_u64,
        unique_pending_id: pending_id,
        proc_checkpoint_unique_id: state.processing_proc_checkpoint_unique_id,
        old_realm_root: guta_gatherer_result.old_realm_root,
        new_realm_root: guta_gatherer_result.new_realm_root,
        update_global_user_tree_nodes_ffs: guta_gatherer_result.update_global_user_tree_nodes_ffs,
        update_user_contract_tree_nodes_ffs: guta_gatherer_result.update_user_contract_tree_nodes_ffs,
        update_contract_state_tree_nodes_ffs: guta_gatherer_result.update_contract_state_tree_nodes_ffs,
        update_user_leaves_ffs: guta_gatherer_result.update_user_leaves_ffs,
    };
    Ok(updates)
}
