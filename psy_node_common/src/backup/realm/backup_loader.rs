use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::protocol::core_types::{QDBHashBase, QNetworkTypesConfig};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{node::realm_processor::RealmProcessorCoreState, prepared_block::realm::PsyPreparedRealmBlockStateUpdates};
use psy_io::tokio::TokioLikeFileSystem;

use crate::realm::processor::gatherers::realm_end_cap_gatherer::{
    get_new_realm_end_cap_gatherer_backup_file_path, read_realm_backup_end_root, read_realm_end_cap_gatherer_backup_file,
};

#[derive(Debug)]
pub struct RealmBackupCandidate {
    pub path: PathBuf,
    pub pending_id: Option<u64>,
}

fn backup_pending_id(file_name: &str, realm_id: u64, realm_sub_id: u64) -> Option<u64> {
    let prefix = format!("realm_end_cap_gatherer_realm_{realm_id}_sub_{realm_sub_id}_pending_");
    file_name.strip_prefix(&prefix)?.strip_suffix(".backup")?.parse().ok()
}

async fn standard_backup_candidates(directory: &Path, realm_id: u64, realm_sub_id: u64) -> anyhow::Result<Vec<RealmBackupCandidate>> {
    let mut entries = match tokio::fs::read_dir(directory).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut candidates = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(pending_id) = backup_pending_id(&file_name, realm_id, realm_sub_id) {
            candidates.push(RealmBackupCandidate {
                path: entry.path(),
                pending_id: Some(pending_id),
            });
        }
    }
    candidates.sort_by_key(|candidate| candidate.pending_id);
    Ok(candidates)
}

async fn proposal_backup_candidates(directory: &Path, realm_id: u64, realm_sub_id: u64) -> anyhow::Result<Vec<RealmBackupCandidate>> {
    let mut entries = match tokio::fs::read_dir(directory).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut proposal_directories = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_dir() && entry.file_name().to_string_lossy().starts_with("proposal_") {
            proposal_directories.push(entry.path());
        }
    }
    proposal_directories.sort();

    let mut candidates = Vec::new();
    for proposal_directory in proposal_directories {
        let mut proposal_entries = match tokio::fs::read_dir(&proposal_directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        while let Some(entry) = proposal_entries.next_entry().await? {
            if !entry.file_type().await?.is_file() {
                continue;
            }
            let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if backup_pending_id(&file_name, realm_id, realm_sub_id).is_some() {
                candidates.push(RealmBackupCandidate {
                    path: entry.path(),
                    pending_id: None,
                });
            }
        }
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(candidates)
}

pub async fn find_realm_backups_by_end_root<FileSystem: TokioLikeFileSystem, Hash: QDBHashBase>(
    file_system: &FileSystem,
    guta_gatherer_backup_directory: &str,
    realm_id: u64,
    realm_sub_id: u64,
    target_end_root: Hash,
) -> anyhow::Result<Vec<RealmBackupCandidate>> {
    let directory = Path::new(guta_gatherer_backup_directory);
    let mut candidates = standard_backup_candidates(directory, realm_id, realm_sub_id).await?;
    candidates.extend(proposal_backup_candidates(directory, realm_id, realm_sub_id).await?);

    let mut matching = Vec::new();
    for candidate in candidates {
        let path = candidate.path.to_string_lossy();
        match read_realm_backup_end_root::<FileSystem, Hash>(file_system, &path).await {
            Ok(end_root) if end_root == target_end_root => matching.push(candidate),
            Ok(_) => {}
            Err(error) => tracing::debug!("Failed to read Realm backup end root path={} error={:#}", path, error),
        }
    }
    Ok(matching)
}

pub async fn generate_realm_output_from_backup_path<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    file_system: &FileSystem,
    backup_path: &Path,
    state: &RealmProcessorCoreState<N::QHash>,
    global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
) -> anyhow::Result<PsyPreparedRealmBlockStateUpdates<N::QHash>> {
    let path_str = backup_path.to_string_lossy();
    tracing::info!(
        "Loading realm backup for recovery: path={}, realm_id={}, realm_sub_id={}, pending_id={}",
        path_str,
        state.realm_id_u64,
        state.realm_sub_id_u64,
        state.processing_unique_pending_id
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

    Ok(PsyPreparedRealmBlockStateUpdates {
        realm_id: state.realm_id_u64,
        realm_sub_id: state.realm_sub_id_u64,
        unique_pending_id: state.processing_unique_pending_id,
        proc_checkpoint_unique_id: state.processing_proc_checkpoint_unique_id,
        old_realm_root: guta_gatherer_result.old_realm_root,
        new_realm_root: guta_gatherer_result.new_realm_root,
        update_global_user_tree_nodes_ffs: guta_gatherer_result.update_global_user_tree_nodes_ffs,
        update_user_contract_tree_nodes_ffs: guta_gatherer_result.update_user_contract_tree_nodes_ffs,
        update_contract_state_tree_nodes_ffs: guta_gatherer_result.update_contract_state_tree_nodes_ffs,
        update_user_leaves_ffs: guta_gatherer_result.update_user_leaves_ffs,
        update_contract_state_imt_leaves_ffs: guta_gatherer_result.update_contract_state_imt_leaves_ffs,
    })
}

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
    let backup_path = get_new_realm_end_cap_gatherer_backup_file_path(
        guta_gatherer_backup_directory,
        state.realm_id_u64,
        state.realm_sub_id_u64,
        pending_id,
    );
    let mut recovery_state = state.clone();
    recovery_state.processing_unique_pending_id = pending_id;
    generate_realm_output_from_backup_path::<N, FileSystem>(file_system, &backup_path, &recovery_state, global_user_tree).await
}
