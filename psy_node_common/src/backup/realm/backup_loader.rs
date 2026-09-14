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
        update_contract_state_imt_leaves_ffs: guta_gatherer_result.update_contract_state_imt_leaves_ffs,
    };
    Ok(updates)
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::MerkleZeroHasher,
        node::realm_identifier::QRealmIdentifier,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{QNetworkTreeConstants, Q256BitHash},
        PHash, PF,
    };
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use psy_data::{guta::header_extended::GlobalUserTreeAggregatorHeaderWithJobId, node::realm_processor::RealmProcessorCoreState};
    use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;
    use psy_serialize::PsyCanonicalSerializeMetadata;

    use crate::realm::processor::gatherers::realm_end_cap_gatherer::{
        get_new_realm_end_cap_gatherer_backup_file_path,
        REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32,
    };
    use crate::test_common::TestNetworkConfig;

    use super::*;

    type Hasher = PoseidonHasher;
    type Hash = PHash;
    type Fs = SimpleMockMemoryFileSystem;
    type N = TestNetworkConfig;

    const REALM_ID: u64 = 1;
    const REALM_SUB_ID: u64 = 2;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    fn h(i: u64) -> Hash {
        PHash::from_values(i * 32 + 1, 0x1234_5678_9ABC_DEF0, 0x0FED_CBA9_8765_4321, i + 5)
    }

    fn realm_state() -> RealmProcessorCoreState<Hash> {
        RealmProcessorCoreState::new_basic(
            7,
            QRealmIdentifier { realm_id: REALM_ID as u32, realm_sub_id: REALM_SUB_ID as u16 },
            5,
            17,
            19u128,
            h(1),
            h(2),
        )
    }

    /// GUTA footer in the on-disk layout parsed by
    /// `read_guta_header_with_job_id_from_backup_bytes`.
    fn footer_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(GlobalUserTreeAggregatorHeaderWithJobId::<PF, PHash>::FIXED_SIZE);
        for i in 70..74u64 {
            bytes.extend_from_slice(&h(i).into_owned_32bytes());
        }
        bytes.extend_from_slice(&1u64.to_le_bytes()); // node_index
        bytes.extend_from_slice(&2u64.to_le_bytes()); // node_level
        for i in 3..8u64 {
            bytes.extend_from_slice(&i.to_le_bytes()); // stats
        }
        bytes.extend_from_slice(&11u64.to_le_bytes()); // total aggregation proofs
        let job_id = QProvingJobDataID::new_proof_job_id(9, 1, ProvingJobCircuitType::GUTATwoEndCap, 0, 0);
        bytes.extend_from_slice(&job_id.to_fixed_bytes());
        assert_eq!(bytes.len(), GlobalUserTreeAggregatorHeaderWithJobId::<PF, PHash>::FIXED_SIZE);
        bytes
    }

    /// End-cap backup with zero end caps: magic + start_root + end_root +
    /// end_caps(0) + guta footer.
    fn end_cap_backup_bytes(start_root: Hash, end_root: Hash) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
        bytes.extend_from_slice(&start_root.into_owned_32bytes());
        bytes.extend_from_slice(&end_root.into_owned_32bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&footer_bytes());
        bytes
    }

    fn backup_path(pending_id: u64) -> String {
        get_new_realm_end_cap_gatherer_backup_file_path("guta", REALM_ID, REALM_SUB_ID, pending_id).to_string_lossy().to_string()
    }

    fn fresh_tree() -> SimpleMemoryMerkleRecorderStore<Hasher, Hash> {
        SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(N::REALM_GLOBAL_USER_TREE_HEIGHT)
    }

    #[tokio::test]
    async fn regenerates_realm_output_from_an_empty_end_cap_backup() -> anyhow::Result<()> {
        let fs = Fs::new();
        let state = realm_state();
        fs.files.insert(backup_path(17), end_cap_backup_bytes(zh(20), h(80)));

        let mut tree = fresh_tree();
        let updates =
            generate_realm_output_from_backups::<N, Fs>(&fs, "guta", &state, None, &mut tree).await?;

        assert_eq!(updates.realm_id, REALM_ID);
        assert_eq!(updates.realm_sub_id, REALM_SUB_ID);
        // no restore id: the processing pending id from the state is used
        assert_eq!(updates.unique_pending_id, state.processing_unique_pending_id);
        assert_eq!(updates.proc_checkpoint_unique_id, state.processing_proc_checkpoint_unique_id);
        assert_eq!(updates.old_realm_root, zh(N::REALM_GLOBAL_USER_TREE_HEIGHT as usize));
        assert_eq!(updates.new_realm_root, h(80));
        // zero end caps: no node updates are emitted
        assert!(updates.update_global_user_tree_nodes_ffs.is_empty());
        assert!(updates.update_user_contract_tree_nodes_ffs.is_empty());
        assert!(updates.update_contract_state_tree_nodes_ffs.is_empty());
        assert!(updates.update_user_leaves_ffs.is_empty());
        assert!(updates.update_contract_state_imt_leaves_ffs.is_empty());
        // the in-memory realm tree is unchanged
        assert_eq!(tree.get_root(), zh(N::REALM_GLOBAL_USER_TREE_HEIGHT as usize));
        Ok(())
    }

    #[tokio::test]
    async fn restore_unique_pending_id_selects_a_different_backup_file() -> anyhow::Result<()> {
        let fs = Fs::new();
        let state = realm_state();
        // only the backup for pending id 88 exists
        fs.files.insert(backup_path(88), end_cap_backup_bytes(zh(20), h(81)));

        let mut tree = fresh_tree();
        let updates = generate_realm_output_from_backups::<N, Fs>(&fs, "guta", &state, Some(88), &mut tree).await?;
        assert_eq!(updates.unique_pending_id, 88);
        assert_eq!(updates.new_realm_root, h(81));

        // restoring without the matching file for the state's pending id fails
        let err = generate_realm_output_from_backups::<N, Fs>(&fs, "guta", &state, None, &mut tree)
            .await
            .err()
            .expect("a missing end-cap backup must fail");
        assert!(err.to_string().to_lowercase().contains("not found"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn fails_when_start_root_does_not_match_the_realm_tree() -> anyhow::Result<()> {
        let fs = Fs::new();
        let state = realm_state();
        fs.files.insert(backup_path(17), end_cap_backup_bytes(h(99), h(80)));

        let mut tree = fresh_tree();
        let err = generate_realm_output_from_backups::<N, Fs>(&fs, "guta", &state, None, &mut tree)
            .await
            .err()
            .expect("a mismatching start root must fail");
        assert!(err.to_string().contains("does not match tree root"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn fails_on_bad_magic_and_truncated_files() -> anyhow::Result<()> {
        let fs = Fs::new();
        let state = realm_state();

        // wrong magic
        let mut bad_magic = end_cap_backup_bytes(zh(20), h(80));
        bad_magic[0] ^= 0xFF;
        fs.files.insert(backup_path(17), bad_magic);
        let mut tree = fresh_tree();
        let err = generate_realm_output_from_backups::<N, Fs>(&fs, "guta", &state, None, &mut tree)
            .await
            .err()
            .expect("a wrong magic must fail");
        assert!(err.to_string().contains("magic"), "unexpected error: {err}");

        // truncated below the constant header size
        let fs2 = Fs::new();
        fs2.files.insert(backup_path(17), vec![0u8; 16]);
        let mut tree2 = fresh_tree();
        let err = generate_realm_output_from_backups::<N, Fs>(&fs2, "guta", &state, None, &mut tree2)
            .await
            .err()
            .expect("a truncated backup must fail");
        assert!(err.to_string().contains("too small"), "unexpected error: {err}");
        Ok(())
    }
}
