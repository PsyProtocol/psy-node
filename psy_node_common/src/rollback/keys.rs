//! Key materialization from finalized gatherer backup FFS blobs.

use psy_core::user_id::get_user_id_from_user_registration_id;

use crate::rollback::generator::BackupKeySource;
use crate::rollback::plan::{PostTargetGeneration, RollbackRole};

const FFS_SIMPLE_MERKLE_NODE: usize = 41;
const FFS_USER_LEAF: usize = 104;
const FFS_SINGLE_ID_NODE: usize = 49;
const FFS_DOUBLE_ID_NODE: usize = 57;
const IMT_LEAF_FFS_V2: usize = 161;

#[derive(Debug, Clone)]
pub struct TempFieldKey {
    pub pending_id: u64,
    pub field: Box<[u8]>,
}

#[derive(Debug, Clone)]
pub struct MerkleNodeKey {
    pub level: u8,
    pub index: u64,
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone)]
pub struct SingleTreeMerkleKey {
    pub tree_id: u64,
    pub level: u8,
    pub index: u64,
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone)]
pub struct DoubleTreeMerkleKey {
    pub tree_id: u64,
    pub tree_sub_id: u64,
    pub level: u8,
    pub index: u64,
    pub checkpoint_id: u64,
}

#[derive(Debug, Clone)]
pub struct ImtLeafKey {
    pub tree_id: i64,
    pub tree_sub_id: i64,
    pub leaf_index: i64,
    pub checkpoint_id: i64,
}

#[derive(Debug, Clone)]
pub struct ImtKeyIndexKey {
    pub tree_id: i64,
    pub tree_sub_id: i64,
    pub key_bucket: i16,
    pub encoded_key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UserTransformParams {
    pub coordinator_global_user_tree_height: u8,
    pub realm_global_user_tree_height: u8,
    pub group_realm_height: u8,
}

pub fn transform_user_id(reg_id: u64, params: &UserTransformParams) -> anyhow::Result<u64> {
    if params.group_realm_height > params.coordinator_global_user_tree_height
        || params.coordinator_global_user_tree_height.saturating_add(params.realm_global_user_tree_height) > 64
        || params.group_realm_height >= 64
        || params.realm_global_user_tree_height >= 64
        || params.coordinator_global_user_tree_height - params.group_realm_height >= 64
    {
        anyhow::bail!(
            "invalid user-id tree heights: coordinator={}, realm={}, group={}",
            params.coordinator_global_user_tree_height,
            params.realm_global_user_tree_height,
            params.group_realm_height
        );
    }
    Ok(get_user_id_from_user_registration_id(
        reg_id,
        params.coordinator_global_user_tree_height,
        params.realm_global_user_tree_height,
        params.group_realm_height,
    ))
}

pub fn filter_temp_fields(
    fields: &[Vec<u8>],
    realm_id: u32,
    realm_sub_id: u16,
    pending_id: u64,
) -> Vec<Vec<u8>> {
    psy_node_core::store::traits::temp_db::filter_temp_kv_fields_by_pending(
        fields,
        realm_id,
        realm_sub_id,
        pending_id,
    )
}

fn parse_zero_id_merkle_nodes(ffs: &[u8], checkpoint_id: u64) -> anyhow::Result<Vec<MerkleNodeKey>> {
    if ffs.len() % FFS_SIMPLE_MERKLE_NODE != 0 {
        anyhow::bail!("zero-id Merkle FFS length {} is not a multiple of {}", ffs.len(), FFS_SIMPLE_MERKLE_NODE);
    }
    ffs.chunks_exact(FFS_SIMPLE_MERKLE_NODE)
        .map(|row| Ok(MerkleNodeKey {
            level: row[0],
            index: u64::from_le_bytes(row[1..9].try_into()?),
            checkpoint_id,
        }))
        .collect()
}

fn parse_single_id_merkle_nodes(ffs: &[u8], checkpoint_id: u64) -> anyhow::Result<Vec<SingleTreeMerkleKey>> {
    if ffs.len() % FFS_SINGLE_ID_NODE != 0 {
        anyhow::bail!("single-id Merkle FFS length {} is not a multiple of {}", ffs.len(), FFS_SINGLE_ID_NODE);
    }
    ffs.chunks_exact(FFS_SINGLE_ID_NODE)
        .map(|row| Ok(SingleTreeMerkleKey {
            tree_id: u64::from_le_bytes(row[0..8].try_into()?),
            level: row[8],
            index: u64::from_le_bytes(row[9..17].try_into()?),
            checkpoint_id,
        }))
        .collect()
}

fn parse_double_id_merkle_nodes(ffs: &[u8], checkpoint_id: u64) -> anyhow::Result<Vec<DoubleTreeMerkleKey>> {
    if ffs.len() % FFS_DOUBLE_ID_NODE != 0 {
        anyhow::bail!("double-id Merkle FFS length {} is not a multiple of {}", ffs.len(), FFS_DOUBLE_ID_NODE);
    }
    ffs.chunks_exact(FFS_DOUBLE_ID_NODE)
        .map(|row| Ok(DoubleTreeMerkleKey {
            tree_id: u64::from_le_bytes(row[0..8].try_into()?),
            tree_sub_id: u64::from_le_bytes(row[8..16].try_into()?),
            level: row[16],
            index: u64::from_le_bytes(row[17..25].try_into()?),
            checkpoint_id,
        }))
        .collect()
}

// user_id sits at offset 96 in each PQEDUserLeaf FFS record.
fn parse_user_leaf_ids(ffs: &[u8]) -> anyhow::Result<Vec<u64>> {
    if ffs.len() % FFS_USER_LEAF != 0 {
        anyhow::bail!("user-leaf FFS length {} is not a multiple of {}", ffs.len(), FFS_USER_LEAF);
    }
    ffs.chunks_exact(FFS_USER_LEAF)
        .map(|row| Ok(u64::from_le_bytes(row[96..104].try_into()?)))
        .collect()
}

pub fn user_leaf_and_pubkey_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<(Vec<(u64, u64)>, Vec<(u64, u64)>)> {
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations
        .iter()
        .filter_map(|entry| entry.checkpoint_id.map(|cp| (entry.pending_id, cp)))
        .collect();
    match role {
        RollbackRole::Realm => {
            let mut leaf_keys = Vec::new();
            for (pending_id, backup) in &backups.realm_end_cap {
                let Some(&checkpoint_id) = pid_to_cp.get(pending_id) else { continue };
                leaf_keys.extend(parse_user_leaf_ids(&backup.update_user_leaves_ffs)?.into_iter().map(|user_id| (user_id, checkpoint_id)));
            }
            Ok((leaf_keys, Vec::new()))
        }
        RollbackRole::Coordinator => {
            let mut public_key_keys = Vec::new();
            for (pending_id, backup) in &backups.register_user {
                let Some(&checkpoint_id) = pid_to_cp.get(pending_id) else { continue };
                if backup.new_user_public_keys_ffs.len() % 72 != 0 {
                    anyhow::bail!("register-user public-key FFS for pending {} has invalid length {}", pending_id, backup.new_user_public_keys_ffs.len());
                }
                for row in backup.new_user_public_keys_ffs.chunks_exact(72) {
                    public_key_keys.push((u64::from_le_bytes(row[0..8].try_into()?), checkpoint_id));
                }
            }
            Ok((Vec::new(), public_key_keys))
        }
    }
}

pub fn contract_metadata_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<Vec<(u64, u64)>> {
    if role != RollbackRole::Coordinator {
        return Ok(Vec::new());
    }
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations
        .iter()
        .filter_map(|e| e.checkpoint_id.map(|cp| (e.pending_id, cp)))
        .collect();

    let mut keys = Vec::new();
    for (pending_id, deploy) in &backups.deploy_contract {
        if let Some(&cp) = pid_to_cp.get(pending_id) {
            for &cid in &deploy.new_contract_ids {
                keys.push((cid, cp));
            }
        }
    }
    for (pending_id, update) in &backups.update_contract {
        if let Some(&cp) = pid_to_cp.get(pending_id) {
            for &cid in &update.updated_contract_ids {
                keys.push((cid, cp));
            }
        }
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

pub fn public_key_hash_user_pairs(
    backups: &BackupKeySource,
    role: RollbackRole,
    params: &UserTransformParams,
) -> anyhow::Result<Vec<([u8; 32], u64)>> {
    if role != RollbackRole::Coordinator {
        return Ok(Vec::new());
    }
    let mut pairs = Vec::new();
    for (pending_id, backup) in &backups.register_user {
        let rows = &backup.new_public_key_hash_to_user_id_rows_ffs;
        if rows.len() % 40 != 0 || rows.len() / 40 != backup.user_count()? {
            anyhow::bail!("register-user hash mapping/public-key count mismatch for pending {}", pending_id);
        }
        for (offset, row) in rows.chunks_exact(40).enumerate() {
            let registration_id = backup.start_next_user_id.checked_add(offset as u64)
                .ok_or_else(|| anyhow::anyhow!("registration id overflow for pending {}", pending_id))?;
            let user_id = u64::from_le_bytes(row[32..40].try_into()?);
            let expected_user_id = transform_user_id(registration_id, params)?;
            if user_id != expected_user_id {
                anyhow::bail!("register-user transformed user id mismatch for pending {} registration {}: row={}, expected={}", pending_id, registration_id, user_id, expected_user_id);
            }
            pairs.push((row[0..32].try_into()?, user_id));
        }
    }
    Ok(pairs)
}

pub fn imt_key_index_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
) -> anyhow::Result<Vec<ImtKeyIndexKey>> {
    if role != RollbackRole::Realm {
        return Ok(Vec::new());
    }
    Ok(backups.realm_end_cap.values().flat_map(|backup| backup.imt_key_index_keys.clone()).collect())
}

pub fn global_user_tree_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<Vec<MerkleNodeKey>> {
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations
        .iter()
        .filter_map(|e| e.checkpoint_id.map(|cp| (e.pending_id, cp)))
        .collect();
    let mut out = Vec::new();
    match role {
        RollbackRole::Coordinator => {
            for (pending_id, backup) in &backups.coordinator_guta {
                if let Some(&checkpoint_id) = pid_to_cp.get(pending_id) {
                    out.extend(parse_zero_id_merkle_nodes(&backup.update_global_user_tree_nodes_ffs, checkpoint_id)?);
                }
            }
        }
        RollbackRole::Realm => {
            for (pending_id, backup) in &backups.realm_end_cap {
                if let Some(&checkpoint_id) = pid_to_cp.get(pending_id) {
                    out.extend(parse_zero_id_merkle_nodes(&backup.update_global_user_tree_nodes_ffs, checkpoint_id)?);
                }
            }
        }
    }
    Ok(out)
}

pub fn global_checkpoint_tree_keys(
    backups: &BackupKeySource,
    _role: RollbackRole,
    checkpoint_ids: &[u64],
) -> anyhow::Result<Vec<MerkleNodeKey>> {
    let mut out = Vec::new();
    for checkpoint_id in checkpoint_ids {
        let nodes = backups.global_checkpoint_tree_delete_path_keys.get(checkpoint_id).ok_or_else(|| {
            anyhow::anyhow!("missing global checkpoint-tree delete path keys for checkpoint {}", checkpoint_id)
        })?;
        if nodes.is_empty() {
            anyhow::bail!("global checkpoint-tree delete path keys are empty for checkpoint {}", checkpoint_id);
        }
        if nodes.iter().any(|node| node.checkpoint_id != *checkpoint_id) {
            anyhow::bail!("global checkpoint-tree delete path keys contain mismatched checkpoint for {}", checkpoint_id);
        }
        out.extend(nodes.iter().cloned());
    }
    Ok(out)
}

pub fn user_registration_tree_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<Vec<MerkleNodeKey>> {
    if role != RollbackRole::Coordinator {
        return Ok(Vec::new());
    }
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations.iter().filter_map(|e| e.checkpoint_id.map(|cp| (e.pending_id, cp))).collect();
    let mut out = Vec::new();
    for (pending_id, backup) in &backups.register_user {
        let Some(&checkpoint_id) = pid_to_cp.get(pending_id) else { continue };
        if backup.user_count()? > 0 && backup.update_user_registration_tree_nodes_ffs.is_empty() {
            anyhow::bail!("register-user pending {} has users but no registration-tree node FFS", pending_id);
        }
        out.extend(parse_zero_id_merkle_nodes(&backup.update_user_registration_tree_nodes_ffs, checkpoint_id)?);
    }
    Ok(out)
}

pub fn global_contract_tree_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<Vec<MerkleNodeKey>> {
    if role != RollbackRole::Coordinator {
        return Ok(Vec::new());
    }
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations
        .iter()
        .filter_map(|e| e.checkpoint_id.map(|cp| (e.pending_id, cp)))
        .collect();
    let pending_ids: std::collections::HashSet<u64> = backups.deploy_contract.keys().chain(backups.update_contract.keys()).copied().collect();
    let mut out = Vec::new();
    for pending_id in pending_ids {
        let Some(&checkpoint_id) = pid_to_cp.get(&pending_id) else { continue };
        if let Some(deploy) = backups.deploy_contract.get(&pending_id) {
            out.extend(parse_zero_id_merkle_nodes(&deploy.update_global_contract_tree_nodes_ffs, checkpoint_id)?);
        }
        if let Some(update) = backups.update_contract.get(&pending_id) {
            out.extend(parse_zero_id_merkle_nodes(&update.update_global_contract_tree_nodes_ffs, checkpoint_id)?);
        }
    }
    out.sort_by_key(|node| (node.checkpoint_id, node.level, node.index));
    out.dedup_by_key(|node| (node.checkpoint_id, node.level, node.index));
    Ok(out)
}

pub fn user_contract_tree_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<Vec<SingleTreeMerkleKey>> {
    if role != RollbackRole::Realm {
        return Ok(Vec::new());
    }
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations
        .iter()
        .filter_map(|e| e.checkpoint_id.map(|cp| (e.pending_id, cp)))
        .collect();
    let mut out = Vec::new();
    for (pending_id, backup) in &backups.realm_end_cap {
        if let Some(&checkpoint_id) = pid_to_cp.get(pending_id) {
            out.extend(parse_single_id_merkle_nodes(&backup.update_user_contract_tree_nodes_ffs, checkpoint_id)?);
        }
    }
    Ok(out)
}

pub fn contract_function_tree_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<Vec<SingleTreeMerkleKey>> {
    if role != RollbackRole::Coordinator {
        return Ok(Vec::new());
    }
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations
        .iter()
        .filter_map(|e| e.checkpoint_id.map(|cp| (e.pending_id, cp)))
        .collect();
    let pending_ids: std::collections::HashSet<u64> = backups.deploy_contract.keys().chain(backups.update_contract.keys()).copied().collect();
    let mut out = Vec::new();
    for pending_id in pending_ids {
        let Some(&checkpoint_id) = pid_to_cp.get(&pending_id) else { continue };
        if let Some(deploy) = backups.deploy_contract.get(&pending_id) {
            out.extend(parse_single_id_merkle_nodes(&deploy.update_contract_function_tree_nodes_ffs, checkpoint_id)?);
        }
        if let Some(update) = backups.update_contract.get(&pending_id) {
            out.extend(parse_single_id_merkle_nodes(&update.update_contract_function_tree_nodes_ffs, checkpoint_id)?);
        }
    }
    Ok(out)
}

pub fn contract_state_tree_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<Vec<DoubleTreeMerkleKey>> {
    if role != RollbackRole::Realm {
        return Ok(Vec::new());
    }
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations
        .iter()
        .filter_map(|e| e.checkpoint_id.map(|cp| (e.pending_id, cp)))
        .collect();
    let mut out = Vec::new();
    for (pending_id, backup) in &backups.realm_end_cap {
        if let Some(&checkpoint_id) = pid_to_cp.get(pending_id) {
            out.extend(parse_double_id_merkle_nodes(&backup.update_contract_state_tree_nodes_ffs, checkpoint_id)?);
        }
    }
    Ok(out)
}

pub fn imt_leaf_keys(
    backups: &BackupKeySource,
    role: RollbackRole,
    post_target_generations: &[PostTargetGeneration],
) -> anyhow::Result<Vec<ImtLeafKey>> {
    if role != RollbackRole::Realm {
        return Ok(Vec::new());
    }
    let pid_to_cp: std::collections::HashMap<u64, u64> = post_target_generations
        .iter()
        .filter_map(|e| e.checkpoint_id.map(|cp| (e.pending_id, cp)))
        .collect();
    let mut out = Vec::new();
    for (pid, b) in &backups.realm_end_cap {
        let Some(&cp) = pid_to_cp.get(pid) else { continue };
        let ffs = &b.update_contract_state_imt_leaves_ffs;
        if ffs.len() % IMT_LEAF_FFS_V2 != 0 {
            anyhow::bail!("IMT leaf FFS length {} not a multiple of {}", ffs.len(), IMT_LEAF_FFS_V2);
        }
        for entry in ffs.chunks_exact(IMT_LEAF_FFS_V2) {
            let tree_id = u64::from_le_bytes(entry[0..8].try_into()?) as i64;
            let tree_sub_id = u64::from_le_bytes(entry[8..16].try_into()?) as i64;
            let leaf_index = u64::from_le_bytes(entry[16..24].try_into()?) as i64;
            out.push(ImtLeafKey { tree_id, tree_sub_id, leaf_index, checkpoint_id: cp as i64 });
        }
    }
    Ok(out)
}

pub fn processor_state_singleton_fields(realm_id: u64, realm_sub_id: u64) -> anyhow::Result<Vec<Vec<u8>>> {
    let realm_le = u32::try_from(realm_id)?.to_le_bytes();
    let sub_le = u16::try_from(realm_sub_id)?.to_le_bytes();
    Ok([[0x50, 0x49], [0x47, 0x50], [0x50, 0x53]].iter().map(|table_id| {
        let mut field = Vec::with_capacity(8);
        field.extend_from_slice(&realm_le);
        field.extend_from_slice(&sub_le);
        field.extend_from_slice(table_id);
        field
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollback::collect_post_target_generations;
    use crate::rollback::generator::{BackupKeySource, CoordinatorGutaBackup, RealmEndCapBackup, RegisterUserBackup, RollbackStateReader};

    #[test]
    fn temp_filter_keeps_pending_namespace_and_rejects_wr() {
        let field = |table: &[u8; 2]| { let mut bytes = vec![0u8; 24]; bytes[0..4].copy_from_slice(&3u32.to_le_bytes()); bytes[4..6].copy_from_slice(&0u16.to_le_bytes()); bytes[6..8].copy_from_slice(table); bytes[8..16].copy_from_slice(&88u64.to_le_bytes()); bytes };
        let ep = field(b"EP");
        assert_eq!(filter_temp_fields(&[ep.clone(), field(b"WR")], 3, 0, 88), vec![ep]);
    }
    fn realm_backup(user_leaves: Vec<u8>) -> RealmEndCapBackup {
        RealmEndCapBackup { update_user_leaves_ffs: user_leaves, update_user_contract_tree_nodes_ffs: vec![], update_contract_state_tree_nodes_ffs: vec![], update_global_user_tree_nodes_ffs: vec![], update_contract_state_imt_leaves_ffs: vec![], imt_key_index_keys: vec![] }
    }
    #[test]
    fn user_hash_pair_validates_authoritative_transform() {
        let params = UserTransformParams { coordinator_global_user_tree_height: 12, realm_global_user_tree_height: 20, group_realm_height: 1 };
        let expected_user_id = transform_user_id(77, &params).unwrap();
        let mut mapping = vec![9u8; 32]; mapping.extend_from_slice(&expected_user_id.to_le_bytes());
        let mut backups = BackupKeySource::default();
        backups.register_user.insert(88, RegisterUserBackup { start_next_user_id: 77, new_user_public_keys_ffs: vec![0u8; 72], new_public_key_hash_to_user_id_rows_ffs: mapping, update_user_registration_tree_nodes_ffs: vec![] });
        assert_eq!(public_key_hash_user_pairs(&backups, RollbackRole::Coordinator, &params).unwrap(), vec![([9u8; 32], expected_user_id)]);
    }

    #[test]
    fn user_table_keys_follow_writer_ownership() {
        let mut public_key_ffs = 77u64.to_le_bytes().to_vec(); public_key_ffs.extend_from_slice(&[3u8; 64]);
        let mut backups = BackupKeySource::default();
        backups.register_user.insert(88, RegisterUserBackup { start_next_user_id: 77, new_user_public_keys_ffs: public_key_ffs, new_public_key_hash_to_user_id_rows_ffs: vec![], update_user_registration_tree_nodes_ffs: vec![] });
        let post_target_generations = vec![PostTargetGeneration { checkpoint_id: Some(200), pending_id: 88, proc_checkpoint_unique_id: 10088 }];
        let (leaves, public_keys) = user_leaf_and_pubkey_keys(&backups, RollbackRole::Coordinator, &post_target_generations).unwrap(); assert!(leaves.is_empty()); assert_eq!(public_keys, vec![(77, 200)]);
        let mut leaf_ffs = vec![0u8; FFS_USER_LEAF]; leaf_ffs[96..104].copy_from_slice(&77u64.to_le_bytes()); backups.realm_end_cap.insert(88, realm_backup(leaf_ffs));
        let (leaves, public_keys) = user_leaf_and_pubkey_keys(&backups, RollbackRole::Realm, &post_target_generations).unwrap(); assert_eq!(leaves, vec![(77, 200)]); assert!(public_keys.is_empty());
    }

    #[test]
    fn empty_imt_ffs_proves_no_updates() {
        let mut no_updates = BackupKeySource::default(); no_updates.realm_end_cap.insert(88, realm_backup(vec![]));
        assert!(imt_leaf_keys(&no_updates, RollbackRole::Realm, &[PostTargetGeneration { checkpoint_id: Some(200), pending_id: 88, proc_checkpoint_unique_id: 10088 }]).unwrap().is_empty());
        let mut uncommitted = BackupKeySource::default(); uncommitted.realm_end_cap.insert(88, realm_backup(vec![]));
        assert!(imt_leaf_keys(&uncommitted, RollbackRole::Realm, &[PostTargetGeneration { checkpoint_id: None, pending_id: 88, proc_checkpoint_unique_id: 10088 }]).unwrap().is_empty());
    }

    #[test]
    fn both_roles_require_checkpoint_delete_path_keys() {
        let mut backups = BackupKeySource::default(); assert!(global_checkpoint_tree_keys(&backups, RollbackRole::Coordinator, &[200]).is_err()); assert!(global_checkpoint_tree_keys(&backups, RollbackRole::Realm, &[200]).is_err());
        backups.global_checkpoint_tree_delete_path_keys.insert(200, vec![MerkleNodeKey { level: 1, index: 2, checkpoint_id: 200 }]); assert_eq!(global_checkpoint_tree_keys(&backups, RollbackRole::Realm, &[200]).unwrap().len(), 1);
    }

    #[test]
    fn unmapped_pending_never_emits_checkpoint_zero_tree_key() {
        let mut ffs = vec![3u8]; ffs.extend_from_slice(&9u64.to_le_bytes()); ffs.extend_from_slice(&[1u8; 32]);
        let mut backups = BackupKeySource::default(); backups.coordinator_guta.insert(94, CoordinatorGutaBackup { update_global_user_tree_nodes_ffs: ffs });
        assert!(global_user_tree_keys(&backups, RollbackRole::Coordinator, &[PostTargetGeneration { checkpoint_id: None, pending_id: 94, proc_checkpoint_unique_id: 10094 }]).unwrap().is_empty());
    }

    struct MockRollbackStateReader { cp_to_pending: std::collections::HashMap<u64, u64>, pending_to_cp: std::collections::HashMap<u64, u64>, pending_to_proc: std::collections::HashMap<u64, u128> }
    #[async_trait::async_trait]
    impl RollbackStateReader for MockRollbackStateReader {
        async fn pending_id_for_checkpoint(&self, id: u64) -> anyhow::Result<Option<u64>> { Ok(self.cp_to_pending.get(&id).copied()) }
        async fn checkpoint_id_for_pending(&self, id: u64) -> anyhow::Result<Option<u64>> { Ok(self.pending_to_cp.get(&id).copied()) }
        async fn proc_id_for_pending(&self, id: u64) -> anyhow::Result<Option<u128>> { Ok(self.pending_to_proc.get(&id).copied()) }
        async fn root_for_checkpoint(&self, _id: u64) -> anyhow::Result<Option<[u8; 32]>> { Ok(None) }
        async fn imt_leaf_at_target(&self, _tree_id: i64, _tree_sub_id: i64, _leaf_index: i64, _target_checkpoint_id: i64) -> anyhow::Result<bool> { Ok(false) }
        async fn imt_next_append_index(&self, _tree_id: i64, _tree_sub_id: i64) -> anyhow::Result<Option<i64>> { Ok(None) }
        async fn global_checkpoint_tree_delete_path_keys(&self, _checkpoint_id: u64) -> anyhow::Result<Vec<MerkleNodeKey>> { Ok(Vec::new()) }
    }
    #[tokio::test]
    async fn post_target_generations_walk_to_counter_high_water() {
        let reader = MockRollbackStateReader { cp_to_pending: [(197, 87)].into_iter().collect(), pending_to_cp: [(88, 200)].into_iter().collect(), pending_to_proc: [(88, 10088u128), (94, 10094)].into_iter().collect() };
        let branch = collect_post_target_generations(&reader, 199, 104).await.unwrap(); assert_eq!(branch.iter().map(|entry| (entry.pending_id, entry.checkpoint_id)).collect::<Vec<_>>(), vec![(88, Some(200)), (94, None)]);
    }

    #[tokio::test]
    async fn post_target_generations_at_genesis_target_freeze_all_post_genesis_pendings() {
        let reader = MockRollbackStateReader {
            cp_to_pending: std::collections::HashMap::new(),
            pending_to_cp: [(1, 1), (3, 3)].into_iter().collect(),
            pending_to_proc: [(1, 1001u128), (2, 1002), (3, 1003), (4, 1004)].into_iter().collect(),
        };
        let branch = collect_post_target_generations(&reader, 0, 4).await.unwrap();
        assert_eq!(
            branch.iter().map(|entry| (entry.pending_id, entry.checkpoint_id, entry.proc_checkpoint_unique_id)).collect::<Vec<_>>(),
            vec![(1, Some(1), 1001), (2, None, 1002), (3, Some(3), 1003), (4, None, 1004)]
        );
    }

    #[test]
    fn ffs_parsers_reject_trailing_bytes() {
        assert!(parse_zero_id_merkle_nodes(&vec![0u8; FFS_SIMPLE_MERKLE_NODE + 1], 1).is_err());
        assert!(parse_single_id_merkle_nodes(&vec![0u8; FFS_SINGLE_ID_NODE + 1], 1).is_err());
        assert!(parse_double_id_merkle_nodes(&vec![0u8; FFS_DOUBLE_ID_NODE + 1], 1).is_err());
        assert!(parse_user_leaf_ids(&vec![0u8; FFS_USER_LEAF + 1]).is_err());
    }
}