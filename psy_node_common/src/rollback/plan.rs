//! Rollback plan data model and atomic JSON persistence.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RollbackRole {
    Coordinator,
    Realm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackNatsConsumerKind {
    CoordinatorRegisterUser,
    CoordinatorDeployContract,
    CoordinatorUpdateContract,
    CoordinatorGuta,
    CoordinatorProving,
    RealmUserUpdate,
    RealmProving,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollbackNatsConsumerTarget {
    pub kind: RollbackNatsConsumerKind,
    pub proc_id: u128,
    pub task_group: u32,
    // The frozen current writer catalog uses task_group 0 only; validation rejects every nonzero group.
}

const COORDINATOR_NATS_CONSUMER_KINDS: &[RollbackNatsConsumerKind] = &[
    RollbackNatsConsumerKind::CoordinatorRegisterUser,
    RollbackNatsConsumerKind::CoordinatorDeployContract,
    RollbackNatsConsumerKind::CoordinatorUpdateContract,
    RollbackNatsConsumerKind::CoordinatorGuta,
    RollbackNatsConsumerKind::CoordinatorProving,
];

const REALM_NATS_CONSUMER_KINDS: &[RollbackNatsConsumerKind] = &[
    RollbackNatsConsumerKind::RealmUserUpdate,
    RollbackNatsConsumerKind::RealmProving,
];

pub fn rollback_nats_consumer_kinds(role: RollbackRole) -> &'static [RollbackNatsConsumerKind] {
    match role {
        RollbackRole::Coordinator => COORDINATOR_NATS_CONSUMER_KINDS,
        RollbackRole::Realm => REALM_NATS_CONSUMER_KINDS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RollbackPhaseStatus {
    Pending,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackIds {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<u64>,
    pub pending_id: u64,
    pub proc_id: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetContractState {
    pub last_finalized_checkpoint_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_checkpoint_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_deposit_tree_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_withdrawal_tree_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_subtree_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proved_deposit_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_deposit_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackSnapshot {
    pub target_info: String,
    pub worker_reputation_fields: Vec<RollbackTempValueSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackTempValueSnapshot {
    pub field: String,
    pub value: Option<String>,
}


// Empty keys is a proved no-op; the phase is still required and the executor still calls the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPhase {
    pub table: String,
    pub api: String,
    pub keys: serde_json::Value,
    pub status: RollbackPhaseStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPlan {
    pub role: RollbackRole,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub target_checkpoint_id: u64,
    pub latest_checkpoint_id: u64,
    pub latest_pending_id: u64,
    pub ids: Vec<RollbackIds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_contract_state: Option<TargetContractState>,
    pub snapshot: RollbackSnapshot,
    pub phases: Vec<RollbackPhase>,
}

impl RollbackPlan {
    pub fn checkpoint_ids(&self) -> Vec<u64> {
        if self.target_checkpoint_id >= self.latest_checkpoint_id {
            return Vec::new();
        }
        (self.target_checkpoint_id + 1..=self.latest_checkpoint_id).collect()
    }

    pub fn mapped_checkpoint_ids(&self) -> Vec<u64> {
        self.ids.iter().filter_map(|entry| entry.checkpoint_id).collect()
    }

    pub fn pending_ids(&self) -> Vec<u64> {
        self.ids.iter().map(|e| e.pending_id).collect()
    }

    pub fn proc_ids(&self) -> Vec<u128> {
        self.ids
            .iter()
            .map(|e| e.proc_id)
            .collect()
    }
}

pub async fn read_rollback_plan(path: impl AsRef<Path>) -> anyhow::Result<RollbackPlan> {
    let bytes = tokio::fs::read(path.as_ref())
        .await
        .with_context(|| format!("failed to read rollback plan at {}", path.as_ref().display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse rollback plan at {}", path.as_ref().display()))
}

pub async fn write_rollback_plan_atomic(
    path: impl AsRef<Path>,
    plan: &RollbackPlan,
    fsync_parent: bool,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rollback plan path has no parent: {}", path.display()))?;
    let json = serde_json::to_vec_pretty(plan).context("failed to serialize rollback plan")?;

    let tmp_path: PathBuf = path.with_extension("tmp.rollback");
    if tmp_path.exists() {
        // Stale temp from a crashed prior write; remove so create succeeds.
        let _ = tokio::fs::remove_file(&tmp_path).await;
    }

    let mut file = tokio::fs::File::create(&tmp_path)
        .await
        .with_context(|| format!("failed to create temp rollback plan at {}", tmp_path.display()))?;
    file.write_all(&json)
        .await
        .with_context(|| format!("failed to write temp rollback plan at {}", tmp_path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("failed to fsync temp rollback plan at {}", tmp_path.display()))?;
    // Drop the file handle before rename (Windows requires it; harmless on POSIX).
    drop(file);

    tokio::fs::rename(&tmp_path, path)
        .await
        .with_context(|| format!("failed to rename temp rollback plan into place at {}", path.display()))?;

    if fsync_parent {
        let dir = tokio::fs::File::open(parent).await?;
        dir.sync_all().await.ok();
        drop(dir);
    }
    Ok(())
}

fn mark_phase_completed(plan: &mut RollbackPlan, index: usize) -> anyhow::Result<()> {
    let phase_count = plan.phases.len();
    let phase = plan
        .phases
        .get_mut(index)
        .ok_or_else(|| anyhow::anyhow!("phase index {} out of bounds ({} phases)", index, phase_count))?;
    phase.status = RollbackPhaseStatus::Completed;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> RollbackPlan {
        RollbackPlan {
            role: RollbackRole::Realm,
            realm_id: 3,
            realm_sub_id: 0,
            target_checkpoint_id: 199,
            latest_checkpoint_id: 210,
            latest_pending_id: 104,
            ids: vec![
                RollbackIds { checkpoint_id: Some(200), pending_id: 88, proc_id: 10088 },
                RollbackIds { checkpoint_id: Some(201), pending_id: 89, proc_id: 10089 },
                RollbackIds { checkpoint_id: None, pending_id: 94, proc_id: 10094 },
            ],
            snapshot: RollbackSnapshot {
                target_info: "010203".into(),
                worker_reputation_fields: vec![RollbackTempValueSnapshot {
                    field: "5752".into(),
                    value: Some("0908".into()),
                }],
            },
            target_contract_state: None,
            phases: vec![
                RollbackPhase {
                    table: "checkpoint_leaf_table".into(),
                    api: "db_delete_many_object_ids".into(),
                    keys: serde_json::json!([200, 201]),
                    status: RollbackPhaseStatus::Pending,
                },
                RollbackPhase {
                    table: "u64_singleton_table".into(),
                    api: "set_latest_checkpoint_id".into(),
                    keys: serde_json::json!([]),
                    status: RollbackPhaseStatus::Pending,
                },
            ],
        }
    }

    #[test]
    fn plan_roundtrips_json() {
        let plan = sample_plan();
        let json = serde_json::to_string_pretty(&plan).unwrap();
        let back: RollbackPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }

    #[test]
    fn optional_contract_state_and_new_snapshot_names_serialize_cleanly() {
        let mut plan = sample_plan();
        let json = serde_json::to_value(&plan).unwrap();
        assert!(json.get("target_contract_state").is_none());
        assert_eq!(json["snapshot"]["target_info"], "010203");
        assert!(json.get("verification").is_none());
        assert!(json["snapshot"].get("latest_info_bytes").is_none());
        assert!(json.get("l1_mode").is_none());
        assert!(json.get("l1_contracts").is_none());

        plan.target_contract_state = Some(TargetContractState {
            last_finalized_checkpoint_id: plan.target_checkpoint_id,
            last_verified_checkpoint_root: Some("abcd".into()),
            last_verified_deposit_tree_root: None,
            last_verified_withdrawal_tree_root: None,
            withdrawal_subtree_root: None,
            deposit_root: None,
            proved_deposit_count: None,
            pending_deposit_count: None,
        });
        let back: RollbackPlan = serde_json::from_value(serde_json::to_value(&plan).unwrap()).unwrap();
        assert_eq!(back, plan);
    }

    #[test]
    fn target_contract_state_requires_checkpoint_id() {
        let error = serde_json::from_value::<TargetContractState>(serde_json::json!({
            "last_verified_checkpoint_root": "abcd"
        }))
        .unwrap_err();
        assert!(error.to_string().contains("last_finalized_checkpoint_id"), "{error}");
    }

    #[test]
    fn plan_rejects_removed_and_misspelled_fields() {
        let mut json = serde_json::to_value(sample_plan()).unwrap();
        json.as_object_mut().unwrap().insert("l1_mode".into(), serde_json::json!("validated"));
        assert!(serde_json::from_value::<RollbackPlan>(json).is_err());

        let mut json = serde_json::to_value(sample_plan()).unwrap();
        json["snapshot"].as_object_mut().unwrap().insert("target_inf".into(), serde_json::json!("010203"));
        assert!(serde_json::from_value::<RollbackPlan>(json).is_err());
    }

    #[test]
    fn ids_helpers() {
        let plan = sample_plan();
        assert_eq!(plan.checkpoint_ids(), (200..=210).collect::<Vec<_>>());
        assert_eq!(plan.mapped_checkpoint_ids(), vec![200, 201]);
        assert_eq!(plan.pending_ids(), vec![88, 89, 94]);
        assert_eq!(plan.proc_ids(), vec![10088u128, 10089, 10094]);
    }

    #[test]
    fn json_surface_is_exact_and_old_keys_are_rejected() {
        let plan_json = serde_json::to_value(sample_plan()).unwrap();
        assert_eq!(plan_json["ids"][0], serde_json::json!({ "checkpoint_id": 200, "pending_id": 88, "proc_id": 10088 }));
        let mut old_plan = plan_json.as_object().unwrap().clone();
        old_plan.insert("post_target_generations".into(), serde_json::json!([]));
        assert!(serde_json::from_value::<RollbackPlan>(serde_json::Value::Object(old_plan)).is_err());
        let old_ids = serde_json::json!({ "pending_id": 88, "proc_id": 10088, "proc_checkpoint_unique_id": 10088 });
        assert!(serde_json::from_value::<RollbackIds>(old_ids).is_err());
    }

    #[test]
    fn absent_checkpoint_id_is_omitted() {
        let entry = RollbackIds { checkpoint_id: None, pending_id: 7, proc_id: 1007 };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"pending_id\""));
        assert!(json.contains("\"proc_id\""));
        assert!(!json.contains("\"checkpoint_id\""));
        let back: RollbackIds = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn mark_phase_completed_in_memory() {
        let mut plan = sample_plan();
        mark_phase_completed(&mut plan, 0).unwrap();
        assert_eq!(plan.phases[0].status, RollbackPhaseStatus::Completed);
        assert_eq!(plan.phases[1].status, RollbackPhaseStatus::Pending);
    }

    #[test]
    fn mark_phase_out_of_bounds_errors() {
        let mut plan = sample_plan();
        assert!(mark_phase_completed(&mut plan, 99).is_err());
    }

    #[tokio::test]
    async fn atomic_plan_progress() {
        let dir = std::env::temp_dir().join("rollback_plan_test_atomic");
        let _ = tokio::fs::create_dir_all(&dir).await;
        let path = dir.join("rp.json");
        let mut plan = sample_plan();
        write_rollback_plan_atomic(&path, &plan, false).await.unwrap();
        let mut read_back = read_rollback_plan(&path).await.unwrap();
        assert_eq!(read_back.phases[0].status, RollbackPhaseStatus::Pending);
        mark_phase_completed(&mut read_back, 0).unwrap();
        write_rollback_plan_atomic(&path, &read_back, false).await.unwrap();
        let read_back2 = read_rollback_plan(&path).await.unwrap();
        assert_eq!(read_back2.phases[0].status, RollbackPhaseStatus::Completed);
        assert_eq!(read_back2.phases[1].status, RollbackPhaseStatus::Pending);
        let tmp = path.with_extension("tmp.rollback");
        assert!(!tmp.exists(), "temp file should have been renamed away");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let _ = &mut plan;
    }
}