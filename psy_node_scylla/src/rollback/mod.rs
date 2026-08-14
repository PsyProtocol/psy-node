//! Typed Scylla identities, primary keys, mutations, and rollback metadata.
//!
//! D-02a remains the registry baseline. G0-06 provides representative fence
//! adapters, D-02T1 adds the closed checkpoint-keyed KIV family, and D-02T2
//! adds the closed checkpoint-clustering Merkle family. D-02T3 adds the five
//! rollback-ready checkpoint-clustering object-single tables. D-02T4 adds the
//! active checkpoint-root bidirectional mapping. D-02T5 adds the key-only
//! public-key projection and its non-key birth metadata. D-02T6 coordinates
//! IMT leaf/index/cursor plans. D-02T7 adds target-restored mutable singleton
//! plans. D-02T8 adds monotonic pending-context mapping rotation. D-02T9 adds
//! counter LWT allocation with pending-to-proc ownership arbitration. D-02T10
//! adds current-pending writes for the operational reward tag-tree namespace.
//! None is connected to production setup or current writers yet.

mod canonical_head_prototype;
mod branch_exact_schema_migration;
mod branch_exact_schema_deployment;
mod branch_exact_schema_deployment_lifecycle;
mod branch_exact_schema_backfill;
mod branch_exact_schema_backfill_executor;
mod branch_exact_schema_operator;
mod branch_exact_schema_exporter;
mod branch_exact_dual_write_executor;
#[allow(dead_code)]
mod branch_exact_cutover_lifecycle;
#[allow(dead_code)]
mod branch_exact_cutover_store;
#[allow(dead_code)]
mod branch_exact_cutover_runtime;
mod branch_exact_schema_setup;
mod branch_exact_shadow_reader;
mod branch_exact_shadow_audit;
mod branch_exact_writer_lifecycle;
mod branch_exact_writer_lifecycle_store;
mod branch_exact_writer_runtime;
#[allow(dead_code)]
pub(crate) mod branch_exact_startup_preflight;
mod branch_exact_pending_runtime;
#[allow(dead_code)]
mod branch_exact_pending_orchestration;
mod pending_generation_pipeline_store;
mod pending_queue_artifact_store;
mod pending_queue_segment_ledger;
mod pending_queue_stream_provision;
#[cfg(test)]
#[path = "../../tests/rf3/d04b6h23c4c2b4d2_stream_provision.rs"]
mod pending_queue_stream_provision_rf3;
mod pending_queue_publish_store;
#[allow(dead_code)]
mod pending_queue_semantic_terminal;
#[allow(dead_code)]
mod pending_queue_semantic_aggregate;
mod pending_queue_generation_terminal;
mod pending_queue_sidecar_schema;
mod realm_edge_durable_publisher;
mod realm_user_update_claim_store;
mod realm_generation_scope;
mod realm_user_update_admission_store;
mod realm_user_update_dependency_store;
#[allow(dead_code)]
mod realm_user_update_durable_consumer;
#[allow(dead_code)]
mod realm_processor_external_dependency_projection;
#[allow(dead_code)]
mod realm_processor_external_dependency_loader;
#[allow(dead_code)]
mod realm_processor_terminal_authorization;
mod realm_user_update_router;
mod realm_user_update_ingress;
mod pending_queue_sidecar_lifecycle;
#[cfg(test)]
#[path = "../../tests/rf3/d04b6h23c4c1_queue_schema.rs"]
mod pending_queue_sidecar_schema_rf3;
#[cfg(test)]
#[path = "../../tests/rf3/d04b6h23c4c2b3b2_claim_admission.rs"]
mod realm_user_update_admission_rf3;
#[allow(dead_code)]
mod pending_queue_segment_lifecycle;
#[allow(dead_code)]
mod pending_queue_nats_capture;
mod realm_processor_durable_capture;
#[allow(dead_code)]
mod realm_processor_application_archive;
mod realm_processor_deferred_carryover;
mod realm_processor_generation_terminal;
mod coordinator_guta_durable_submission_store;
#[allow(dead_code)]
mod coordinator_processor_durable_capture;
mod coordinator_processor_full_commit;
mod coordinator_commit_source_store;
mod coordinator_rollback_floor_singleton_anchor;
pub(crate) use coordinator_rollback_floor_singleton_anchor::*;
mod coordinator_commit_physical_inventory;
#[allow(dead_code)]
mod coordinator_commit_physical_write_plan;
#[allow(dead_code)]
mod coordinator_commit_physical_execution;
#[allow(dead_code)]
mod coordinator_commit_physical_scylla;
#[allow(dead_code)]
mod coordinator_commit_full_write;
#[allow(dead_code)]
mod coordinator_commit_full_manifest;
#[allow(dead_code)]
mod coordinator_commit_full_manifest_store;
#[allow(dead_code)]
mod coordinator_commit_full_completion;
#[allow(dead_code)]
mod coordinator_commit_full_completion_store;
mod coordinator_commit_physical_before_image;
mod coordinator_commit_target_restore;
mod coordinator_commit_physical_archive_store;
mod coordinator_rollback_maintenance;
pub(crate) use coordinator_rollback_maintenance::prepare_coordinator_rollback_archive;
mod coordinator_rollback_global_progress;
pub(crate) use coordinator_rollback_global_progress::progress_coordinator_global_rollback;
mod coordinator_commit_delete_restore_plan;
mod coordinator_commit_delete_restore_plan_store;
mod coordinator_commit_delete_restore_executor;
mod coordinator_rollback_delete_completion_store;
mod rollback_global_archive_barrier;
mod rollback_global_delete_barrier;
mod rollback_global_restore_barrier;
mod rollback_global_restore_orchestrator;
mod coordinator_rollback_runtime_publication;
pub(crate) use coordinator_rollback_runtime_publication::try_publish_restored_runtime;
mod rollback_runtime_rebuild_store;
pub(crate) use rollback_runtime_rebuild_store::ScyllaRollbackRuntimeRebuildStore;
mod realm_rollback_runtime_control;
#[cfg(test)]
mod rollback_joint_production_control_scylla;
pub use realm_rollback_runtime_control::ScyllaRealmRollbackRuntimeControl;
mod realm_rollback_target_restore_plan;
mod realm_rollback_target_restore_planner;
mod realm_rollback_target_restore_executor;
mod realm_rollback_target_restore_completion;
mod rollback_participant_plan_store;
pub(crate) use rollback_participant_plan_store::ScyllaRollbackParticipantPlanStore;
pub(crate) use coordinator_commit_source_store::ScyllaCoordinatorCommitSourceStore;
#[cfg(all(test, feature = "rf3-test-support"))]
#[path = "../../tests/rf3/d04b6h23c4c4b2b_terminal_carryover.rs"]
mod realm_processor_terminal_carryover_rf3;
mod pending_queue_consumer_gate;
#[cfg(test)]
#[path = "../../tests/rf3/d04b6h22e_consumer_gate.rs"]
mod pending_queue_consumer_gate_rf3;
#[cfg(test)]
#[path = "../../tests/rf3/d04b6h22e2b_segment_lifecycle.rs"]
mod pending_queue_segment_lifecycle_rf3;
#[cfg(test)]
#[path = "../../tests/rf3/d04b6h22e3_cutover.rs"]
mod branch_exact_cutover_rf3;
#[cfg(test)]
#[path = "../../tests/rf3/d04b6h23c4c2b4e3_edge_handler_ingress.rs"]
mod realm_edge_handler_ingress_rf3;
#[cfg(test)]
mod branch_exact_shadow_reader_rf3_gate;
#[cfg(test)]
mod branch_exact_writer_rf3_gate;
#[cfg(test)]
mod branch_exact_schema_setup_rf3_gate;
mod authority_local_head_prototype;
mod authority_timestamp_prototype;
mod checkpoint_kiv;
mod checkpoint_merkle;
mod checkpoint_object_single;
mod checkpoint_root_pair;
mod public_key_projection;
mod realm_imt_predecessor;
mod realm_normal_commit_coverage;
#[allow(dead_code)]
mod realm_full_commit_plan;
#[allow(dead_code)]
mod realm_full_commit_execution;
mod realm_rollback_commit_inventory;
mod realm_rollback_commit_inventory_store;
mod realm_rollback_physical_catalog;
mod realm_rollback_physical_before_image;
mod realm_rollback_physical_archive_store;
mod realm_rollback_physical_archive_owner;
mod realm_rollback_delete_restore_executor;
mod realm_rollback_delete_completion;
mod realm_rollback_participant_completion;
#[allow(dead_code)]
mod realm_full_commit_scylla;
#[allow(dead_code)]
mod realm_full_commit_manifest;
#[allow(dead_code)]
mod realm_full_commit_manifest_store;
#[allow(dead_code)]
mod realm_prepared_state_physical_plan;
#[cfg(test)]
mod realm_imt_predecessor_rf3_gate;
mod imt_family;
mod coordinator_rollback_archive_plan;
#[allow(dead_code)]
mod coordinator_rollback_archive_store;
#[allow(dead_code)]
mod coordinator_rollback_branch_catalog;
#[allow(dead_code)]
mod coordinator_rollback_realm_reward_catalog;
#[cfg(all(test, feature = "rf3-test-support"))]
#[path = "../../tests/rf3/d1a08_coordinator_archive.rs"]
mod coordinator_rollback_archive_rf3;
mod rollback_admission;
mod rollback_abort_convergence_store;
mod identity;
mod key;
mod manifest_artifact;
mod manifest_prepared;
mod mutation;
mod mutable_singleton;
mod pending_counter;
mod pending_context;
#[cfg(test)]
mod pending_namespace_rf3_gate;
mod confinement;
mod namespace;
mod namespace_prototype;
mod normal_commit_prototype;
mod normal_state_replay_prototype;
#[cfg(test)]
mod normal_state_replay_rf3_gate;
mod representative_normal_commit_prototype;
mod raw_access;
mod replay;
mod reward_tag_tree;
mod timestamp_prototype;
mod timestamped;
mod registry;

pub use canonical_head_prototype::*;
pub use branch_exact_schema_migration::*;
pub use branch_exact_schema_deployment::*;
pub use branch_exact_schema_deployment_lifecycle::*;
pub use branch_exact_schema_backfill::*;
pub use branch_exact_schema_backfill_executor::*;
pub(crate) use branch_exact_schema_operator::*;
pub use branch_exact_schema_exporter::*;
pub use branch_exact_cutover_lifecycle::*;
pub use branch_exact_cutover_store::*;
pub use branch_exact_cutover_runtime::*;
pub use branch_exact_schema_setup::*;
pub use branch_exact_shadow_reader::*;
pub use branch_exact_shadow_audit::*;
pub use branch_exact_writer_lifecycle::*;
pub use branch_exact_writer_lifecycle_store::*;
pub use branch_exact_writer_runtime::*;
pub use pending_generation_pipeline_store::*;
pub use pending_queue_artifact_store::*;
pub use pending_queue_segment_ledger::*;
pub use pending_queue_publish_store::*;
pub use pending_queue_sidecar_schema::*;
pub use realm_edge_durable_publisher::*;
pub use realm_user_update_claim_store::*;
pub(crate) use realm_user_update_admission_store::*;
pub use realm_user_update_dependency_store::*;
pub(crate) use realm_user_update_durable_consumer::*;
pub(crate) use realm_user_update_router::*;
pub(crate) use realm_user_update_ingress::*;
pub use pending_queue_sidecar_lifecycle::*;
pub(crate) use coordinator_guta_durable_submission_store::*;
pub(crate) use coordinator_processor_durable_capture::ScyllaCoordinatorProcessorDurableCaptureFactory;
pub(crate) use coordinator_processor_full_commit::ScyllaCoordinatorProcessorFullCommitStore;
pub use authority_local_head_prototype::*;
pub use authority_timestamp_prototype::*;
pub use checkpoint_kiv::*;
pub use checkpoint_merkle::*;
pub use checkpoint_object_single::*;
pub use checkpoint_root_pair::*;
pub use coordinator_commit_physical_inventory::*;
pub(crate) use coordinator_commit_physical_before_image::*;
pub(crate) use coordinator_commit_physical_archive_store::*;
pub(crate) use coordinator_commit_delete_restore_plan::*;
pub use public_key_projection::*;
pub use realm_imt_predecessor::*;
pub use realm_normal_commit_coverage::*;
pub use imt_family::*;
pub use coordinator_rollback_archive_plan::*;
pub use rollback_admission::*;
pub use identity::*;
pub use key::*;
pub use manifest_artifact::*;
pub use manifest_prepared::*;
pub use mutation::*;
pub use mutable_singleton::*;
pub use pending_counter::*;
pub use pending_context::*;
pub use confinement::*;
pub use namespace::*;
pub use namespace_prototype::*;
pub use normal_commit_prototype::*;
pub use normal_state_replay_prototype::*;
pub use representative_normal_commit_prototype::*;
pub use raw_access::*;
pub use replay::*;
pub use reward_tag_tree::*;
pub use timestamp_prototype::*;
pub use timestamped::*;
pub use registry::*;
