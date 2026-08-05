use std::fs;

use parth_core::PHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    NetworkId,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
    rollback_admission::{
        RollbackAdmissionCommand, RollbackAdmissionSlotBootstrap,
        RollbackAdmissionSlotState, SealedRollbackAdmissionSlotCas,
    },
    rollback_control::{
        RollbackExecutionMode, RollbackPlanDigest, RollbackRequest,
    },
    timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
};
use psy_node_scylla::rollback::{
    decode_rollback_admission_persisted_cells, CanonicalHeadNoTabletKeyspace,
    RollbackAdmissionBootstrapBinding, RollbackAdmissionCasBinding,
    RollbackAdmissionQueries, RollbackAdmissionScyllaError,
};

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(0x6979_7350).unwrap()
}

fn checkpoint(height: u64, seed: u64) -> CheckpointRef<PHash> {
    CheckpointRef::new(
        CheckpointId::new(height),
        CheckpointHash::from_last_chain_hash(PHash::from_values(
            seed,
            seed + 1,
            seed + 2,
            seed + 3,
        )),
    )
}

fn command() -> RollbackAdmissionCommand<PHash> {
    let expected = *CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::PostGenesisFloor,
        CanonicalChainRef::new(network(), ChainEpoch::new(0), checkpoint(100, 10)),
    )
    .unwrap()
    .candidate();
    RollbackAdmissionCommand::try_new(
        expected,
        RollbackRequest::try_new(
            *expected.canonical_ref().checkpoint(),
            checkpoint(90, 20),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn query_and_bind_order_match_golden_contract() {
    let keyspace =
        CanonicalHeadNoTabletKeyspace::try_new("psy_c01d_control_no_tablet").unwrap();
    let queries = RollbackAdmissionQueries::new(&keyspace);
    assert_eq!(
        queries.render_golden(),
        include_str!("golden/rollback_admission_inbox_v1.txt")
    );

    let bootstrap = RollbackAdmissionSlotBootstrap::<PHash>::new(network());
    let bootstrap_binding = RollbackAdmissionBootstrapBinding::from_bootstrap(&bootstrap);
    let bootstrap_values = bootstrap_binding.golden_values();
    assert_eq!(bootstrap_values.len(), 3);
    assert!(bootstrap_values[0].starts_with("BIGINT:"));
    assert_eq!(bootstrap_values[1], "BIGINT:0");
    assert!(bootstrap_values[2].starts_with("BLOB:5053595242494e42"));

    let offer = SealedRollbackAdmissionSlotCas::offer(
        network(),
        *bootstrap.candidate(),
        command(),
    )
    .unwrap();
    let cas_values = RollbackAdmissionCasBinding::from_sealed(&offer).golden_values();
    assert_eq!(cas_values.len(), 5);
    assert_eq!(cas_values[0], "BIGINT:1");
    assert!(cas_values[1].starts_with("BLOB:5053595242494e42"));
    assert!(cas_values[2].starts_with("BIGINT:"));
    assert_eq!(cas_values[3], "BIGINT:0");
    assert!(cas_values[4].starts_with("BLOB:5053595242494e42"));
}

#[test]
fn persisted_cells_are_fail_closed() {
    let bootstrap = RollbackAdmissionSlotBootstrap::<PHash>::new(network());
    let payload = bootstrap.candidate_payload();
    let chain_id = i64::from(network().chain_id());
    let decoded = decode_rollback_admission_persisted_cells::<PHash>(
        network(),
        chain_id,
        Some(0),
        Some(payload),
    )
    .unwrap();
    assert!(decoded.state().is_empty());

    assert_eq!(
        decode_rollback_admission_persisted_cells::<PHash>(
            network(),
            chain_id,
            None,
            Some(payload),
        ),
        Err(RollbackAdmissionScyllaError::MissingRevision)
    );
    assert_eq!(
        decode_rollback_admission_persisted_cells::<PHash>(
            network(),
            chain_id,
            Some(0),
            None,
        ),
        Err(RollbackAdmissionScyllaError::MissingSlot)
    );
    let mut malformed = *payload;
    malformed[0] ^= 0xFF;
    assert!(decode_rollback_admission_persisted_cells::<PHash>(
        network(),
        chain_id,
        Some(0),
        Some(&malformed),
    )
    .is_err());
}

#[test]
fn production_wiring_keeps_edge_inbox_only_and_processor_at_loop_boundary() {
    let setup = fs::read_to_string("src/psy_setup.rs").unwrap();
    assert!(setup.contains("initialize_coordinator_rollback_admission(create_tables)"));

    let runner = fs::read_to_string("../psy_node_common/src/coordinator/processor/core/runner.rs")
        .unwrap();
    let boundary = runner
        .find("reconcile_rollback_admission_at_loop_boundary")
        .unwrap();
    let process = runner.find("processor.process_block().await").unwrap();
    assert!(boundary < process);

    let edge = fs::read_to_string("../psy_node_common/src/coordinator/edge/handler.rs").unwrap();
    assert!(!edge.contains("CoordinatorRollbackAdmissionStore"));
    assert!(!edge.contains("CoordinatorCanonicalHeadStore"));
    assert!(!edge.contains("compare_and_set_canonical_head"));
    assert!(edge.contains("admin_start_rollback_internal"));
    assert!(edge.contains("rollback_admin_inbox.start(intent)"));
}

#[test]
fn empty_slot_is_canonical_not_null_or_delete_based() {
    let empty = RollbackAdmissionSlotState::<PHash>::Empty.to_canonical_bytes();
    assert!(empty.iter().any(|byte| *byte != 0));
    let golden = include_str!("golden/rollback_admission_inbox_v1.txt");
    assert!(!golden.contains("DELETE FROM"));
    assert!(!golden.contains("ALLOW FILTERING"));
}
