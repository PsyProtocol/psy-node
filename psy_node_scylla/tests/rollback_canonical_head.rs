use std::sync::{Arc, Barrier, Mutex};

use parth_core::PHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    NetworkId,
};
use psy_node_core::store::canonical_head::{
    CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile,
    CanonicalHeadModelError, CanonicalHeadReadState, CanonicalHeadTransition,
    CanonicalHeadWriteOutcome, SealedCanonicalHeadCas, StoredCanonicalHead,
};
use psy_node_core::store::{
    rollback_control::{
        RollbackControlState, RollbackExecutionMode, RollbackPlanDigest,
        RollbackRequest,
    },
    timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
};
use psy_node_scylla::rollback::{
    decode_canonical_head_persisted_cells,
    CanonicalHeadBindValue, CanonicalHeadBootstrapBinding,
    CanonicalHeadCasBinding, CanonicalHeadLwtContract,
    CanonicalHeadNoTabletKeyspace, CanonicalHeadQueries,
    CanonicalHeadStoreError, COORDINATOR_CANONICAL_HEAD_TABLE,
};
use scylla::statement::{Consistency, SerialConsistency};

const GOLDEN: &str = include_str!("golden/canonical_head_v1.txt");
const D01_GOLDEN: &str =
    include_str!("../../psy_data/tests/golden/canonical_chain_vectors_v1.txt");

fn hash(seed: u64) -> PHash {
    PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn canonical_ref(
    network: NetworkId,
    epoch: u64,
    checkpoint: u64,
    hash_seed: u64,
) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network,
        ChainEpoch::new(epoch),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(hash_seed)),
        ),
    )
}

fn mainnet() -> NetworkId {
    NetworkId::try_from_chain_id(0x69797350).unwrap()
}

fn public_canary() -> NetworkId {
    NetworkId::try_from_chain_id(0xCFCFCFCF).unwrap()
}

fn genesis() -> CanonicalHeadBootstrap<PHash> {
    CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        canonical_ref(mainnet(), 0, 0, 1),
    )
    .unwrap()
}

fn stored(revision: i64, canonical_ref: CanonicalChainRef<PHash>) -> StoredCanonicalHead<PHash> {
    let idle = RollbackControlState::<PHash>::Idle.to_canonical_bytes();
    StoredCanonicalHead::decode_persisted(
        canonical_ref.network_id(),
        revision,
        &canonical_ref.to_canonical_bytes(),
        &idle,
    )
    .unwrap()
}

fn advance(
    expected: StoredCanonicalHead<PHash>,
    hash_seed: u64,
) -> SealedCanonicalHeadCas<PHash> {
    let current = expected.canonical_ref();
    let proposed = canonical_ref(
        current.network_id(),
        current.chain_epoch().get(),
        current.checkpoint().checkpoint_id().get() + 1,
        hash_seed,
    );
    CanonicalHeadTransition::normal_checkpoint_advance(expected, proposed)
        .unwrap()
        .seal()
}

fn rollback_request(
    requested: StoredCanonicalHead<PHash>,
    target: CheckpointRef<PHash>,
) -> RollbackRequest<PHash> {
    RollbackRequest::try_new(
        *requested.canonical_ref().checkpoint(),
        target,
        TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            2_000,
            3_000,
        )
        .unwrap(),
        RollbackExecutionMode::InPlace,
        RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
    )
    .unwrap()
}

fn d01_golden(name: &str) -> &str {
    D01_GOLDEN
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawCanonicalHeadRow {
    network_chain_id: i64,
    revision: Option<i64>,
    canonical_ref: Option<Vec<u8>>,
    rollback_control: Option<Vec<u8>>,
}

impl RawCanonicalHeadRow {
    fn from_stored(head: &StoredCanonicalHead<PHash>) -> Self {
        Self {
            network_chain_id: i64::from(
                head.canonical_ref().network_id().chain_id(),
            ),
            revision: Some(head.revision().as_i64()),
            canonical_ref: Some(head.canonical_ref_bytes().to_vec()),
            rollback_control: Some(head.rollback_control_bytes().to_vec()),
        }
    }

    fn decode(
        &self,
        requested_network: NetworkId,
    ) -> Result<StoredCanonicalHead<PHash>, TestModelError> {
        let returned_chain_id = u32::try_from(self.network_chain_id)
            .map_err(|_| TestModelError::Malformed)?;
        let returned_network = NetworkId::try_from_chain_id(returned_chain_id)
            .map_err(|_| TestModelError::Malformed)?;
        if returned_network != requested_network {
            return Err(TestModelError::Malformed);
        }
        let revision = self.revision.ok_or(TestModelError::Malformed)?;
        let canonical_ref = self
            .canonical_ref
            .as_deref()
            .ok_or(TestModelError::Malformed)?;
        let rollback_control = self
            .rollback_control
            .as_deref()
            .ok_or(TestModelError::Malformed)?;
        StoredCanonicalHead::decode_persisted(
            returned_network,
            revision,
            canonical_ref,
            rollback_control,
        )
        .map_err(TestModelError::Model)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TestModelError {
    Uninitialized,
    Malformed,
    Model(CanonicalHeadModelError),
}

#[derive(Default)]
struct DeterministicCanonicalHeadStore {
    row: Mutex<Option<RawCanonicalHeadRow>>,
}

impl DeterministicCanonicalHeadStore {
    fn read(
        &self,
        network: NetworkId,
    ) -> Result<CanonicalHeadReadState<PHash>, TestModelError> {
        let row = self.row.lock().unwrap();
        match row.as_ref() {
            None => Ok(CanonicalHeadReadState::Uninitialized),
            Some(row) => Ok(CanonicalHeadReadState::Current(row.decode(network)?)),
        }
    }

    fn bootstrap(
        &self,
        bootstrap: &CanonicalHeadBootstrap<PHash>,
    ) -> Result<CanonicalHeadWriteOutcome<PHash>, TestModelError> {
        let mut row = self.row.lock().unwrap();
        match row.as_ref() {
            None => {
                *row = Some(RawCanonicalHeadRow::from_stored(bootstrap.candidate()));
                Ok(CanonicalHeadWriteOutcome::Applied(*bootstrap.candidate()))
            }
            Some(current) => bootstrap
                .classify_lwt_observation(
                    false,
                    current.decode(
                        bootstrap.candidate().canonical_ref().network_id(),
                    )?,
                )
                .map_err(TestModelError::Model),
        }
    }

    fn compare_and_set(
        &self,
        sealed: &SealedCanonicalHeadCas<PHash>,
    ) -> Result<CanonicalHeadWriteOutcome<PHash>, TestModelError> {
        let mut row = self.row.lock().unwrap();
        let current = row
            .as_ref()
            .ok_or(TestModelError::Uninitialized)?
            .decode(sealed.expected().canonical_ref().network_id())?;
        if current == *sealed.expected() {
            *row = Some(RawCanonicalHeadRow::from_stored(sealed.candidate()));
            sealed
                .classify_lwt_observation(true, *sealed.candidate())
                .map_err(TestModelError::Model)
        } else {
            sealed
                .classify_lwt_observation(false, current)
                .map_err(TestModelError::Model)
        }
    }

    fn inject_raw(&self, row: RawCanonicalHeadRow) {
        *self.row.lock().unwrap() = Some(row);
    }

    fn raw(&self) -> Option<RawCanonicalHeadRow> {
        self.row.lock().unwrap().clone()
    }
}

#[test]
fn schema_query_and_binding_golden_are_single_source_and_stable() {
    let keyspace = CanonicalHeadNoTabletKeyspace::try_new(
        "psy_c01a_control_no_tablet",
    )
    .unwrap();
    let queries = CanonicalHeadQueries::new(&keyspace);

    let expected = stored(
        7,
        canonical_ref(mainnet(), 42, 367, 1),
    );
    let sealed = advance(expected, 5);
    let bootstrap = genesis();
    let rendered = format!(
        "{}BOOTSTRAP_BIND\n{}\nCAS_BIND\n{}\n",
        queries.render_golden(),
        CanonicalHeadBootstrapBinding::from_bootstrap(&bootstrap)
            .render_golden(),
        CanonicalHeadCasBinding::from_sealed(&sealed).render_golden(),
    );
    assert_eq!(rendered, GOLDEN);

    assert!(queries
        .create_table()
        .cql()
        .contains("network_chain_id bigint PRIMARY KEY"));
    assert!(!queries.create_table().cql().contains("network_chain_id int "));
    assert!(queries.bootstrap().cql().ends_with("IF NOT EXISTS"));
    assert!(queries
        .compare_and_set()
        .cql()
        .ends_with("IF revision = ? AND canonical_ref = ? AND rollback_control = ?"));
    assert_eq!(queries.compare_and_set().cql().matches('?').count(), 7);
    assert!(!queries.create_table().cql().contains("chain_epoch"));
    assert!(!queries.create_table().cql().contains("checkpoint_id"));
    assert!(!queries.create_table().cql().contains("checkpoint_hash"));
    assert!(queries
        .create_table()
        .cql()
        .contains(COORDINATOR_CANONICAL_HEAD_TABLE));
}

#[test]
fn bind_order_is_typed_and_reuses_d01_payload_bytes() {
    let bootstrap = genesis();
    let bootstrap_binding =
        CanonicalHeadBootstrapBinding::from_bootstrap(&bootstrap);
    assert_eq!(
        bootstrap_binding.values(),
        vec![
            CanonicalHeadBindValue::BigInt(i64::from(
                mainnet().chain_id(),
            )),
            CanonicalHeadBindValue::BigInt(0),
            CanonicalHeadBindValue::Blob(
                bootstrap.candidate().canonical_ref().to_canonical_bytes().to_vec(),
            ),
            CanonicalHeadBindValue::Blob(
                bootstrap.candidate().rollback_control_bytes().to_vec(),
            ),
        ]
    );

    let expected = stored(
        7,
        canonical_ref(mainnet(), 42, 367, 1),
    );
    assert_eq!(
        hex::encode(expected.canonical_ref_bytes()),
        d01_golden("canonical_mainnet_epoch_42_checkpoint_367_hash_1_2_3_4")
    );
    let sealed = advance(expected, 5);
    let first = CanonicalHeadCasBinding::from_sealed(&sealed);
    let retry = CanonicalHeadCasBinding::from_sealed(&sealed);
    assert_eq!(first, retry);
    assert_eq!(
        first.values(),
        vec![
            CanonicalHeadBindValue::BigInt(8),
            CanonicalHeadBindValue::Blob(sealed.candidate_payload().to_vec()),
            CanonicalHeadBindValue::Blob(sealed.candidate_control_payload().to_vec()),
            CanonicalHeadBindValue::BigInt(i64::from(
                mainnet().chain_id(),
            )),
            CanonicalHeadBindValue::BigInt(7),
            CanonicalHeadBindValue::Blob(sealed.expected_payload().to_vec()),
            CanonicalHeadBindValue::Blob(sealed.expected_control_payload().to_vec()),
        ]
    );
    assert_eq!(sealed.expected_payload(), &expected.canonical_ref_bytes());
}

#[test]
fn all_u32_network_ids_fit_the_bigint_partition_contract() {
    let canary = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        canonical_ref(public_canary(), 0, 0, 1),
    )
    .unwrap();
    let values = CanonicalHeadBootstrapBinding::from_bootstrap(&canary).values();
    assert_eq!(
        values[0],
        CanonicalHeadBindValue::BigInt(0xCFCFCFCF_u32 as i64)
    );
    assert!(0xCFCFCFCF_u32 > i32::MAX as u32);
}

#[test]
fn keyspace_and_lwt_contract_are_explicit() {
    assert!(CanonicalHeadNoTabletKeyspace::try_new("psy_control").is_err());
    assert!(CanonicalHeadNoTabletKeyspace::try_new("psy_control_no_tablet").is_ok());
    assert!(CanonicalHeadNoTabletKeyspace::try_new("psy_recovery_nt").is_ok());
    let contract = CanonicalHeadLwtContract::rf3_default();
    assert_eq!(contract.regular(), Consistency::Quorum);
    assert_eq!(contract.serial(), SerialConsistency::LocalSerial);
}

#[test]
fn missing_row_is_uninitialized_and_does_not_invent_epoch_zero() {
    let store = DeterministicCanonicalHeadStore::default();
    assert_eq!(
        store
            .read(mainnet())
            .unwrap(),
        CanonicalHeadReadState::Uninitialized
    );
}

#[test]
fn nullable_or_invalid_persisted_cells_fail_closed() {
    let payload = genesis().candidate().canonical_ref_bytes();
    let control = genesis().candidate().rollback_control_bytes();
    assert_eq!(
        decode_canonical_head_persisted_cells::<PHash>(
            mainnet(),
            i64::from(mainnet().chain_id()),
            None,
            Some(&payload),
            Some(&control),
        ),
        Err(CanonicalHeadStoreError::MissingRevision)
    );
    assert_eq!(
        decode_canonical_head_persisted_cells::<PHash>(
            mainnet(),
            i64::from(mainnet().chain_id()),
            Some(0),
            None,
            Some(&control),
        ),
        Err(CanonicalHeadStoreError::MissingCanonicalPayload)
    );
    assert_eq!(
        decode_canonical_head_persisted_cells::<PHash>(
            mainnet(),
            -1,
            Some(0),
            Some(&payload),
            Some(&control),
        ),
        Err(CanonicalHeadStoreError::NetworkChainIdOutOfRange(-1))
    );
    assert!(matches!(
        decode_canonical_head_persisted_cells::<PHash>(
            public_canary(),
            i64::from(mainnet().chain_id()),
            Some(0),
            Some(&payload),
            Some(&control),
        ),
        Err(CanonicalHeadStoreError::SelectedPartitionMismatch { .. })
    ));
    assert_eq!(
        decode_canonical_head_persisted_cells::<PHash>(
            mainnet(),
            i64::from(mainnet().chain_id()),
            Some(0),
            Some(&payload),
            None,
        ),
        Err(CanonicalHeadStoreError::MissingRollbackControlPayload)
    );
}

#[test]
fn bootstrap_is_atomic_idempotent_and_conflict_returns_full_current() {
    let store = DeterministicCanonicalHeadStore::default();
    let bootstrap = genesis();
    assert!(store.bootstrap(&bootstrap).unwrap().was_applied());
    assert!(store.bootstrap(&bootstrap).unwrap().was_idempotent());

    let conflicting = CanonicalHeadBootstrap::try_new(
        CanonicalHeadBootstrapProfile::GenesisNative,
        canonical_ref(mainnet(), 0, 0, 99),
    )
    .unwrap();
    assert!(matches!(
        store.bootstrap(&conflicting).unwrap(),
        CanonicalHeadWriteOutcome::Conflict { current }
            if current == *bootstrap.candidate()
    ));
}

#[test]
fn concurrent_identical_bootstrap_has_one_applied_winner() {
    const WORKERS: usize = 64;
    let store = Arc::new(DeterministicCanonicalHeadStore::default());
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let bootstrap = genesis();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store.bootstrap(&bootstrap).unwrap()
        }));
    }
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.was_applied()).count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.was_idempotent())
            .count(),
        WORKERS - 1
    );
}

#[test]
fn concurrent_cas_has_one_expected_state_winner() {
    const WORKERS: usize = 64;
    let store = Arc::new(DeterministicCanonicalHeadStore::default());
    let bootstrap = genesis();
    store.bootstrap(&bootstrap).unwrap();
    let expected = *bootstrap.candidate();
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut handles = Vec::new();
    for worker in 0..WORKERS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let sealed = advance(expected, 100 + worker as u64 * 4);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store.compare_and_set(&sealed).unwrap()
        }));
    }
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.was_applied()).count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| !outcome.was_applied())
            .count(),
        WORKERS - 1
    );
    let durable = match store
        .read(mainnet())
        .unwrap()
    {
        CanonicalHeadReadState::Current(current) => current,
        CanonicalHeadReadState::Uninitialized => panic!("winner must publish"),
    };
    for outcome in outcomes {
        if let CanonicalHeadWriteOutcome::Conflict { current } = outcome {
            assert_eq!(current, durable);
        }
    }
}

#[test]
fn normal_publish_and_rollback_admission_compete_on_one_atomic_row() {
    const WORKERS: usize = 64;
    let store = Arc::new(DeterministicCanonicalHeadStore::default());
    let bootstrap = genesis();
    store.bootstrap(&bootstrap).unwrap();

    let first_advance = advance(*bootstrap.candidate(), 10);
    assert!(store.compare_and_set(&first_advance).unwrap().was_applied());
    let expected = *first_advance.candidate();
    let normal_publish = advance(expected, 20);
    let rollback_admission = CanonicalHeadTransition::start_rollback(
        expected,
        rollback_request(
            expected,
            *bootstrap.candidate().canonical_ref().checkpoint(),
        ),
    )
    .unwrap()
    .seal();

    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut handles = Vec::new();
    for worker in 0..WORKERS {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let sealed = if worker % 2 == 0 {
            normal_publish
        } else {
            rollback_admission
        };
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store.compare_and_set(&sealed).unwrap()
        }));
    }

    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.was_applied()).count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| !outcome.was_applied())
            .count(),
        WORKERS - 1
    );

    let durable = match store.read(mainnet()).unwrap() {
        CanonicalHeadReadState::Current(current) => current,
        CanonicalHeadReadState::Uninitialized => panic!("winner must publish"),
    };
    assert_eq!(durable.revision().get(), expected.revision().get() + 1);
    match durable.rollback_control() {
        RollbackControlState::Idle => {
            assert_eq!(durable.canonical_ref().chain_epoch(), ChainEpoch::new(0));
            assert_eq!(
                durable.canonical_ref().checkpoint().checkpoint_id(),
                CheckpointId::new(2)
            );
        }
        RollbackControlState::Requested(request) => {
            assert_eq!(durable.canonical_ref().chain_epoch(), ChainEpoch::new(1));
            assert_eq!(
                durable.canonical_ref().checkpoint().checkpoint_id(),
                CheckpointId::new(1)
            );
            assert_eq!(
                request.requested_head(),
                expected.canonical_ref().checkpoint()
            );
            assert_eq!(
                request.target(),
                bootstrap.candidate().canonical_ref().checkpoint()
            );
        }
        RollbackControlState::Archiving(_)
        | RollbackControlState::ArchiveBarrierReady(_)
        | RollbackControlState::Deleting(_)
        | RollbackControlState::Restoring(_)
        | RollbackControlState::Verifying(_)
        | RollbackControlState::AllRealmsReady(_)
        | RollbackControlState::Aborting(_) => {
            panic!("admission race can only publish IDLE or REQUESTED")
        }
    }
    assert!(outcomes.iter().all(|outcome| outcome.current() == &durable));
}

#[test]
fn revision_blocks_aba_and_old_expected_never_writes_again() {
    let store = DeterministicCanonicalHeadStore::default();
    let bootstrap = genesis();
    store.bootstrap(&bootstrap).unwrap();
    let old_a = *bootstrap.candidate();
    let a_to_b = advance(old_a, 10);
    store.compare_and_set(&a_to_b).unwrap();

    // Test-only raw injection represents A -> B -> A. The payload is A again,
    // but the monotonic durable revision is two, so the old A expectation must
    // not win.
    let mut returned_a = RawCanonicalHeadRow::from_stored(&old_a);
    returned_a.revision = Some(2);
    store.inject_raw(returned_a);
    assert!(matches!(
        store.compare_and_set(&a_to_b).unwrap(),
        CanonicalHeadWriteOutcome::Conflict { current }
            if current.revision().get() == 2
                && current.canonical_ref() == old_a.canonical_ref()
    ));
}

#[test]
fn response_loss_retry_is_idempotent_and_prewrite_crash_keeps_old_head() {
    let store = DeterministicCanonicalHeadStore::default();
    let bootstrap = genesis();
    store.bootstrap(&bootstrap).unwrap();
    let expected = *bootstrap.candidate();
    let sealed = advance(expected, 10);

    // Sealing alone is the write-before crash point.
    assert_eq!(
        store
            .read(expected.canonical_ref().network_id())
            .unwrap(),
        CanonicalHeadReadState::Current(expected)
    );

    let lost_response = store.compare_and_set(&sealed).unwrap();
    assert!(lost_response.was_applied());
    let retry = store.compare_and_set(&sealed).unwrap();
    assert!(retry.was_idempotent());
    assert_eq!(retry.current(), sealed.candidate());
}

#[test]
fn malformed_current_row_is_not_repaired_or_overwritten() {
    let store = DeterministicCanonicalHeadStore::default();
    let bootstrap = genesis();
    store.bootstrap(&bootstrap).unwrap();
    let sealed = advance(*bootstrap.candidate(), 10);

    let mut malformed = RawCanonicalHeadRow::from_stored(bootstrap.candidate());
    let payload = malformed.canonical_ref.as_mut().unwrap();
    payload[8..10].copy_from_slice(&99_u16.to_le_bytes());
    store.inject_raw(malformed.clone());
    assert!(matches!(
        store.compare_and_set(&sealed),
        Err(TestModelError::Model(CanonicalHeadModelError::Codec(_)))
    ));
    assert_eq!(store.raw(), Some(malformed));
}

/// A head advance must name a strictly forward candidate.  Rewinding is a
/// rollback, and rollback only ever happens through the phase machine, never
/// through the ordinary advance builder (design-r1 I1/I3).
#[test]
fn arbitrary_rewind_cannot_be_sealed_by_the_advance_builder() {
    let old = stored(7, canonical_ref(mainnet(), 42, 367, 1));
    let rewind = canonical_ref(mainnet(), 43, 100, 99);
    assert!(CanonicalHeadTransition::normal_checkpoint_advance(old, rewind).is_err());
}
