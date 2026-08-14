use std::collections::{BTreeMap, BTreeSet};

use parth_core::PHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadTransition, StoredCanonicalHead},
    rollback_control::RollbackControlState,
    rollback_participant_plan::{RollbackParticipantPlan, RollbackRealmParticipant},
    rollback_topology::RollbackTopologySnapshot,
    timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Participant {
    Coordinator,
    Realm { realm_id: u32, realm_sub_id: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VersionedValue {
    value: &'static str,
    writetime_us: i64,
}

#[derive(Clone, Debug)]
struct AuthorityData {
    hot: BTreeMap<u64, VersionedValue>,
    archive: BTreeMap<u64, VersionedValue>,
    delete_fence_us: Option<i64>,
    restored_head: u64,
}

impl AuthorityData {
    fn at_a3() -> Self {
        Self {
            hot: BTreeMap::from([
                (1, VersionedValue { value: "A1", writetime_us: 100 }),
                (2, VersionedValue { value: "A2", writetime_us: 100 }),
                (3, VersionedValue { value: "A3", writetime_us: 100 }),
            ]),
            archive: BTreeMap::new(),
            delete_fence_us: None,
            restored_head: 3,
        }
    }

    fn archive_suffix_and_read_back(&mut self, target: u64) {
        for (&checkpoint, row) in self.hot.range((target + 1)..) {
            self.archive.insert(checkpoint, row.clone());
        }
        let expected = self
            .hot
            .range((target + 1)..)
            .map(|(&checkpoint, row)| (checkpoint, row.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(self.archive, expected, "archive read-back must equal the hot suffix");
    }

    fn delete_suffix_and_restore_target(&mut self, target: u64, fence_us: i64) {
        assert_eq!(self.archive.len(), 2, "delete requires the complete A2/A3 archive");
        self.hot.retain(|&checkpoint, _| checkpoint <= target);
        self.delete_fence_us = Some(fence_us);
        self.restored_head = target;
    }

    fn put(&mut self, checkpoint: u64, value: &'static str, writetime_us: i64) {
        if self
            .delete_fence_us
            .is_some_and(|delete_fence| writetime_us <= delete_fence)
        {
            return;
        }
        match self.hot.get(&checkpoint) {
            Some(current) if current.writetime_us >= writetime_us => {}
            _ => {
                self.hot.insert(checkpoint, VersionedValue { value, writetime_us });
                self.restored_head = self.restored_head.max(checkpoint);
            }
        }
    }
}

fn hash(seed: u8) -> PHash {
    let seed = u64::from(seed);
    PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1).unwrap()
}

fn chain(epoch: u64, checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(epoch),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn idle_head(canonical: CanonicalChainRef<PHash>) -> StoredCanonicalHead<PHash> {
    StoredCanonicalHead::decode_persisted(
        canonical.network_id(),
        0,
        &canonical.to_canonical_bytes(),
        &RollbackControlState::<PHash>::Idle.to_canonical_bytes(),
    )
    .unwrap()
}

#[test]
fn explicit_request_rolls_coordinator_and_every_realm_to_one_target_then_continues() {
    let realms = vec![
        RollbackRealmParticipant::new(10, 0),
        RollbackRealmParticipant::new(20, 0),
    ];
    let topology = RollbackTopologySnapshot::try_new(network(), 1, realms.clone()).unwrap();
    let old_head = idle_head(chain(0, 3, 0xA3));
    let target = chain(0, 1, 0xA1);
    let fence = TimestampFenceWindow::try_new(
        CommitWriteTimestampUs::try_from_i128(100).unwrap(),
        200,
        300,
    )
    .unwrap();
    let plan = RollbackParticipantPlan::try_new(
        old_head,
        target,
        fence,
        topology.revision(),
        *topology.digest(),
        realms,
    )
    .unwrap();
    assert!(topology.validates_plan(&plan));

    let participants = [
        Participant::Coordinator,
        Participant::Realm { realm_id: 10, realm_sub_id: 0 },
        Participant::Realm { realm_id: 20, realm_sub_id: 0 },
    ];
    let mut data = participants
        .into_iter()
        .map(|participant| (participant, AuthorityData::at_a3()))
        .collect::<BTreeMap<_, _>>();

    // Nothing happens until the explicit request is admitted.
    assert!(old_head.rollback_control().is_idle());
    assert!(data.values().all(|authority| authority.archive.is_empty()));
    let requested = CanonicalHeadTransition::start_rollback(old_head, plan.rollback_request().unwrap())
        .unwrap();
    let archiving = CanonicalHeadTransition::begin_rollback_archive(*requested.candidate()).unwrap();

    // Coordinator plus only one Realm is not a global archive barrier. No hot
    // row may be deleted while one topology-selected participant is missing.
    let mut archived = BTreeSet::new();
    for participant in participants.into_iter().take(2) {
        data.get_mut(&participant).unwrap().archive_suffix_and_read_back(1);
        archived.insert(participant);
    }
    assert_eq!(archived.len(), 2);
    assert_eq!(plan.participant_count(), 3);
    assert!(data.values().all(|authority| authority.hot.len() == 3));
    assert!(CanonicalHeadTransition::begin_rollback_delete(*archiving.candidate()).is_err());

    let last = participants[2];
    data.get_mut(&last).unwrap().archive_suffix_and_read_back(1);
    archived.insert(last);
    assert_eq!(archived.len(), plan.participant_count());

    let archive_barrier =
        CanonicalHeadTransition::complete_rollback_archive_barrier(*archiving.candidate()).unwrap();
    assert!(archive_barrier.candidate().rollback_control().archive_barrier_ready());
    assert!(!archive_barrier.candidate().rollback_control().destructive_started());
    assert!(data.values().all(|authority| authority.hot.len() == 3));

    let deleting = CanonicalHeadTransition::begin_rollback_delete(*archive_barrier.candidate()).unwrap();
    assert!(deleting.candidate().rollback_control().destructive_started());
    for authority in data.values_mut() {
        authority.delete_suffix_and_restore_target(1, fence.delete_fence().as_i64());
    }
    assert!(data.values().all(|authority| {
        authority.hot.keys().copied().collect::<Vec<_>>() == vec![1]
            && authority.restored_head == 1
    }));

    let restoring = CanonicalHeadTransition::begin_rollback_restore(*deleting.candidate()).unwrap();
    let verifying = CanonicalHeadTransition::begin_rollback_verify(*restoring.candidate()).unwrap();
    let all_realms_ready =
        CanonicalHeadTransition::complete_rollback_realm_barrier(*verifying.candidate()).unwrap();
    let published = CanonicalHeadTransition::complete_rollback(*all_realms_ready.candidate()).unwrap();
    assert_eq!(
        published.candidate().canonical_ref().checkpoint(),
        target.checkpoint()
    );
    assert_eq!(
        published.candidate().canonical_ref().chain_epoch().get(),
        1
    );
    assert!(published.candidate().rollback_control().is_idle());

    // Reusing the same heights is safe only with timestamps after the delete
    // fence. Late A-branch writes cannot resurrect the discarded suffix.
    for authority in data.values_mut() {
        authority.put(2, "A2-late", 100);
        authority.put(3, "A3-late", 100);
        authority.put(2, "B2", fence.new_branch_write().as_commit_timestamp().as_i64());
        authority.put(3, "B3", fence.new_branch_write().as_commit_timestamp().as_i64() + 1);
    }
    let b2 = CanonicalHeadTransition::normal_checkpoint_advance(
        *published.candidate(),
        chain(1, 2, 0xB2),
    )
    .unwrap();
    let b3 = CanonicalHeadTransition::normal_checkpoint_advance(*b2.candidate(), chain(1, 3, 0xB3))
        .unwrap();
    assert_eq!(b3.candidate().canonical_ref().checkpoint().checkpoint_id().get(), 3);

    for authority in data.values() {
        assert_eq!(
            authority
                .hot
                .iter()
                .map(|(&checkpoint, row)| (checkpoint, row.value))
                .collect::<Vec<_>>(),
            vec![(1, "A1"), (2, "B2"), (3, "B3")],
        );
        assert_eq!(
            authority
                .archive
                .iter()
                .map(|(&checkpoint, row)| (checkpoint, row.value))
                .collect::<Vec<_>>(),
            vec![(2, "A2"), (3, "A3")],
        );
    }
}
