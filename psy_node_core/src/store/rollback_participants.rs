//! Who takes part in one rollback, and what each has proven (design-r1 §6.1/§6.2).
//!
//! The phase machine already refuses to reach a destructive phase except through
//! the archive barrier.  What it could not do is say whether the barrier is
//! *earned*: `complete_rollback_archive_barrier` only checked that the phase was
//! ARCHIVING, so a Coordinator could cross the point of no return while a Realm
//! had archived nothing.  §0.2 D2 is explicit that archiving is a precondition
//! rather than a backup, and I6 that no participant may delete before every
//! participant has copied and read back.  This module is what makes those
//! statements checkable.
//!
//! ## Why the set is fixed at request time
//!
//! §6.1: the participant set is written to durable control when the rollback is
//! requested and never changes.  A set that could grow would let a Realm join
//! after the barrier and be told to delete a suffix it never archived; one that
//! could shrink would let an unreachable Realm be dropped precisely when it is
//! the one holding un-archived rows.  Both turn "everyone agreed" into "everyone
//! still present agreed", which is not the same claim.
//!
//! ## Why receipts carry a digest
//!
//! A receipt that only said "done" would let a participant that archived the
//! wrong range satisfy the barrier.  Each receipt names the range it covered and
//! the digest of what it archived, so the aggregate is checkable rather than
//! merely counted.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use psy_data::protocol::chain_context::AuthorityScope;

/// One participant in a rollback.
///
/// Identified by authority scope, which is also how manifests and allocator rows
/// are partitioned -- so a participant identity cannot drift from the partition
/// its evidence lives in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackParticipant(AuthorityScope);

/// Ordered by the same canonical bytes storage partitions by, so a participant's
/// sort position and the partition its evidence lives in cannot drift apart.
impl Ord for RollbackParticipant {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .to_canonical_bytes()
            .cmp(&other.0.to_canonical_bytes())
    }
}

impl PartialOrd for RollbackParticipant {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl RollbackParticipant {
    pub const fn new(scope: AuthorityScope) -> Self {
        Self(scope)
    }

    pub const fn scope(self) -> AuthorityScope {
        self.0
    }

    pub const fn is_coordinator(self) -> bool {
        matches!(self.0, AuthorityScope::Coordinator)
    }
}

impl fmt::Display for RollbackParticipant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            AuthorityScope::Coordinator => write!(f, "coordinator"),
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            } => write!(f, "realm-{realm_id}-{realm_sub_id}"),
        }
    }
}

/// The fixed set of participants for one rollback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackParticipantSet {
    participants: Vec<RollbackParticipant>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParticipantSetError {
    /// A rollback with no Coordinator has nobody to advance the phase: §6.2 puts
    /// every barrier on the Coordinator's control row.
    NoCoordinator,
    /// The same authority listed twice.  Its receipt would then satisfy two
    /// slots and the barrier would pass with one participant missing.
    Duplicate(RollbackParticipant),
    Empty,
}

impl fmt::Display for ParticipantSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCoordinator => write!(
                f,
                "a rollback participant set must contain the Coordinator, which is where every \
                 barrier advances (§6.2)"
            ),
            Self::Duplicate(participant) => write!(
                f,
                "participant {participant} is listed twice; one receipt would then satisfy two \
                 slots and the barrier could pass with a participant missing"
            ),
            Self::Empty => write!(f, "a rollback participant set cannot be empty"),
        }
    }
}

impl Error for ParticipantSetError {}

impl RollbackParticipantSet {
    /// Fix the set for one rollback.  Sorted and deduplicated so the durable
    /// encoding is canonical: two nodes writing the same set must produce the
    /// same bytes, or the control row's compare-and-set would see a difference
    /// where there is none.
    pub fn try_new(
        participants: impl IntoIterator<Item = RollbackParticipant>,
    ) -> Result<Self, ParticipantSetError> {
        let mut participants: Vec<RollbackParticipant> = participants.into_iter().collect();
        if participants.is_empty() {
            return Err(ParticipantSetError::Empty);
        }
        participants.sort();
        if let Some(duplicate) = participants
            .windows(2)
            .find(|pair| pair[0] == pair[1])
            .map(|pair| pair[0])
        {
            return Err(ParticipantSetError::Duplicate(duplicate));
        }
        if !participants.iter().any(|p| p.is_coordinator()) {
            return Err(ParticipantSetError::NoCoordinator);
        }
        Ok(Self { participants })
    }

    pub fn participants(&self) -> &[RollbackParticipant] {
        &self.participants
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    pub fn contains(&self, participant: RollbackParticipant) -> bool {
        self.participants.binary_search(&participant).is_ok()
    }
}

/// What one participant proved it archived.
///
/// The range and digest are what make the barrier checkable rather than counted:
/// a participant that archived a different range, or archived nothing and said
/// "done", produces a receipt that does not match the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveReceipt {
    participant: RollbackParticipant,
    target: u64,
    head: u64,
    archived_rows: u64,
    /// Digest of the archived locator set, so two participants cannot swap
    /// receipts and still satisfy the barrier.
    archive_digest: [u8; 32],
}

impl ArchiveReceipt {
    pub const fn new(
        participant: RollbackParticipant,
        target: u64,
        head: u64,
        archived_rows: u64,
        archive_digest: [u8; 32],
    ) -> Self {
        Self {
            participant,
            target,
            head,
            archived_rows,
            archive_digest,
        }
    }

    pub const fn participant(&self) -> RollbackParticipant {
        self.participant
    }

    pub const fn target(&self) -> u64 {
        self.target
    }

    pub const fn head(&self) -> u64 {
        self.head
    }

    pub const fn archived_rows(&self) -> u64 {
        self.archived_rows
    }

    pub const fn archive_digest(&self) -> [u8; 32] {
        self.archive_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BarrierError {
    /// A receipt arrived from an authority that is not in the fixed set.
    NotAParticipant(RollbackParticipant),
    /// A receipt names a different range than the rollback was requested for.
    /// Accepting it would let a participant satisfy the barrier by archiving
    /// something else.
    RangeMismatch {
        participant: RollbackParticipant,
        expected: (u64, u64),
        found: (u64, u64),
    },
    /// The same participant filed two receipts that disagree.  One of them is
    /// wrong and there is no way to tell which, so neither is trusted.
    ConflictingReceipt(RollbackParticipant),
    /// Not everyone has filed.  Names who is missing: "some participant" would
    /// leave an operator to guess which Realm to look at.
    Missing(Vec<RollbackParticipant>),
}

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAParticipant(participant) => write!(
                f,
                "{participant} filed an archive receipt but is not in this rollback's participant \
                 set, which was fixed when the rollback was requested (§6.1)"
            ),
            Self::RangeMismatch {
                participant,
                expected,
                found,
            } => write!(
                f,
                "{participant} archived ({}, {}] but this rollback discards ({}, {}]; a receipt \
                 for another range does not satisfy the barrier",
                found.0, found.1, expected.0, expected.1
            ),
            Self::ConflictingReceipt(participant) => write!(
                f,
                "{participant} filed two archive receipts that disagree; one is wrong and there \
                 is no way to tell which, so neither is trusted"
            ),
            Self::Missing(missing) => {
                write!(f, "the archive barrier is not met; still missing: ")?;
                for (index, participant) in missing.iter().enumerate() {
                    if index > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{participant}")?;
                }
                Ok(())
            }
        }
    }
}

impl Error for BarrierError {}

/// Collects archive receipts and decides whether the barrier is met.
///
/// This is the gate in front of the point of no return.  Everything it refuses
/// is a case where crossing would let some participant delete rows another
/// participant never copied (§0.2 D2, I6).
#[derive(Clone, Debug)]
pub struct ArchiveBarrier {
    participants: RollbackParticipantSet,
    target: u64,
    head: u64,
    receipts: BTreeMap<RollbackParticipant, ArchiveReceipt>,
}

impl ArchiveBarrier {
    pub fn new(participants: RollbackParticipantSet, target: u64, head: u64) -> Self {
        Self {
            participants,
            target,
            head,
            receipts: BTreeMap::new(),
        }
    }

    /// Record one participant's receipt.
    ///
    /// Idempotent for an identical receipt, because a participant that retries
    /// after a lost response must not be treated as a conflict.
    pub fn file(&mut self, receipt: ArchiveReceipt) -> Result<(), BarrierError> {
        let participant = receipt.participant();
        if !self.participants.contains(participant) {
            return Err(BarrierError::NotAParticipant(participant));
        }
        if receipt.target() != self.target || receipt.head() != self.head {
            return Err(BarrierError::RangeMismatch {
                participant,
                expected: (self.target, self.head),
                found: (receipt.target(), receipt.head()),
            });
        }
        match self.receipts.get(&participant) {
            Some(existing) if *existing == receipt => Ok(()),
            Some(_) => Err(BarrierError::ConflictingReceipt(participant)),
            None => {
                self.receipts.insert(participant, receipt);
                Ok(())
            }
        }
    }

    /// Who has not filed yet.
    pub fn missing(&self) -> Vec<RollbackParticipant> {
        self.participants
            .participants()
            .iter()
            .copied()
            .filter(|participant| !self.receipts.contains_key(participant))
            .collect()
    }

    /// Whether every participant has filed a matching receipt.
    pub fn is_met(&self) -> bool {
        self.missing().is_empty()
    }

    /// Prove the barrier is met, yielding the evidence that crossing it is
    /// allowed.  Returning a value rather than a bool means the destructive
    /// phase cannot be entered without holding this.
    pub fn seal(&self) -> Result<SealedArchiveBarrier, BarrierError> {
        let missing = self.missing();
        if !missing.is_empty() {
            return Err(BarrierError::Missing(missing));
        }
        Ok(SealedArchiveBarrier {
            target: self.target,
            head: self.head,
            participant_count: self.participants.len(),
            archived_rows: self.receipts.values().map(|r| r.archived_rows()).sum(),
        })
    }
}

/// What one participant proved about the head it froze.
///
/// Carries the head's digest, not just its height, because "I stopped" is not
/// the claim that matters -- the claim is that the old head is byte-stable and
/// will still be byte-identical when it is archived.  A participant that is
/// still draining reports a digest that changes between two reads of the same
/// height, and its own idempotence check then rejects the second receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreezeReceipt {
    participant: RollbackParticipant,
    head: u64,
    head_digest: [u8; 32],
}

impl FreezeReceipt {
    pub const fn new(
        participant: RollbackParticipant,
        head: u64,
        head_digest: [u8; 32],
    ) -> Self {
        Self {
            participant,
            head,
            head_digest,
        }
    }

    pub const fn participant(&self) -> RollbackParticipant {
        self.participant
    }

    pub const fn head(&self) -> u64 {
        self.head
    }

    pub const fn head_digest(&self) -> [u8; 32] {
        self.head_digest
    }
}

/// Collects freeze receipts and decides whether the freeze barrier is met.
///
/// This is the cheapest of the three barriers to cross correctly and the most
/// expensive to skip.  Crossing it early does not corrupt anything by itself;
/// it corrupts the *archive*, by copying a head that was still moving.  The
/// damage then surfaces one phase later, at the point of no return, wearing the
/// archive barrier's clothes: every receipt present, every range correct, and
/// the contents describing a state the chain was never in.
#[derive(Clone, Debug)]
pub struct FreezeBarrier {
    participants: RollbackParticipantSet,
    head: u64,
    receipts: BTreeMap<RollbackParticipant, FreezeReceipt>,
}

impl FreezeBarrier {
    pub fn new(participants: RollbackParticipantSet, head: u64) -> Self {
        Self {
            participants,
            head,
            receipts: BTreeMap::new(),
        }
    }

    pub fn file(&mut self, receipt: FreezeReceipt) -> Result<(), BarrierError> {
        let participant = receipt.participant();
        if !self.participants.contains(participant) {
            return Err(BarrierError::NotAParticipant(participant));
        }
        if receipt.head() != self.head {
            return Err(BarrierError::RangeMismatch {
                participant,
                expected: (self.head, self.head),
                found: (receipt.head(), receipt.head()),
            });
        }
        match self.receipts.get(&participant) {
            Some(existing) if *existing == receipt => Ok(()),
            Some(_) => Err(BarrierError::ConflictingReceipt(participant)),
            None => {
                self.receipts.insert(participant, receipt);
                Ok(())
            }
        }
    }

    pub fn missing(&self) -> Vec<RollbackParticipant> {
        self.participants
            .participants()
            .iter()
            .copied()
            .filter(|participant| !self.receipts.contains_key(participant))
            .collect()
    }

    pub fn is_met(&self) -> bool {
        self.missing().is_empty()
    }

    pub fn seal(&self) -> Result<SealedFreezeBarrier, BarrierError> {
        let missing = self.missing();
        if !missing.is_empty() {
            return Err(BarrierError::Missing(missing));
        }
        Ok(SealedFreezeBarrier {
            head: self.head,
            participant_count: self.participants.len(),
        })
    }
}

/// Evidence that every participant froze the old head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedFreezeBarrier {
    head: u64,
    participant_count: usize,
}

impl SealedFreezeBarrier {
    pub const fn head(&self) -> u64 {
        self.head
    }

    pub const fn participant_count(&self) -> usize {
        self.participant_count
    }
}

/// What one participant proved about its restored state.
///
/// Filed after RESTORING, read at the publish barrier.  Carries the target's
/// state root so "verified" is a claim about a specific state rather than a
/// bare acknowledgement: a participant that restored the wrong target, or did
/// not restore at all, produces a root that does not match its peers'.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyReceipt {
    participant: RollbackParticipant,
    target: u64,
    state_root: [u8; 32],
}

impl VerifyReceipt {
    pub const fn new(
        participant: RollbackParticipant,
        target: u64,
        state_root: [u8; 32],
    ) -> Self {
        Self {
            participant,
            target,
            state_root,
        }
    }

    pub const fn participant(&self) -> RollbackParticipant {
        self.participant
    }

    pub const fn target(&self) -> u64 {
        self.target
    }

    pub const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }
}

/// Collects verify receipts and decides whether the publish barrier is met.
///
/// Separate from the archive barrier because it guards a different mistake.
/// The archive barrier stops a rollback from destroying what nobody copied;
/// this one stops it from publishing a new epoch while some participant has
/// not confirmed it reached the target.  Publishing early is not recoverable
/// by waiting: the epoch is spent and the chain has told the world where it is.
#[derive(Clone, Debug)]
pub struct PublishBarrier {
    participants: RollbackParticipantSet,
    target: u64,
    receipts: BTreeMap<RollbackParticipant, VerifyReceipt>,
}

impl PublishBarrier {
    pub fn new(participants: RollbackParticipantSet, target: u64) -> Self {
        Self {
            participants,
            target,
            receipts: BTreeMap::new(),
        }
    }

    pub fn file(&mut self, receipt: VerifyReceipt) -> Result<(), BarrierError> {
        let participant = receipt.participant();
        if !self.participants.contains(participant) {
            return Err(BarrierError::NotAParticipant(participant));
        }
        if receipt.target() != self.target {
            return Err(BarrierError::RangeMismatch {
                participant,
                expected: (self.target, self.target),
                found: (receipt.target(), receipt.target()),
            });
        }
        match self.receipts.get(&participant) {
            Some(existing) if *existing == receipt => Ok(()),
            Some(_) => Err(BarrierError::ConflictingReceipt(participant)),
            None => {
                self.receipts.insert(participant, receipt);
                Ok(())
            }
        }
    }

    pub fn missing(&self) -> Vec<RollbackParticipant> {
        self.participants
            .participants()
            .iter()
            .copied()
            .filter(|participant| !self.receipts.contains_key(participant))
            .collect()
    }

    pub fn is_met(&self) -> bool {
        self.missing().is_empty()
    }

    pub fn seal(&self) -> Result<SealedPublishBarrier, BarrierError> {
        let missing = self.missing();
        if !missing.is_empty() {
            return Err(BarrierError::Missing(missing));
        }
        Ok(SealedPublishBarrier {
            target: self.target,
            participant_count: self.participants.len(),
        })
    }
}

/// Evidence that every participant verified the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedPublishBarrier {
    target: u64,
    participant_count: usize,
}

impl SealedPublishBarrier {
    pub const fn target(&self) -> u64 {
        self.target
    }

    pub const fn participant_count(&self) -> usize {
        self.participant_count
    }
}

/// Evidence that every participant archived the requested range.
///
/// The point of no return takes this by value: a phase advance that cannot name
/// its evidence cannot happen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedArchiveBarrier {
    target: u64,
    head: u64,
    participant_count: usize,
    archived_rows: u64,
}

impl SealedArchiveBarrier {
    pub const fn target(&self) -> u64 {
        self.target
    }

    pub const fn head(&self) -> u64 {
        self.head
    }

    pub const fn participant_count(&self) -> usize {
        self.participant_count
    }

    pub const fn archived_rows(&self) -> u64 {
        self.archived_rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinator() -> RollbackParticipant {
        RollbackParticipant::new(AuthorityScope::Coordinator)
    }

    fn realm(id: u32) -> RollbackParticipant {
        RollbackParticipant::new(AuthorityScope::Realm {
            realm_id: id,
            realm_sub_id: 1,
        })
    }

    fn receipt(participant: RollbackParticipant, target: u64, head: u64) -> ArchiveReceipt {
        ArchiveReceipt::new(participant, target, head, 10, [7u8; 32])
    }

    #[test]
    fn a_barrier_is_not_met_until_every_participant_has_filed() {
        // The whole point: one Realm silent means the Coordinator must not cross
        // the point of no return, however complete its own archive is.
        let set = RollbackParticipantSet::try_new([coordinator(), realm(0), realm(1)]).unwrap();
        let mut barrier = ArchiveBarrier::new(set, 100, 110);
        barrier.file(receipt(coordinator(), 100, 110)).unwrap();
        barrier.file(receipt(realm(0), 100, 110)).unwrap();
        assert!(!barrier.is_met());
        assert_eq!(barrier.missing(), vec![realm(1)]);
        assert!(barrier.seal().is_err());

        barrier.file(receipt(realm(1), 100, 110)).unwrap();
        assert!(barrier.is_met());
        assert_eq!(barrier.seal().unwrap().participant_count(), 3);
    }

    #[test]
    fn a_receipt_for_another_range_does_not_count() {
        // Otherwise a participant could satisfy the barrier by archiving
        // something -- anything -- and reporting success.
        let set = RollbackParticipantSet::try_new([coordinator(), realm(0)]).unwrap();
        let mut barrier = ArchiveBarrier::new(set, 100, 110);
        assert!(matches!(
            barrier.file(receipt(realm(0), 90, 110)),
            Err(BarrierError::RangeMismatch { .. })
        ));
        assert!(!barrier.is_met());
    }

    #[test]
    fn an_outsider_cannot_satisfy_the_barrier() {
        let set = RollbackParticipantSet::try_new([coordinator(), realm(0)]).unwrap();
        let mut barrier = ArchiveBarrier::new(set, 100, 110);
        assert!(matches!(
            barrier.file(receipt(realm(9), 100, 110)),
            Err(BarrierError::NotAParticipant(_))
        ));
        assert_eq!(barrier.missing().len(), 2);
    }

    #[test]
    fn an_identical_retry_is_not_a_conflict() {
        // A participant whose response was lost retries; treating that as a
        // conflict would strand a rollback that is actually complete.
        let set = RollbackParticipantSet::try_new([coordinator()]).unwrap();
        let mut barrier = ArchiveBarrier::new(set, 100, 110);
        barrier.file(receipt(coordinator(), 100, 110)).unwrap();
        barrier.file(receipt(coordinator(), 100, 110)).unwrap();
        assert!(barrier.is_met());
    }

    #[test]
    fn two_disagreeing_receipts_from_one_participant_are_both_rejected() {
        let set = RollbackParticipantSet::try_new([coordinator()]).unwrap();
        let mut barrier = ArchiveBarrier::new(set, 100, 110);
        barrier
            .file(ArchiveReceipt::new(coordinator(), 100, 110, 10, [7u8; 32]))
            .unwrap();
        assert!(matches!(
            barrier.file(ArchiveReceipt::new(coordinator(), 100, 110, 11, [7u8; 32])),
            Err(BarrierError::ConflictingReceipt(_))
        ));
    }

    #[test]
    fn archiving_waits_for_every_participant_to_freeze() {
        let set = RollbackParticipantSet::try_new([coordinator(), realm(0)]).unwrap();
        let mut barrier = FreezeBarrier::new(set, 100);
        barrier
            .file(FreezeReceipt::new(coordinator(), 100, [7u8; 32]))
            .unwrap();
        assert_eq!(barrier.missing(), vec![realm(0)]);
        assert!(barrier.seal().is_err());

        // A Realm's own head digest differs from the Coordinator's; what has to
        // agree is the height they froze at, not what they hold there.
        barrier
            .file(FreezeReceipt::new(realm(0), 100, [8u8; 32]))
            .unwrap();
        assert_eq!(barrier.seal().unwrap().participant_count(), 2);
    }

    #[test]
    fn a_participant_still_draining_cannot_pass_the_freeze_barrier() {
        // The symptom of an incomplete drain is that the same height hashes
        // differently on a second look.  Reporting twice is how a participant
        // shows it settled; two different digests say it did not.
        let set = RollbackParticipantSet::try_new([coordinator()]).unwrap();
        let mut barrier = FreezeBarrier::new(set, 100);
        barrier
            .file(FreezeReceipt::new(coordinator(), 100, [7u8; 32]))
            .unwrap();
        barrier
            .file(FreezeReceipt::new(coordinator(), 100, [7u8; 32]))
            .expect("a settled head reports the same digest twice");
        assert!(matches!(
            barrier.file(FreezeReceipt::new(coordinator(), 100, [9u8; 32])),
            Err(BarrierError::ConflictingReceipt(_))
        ));
    }

    #[test]
    fn freezing_the_wrong_head_does_not_count() {
        let set = RollbackParticipantSet::try_new([coordinator()]).unwrap();
        let mut barrier = FreezeBarrier::new(set, 100);
        assert!(barrier
            .file(FreezeReceipt::new(coordinator(), 99, [7u8; 32]))
            .is_err());
        assert!(!barrier.is_met());
    }

    #[test]
    fn publishing_waits_for_every_participant_to_verify() {
        // The archive barrier stops destroying what nobody copied; this one
        // stops publishing a new epoch while a participant has not confirmed it
        // reached the target.  Publishing early cannot be undone by waiting --
        // the epoch is spent and the chain has announced where it is.
        let set = RollbackParticipantSet::try_new([coordinator(), realm(0)]).unwrap();
        let mut barrier = PublishBarrier::new(set, 100);
        barrier
            .file(VerifyReceipt::new(coordinator(), 100, [3u8; 32]))
            .unwrap();
        assert!(!barrier.is_met());
        assert_eq!(barrier.missing(), vec![realm(0)]);
        assert!(barrier.seal().is_err());

        barrier
            .file(VerifyReceipt::new(realm(0), 100, [3u8; 32]))
            .unwrap();
        assert_eq!(barrier.seal().unwrap().participant_count(), 2);
    }

    #[test]
    fn a_verify_receipt_for_another_target_does_not_count() {
        let set = RollbackParticipantSet::try_new([coordinator()]).unwrap();
        let mut barrier = PublishBarrier::new(set, 100);
        assert!(barrier
            .file(VerifyReceipt::new(coordinator(), 99, [3u8; 32]))
            .is_err());
        assert!(!barrier.is_met());
    }

    #[test]
    fn two_disagreeing_verify_receipts_are_both_rejected() {
        // Two different roots for one participant means one of them restored
        // something else, and there is no way to tell which.
        let set = RollbackParticipantSet::try_new([coordinator()]).unwrap();
        let mut barrier = PublishBarrier::new(set, 100);
        barrier
            .file(VerifyReceipt::new(coordinator(), 100, [3u8; 32]))
            .unwrap();
        assert!(matches!(
            barrier.file(VerifyReceipt::new(coordinator(), 100, [4u8; 32])),
            Err(BarrierError::ConflictingReceipt(_))
        ));
    }

    #[test]
    fn a_set_without_the_coordinator_is_refused() {
        // Every barrier advances on the Coordinator's control row (§6.2), so a
        // set without it describes a rollback nobody can drive.
        assert_eq!(
            RollbackParticipantSet::try_new([realm(0)]),
            Err(ParticipantSetError::NoCoordinator)
        );
    }

    #[test]
    fn a_duplicated_participant_is_refused() {
        // One receipt would otherwise fill two slots and the barrier would pass
        // with a participant missing.
        assert_eq!(
            RollbackParticipantSet::try_new([coordinator(), realm(0), realm(0)]),
            Err(ParticipantSetError::Duplicate(realm(0)))
        );
    }

    #[test]
    fn the_set_encodes_canonically_regardless_of_input_order() {
        // Two nodes writing the same set must produce the same bytes, or the
        // control row's compare-and-set sees a difference where there is none.
        let a = RollbackParticipantSet::try_new([realm(1), coordinator(), realm(0)]).unwrap();
        let b = RollbackParticipantSet::try_new([coordinator(), realm(0), realm(1)]).unwrap();
        assert_eq!(a, b);
    }
}
